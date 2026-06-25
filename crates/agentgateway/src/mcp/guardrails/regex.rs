//! The regex/PII MCP guardrail variant.
//!
//! Regexes run directly over the MCP JSON payload. This avoids materializing the
//! payload as synthetic LLM messages while sharing the existing regex semantics.

use bytes::Bytes;
use rmcp::model::{ErrorCode, ErrorData, ServerResult};
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::methods;
use super::{FailureMode, McpRejection, Outcome};
use crate::llm::policy::{Policy, RegexResult, RegexRules};
use crate::*;

#[apply(schema!)]
pub struct RegexProcessor {
	#[serde(flatten)]
	pub rules: RegexRules,
	/// Error returned to the client when a rule matches under `action: reject`.
	#[serde(default)]
	pub rejection: McpRejection,
	/// Behavior when the body cannot be inspected or re-encoded.
	#[serde(default)]
	pub failure_mode: FailureMode,
}

enum TextDecision {
	Pass,
	Replace(String),
	Reject,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum VisitOutcome {
	Pass,
	Mutated,
	Rejected,
}

impl VisitOutcome {
	fn merge(self, other: Self) -> Self {
		match (self, other) {
			(Self::Rejected, _) | (_, Self::Rejected) => Self::Rejected,
			(Self::Mutated, _) | (_, Self::Mutated) => Self::Mutated,
			_ => Self::Pass,
		}
	}
}

pub(crate) async fn run_request<P: DeserializeOwned>(
	rp: &RegexProcessor,
	method: &str,
	params: Option<&mut Bytes>,
) -> Outcome<P> {
	if !supports_request(method) {
		return Outcome::Pass;
	}
	let Some(body) = params else {
		return Outcome::Pass;
	};
	let mut value = match serde_json::from_slice::<Value>(body) {
		Ok(value) => value,
		Err(error) => {
			return on_error(rp.failure_mode, method, &format!("decode params: {error}"));
		},
	};
	let outcome = visit_request(method, &mut value, &mut |text| inspect(rp, text));
	finish::<P>(rp, method, body, value, outcome, "re-encode masked params")
}

pub(crate) async fn run_response(
	rp: &RegexProcessor,
	method: &str,
	body: &mut Bytes,
) -> Outcome<ServerResult> {
	if !supports_response(method) {
		return Outcome::Pass;
	}
	let mut value = match serde_json::from_slice::<Value>(body) {
		Ok(value) => value,
		Err(error) => {
			return on_error(rp.failure_mode, method, &format!("decode result: {error}"));
		},
	};
	let outcome = if is_list_response(method) {
		filter_list_entries(method, &mut value, &mut |text| inspect(rp, text))
	} else {
		visit_response(method, &mut value, &mut |text| inspect(rp, text))
	};
	finish::<ServerResult>(rp, method, body, value, outcome, "re-encode masked result")
}

fn supports_request(method: &str) -> bool {
	matches!(
		method,
		methods::TOOLS_CALL | methods::PROMPTS_GET | methods::RESOURCES_READ
	)
}

fn supports_response(method: &str) -> bool {
	matches!(
		method,
		methods::TOOLS_CALL
			| methods::PROMPTS_GET
			| methods::RESOURCES_READ
			| methods::TOOLS_LIST
			| methods::PROMPTS_LIST
			| methods::RESOURCES_LIST
			| methods::RESOURCES_TEMPLATES_LIST
	)
}

fn is_list_response(method: &str) -> bool {
	list_field(method).is_some()
}

fn list_field(method: &str) -> Option<&'static str> {
	match method {
		methods::TOOLS_LIST => Some("tools"),
		methods::PROMPTS_LIST => Some("prompts"),
		methods::RESOURCES_LIST => Some("resources"),
		methods::RESOURCES_TEMPLATES_LIST => Some("resourceTemplates"),
		_ => None,
	}
}

fn visit_request(
	method: &str,
	params: &mut Value,
	visit: &mut impl FnMut(&str) -> TextDecision,
) -> VisitOutcome {
	match method {
		methods::TOOLS_CALL | methods::PROMPTS_GET => params
			.get_mut("arguments")
			.map(|arguments| walk(arguments, visit))
			.unwrap_or(VisitOutcome::Pass),
		methods::RESOURCES_READ => field(params, "uri", visit),
		_ => VisitOutcome::Pass,
	}
}

fn visit_response(
	method: &str,
	result: &mut Value,
	visit: &mut impl FnMut(&str) -> TextDecision,
) -> VisitOutcome {
	match method {
		methods::TOOLS_CALL => {
			let mut outcome = content_array(result, "content", visit);
			if outcome != VisitOutcome::Rejected {
				if let Some(structured) = result.get_mut("structuredContent") {
					outcome = outcome.merge(walk(structured, visit));
				}
			}
			outcome
		},
		methods::RESOURCES_READ => array_fields(result, "contents", "text", visit),
		methods::PROMPTS_GET => {
			let mut outcome = field(result, "description", visit);
			if outcome != VisitOutcome::Rejected {
				if let Some(messages) = result.get_mut("messages").and_then(Value::as_array_mut) {
					for message in messages {
						let Some(content) = message.get_mut("content") else {
							continue;
						};
						outcome = outcome.merge(content_block(content, visit));
						if outcome == VisitOutcome::Rejected {
							break;
						}
					}
				}
			}
			outcome
		},
		_ => VisitOutcome::Pass,
	}
}

/// Drop list entries for which any inspected field would be rewritten. A rejection
/// still rejects the entire response.
fn filter_list_entries(
	method: &str,
	result: &mut Value,
	visit: &mut impl FnMut(&str) -> TextDecision,
) -> VisitOutcome {
	let Some(field_name) = list_field(method) else {
		return VisitOutcome::Pass;
	};
	let Some(entries) = result.get_mut(field_name).and_then(Value::as_array_mut) else {
		return VisitOutcome::Pass;
	};

	let mut drop = vec![false; entries.len()];
	for (index, entry) in entries.iter().enumerate() {
		for key in ["name", "title", "description"] {
			let Some(text) = entry.get(key).and_then(Value::as_str) else {
				continue;
			};
			match visit(text) {
				TextDecision::Pass => {},
				TextDecision::Replace(_) => {
					drop[index] = true;
					break;
				},
				TextDecision::Reject => return VisitOutcome::Rejected,
			}
		}
	}

	if !drop.iter().any(|drop| *drop) {
		return VisitOutcome::Pass;
	}
	let mut index = 0;
	entries.retain(|_| {
		let keep = !drop[index];
		index += 1;
		keep
	});
	VisitOutcome::Mutated
}

fn apply(text: &mut String, visit: &mut impl FnMut(&str) -> TextDecision) -> VisitOutcome {
	match visit(text) {
		TextDecision::Pass => VisitOutcome::Pass,
		TextDecision::Replace(replacement) if replacement == *text => VisitOutcome::Pass,
		TextDecision::Replace(replacement) => {
			*text = replacement;
			VisitOutcome::Mutated
		},
		TextDecision::Reject => VisitOutcome::Rejected,
	}
}

fn field(
	value: &mut Value,
	key: &str,
	visit: &mut impl FnMut(&str) -> TextDecision,
) -> VisitOutcome {
	match value.get_mut(key) {
		Some(Value::String(text)) => apply(text, visit),
		_ => VisitOutcome::Pass,
	}
}

fn walk(value: &mut Value, visit: &mut impl FnMut(&str) -> TextDecision) -> VisitOutcome {
	match value {
		Value::String(text) => apply(text, visit),
		Value::Array(values) => {
			let mut outcome = VisitOutcome::Pass;
			for value in values {
				outcome = outcome.merge(walk(value, visit));
				if outcome == VisitOutcome::Rejected {
					break;
				}
			}
			outcome
		},
		Value::Object(values) => {
			let mut outcome = VisitOutcome::Pass;
			for value in values.values_mut() {
				outcome = outcome.merge(walk(value, visit));
				if outcome == VisitOutcome::Rejected {
					break;
				}
			}
			outcome
		},
		_ => VisitOutcome::Pass,
	}
}

fn content_array(
	result: &mut Value,
	field_name: &str,
	visit: &mut impl FnMut(&str) -> TextDecision,
) -> VisitOutcome {
	let Some(contents) = result.get_mut(field_name).and_then(Value::as_array_mut) else {
		return VisitOutcome::Pass;
	};
	let mut outcome = VisitOutcome::Pass;
	for content in contents {
		outcome = outcome.merge(content_block(content, visit));
		if outcome == VisitOutcome::Rejected {
			break;
		}
	}
	outcome
}

fn array_fields(
	result: &mut Value,
	array_name: &str,
	field_name: &str,
	visit: &mut impl FnMut(&str) -> TextDecision,
) -> VisitOutcome {
	let Some(values) = result.get_mut(array_name).and_then(Value::as_array_mut) else {
		return VisitOutcome::Pass;
	};
	let mut outcome = VisitOutcome::Pass;
	for value in values {
		outcome = outcome.merge(field(value, field_name, visit));
		if outcome == VisitOutcome::Rejected {
			break;
		}
	}
	outcome
}

fn content_block(block: &mut Value, visit: &mut impl FnMut(&str) -> TextDecision) -> VisitOutcome {
	match block.get("type").and_then(Value::as_str) {
		Some("text") => field(block, "text", visit),
		Some("resource") => {
			let Some(resource) = block.get_mut("resource") else {
				return VisitOutcome::Pass;
			};
			let mut outcome = field(resource, "text", visit);
			if outcome != VisitOutcome::Rejected {
				if let Some(contents) = resource.get_mut("resource") {
					outcome = outcome.merge(field(contents, "text", visit));
				}
			}
			outcome
		},
		Some("resource_link") => {
			let mut outcome = VisitOutcome::Pass;
			for key in ["name", "title", "description"] {
				outcome = outcome.merge(field(block, key, visit));
				if outcome == VisitOutcome::Rejected {
					break;
				}
			}
			outcome
		},
		_ => VisitOutcome::Pass,
	}
}

fn inspect(rp: &RegexProcessor, text: &str) -> TextDecision {
	match Policy::apply_prompt_guard_regex(text, &rp.rules) {
		None => TextDecision::Pass,
		Some(RegexResult::Mask(replacement)) => TextDecision::Replace(replacement),
		Some(RegexResult::Reject) => TextDecision::Reject,
	}
}

fn finish<P: DeserializeOwned>(
	rp: &RegexProcessor,
	method: &str,
	body: &mut Bytes,
	value: Value,
	outcome: VisitOutcome,
	encode_error: &str,
) -> Outcome<P> {
	match outcome {
		VisitOutcome::Pass => Outcome::Pass,
		VisitOutcome::Rejected => Outcome::Reject(rp.rejection.to_error()),
		VisitOutcome::Mutated => match reserialize::<P>(&value) {
			Some((parsed, bytes)) => {
				*body = bytes;
				Outcome::Mutated(parsed)
			},
			None => on_error(rp.failure_mode, method, encode_error),
		},
	}
}

fn reserialize<P: DeserializeOwned>(value: &Value) -> Option<(P, Bytes)> {
	let bytes: Bytes = serde_json::to_vec(value).ok()?.into();
	let parsed = serde_json::from_slice::<P>(&bytes)
		.inspect_err(|error| tracing::warn!(%error, "mcpGuardrails: re-encode failed to parse"))
		.ok()?;
	Some((parsed, bytes))
}

fn on_error<T>(failure_mode: FailureMode, method: &str, reason: &str) -> Outcome<T> {
	match failure_mode {
		FailureMode::FailOpen => {
			tracing::warn!(method, reason, "mcpGuardrails: processor failing open");
			Outcome::Pass
		},
		FailureMode::FailClosed => {
			tracing::warn!(method, reason, "mcpGuardrails: processor failing closed");
			Outcome::Reject(ErrorData::new(
				ErrorCode::INTERNAL_ERROR,
				"mcpGuardrails processor error",
				None,
			))
		},
	}
}

#[cfg(test)]
mod tests {
	use rmcp::model::CallToolRequestParams;
	use serde_json::{Value, json};

	use super::*;
	use crate::llm::policy::{Action, RegexRule};
	use crate::mcp::guardrails::{client, methods};

	fn processor(action: Action, patterns: &[&str]) -> RegexProcessor {
		RegexProcessor {
			rules: RegexRules {
				action,
				rules: patterns
					.iter()
					.map(|p| RegexRule::Regex {
						pattern: regex::Regex::new(p).unwrap(),
					})
					.collect(),
			},
			rejection: McpRejection::default(),
			failure_mode: FailureMode::default(),
		}
	}

	fn ssn_processor(action: Action) -> RegexProcessor {
		RegexProcessor {
			rules: RegexRules {
				action,
				rules: vec![RegexRule::Builtin {
					builtin: crate::llm::policy::Builtin::Ssn,
				}],
			},
			rejection: McpRejection::default(),
			failure_mode: FailureMode::default(),
		}
	}

	async fn req<P: DeserializeOwned>(
		rp: &RegexProcessor,
		method: &str,
		params: Option<&mut Bytes>,
	) -> Outcome<P> {
		run_request::<P>(rp, method, params).await
	}

	async fn resp(rp: &RegexProcessor, method: &str, body: &mut Bytes) -> Outcome<ServerResult> {
		run_response(rp, method, body).await
	}

	#[test]
	fn deser_regex_processor() {
		let cfg = r#"
action: mask
rules:
  - builtin: ssn
  - pattern: "AKIA[0-9A-Z]{16}"
rejection:
  message: nope
"#;
		let rp: RegexProcessor = serde_yaml::from_str(cfg).unwrap();
		assert_eq!(rp.rules.rules.len(), 2);
		assert_eq!(rp.rejection.message.as_deref(), Some("nope"));
		assert_eq!(rp.failure_mode, FailureMode::FailClosed);
	}

	#[tokio::test]
	async fn unparseable_body_honors_failure_mode() {
		let mut rp = ssn_processor(Action::Mask);
		let mut bytes: Bytes = Bytes::from_static(b"not json");
		assert!(matches!(
			req::<CallToolRequestParams>(&rp, methods::TOOLS_CALL, Some(&mut bytes)).await,
			Outcome::Reject(_)
		));

		rp.failure_mode = FailureMode::FailOpen;
		let mut bytes: Bytes = Bytes::from_static(b"not json");
		assert!(matches!(
			req::<CallToolRequestParams>(&rp, methods::TOOLS_CALL, Some(&mut bytes)).await,
			Outcome::Pass
		));
	}

	#[tokio::test]
	async fn request_mask_rewrites_arguments() {
		let rp = ssn_processor(Action::Mask);
		let params = json!({"name": "echo", "arguments": {"note": "ssn 123-45-6789 here"}});
		let mut bytes: Bytes = serde_json::to_vec(&params).unwrap().into();
		let outcome = req::<CallToolRequestParams>(&rp, methods::TOOLS_CALL, Some(&mut bytes)).await;
		assert!(matches!(outcome, Outcome::Mutated(_)));
		let masked: Value = serde_json::from_slice(&bytes).unwrap();
		assert_eq!(masked["arguments"]["note"], json!("ssn <SSN> here"));
	}

	#[tokio::test]
	async fn request_reject_returns_error() {
		let mut rp = ssn_processor(Action::Reject);
		rp.rejection.message = Some("blocked SSN".to_string());
		let params = json!({"name": "echo", "arguments": {"note": "123-45-6789"}});
		let mut bytes: Bytes = serde_json::to_vec(&params).unwrap().into();
		let Outcome::Reject(err) =
			req::<CallToolRequestParams>(&rp, methods::TOOLS_CALL, Some(&mut bytes)).await
		else {
			panic!("expected reject");
		};
		assert_eq!(err.code, client::PERMISSION_DENIED);
		assert_eq!(err.message.as_ref(), "blocked SSN");
	}

	#[tokio::test]
	async fn request_no_match_passes() {
		let rp = ssn_processor(Action::Mask);
		let params = json!({"name": "echo", "arguments": {"note": "nothing here"}});
		let mut bytes: Bytes = serde_json::to_vec(&params).unwrap().into();
		let outcome = req::<CallToolRequestParams>(&rp, methods::TOOLS_CALL, Some(&mut bytes)).await;
		assert!(matches!(outcome, Outcome::Pass));
	}

	#[tokio::test]
	async fn request_without_body_passes() {
		let rp = ssn_processor(Action::Mask);
		let outcome = req::<CallToolRequestParams>(&rp, "tools/list", None).await;
		assert!(matches!(outcome, Outcome::Pass));
	}

	#[tokio::test]
	async fn unsupported_method_does_not_parse_body() {
		let rp = ssn_processor(Action::Mask);
		let mut request = Bytes::from_static(b"not json");
		assert!(matches!(
			req::<CallToolRequestParams>(&rp, "custom/method", Some(&mut request)).await,
			Outcome::Pass
		));

		let mut response = Bytes::from_static(b"not json");
		assert!(matches!(
			resp(&rp, "custom/method", &mut response).await,
			Outcome::Pass
		));
	}

	#[tokio::test]
	async fn response_tools_call_masks_text_content() {
		let rp = processor(Action::Mask, &["secret"]);
		let result = json!({"content": [{"type": "text", "text": "the secret value"}]});
		let mut bytes: Bytes = serde_json::to_vec(&result).unwrap().into();
		let outcome = resp(&rp, methods::TOOLS_CALL, &mut bytes).await;
		assert!(matches!(outcome, Outcome::Mutated(_)));
		let masked: Value = serde_json::from_slice(&bytes).unwrap();
		assert_eq!(masked["content"][0]["text"], json!("the <masked> value"));
	}

	#[tokio::test]
	async fn response_tools_call_masks_embedded_resource() {
		let rp = processor(Action::Mask, &["secret"]);
		let result = json!({"content": [
			{"type": "resource", "resource": {"uri": "file://x", "text": "a secret here"}},
		]});
		let mut bytes: Bytes = serde_json::to_vec(&result).unwrap().into();
		let outcome = resp(&rp, methods::TOOLS_CALL, &mut bytes).await;
		assert!(matches!(outcome, Outcome::Mutated(_)));
		let masked: Value = serde_json::from_slice(&bytes).unwrap();
		assert_eq!(
			masked["content"][0]["resource"]["text"],
			json!("a <masked> here")
		);
	}

	#[tokio::test]
	async fn response_tools_call_masks_structured_content_and_resource_links() {
		let rp = processor(Action::Mask, &["secret"]);
		let result = json!({
			"content": [{
				"type": "resource_link",
				"uri": "file://x",
				"name": "secret link",
				"description": "contains secret",
			}],
			"structuredContent": {"nested": {"value": "deep secret"}},
		});
		let mut bytes: Bytes = serde_json::to_vec(&result).unwrap().into();
		assert!(matches!(
			resp(&rp, methods::TOOLS_CALL, &mut bytes).await,
			Outcome::Mutated(_)
		));
		let masked: Value = serde_json::from_slice(&bytes).unwrap();
		assert_eq!(masked["content"][0]["name"], json!("<masked> link"));
		assert_eq!(
			masked["content"][0]["description"],
			json!("contains <masked>")
		);
		assert_eq!(
			masked["structuredContent"]["nested"]["value"],
			json!("deep <masked>")
		);
	}

	#[tokio::test]
	async fn response_prompts_get_masks_description_and_embedded_resource() {
		let rp = processor(Action::Mask, &["secret"]);
		let result = json!({
			"description": "secret prompt",
			"messages": [{
				"role": "user",
				"content": {
					"type": "resource",
					"resource": {"resource": {"uri": "file://x", "text": "secret resource"}}
				}
			}],
		});
		let mut bytes: Bytes = serde_json::to_vec(&result).unwrap().into();
		assert!(matches!(
			resp(&rp, methods::PROMPTS_GET, &mut bytes).await,
			Outcome::Mutated(_)
		));
		let masked: Value = serde_json::from_slice(&bytes).unwrap();
		assert_eq!(masked["description"], json!("<masked> prompt"));
		assert_eq!(
			masked["messages"][0]["content"]["resource"]["resource"]["text"],
			json!("<masked> resource")
		);
	}

	#[tokio::test]
	async fn response_list_drops_matching_entry() {
		let rp = processor(Action::Mask, &["dangerous"]);
		let result = json!({"tools": [
			{"name": "safe", "description": "ok"},
			{"name": "evil", "description": "dangerous tool"},
		]});
		let mut bytes: Bytes = serde_json::to_vec(&result).unwrap().into();
		let outcome = resp(&rp, methods::TOOLS_LIST, &mut bytes).await;
		assert!(matches!(outcome, Outcome::Mutated(_)));
		let filtered: Value = serde_json::from_slice(&bytes).unwrap();
		assert_eq!(filtered["tools"].as_array().unwrap().len(), 1);
		assert_eq!(filtered["tools"][0]["name"], json!("safe"));
	}

	#[tokio::test]
	async fn response_list_drops_entry_on_name_match() {
		let rp = processor(Action::Mask, &["^delete_"]);
		let result = json!({"tools": [
			{"name": "echo", "description": "echoes input"},
			{"name": "delete_db", "description": "drops a database"},
		]});
		let mut bytes: Bytes = serde_json::to_vec(&result).unwrap().into();
		let outcome = resp(&rp, methods::TOOLS_LIST, &mut bytes).await;
		assert!(matches!(outcome, Outcome::Mutated(_)));
		let filtered: Value = serde_json::from_slice(&bytes).unwrap();
		assert_eq!(filtered["tools"].as_array().unwrap().len(), 1);
		assert_eq!(filtered["tools"][0]["name"], json!("echo"));
	}

	#[tokio::test]
	async fn response_list_reject_blocks_whole_response() {
		let rp = processor(Action::Reject, &["dangerous"]);
		let result = json!({"tools": [
			{"name": "safe", "description": "ok"},
			{"name": "evil", "description": "dangerous tool"},
		]});
		let mut bytes: Bytes = serde_json::to_vec(&result).unwrap().into();
		let outcome = resp(&rp, methods::TOOLS_LIST, &mut bytes).await;
		assert!(matches!(outcome, Outcome::Reject(_)));
	}
}
