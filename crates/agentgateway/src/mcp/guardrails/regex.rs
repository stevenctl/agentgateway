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
	#[serde(default)]
	pub rejection: McpRejection,
	#[serde(default)]
	pub failure_mode: FailureMode,
}

pub(crate) async fn run_request<P: DeserializeOwned>(
	rp: &RegexProcessor,
	method: &str,
	params: Option<&mut Bytes>,
) -> Outcome<P> {
	let Some(body) = params else {
		return Outcome::Pass;
	};
	let rules = &rp.rules;
	match method {
		methods::TOOLS_CALL | methods::PROMPTS_GET => edit(rp, method, body, "params", |body| {
			mask_all(body, "arguments", rules)
		}),
		methods::RESOURCES_READ => edit(rp, method, body, "params", |body| {
			mask_field(body, "uri", rules)
		}),
		_ => Outcome::Pass,
	}
}

pub(crate) async fn run_response(
	rp: &RegexProcessor,
	method: &str,
	body: &mut Bytes,
) -> Outcome<ServerResult> {
	let rules = &rp.rules;
	match method {
		methods::TOOLS_LIST => edit(rp, method, body, "result", |b| {
			drop_matching(b, "tools", rules)
		}),
		methods::PROMPTS_LIST => edit(rp, method, body, "result", |b| {
			drop_matching(b, "prompts", rules)
		}),
		methods::RESOURCES_LIST => edit(rp, method, body, "result", |b| {
			drop_matching(b, "resources", rules)
		}),
		methods::RESOURCES_TEMPLATES_LIST => edit(rp, method, body, "result", |b| {
			drop_matching(b, "resourceTemplates", rules)
		}),
		methods::TOOLS_CALL => edit(rp, method, body, "result", |b| {
			mask_array(b, "content", |c| mask_content_block(c, rules))
				.then(|| mask_all(b, "structuredContent", rules))
		}),
		methods::RESOURCES_READ => edit(rp, method, body, "result", |b| {
			mask_array(b, "contents", |v| mask_field(v, "text", rules))
		}),
		methods::PROMPTS_GET => edit(rp, method, body, "result", |b| {
			mask_field(b, "description", rules).then(|| {
				mask_array(b, "messages", |msg| match msg.get_mut("content") {
					Some(content) => mask_content_block(content, rules),
					None => VisitOutcome::Pass,
				})
			})
		}),
		_ => Outcome::Pass,
	}
}

fn edit<P: DeserializeOwned>(
	rp: &RegexProcessor,
	method: &str,
	body: &mut Bytes,
	what: &str,
	visit: impl FnOnce(&mut Value) -> VisitOutcome,
) -> Outcome<P> {
	let mut value = match serde_json::from_slice::<Value>(body) {
		Ok(value) => value,
		Err(error) => return on_error(rp.failure_mode, method, &format!("decode {what}: {error}")),
	};
	match visit(&mut value) {
		VisitOutcome::Pass => Outcome::Pass,
		VisitOutcome::Rejected => Outcome::Reject(rp.rejection.to_error()),
		VisitOutcome::Mutated => match reserialize::<P>(&value) {
			Some((parsed, bytes)) => {
				*body = bytes;
				Outcome::Mutated(parsed)
			},
			None => on_error(rp.failure_mode, method, &format!("re-encode masked {what}")),
		},
	}
}

enum TextDecision {
	Pass,
	Replace(String),
	Reject,
}

fn inspect(text: &str, rules: &RegexRules) -> TextDecision {
	match Policy::apply_prompt_guard_regex(text, rules) {
		None => TextDecision::Pass,
		Some(RegexResult::Mask(replacement)) => TextDecision::Replace(replacement),
		Some(RegexResult::Reject) => TextDecision::Reject,
	}
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

	fn then(self, next: impl FnOnce() -> Self) -> Self {
		if self == Self::Rejected {
			self // alredy rejected, short-circuit
		} else {
			self.merge(next())
		}
	}
}

fn each<T>(
	items: impl IntoIterator<Item = T>,
	mut f: impl FnMut(T) -> VisitOutcome,
) -> VisitOutcome {
	let mut outcome = VisitOutcome::Pass;
	for item in items {
		outcome = outcome.merge(f(item));
		if outcome == VisitOutcome::Rejected {
			break;
		}
	}
	outcome
}

fn walk(value: &mut Value, rules: &RegexRules) -> VisitOutcome {
	match value {
		// TODO we need to look at non-string fields too probably
		Value::String(text) => mask_string(text, rules),
		Value::Array(values) => each(values, |v| walk(v, rules)),
		Value::Object(values) => each(values.values_mut(), |v| walk(v, rules)),
		_ => VisitOutcome::Pass,
	}
}

// look at a specific field by name
fn mask_field(value: &mut Value, key: &str, rules: &RegexRules) -> VisitOutcome {
	match value.get_mut(key) {
		Some(Value::String(text)) => mask_string(text, rules),
		_ => VisitOutcome::Pass,
	}
}

// look at the entirety of the object at the given key, recursively
fn mask_all(value: &mut Value, key: &str, rules: &RegexRules) -> VisitOutcome {
	match value.get_mut(key) {
		Some(child) => walk(child, rules),
		None => VisitOutcome::Pass,
	}
}

// look at each element of the array at the given key,
// used when a specific shape is expected for each element
fn mask_array(
	value: &mut Value,
	key: &str,
	mut f: impl FnMut(&mut Value) -> VisitOutcome,
) -> VisitOutcome {
	match value.get_mut(key).and_then(Value::as_array_mut) {
		Some(items) => each(items, |item| f(item)),
		None => VisitOutcome::Pass,
	}
}

fn mask_string(text: &mut String, rules: &RegexRules) -> VisitOutcome {
	match inspect(text, rules) {
		TextDecision::Pass => VisitOutcome::Pass,
		TextDecision::Replace(replacement) if replacement == *text => VisitOutcome::Pass,
		TextDecision::Replace(replacement) => {
			*text = replacement;
			VisitOutcome::Mutated
		},
		TextDecision::Reject => VisitOutcome::Rejected,
	}
}

fn mask_content_block(block: &mut Value, rules: &RegexRules) -> VisitOutcome {
	match block.get("type").and_then(Value::as_str) {
		Some("text") => mask_field(block, "text", rules),
		Some("resource") => match block.get_mut("resource") {
			Some(resource) => {
				mask_field(resource, "text", rules).then(|| match resource.get_mut("resource") {
					Some(contents) => mask_field(contents, "text", rules),
					None => VisitOutcome::Pass,
				})
			},
			None => VisitOutcome::Pass,
		},
		Some("resource_link") => each(["name", "title", "description"], |key| {
			mask_field(block, key, rules)
		}),
		_ => VisitOutcome::Pass,
	}
}

// drop_matching removes entries rather than mutating masking.
// this is a conservative way to avoid mutating things like identifiers and schema that
// the client/agent would rely on for subsequent calls, for example:
// tools/list -> modify get_ssn to get_<masked> -> tools/call get_<masked> -> error because tool not found
fn drop_matching(value: &mut Value, list_key: &str, rules: &RegexRules) -> VisitOutcome {
	let Some(entries) = value.get_mut(list_key).and_then(Value::as_array_mut) else {
		return VisitOutcome::Pass;
	};

	let mut outcome = VisitOutcome::Pass;
	entries.retain_mut(|entry| match walk(entry, rules) {
		VisitOutcome::Pass => true,
		VisitOutcome::Mutated => {
			outcome = outcome.merge(VisitOutcome::Mutated);
			false
		},
		VisitOutcome::Rejected => {
			outcome = VisitOutcome::Rejected;
			false
		},
	});
	outcome
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
	use serde_json::{json, Value};

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
