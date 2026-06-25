use bytes::Bytes;
use rmcp::model::ServerResult;
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::payload::{self, on_error, reserialize, VisitOutcome};
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
	let Some(visit) = payload::request_visit(method) else {
		return Outcome::Pass;
	};
	let Some(body) = params else {
		return Outcome::Pass;
	};
	let mut leaf = |text: &mut String| mask_string(text, &rp.rules);
	edit(rp, method, body, "params", |value| visit(value, &mut leaf))
}

pub(crate) async fn run_response(
	rp: &RegexProcessor,
	method: &str,
	body: &mut Bytes,
) -> Outcome<ServerResult> {
	let Some(visit) = payload::response_visit(method) else {
		return Outcome::Pass;
	};
	let mut leaf = |text: &mut String| mask_string(text, &rp.rules);
	edit(rp, method, body, "result", |value| visit(value, &mut leaf))
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
