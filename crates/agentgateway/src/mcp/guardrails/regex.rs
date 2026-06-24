use bytes::Bytes;
use rmcp::model::{ErrorCode, ErrorData, ServerResult};
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::payload::{self, LeafVerdict, Scan};
use super::{FailureMode, Outcome, client};
use crate::llm::policy::{Policy, RegexResult, RegexRules};
use crate::*;

const DEFAULT_REJECTION: &str = "Request blocked by guardrail policy";

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

#[apply(schema!)]
#[derive(Default)]
pub struct McpRejection {
	/// JSON-RPC error message. Defaults to a generic policy-violation message.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub message: Option<String>,
}

impl RegexProcessor {
	fn rule_rejection(&self) -> ErrorData {
		let message = self
			.rejection
			.message
			.clone()
			.unwrap_or_else(|| DEFAULT_REJECTION.to_string());
		ErrorData::new(client::PERMISSION_DENIED, message, None)
	}

	fn on_error<T>(&self, method: &str, reason: &str) -> Outcome<T> {
		match self.failure_mode {
			FailureMode::FailOpen => {
				tracing::warn!(
					method,
					reason,
					"mcpGuardrails: regex processor failing open"
				);
				Outcome::Pass
			},
			FailureMode::FailClosed => {
				tracing::warn!(
					method,
					reason,
					"mcpGuardrails: regex processor failing closed"
				);
				Outcome::Reject(ErrorData::new(
					ErrorCode::INTERNAL_ERROR,
					format!("mcpGuardrails regex processor error: {reason}"),
					None,
				))
			},
		}
	}
}

pub(crate) fn run_request<P: DeserializeOwned>(
	rp: &RegexProcessor,
	method: &str,
	params: Option<&mut Bytes>,
) -> Outcome<P> {
	if !payload::supports_request(method) {
		return Outcome::Pass;
	}
	let Some(dest) = params else {
		return Outcome::Pass;
	};
	let mut value = match serde_json::from_slice::<Value>(dest) {
		Ok(v) => v,
		Err(e) => return rp.on_error(method, &format!("decode params: {e}")),
	};
	let edits = match payload::scan_request(method, &value, &mut |t| verdict(rp, t)) {
		Scan::Pass => return Outcome::Pass,
		Scan::Reject => return Outcome::Reject(rp.rule_rejection()),
		Scan::Edits(edits) => edits,
	};
	payload::apply_edits(&mut value, edits);
	match reserialize::<P>(&value) {
		Some((parsed, bytes)) => {
			*dest = bytes;
			Outcome::Mutated(parsed)
		},
		None => rp.on_error(method, "re-encode masked params"),
	}
}

pub(crate) fn run_response(
	rp: &RegexProcessor,
	method: &str,
	body: &mut Bytes,
) -> Outcome<ServerResult> {
	if !payload::supports_response(method) {
		return Outcome::Pass;
	}
	let mut value = match serde_json::from_slice::<Value>(body) {
		Ok(v) => v,
		Err(e) => return rp.on_error(method, &format!("decode result: {e}")),
	};
	let edits = match payload::scan_response(method, &value, &mut |t| verdict(rp, t)) {
		Scan::Pass => return Outcome::Pass,
		Scan::Reject => return Outcome::Reject(rp.rule_rejection()),
		Scan::Edits(edits) => edits,
	};
	payload::apply_edits(&mut value, edits);
	match reserialize::<ServerResult>(&value) {
		Some((parsed, bytes)) => {
			*body = bytes;
			Outcome::Mutated(parsed)
		},
		None => rp.on_error(method, "re-encode masked result"),
	}
}

fn verdict(rp: &RegexProcessor, text: &str) -> LeafVerdict {
	match Policy::apply_prompt_guard_regex(text, &rp.rules) {
		None => LeafVerdict::Clean,
		Some(RegexResult::Mask(masked)) => LeafVerdict::Masked(masked),
		Some(RegexResult::Reject) => LeafVerdict::Rejected,
	}
}

fn reserialize<P: DeserializeOwned>(value: &Value) -> Option<(P, Bytes)> {
	let bytes: Bytes = serde_json::to_vec(value).ok()?.into();
	let parsed = serde_json::from_slice::<P>(&bytes)
		.inspect_err(|e| tracing::warn!(error = %e, "mcpGuardrails: regex re-encode failed to parse"))
		.ok()?;
	Some((parsed, bytes))
}

#[cfg(test)]
mod tests {
	use rmcp::model::CallToolRequestParams;
	use serde_json::json;

	use super::*;
	use crate::llm::policy::{Action, RegexRule};
	use crate::mcp::guardrails::methods;

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

	#[test]
	fn unparseable_body_honors_failure_mode() {
		let mut rp = ssn_processor(Action::Mask);
		let mut bytes: Bytes = Bytes::from_static(b"not json");
		let out = run_request::<CallToolRequestParams>(&rp, methods::TOOLS_CALL, Some(&mut bytes));
		assert!(matches!(out, Outcome::Reject(_)));

		rp.failure_mode = FailureMode::FailOpen;
		let mut bytes: Bytes = Bytes::from_static(b"not json");
		let out = run_request::<CallToolRequestParams>(&rp, methods::TOOLS_CALL, Some(&mut bytes));
		assert!(matches!(out, Outcome::Pass));
	}

	#[test]
	fn request_mask_rewrites_arguments() {
		let rp = ssn_processor(Action::Mask);
		let params = json!({"name": "echo", "arguments": {"note": "ssn 123-45-6789 here"}});
		let mut bytes: Bytes = serde_json::to_vec(&params).unwrap().into();
		let outcome = run_request::<CallToolRequestParams>(&rp, methods::TOOLS_CALL, Some(&mut bytes));
		assert!(matches!(outcome, Outcome::Mutated(_)));
		let masked: Value = serde_json::from_slice(&bytes).unwrap();
		assert_eq!(masked["arguments"]["note"], json!("ssn <SSN> here"));
	}

	#[test]
	fn request_reject_returns_error() {
		let rp = ssn_processor(Action::Reject);
		let params = json!({"name": "echo", "arguments": {"note": "123-45-6789"}});
		let mut bytes: Bytes = serde_json::to_vec(&params).unwrap().into();
		let outcome = run_request::<CallToolRequestParams>(&rp, methods::TOOLS_CALL, Some(&mut bytes));
		let Outcome::Reject(err) = outcome else {
			panic!("expected reject");
		};
		assert_eq!(err.code, client::PERMISSION_DENIED);
	}

	#[test]
	fn request_no_match_passes() {
		let rp = ssn_processor(Action::Mask);
		let params = json!({"name": "echo", "arguments": {"note": "nothing here"}});
		let mut bytes: Bytes = serde_json::to_vec(&params).unwrap().into();
		let outcome = run_request::<CallToolRequestParams>(&rp, methods::TOOLS_CALL, Some(&mut bytes));
		assert!(matches!(outcome, Outcome::Pass));
	}

	#[test]
	fn request_without_body_passes() {
		let rp = ssn_processor(Action::Mask);
		let outcome = run_request::<CallToolRequestParams>(&rp, "tools/list", None);
		assert!(matches!(outcome, Outcome::Pass));
	}

	#[test]
	fn unsupported_method_does_not_parse_body() {
		let rp = ssn_processor(Action::Mask);
		let mut request = Bytes::from_static(b"not json");
		assert!(matches!(
			run_request::<CallToolRequestParams>(&rp, "custom/method", Some(&mut request)),
			Outcome::Pass
		));

		let mut response = Bytes::from_static(b"not json");
		assert!(matches!(
			run_response(&rp, "custom/method", &mut response),
			Outcome::Pass
		));
	}

	#[test]
	fn response_tools_call_masks_text_content() {
		let rp = processor(Action::Mask, &["secret"]);
		let result = json!({"content": [{"type": "text", "text": "the secret value"}]});
		let mut bytes: Bytes = serde_json::to_vec(&result).unwrap().into();
		let outcome = run_response(&rp, methods::TOOLS_CALL, &mut bytes);
		assert!(matches!(outcome, Outcome::Mutated(_)));
		let masked: Value = serde_json::from_slice(&bytes).unwrap();
		assert_eq!(masked["content"][0]["text"], json!("the <masked> value"));
	}

	#[test]
	fn response_tools_call_masks_embedded_resource() {
		let rp = processor(Action::Mask, &["secret"]);
		let result = json!({"content": [
			{"type": "resource", "resource": {"uri": "file://x", "text": "a secret here"}},
		]});
		let mut bytes: Bytes = serde_json::to_vec(&result).unwrap().into();
		let outcome = run_response(&rp, methods::TOOLS_CALL, &mut bytes);
		assert!(matches!(outcome, Outcome::Mutated(_)));
		let masked: Value = serde_json::from_slice(&bytes).unwrap();
		assert_eq!(
			masked["content"][0]["resource"]["text"],
			json!("a <masked> here")
		);
	}

	#[test]
	fn response_list_drops_matching_entry() {
		let rp = processor(Action::Mask, &["dangerous"]);
		let result = json!({"tools": [
			{"name": "safe", "description": "ok"},
			{"name": "evil", "description": "dangerous tool"},
		]});
		let mut bytes: Bytes = serde_json::to_vec(&result).unwrap().into();
		let outcome = run_response(&rp, methods::TOOLS_LIST, &mut bytes);
		assert!(matches!(outcome, Outcome::Mutated(_)));
		let filtered: Value = serde_json::from_slice(&bytes).unwrap();
		assert_eq!(filtered["tools"].as_array().unwrap().len(), 1);
		assert_eq!(filtered["tools"][0]["name"], json!("safe"));
	}
}
