//! The regex/PII MCP guardrail variant.
//!
//! Thin glue over the shared adapter: build the matching LLM `RequestGuard` /
//! `ResponseGuard` from config and let [`super::adapter`] run it through the LLM
//! regex driver — including list responses, which the adapter filters per-entry.

use bytes::Bytes;
use rmcp::model::ServerResult;
use serde::de::DeserializeOwned;

use super::{FailureMode, McpRejection, Outcome, adapter};
use crate::llm::policy::{
	RegexRules, RequestGuard, RequestGuardKind, RequestRejection, ResponseGuard, ResponseGuardKind,
};
use crate::proxy::httpproxy::PolicyClient;
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

impl RegexProcessor {
	fn request_guard(&self) -> RequestGuard {
		RequestGuard {
			rejection: RequestRejection::default(),
			kind: RequestGuardKind::Regex(self.rules.clone()),
		}
	}

	fn response_guard(&self) -> ResponseGuard {
		ResponseGuard {
			rejection: RequestRejection::default(),
			kind: ResponseGuardKind::Regex(self.rules.clone()),
		}
	}
}

pub(crate) async fn run_request<P: DeserializeOwned>(
	rp: &RegexProcessor,
	method: &str,
	params: Option<&mut Bytes>,
	headers: &::http::HeaderMap,
	client: &PolicyClient,
) -> Outcome<P> {
	adapter::run_request_guard::<P>(
		&rp.request_guard(),
		method,
		params,
		&rp.rejection.to_error(),
		rp.failure_mode,
		headers,
		client,
		None,
	)
	.await
}

pub(crate) async fn run_response(
	rp: &RegexProcessor,
	method: &str,
	body: &mut Bytes,
	headers: &::http::HeaderMap,
	client: &PolicyClient,
) -> Outcome<ServerResult> {
	adapter::run_response_guard(
		&rp.response_guard(),
		method,
		body,
		&rp.rejection.to_error(),
		rp.failure_mode,
		headers,
		client,
	)
	.await
}

#[cfg(test)]
mod tests {
	use rmcp::model::CallToolRequestParams;
	use serde_json::{Value, json};

	use super::*;
	use crate::llm::policy::{Action, RegexRule};
	use crate::mcp::guardrails::{client, methods};

	// Regex guards never touch the PolicyClient or headers, but the adapter
	// signature requires them.
	fn test_client() -> PolicyClient {
		PolicyClient::new(
			crate::test_helpers::proxymock::setup_proxy_test("{}")
				.unwrap()
				.pi,
		)
	}

	fn headers() -> ::http::HeaderMap {
		::http::HeaderMap::new()
	}

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
		run_request::<P>(rp, method, params, &headers(), &test_client()).await
	}

	async fn resp(rp: &RegexProcessor, method: &str, body: &mut Bytes) -> Outcome<ServerResult> {
		run_response(rp, method, body, &headers(), &test_client()).await
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
		let rp = ssn_processor(Action::Reject);
		let params = json!({"name": "echo", "arguments": {"note": "123-45-6789"}});
		let mut bytes: Bytes = serde_json::to_vec(&params).unwrap().into();
		let Outcome::Reject(err) =
			req::<CallToolRequestParams>(&rp, methods::TOOLS_CALL, Some(&mut bytes)).await
		else {
			panic!("expected reject");
		};
		assert_eq!(err.code, client::PERMISSION_DENIED);
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
