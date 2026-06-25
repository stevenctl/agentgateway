//! In-process MCP guardrails backed by the async LLM guard providers.
//!
//! Each provider gets a thin wrapper (`WebhookProcessor`, `BedrockGuardrailsProcessor`,
//! ...) that slots into [`super::ProcessorKind`] next to `regex`/`remote`. The wrappers
//! share one driver: it reuses [`super::payload`]'s method→traversal switch to find the
//! inspectable text of an MCP body, then runs the real guard (`crate::llm::policy`) over
//! it. Because the driver is async and batched we can't hold a `&mut String` across the
//! network call, so we walk the body twice: pass 1 collects every text leaf in document
//! order, pass 2 writes the guard's results back onto the same leaves in the same order.
//! See `LLM_GUARDS.md`.

use bytes::Bytes;
use rmcp::model::ServerResult;
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::payload::{self, on_error, reserialize, VisitOutcome};
use super::{FailureMode, McpRejection, Outcome};
use crate::http::jwt::Claims;
use crate::llm::policy::webhook::ResponseChoice;
use crate::llm::policy::{
	AzureContentSafety, BedrockGuardrails, GoogleModelArmor, GuardrailOutcome, Policy, RequestGuard,
	RequestGuardKind, RequestRejection, ResponseGuard, ResponseGuardKind, Webhook,
};
use crate::llm::{
	AIError, LLMRequest, LLMResponse, RequestType, ResponseType, SimpleChatCompletionMessage,
};
use crate::proxy::httpproxy::PolicyClient;
use crate::*;

// ── per-provider wrappers ───────────────────────────────────────────────────────
//
// Each holds its provider config plus the MCP `rejection`, and builds the matching
// LLM `RequestGuard`/`ResponseGuard` for the shared driver. Providers without their
// own `failure_mode` (Bedrock/Model Armor/Azure) add one; the webhook reuses its own.

/// Call a webhook to evaluate the inspectable text of MCP bodies.
#[apply(schema!)]
pub struct WebhookProcessor {
	#[serde(flatten)]
	pub webhook: Webhook,
	/// Error returned to the client when the guard rejects.
	#[serde(default)]
	pub rejection: McpRejection,
}

impl WebhookProcessor {
	pub(crate) async fn run_request<P: DeserializeOwned>(
		&self,
		method: &str,
		params: Option<&mut Bytes>,
		headers: &::http::HeaderMap,
		client: &PolicyClient,
		claims: Option<Claims>,
	) -> Outcome<P> {
		let guard = RequestGuard {
			rejection: RequestRejection::default(),
			kind: RequestGuardKind::Webhook(self.webhook.clone()),
		};
		run_request(
			&guard,
			&self.rejection,
			self.failure_mode(),
			method,
			params,
			headers,
			client,
			claims,
		)
		.await
	}

	pub(crate) async fn run_response(
		&self,
		method: &str,
		body: &mut Bytes,
		headers: &::http::HeaderMap,
		client: &PolicyClient,
	) -> Outcome<ServerResult> {
		let guard = ResponseGuard {
			rejection: RequestRejection::default(),
			kind: ResponseGuardKind::Webhook(self.webhook.clone()),
		};
		run_response(
			&guard,
			&self.rejection,
			self.failure_mode(),
			method,
			body,
			headers,
			client,
		)
		.await
	}

	fn failure_mode(&self) -> FailureMode {
		map_failure_mode(self.webhook.failure_mode)
	}
}

/// Use AWS Bedrock Guardrails to evaluate the inspectable text of MCP bodies.
#[apply(schema!)]
pub struct BedrockGuardrailsProcessor {
	#[serde(flatten)]
	pub bedrock: BedrockGuardrails,
	/// Error returned to the client when the guard rejects.
	#[serde(default)]
	pub rejection: McpRejection,
	/// Behavior when the body can't be inspected or the guard is unavailable.
	#[serde(default)]
	pub failure_mode: FailureMode,
}

impl BedrockGuardrailsProcessor {
	pub(crate) async fn run_request<P: DeserializeOwned>(
		&self,
		method: &str,
		params: Option<&mut Bytes>,
		headers: &::http::HeaderMap,
		client: &PolicyClient,
		claims: Option<Claims>,
	) -> Outcome<P> {
		let guard = RequestGuard {
			rejection: RequestRejection::default(),
			kind: RequestGuardKind::BedrockGuardrails(self.bedrock.clone()),
		};
		run_request(
			&guard,
			&self.rejection,
			self.failure_mode,
			method,
			params,
			headers,
			client,
			claims,
		)
		.await
	}

	pub(crate) async fn run_response(
		&self,
		method: &str,
		body: &mut Bytes,
		headers: &::http::HeaderMap,
		client: &PolicyClient,
	) -> Outcome<ServerResult> {
		let guard = ResponseGuard {
			rejection: RequestRejection::default(),
			kind: ResponseGuardKind::BedrockGuardrails(self.bedrock.clone()),
		};
		run_response(
			&guard,
			&self.rejection,
			self.failure_mode,
			method,
			body,
			headers,
			client,
		)
		.await
	}
}

/// Use Google Model Armor to evaluate the inspectable text of MCP bodies.
#[apply(schema!)]
pub struct GoogleModelArmorProcessor {
	#[serde(flatten)]
	pub model_armor: GoogleModelArmor,
	/// Error returned to the client when the guard rejects.
	#[serde(default)]
	pub rejection: McpRejection,
	/// Behavior when the body can't be inspected or the guard is unavailable.
	#[serde(default)]
	pub failure_mode: FailureMode,
}

impl GoogleModelArmorProcessor {
	pub(crate) async fn run_request<P: DeserializeOwned>(
		&self,
		method: &str,
		params: Option<&mut Bytes>,
		headers: &::http::HeaderMap,
		client: &PolicyClient,
		claims: Option<Claims>,
	) -> Outcome<P> {
		let guard = RequestGuard {
			rejection: RequestRejection::default(),
			kind: RequestGuardKind::GoogleModelArmor(self.model_armor.clone()),
		};
		run_request(
			&guard,
			&self.rejection,
			self.failure_mode,
			method,
			params,
			headers,
			client,
			claims,
		)
		.await
	}

	pub(crate) async fn run_response(
		&self,
		method: &str,
		body: &mut Bytes,
		headers: &::http::HeaderMap,
		client: &PolicyClient,
	) -> Outcome<ServerResult> {
		let guard = ResponseGuard {
			rejection: RequestRejection::default(),
			kind: ResponseGuardKind::GoogleModelArmor(self.model_armor.clone()),
		};
		run_response(
			&guard,
			&self.rejection,
			self.failure_mode,
			method,
			body,
			headers,
			client,
		)
		.await
	}
}

/// Use Azure Content Safety to evaluate the inspectable text of MCP bodies.
#[apply(schema!)]
pub struct AzureContentSafetyProcessor {
	#[serde(flatten)]
	pub azure: AzureContentSafety,
	/// Error returned to the client when the guard rejects.
	#[serde(default)]
	pub rejection: McpRejection,
	/// Behavior when the body can't be inspected or the guard is unavailable.
	#[serde(default)]
	pub failure_mode: FailureMode,
}

impl AzureContentSafetyProcessor {
	pub(crate) async fn run_request<P: DeserializeOwned>(
		&self,
		method: &str,
		params: Option<&mut Bytes>,
		headers: &::http::HeaderMap,
		client: &PolicyClient,
		claims: Option<Claims>,
	) -> Outcome<P> {
		let guard = RequestGuard {
			rejection: RequestRejection::default(),
			kind: RequestGuardKind::AzureContentSafety(self.azure.clone()),
		};
		run_request(
			&guard,
			&self.rejection,
			self.failure_mode,
			method,
			params,
			headers,
			client,
			claims,
		)
		.await
	}

	pub(crate) async fn run_response(
		&self,
		method: &str,
		body: &mut Bytes,
		headers: &::http::HeaderMap,
		client: &PolicyClient,
	) -> Outcome<ServerResult> {
		let guard = ResponseGuard {
			rejection: RequestRejection::default(),
			kind: ResponseGuardKind::AzureContentSafety(self.azure.clone()),
		};
		run_response(
			&guard,
			&self.rejection,
			self.failure_mode,
			method,
			body,
			headers,
			client,
		)
		.await
	}
}

/// The webhook guard carries its own (HTTP-style) failure mode; reuse it for the
/// MCP processor so a webhook is configured in one place.
fn map_failure_mode(mode: crate::llm::policy::FailureMode) -> FailureMode {
	match mode {
		crate::llm::policy::FailureMode::FailClosed => FailureMode::FailClosed,
		crate::llm::policy::FailureMode::FailOpen => FailureMode::FailOpen,
	}
}

// ── shared two-pass driver ──────────────────────────────────────────────────────

/// Run a request-side LLM guard over the editable text of an MCP request body.
/// The guard's own rejection response is unused: a batch reject is rendered as the
/// MCP `rejection` JSON-RPC error.
async fn run_request<P: DeserializeOwned>(
	guard: &RequestGuard,
	rejection: &McpRejection,
	failure_mode: FailureMode,
	method: &str,
	params: Option<&mut Bytes>,
	headers: &::http::HeaderMap,
	client: &PolicyClient,
	claims: Option<Claims>,
) -> Outcome<P> {
	let Some(visit) = payload::request_visit(method) else {
		return Outcome::Pass;
	};
	let Some(body) = params else {
		return Outcome::Pass;
	};
	let mut value = match serde_json::from_slice::<Value>(body) {
		Ok(v) => v,
		Err(e) => return on_error(failure_mode, method, &format!("decode params: {e}")),
	};
	let Some(texts) = collect(visit, &mut value) else {
		return Outcome::Pass;
	};

	let mut adapter = McpAdapter::new(texts);
	let outcome =
		Policy::apply_single_request_guard(guard, &mut adapter, headers, client, claims).await;
	if let Drive::ShortCircuit(out) = normalize(outcome, &adapter, rejection, failure_mode, method) {
		return out;
	}

	splice_back::<P>(
		visit,
		&mut value,
		adapter,
		rejection,
		failure_mode,
		method,
		body,
		"params",
	)
}

/// Run a response-side LLM guard over the editable text of an MCP response body.
async fn run_response(
	guard: &ResponseGuard,
	rejection: &McpRejection,
	failure_mode: FailureMode,
	method: &str,
	body: &mut Bytes,
	headers: &::http::HeaderMap,
	client: &PolicyClient,
) -> Outcome<ServerResult> {
	let Some(visit) = payload::response_visit(method) else {
		return Outcome::Pass;
	};
	let mut value = match serde_json::from_slice::<Value>(body) {
		Ok(v) => v,
		Err(e) => return on_error(failure_mode, method, &format!("decode result: {e}")),
	};
	let Some(texts) = collect(visit, &mut value) else {
		return Outcome::Pass;
	};

	let mut adapter = McpAdapter::new(texts);
	let outcome = Policy::apply_single_response_guard(guard, &mut adapter, headers, client).await;
	if let Drive::ShortCircuit(out) = normalize(outcome, &adapter, rejection, failure_mode, method) {
		return out;
	}

	splice_back::<ServerResult>(
		visit,
		&mut value,
		adapter,
		rejection,
		failure_mode,
		method,
		body,
		"result",
	)
}

/// Pass 1: collect every inspectable text leaf in document order, mutating nothing.
/// `None` means there's nothing to guard.
///
/// Note: for `*/list` methods the switch routes through `drop_matching`, which walks
/// each entry in full — so every string in a list entry (nested `inputSchema` property
/// names, enum values, ...) is sent to the guard, and rewriting any of them drops the
/// whole entry in pass 2.
fn collect(visit: payload::Visit, value: &mut Value) -> Option<Vec<String>> {
	let mut texts = Vec::new();
	visit(value, &mut |s| {
		texts.push(s.clone());
		VisitOutcome::Pass
	});
	(!texts.is_empty()).then_some(texts)
}

/// Pass 2: write the guard's results back onto the same leaves in the same order, then
/// re-encode if anything changed. For `*/list` methods a rewritten leaf reports
/// `Mutated`, which `drop_matching` turns into dropping that entry.
#[allow(clippy::too_many_arguments)]
fn splice_back<P: DeserializeOwned>(
	visit: payload::Visit,
	value: &mut Value,
	adapter: McpAdapter,
	rejection: &McpRejection,
	failure_mode: FailureMode,
	method: &str,
	body: &mut Bytes,
	what: &str,
) -> Outcome<P> {
	let mut out = adapter.into_current().into_iter();
	let changed = visit(value, &mut |s| match out.next() {
		Some(new) if new != *s => {
			*s = new;
			VisitOutcome::Mutated
		},
		_ => VisitOutcome::Pass,
	});
	match changed {
		VisitOutcome::Pass => Outcome::Pass,
		// The pass-2 leaf never rejects; the batch reject decision is made in `normalize`.
		VisitOutcome::Rejected => Outcome::Reject(rejection.to_error()),
		VisitOutcome::Mutated => match reserialize::<P>(value) {
			Some((parsed, bytes)) => {
				*body = bytes;
				Outcome::Mutated(parsed)
			},
			None => on_error(failure_mode, method, &format!("re-encode masked {what}")),
		},
	}
}

enum Drive<T> {
	/// Short-circuit with this outcome (rejected, or couldn't evaluate).
	ShortCircuit(Outcome<T>),
	/// Guard allowed (possibly after masking); proceed to pass 2.
	Allowed,
}

/// Normalize the guard result. Reject is decided once for the whole batch here, not per
/// leaf. A length mismatch means the guard returned a different number of texts than we
/// handed it, so the pass-2 mapping is meaningless: fail per failure mode rather than
/// apply a partial, possibly-unguarded result.
fn normalize<T>(
	outcome: anyhow::Result<GuardrailOutcome>,
	adapter: &McpAdapter,
	rejection: &McpRejection,
	failure_mode: FailureMode,
	method: &str,
) -> Drive<T> {
	if adapter.length_mismatch {
		return Drive::ShortCircuit(on_error(
			failure_mode,
			method,
			"guard returned a mismatched message count",
		));
	}
	match outcome {
		Ok(GuardrailOutcome::Rejected(_)) => Drive::ShortCircuit(Outcome::Reject(rejection.to_error())),
		Ok(GuardrailOutcome::Masked | GuardrailOutcome::None) => Drive::Allowed,
		// Prefer the MCP processor's failure mode over the guard's own.
		Ok(GuardrailOutcome::FailOpen) => Drive::ShortCircuit(on_error(
			failure_mode,
			method,
			"underlying guard unavailable",
		)),
		Err(e) => Drive::ShortCircuit(on_error(failure_mode, method, &format!("guard error: {e}"))),
	}
}

/// Presents the collected texts as a degenerate LLM request/response: one chat message
/// per text, in document order. `set_*` writes the guard's texts back 1:1, recording a
/// `length_mismatch` if the count differs so the caller can fail safe.
struct McpAdapter {
	current: Vec<String>,
	model: Option<String>,
	length_mismatch: bool,
}

impl McpAdapter {
	fn new(texts: Vec<String>) -> Self {
		Self {
			current: texts,
			model: None,
			length_mismatch: false,
		}
	}

	fn into_current(self) -> Vec<String> {
		self.current
	}

	fn write_back(&mut self, contents: Vec<String>) {
		if contents.len() != self.current.len() {
			self.length_mismatch = true;
			return;
		}
		self.current = contents;
	}
}

impl RequestType for McpAdapter {
	fn supports_model(&self) -> bool {
		false
	}
	fn model(&mut self) -> &mut Option<String> {
		&mut self.model
	}
	fn prepend_prompts(&mut self, _prompts: Vec<SimpleChatCompletionMessage>) {}
	fn append_prompts(&mut self, _prompts: Vec<SimpleChatCompletionMessage>) {}
	fn to_llm_request(&self, _provider: Strng, _tokenize: bool) -> Result<LLMRequest, AIError> {
		Err(AIError::UnsupportedConversion(strng::literal!(
			"mcp-adapter"
		)))
	}
	fn get_messages(&self) -> Vec<SimpleChatCompletionMessage> {
		self
			.current
			.iter()
			.map(|c| SimpleChatCompletionMessage {
				role: strng::literal!("user"),
				content: c.as_str().into(),
			})
			.collect()
	}
	fn set_messages(&mut self, messages: Vec<SimpleChatCompletionMessage>) {
		self.write_back(
			messages
				.into_iter()
				.map(|m| m.content.to_string())
				.collect(),
		);
	}
}

impl ResponseType for McpAdapter {
	fn to_llm_response(&self, _include_completion_in_log: bool) -> LLMResponse {
		LLMResponse::default()
	}
	fn to_webhook_choices(&self) -> Vec<ResponseChoice> {
		self
			.current
			.iter()
			.map(|c| ResponseChoice {
				message: SimpleChatCompletionMessage {
					role: strng::literal!("assistant"),
					content: c.as_str().into(),
				},
			})
			.collect()
	}
	fn set_webhook_choices(&mut self, resp: Vec<ResponseChoice>) -> anyhow::Result<()> {
		self.write_back(
			resp
				.into_iter()
				.map(|c| c.message.content.to_string())
				.collect(),
		);
		Ok(())
	}
	fn serialize(&self) -> serde_json::Result<Vec<u8>> {
		serde_json::to_vec(&self.current)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn deser_webhook_processor() {
		// The webhook carries its own failureMode; the processor reuses it.
		let cfg = r#"
target:
  host: 127.0.0.1:9999
failureMode: failOpen
rejection:
  message: nope
"#;
		let p: WebhookProcessor = serde_yaml::from_str(cfg).expect("deser WebhookProcessor");
		assert_eq!(p.rejection.message.as_deref(), Some("nope"));
		assert_eq!(p.failure_mode(), FailureMode::FailOpen);
	}

	#[test]
	fn deser_bedrock_processor() {
		// Bedrock has no failureMode of its own, so the processor adds one.
		let cfg = r#"
guardrailIdentifier: gr-123
guardrailVersion: "1"
region: us-east-1
failureMode: failOpen
"#;
		let p: BedrockGuardrailsProcessor =
			serde_yaml::from_str(cfg).expect("deser BedrockGuardrailsProcessor");
		assert_eq!(p.bedrock.region.as_str(), "us-east-1");
		assert_eq!(p.failure_mode, FailureMode::FailOpen);
	}

	#[test]
	fn write_back_flags_length_mismatch() {
		let mut adapter = McpAdapter::new(vec!["a".to_string(), "b".to_string()]);
		adapter.write_back(vec!["x".to_string()]);
		assert!(adapter.length_mismatch);
		// Partial result discarded so the caller fails safe rather than leaving some
		// leaves unguarded.
		assert_eq!(adapter.current, vec!["a".to_string(), "b".to_string()]);
	}

	#[test]
	fn write_back_applies_equal_length() {
		let mut adapter = McpAdapter::new(vec!["a".to_string(), "b".to_string()]);
		adapter.write_back(vec!["x".to_string(), "y".to_string()]);
		assert!(!adapter.length_mismatch);
		assert_eq!(adapter.current, vec!["x".to_string(), "y".to_string()]);
	}

	#[test]
	fn length_mismatch_defers_to_failure_mode() {
		let mut adapter = McpAdapter::new(vec!["a".to_string()]);
		adapter.length_mismatch = true;
		let rejection = McpRejection::default();

		let closed = normalize::<ServerResult>(
			Ok(GuardrailOutcome::None),
			&adapter,
			&rejection,
			FailureMode::FailClosed,
			"tools/call",
		);
		assert!(matches!(closed, Drive::ShortCircuit(Outcome::Reject(_))));

		let open = normalize::<ServerResult>(
			Ok(GuardrailOutcome::None),
			&adapter,
			&rejection,
			FailureMode::FailOpen,
			"tools/call",
		);
		assert!(matches!(open, Drive::ShortCircuit(Outcome::Pass)));
	}

	#[test]
	fn fail_open_outcome_defers_to_failure_mode() {
		let adapter = McpAdapter::new(vec![]);
		let rejection = McpRejection::default();

		let closed = normalize::<ServerResult>(
			Ok(GuardrailOutcome::FailOpen),
			&adapter,
			&rejection,
			FailureMode::FailClosed,
			"tools/call",
		);
		assert!(matches!(closed, Drive::ShortCircuit(Outcome::Reject(_))));

		let open = normalize::<ServerResult>(
			Ok(GuardrailOutcome::FailOpen),
			&adapter,
			&rejection,
			FailureMode::FailOpen,
			"tools/call",
		);
		assert!(matches!(open, Drive::ShortCircuit(Outcome::Pass)));
	}
}
