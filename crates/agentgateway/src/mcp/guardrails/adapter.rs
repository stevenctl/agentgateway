use std::collections::HashSet;

use bytes::Bytes;
use rmcp::model::{ErrorCode, ErrorData, ServerResult};
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::payload::{self, TextSlot};
use super::{FailureMode, Outcome};
use crate::http::jwt::Claims;
use crate::llm::policy::webhook::ResponseChoice;
use crate::llm::policy::{GuardrailOutcome, Policy, RequestGuard, ResponseGuard};
use crate::llm::{
	AIError, LLMRequest, LLMResponse, RequestType, ResponseType, SimpleChatCompletionMessage,
};
use crate::proxy::httpproxy::PolicyClient;
use crate::*;

/// Run one request-side LLM guard over the editable text of an MCP request body.
pub(crate) async fn run_request_guard<P: DeserializeOwned>(
	guard: &RequestGuard,
	method: &str,
	params: Option<&mut Bytes>,
	on_reject: &ErrorData,
	failure_mode: FailureMode,
	headers: &::http::HeaderMap,
	client: &PolicyClient,
	claims: Option<Claims>,
) -> Outcome<P> {
	if !payload::supports_request(method) {
		return Outcome::Pass;
	}
	let Some(dest) = params else {
		return Outcome::Pass;
	};
	let mut value = match serde_json::from_slice::<Value>(dest) {
		Ok(v) => v,
		Err(e) => return on_error(failure_mode, method, &format!("decode params: {e}")),
	};
	let slots = payload::extract_request(method, &value);
	if slots.is_empty() {
		return Outcome::Pass;
	}
	let mut adapter = McpAdapter::new(slots.iter().map(|s| s.text.clone()).collect());
	let outcome =
		Policy::apply_single_request_guard(guard, &mut adapter, headers, client, claims).await;
	if let Drive::ShortCircuit(out) = after_drive(outcome, &adapter, on_reject, failure_mode, method)
	{
		return out;
	}
	if !splice_back(&slots, &adapter, &mut value) {
		return Outcome::Pass;
	}
	match reserialize::<P>(&value) {
		Some((parsed, bytes)) => {
			*dest = bytes;
			Outcome::Mutated(parsed)
		},
		None => on_error(failure_mode, method, "re-encode masked params"),
	}
}

/// Run one response-side LLM guard over the editable text of an MCP response body.
/// List responses are filtered per-entry; others are masked in place.
pub(crate) async fn run_response_guard(
	guard: &ResponseGuard,
	method: &str,
	body: &mut Bytes,
	on_reject: &ErrorData,
	failure_mode: FailureMode,
	headers: &::http::HeaderMap,
	client: &PolicyClient,
) -> Outcome<ServerResult> {
	if !payload::supports_response(method) {
		return Outcome::Pass;
	}
	let mut value = match serde_json::from_slice::<Value>(body) {
		Ok(v) => v,
		Err(e) => return on_error(failure_mode, method, &format!("decode result: {e}")),
	};
	if payload::is_list_response(method) {
		return filter_list(
			guard,
			method,
			&mut value,
			body,
			on_reject,
			failure_mode,
			headers,
			client,
		)
		.await;
	}
	let slots = payload::extract_response(method, &value);
	if slots.is_empty() {
		return Outcome::Pass;
	}
	let mut adapter = McpAdapter::new(slots.iter().map(|s| s.text.clone()).collect());
	let outcome = Policy::apply_single_response_guard(guard, &mut adapter, headers, client).await;
	if let Drive::ShortCircuit(out) = after_drive(outcome, &adapter, on_reject, failure_mode, method)
	{
		return out;
	}
	if !splice_back(&slots, &adapter, &mut value) {
		return Outcome::Pass;
	}
	match reserialize::<ServerResult>(&value) {
		Some((parsed, bytes)) => {
			*body = bytes;
			Outcome::Mutated(parsed)
		},
		None => on_error(failure_mode, method, "re-encode masked result"),
	}
}

/// Run the driver over every `*/list` entry's text at once. A `Rejected` blocks
/// the whole response; otherwise any entry the driver rewrote is dropped (a
/// catalog entry can't be partially redacted the way free text can).
async fn filter_list(
	guard: &ResponseGuard,
	method: &str,
	value: &mut Value,
	body: &mut Bytes,
	on_reject: &ErrorData,
	failure_mode: FailureMode,
	headers: &::http::HeaderMap,
	client: &PolicyClient,
) -> Outcome<ServerResult> {
	let entries = payload::extract_list_entries(method, value);
	if entries.is_empty() {
		return Outcome::Pass;
	}
	let mut adapter = McpAdapter::new(entries.iter().map(|e| e.text.clone()).collect());
	let outcome = Policy::apply_single_response_guard(guard, &mut adapter, headers, client).await;
	if let Drive::ShortCircuit(out) = after_drive(outcome, &adapter, on_reject, failure_mode, method)
	{
		return out;
	}
	let mut drop: HashSet<usize> = HashSet::new();
	for (i, e) in entries.iter().enumerate() {
		if adapter.current[i] != e.text {
			drop.insert(e.entry);
		}
	}
	if drop.is_empty() {
		return Outcome::Pass;
	}
	payload::drop_list_entries(method, value, &drop);
	match reserialize::<ServerResult>(value) {
		Some((parsed, bytes)) => {
			*body = bytes;
			Outcome::Mutated(parsed)
		},
		None => on_error(failure_mode, method, "re-encode filtered result"),
	}
}

enum Drive<T> {
	/// Short-circuit with this outcome (rejected, or couldn't evaluate).
	ShortCircuit(Outcome<T>),
	/// Driver allowed (possibly after masking); proceed to splice / drop.
	Allowed,
}

/// Normalize the driver result. A length mismatch means the driver rewrote a
/// different number of messages than we handed it: the splice/drop mapping is no
/// longer trustworthy (it could leave unguarded text), so we fail per failure
/// mode rather than apply a partial result.
fn after_drive<T>(
	outcome: anyhow::Result<GuardrailOutcome>,
	adapter: &McpAdapter,
	on_reject: &ErrorData,
	failure_mode: FailureMode,
	method: &str,
) -> Drive<T> {
	if adapter.length_mismatch {
		return Drive::ShortCircuit(on_error(
			failure_mode,
			method,
			"driver returned a mismatched message count",
		));
	}
	match outcome {
		Ok(GuardrailOutcome::Rejected(_)) => Drive::ShortCircuit(Outcome::Reject(on_reject.clone())),
		Ok(GuardrailOutcome::Masked | GuardrailOutcome::None) => Drive::Allowed,
		Ok(GuardrailOutcome::FailOpen) => Drive::ShortCircuit(on_error(
			failure_mode, // prefer the MCP processor's failure mode over the driver's
			method,
			"underlying guard unavailable",
		)),
		Err(e) => Drive::ShortCircuit(on_error(failure_mode, method, &format!("guard error: {e}"))),
	}
}

/// Collect rewritten slot texts and splice them back into `value`. Returns whether
/// anything actually changed.
fn splice_back(slots: &[TextSlot], adapter: &McpAdapter, value: &mut Value) -> bool {
	let mut replacements = Vec::new();
	for (i, slot) in slots.iter().enumerate() {
		let current = &adapter.current[i];
		if current != &slot.text {
			replacements.push((slot.location.clone(), current.clone()));
		}
	}
	if replacements.is_empty() {
		return false;
	}
	payload::apply_replacements(value, replacements);
	true
}

/// Honor the processor's failure mode when the body can't be inspected/re-encoded
/// or a driver errors or misbehaves.
pub(crate) fn on_error<T>(failure_mode: FailureMode, method: &str, reason: &str) -> Outcome<T> {
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

/// Re-encode a mutated body and re-parse it into the typed response so the proxy
/// can keep working with a strongly-typed value.
pub(crate) fn reserialize<P: DeserializeOwned>(value: &Value) -> Option<(P, Bytes)> {
	let bytes: Bytes = serde_json::to_vec(value).ok()?.into();
	let parsed = serde_json::from_slice::<P>(&bytes)
		.inspect_err(|e| tracing::warn!(error = %e, "mcpGuardrails: re-encode failed to parse"))
		.ok()?;
	Some((parsed, bytes))
}

/// Presents MCP text as a degenerate LLM request/response: one "message" per text
/// slot, in document order. Mutating `set_messages`/`set_webhook_choices` records
/// changes (so the caller knows whether to splice) and flags any count mismatch.
struct McpAdapter {
	current: Vec<String>,
	model: Option<String>,
	any_changed: bool,
	length_mismatch: bool,
}

impl McpAdapter {
	fn new(texts: Vec<String>) -> Self {
		Self {
			current: texts,
			model: None,
			any_changed: false,
			length_mismatch: false,
		}
	}

	/// Apply driver-returned texts 1:1 onto the slots. A length mismatch is
	/// recorded and the partial result discarded — the caller fails per failure
	/// mode rather than leave some slots unguarded.
	fn write_back(&mut self, contents: Vec<String>) {
		if contents.len() != self.current.len() {
			self.length_mismatch = true;
			return;
		}
		for (slot, new) in self.current.iter_mut().zip(contents) {
			if *slot != new {
				*slot = new;
				self.any_changed = true;
			}
		}
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

	fn reject() -> ErrorData {
		ErrorData::new(ErrorCode::INTERNAL_ERROR, "rejected", None)
	}

	#[test]
	fn fail_open_outcome_defers_to_processor_failure_mode() {
		let adapter = McpAdapter::new(vec![]);

		let closed = after_drive::<ServerResult>(
			Ok(GuardrailOutcome::FailOpen),
			&adapter,
			&reject(),
			FailureMode::FailClosed,
			"tools/call",
		);
		assert!(matches!(closed, Drive::ShortCircuit(Outcome::Reject(_))));

		let open = after_drive::<ServerResult>(
			Ok(GuardrailOutcome::FailOpen),
			&adapter,
			&reject(),
			FailureMode::FailOpen,
			"tools/call",
		);
		assert!(matches!(open, Drive::ShortCircuit(Outcome::Pass)));
	}
}
