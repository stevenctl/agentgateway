//! Streaming guardrail infrastructure: `GuardedSseBody` and per-guardrail evaluators.
//!
//! `GuardedSseBody` implements **windowed guardrail evaluation**:
//!
//! 1. Incoming SSE byte frames are held (not forwarded) while text deltas are
//!    accumulated into a pending batch.
//! 2. When the batch reaches `eval_threshold` bytes of text (or the stream ends),
//!    all `StreamingEvaluator`s are run against a window consisting of an
//!    *overlap tail* from previously evaluated text plus the pending batch. The
//!    overlap ensures patterns spanning a batch boundary are still seen
//!    contiguously by at least one evaluation.
//! 3. **Pass** → the held frames are flushed to the client and buffering resumes.
//!    **Block** → the held (never-forwarded) frames are discarded and a synthetic
//!    SSE error event is emitted. Content flushed by earlier passing windows
//!    cannot be retracted — an accepted accuracy/latency tradeoff.
//!
//! This is not 100% accurate: a guard that needs full-response context, or a
//! pattern spanning more than the overlap window, can be missed.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use ::http::HeaderMap;
use bytes::Bytes;
use http_body::Frame;
use pin_project_lite::pin_project;
use tokio_sse_codec::{Event, Frame as SseFrame, SseDecoder};
use tokio_util::codec::Decoder;
use tracing::warn;

use super::{FailureMode, ResponseGuard, StreamingEvaluator, StreamingGuardrailOutcome};
use crate::cel::RequestSnapshot;
use crate::llm::ContentScope;
use crate::llm::policy::{Policy, PromptGuard};
use crate::proxy::httpproxy::PolicyClient;
use crate::telemetry::log::GuardrailLog;
use crate::telemetry::metrics::{GuardrailAction, GuardrailPhase};

/// Text bytes accumulated before triggering a guardrail evaluation.
/// Larger values reduce guardrail API calls but increase time-to-first-byte
/// and the amount of content discarded on a mid-stream block.
pub const DEFAULT_EVAL_THRESHOLD: usize = 1024;

/// Tail bytes of previously evaluated text prepended to each new window so
/// patterns spanning a batch boundary are still seen contiguously.
pub const OVERLAP_BYTES: usize = 256;

/// Return the last `max_bytes` of `s`, respecting UTF-8 char boundaries.
pub fn tail_chars(s: &str, max_bytes: usize) -> &str {
	if s.len() <= max_bytes {
		return s;
	}
	let mut start = s.len() - max_bytes;
	while !s.is_char_boundary(start) {
		start += 1;
	}
	&s[start..]
}

const FAIL_CLOSED_BODY: &[u8] = b"Content blocked by guardrail policy";

/// Run the evaluators covering `scope` against a window. Returns the rejection body if any evaluator blocked.
pub async fn evaluate_window(
	evaluators: &mut [Box<dyn StreamingEvaluator>],
	scope: ContentScope,
	window: &str,
) -> Option<Bytes> {
	for ev in evaluators.iter_mut().filter(|ev| ev.covers(scope)) {
		match ev.evaluate(window).await {
			Ok(Some(StreamingGuardrailOutcome::Blocked(body))) => {
				tracing::debug!("streaming guardrail blocked response window");
				return Some(body);
			},
			Ok(None) => {},
			Err(e) => match ev.failure_mode() {
				FailureMode::FailClosed => {
					warn!("streaming guardrail error, failing closed: {e}");
					return Some(Bytes::from_static(FAIL_CLOSED_BODY));
				},
				FailureMode::FailOpen => {
					warn!("streaming guardrail error, failing open: {e}");
				},
			},
		}
	}
	None
}

/// Evaluate windows until one blocks
async fn evaluate_windows(
	mut evaluators: Vec<Box<dyn StreamingEvaluator>>,
	windows: Vec<(ContentScope, String)>,
) -> (Vec<Box<dyn StreamingEvaluator>>, Option<Bytes>) {
	for (scope, window) in windows {
		if let Some(blocked) = evaluate_window(&mut evaluators, scope, &window).await {
			return (evaluators, Some(blocked));
		}
	}
	(evaluators, None)
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Construct a boxed `StreamingEvaluator` for the given `ResponseGuard`.
pub fn make_evaluator(
	guard: &ResponseGuard,
	client: PolicyClient,
	http_headers: HeaderMap,
	original: Option<Arc<RequestSnapshot>>,
	guardrail_log: GuardrailLog,
) -> Box<dyn StreamingEvaluator> {
	Box::new(ResponseGuardEvaluator {
		guard: guard.clone(),
		client,
		http_headers,
		original,
		guardrail_log,
		worst_action: GuardrailAction::Allow,
		audit_recorded: false,
		allow_recorded: false,
		fail_open_recorded: false,
	})
}

struct ResponseGuardEvaluator {
	guard: ResponseGuard,
	client: PolicyClient,
	http_headers: HeaderMap,
	original: Option<Arc<RequestSnapshot>>,
	guardrail_log: GuardrailLog,
	// Fold window results into one metric for the stream.
	worst_action: GuardrailAction,
	// Only log the audit action once per stream, even if triggered by multiple windows.
	audit_recorded: bool,
	// Deduplicate passing windows
	allow_recorded: bool,
	fail_open_recorded: bool,
}

impl ResponseGuardEvaluator {
	fn observe_action(&mut self, action: GuardrailAction) {
		self.worst_action = self.worst_action.max(action);
	}
}

impl Drop for ResponseGuardEvaluator {
	fn drop(&mut self) {
		Policy::record_guardrail_trip(&self.client, GuardrailPhase::Response, self.worst_action);
	}
}

#[async_trait::async_trait]
impl StreamingEvaluator for ResponseGuardEvaluator {
	fn failure_mode(&self) -> FailureMode {
		self.guard.failure_mode()
	}

	fn covers(&self, scope: ContentScope) -> bool {
		self.guard.scope.contains(&scope)
	}

	async fn evaluate(&mut self, window: &str) -> anyhow::Result<Option<StreamingGuardrailOutcome>> {
		let log = if self.audit_recorded {
			None
		} else {
			Some(&self.guardrail_log)
		};

		match PromptGuard::evaluate_streaming_response_window(
			&self.guard,
			window,
			&self.client,
			&self.http_headers,
			self.original.as_deref(),
			log,
			&mut self.allow_recorded,
		)
		.await
		{
			Ok((outcome, action)) => {
				if action == GuardrailAction::Audit {
					self.audit_recorded = true;
				}
				self.observe_action(action);
				Ok(outcome)
			},
			Err(e) => {
				let action = match self.failure_mode() {
					FailureMode::FailClosed => GuardrailAction::Reject,
					FailureMode::FailOpen => GuardrailAction::FailOpen,
				};
				if action != GuardrailAction::FailOpen || !self.fail_open_recorded {
					super::record_guardrail(
						Some(&self.guardrail_log),
						GuardrailPhase::Response,
						self.guard.kind.name(),
						action,
						None,
					);
					self.fail_open_recorded |= action == GuardrailAction::FailOpen;
				}
				self.observe_action(action);
				Err(e)
			},
		}
	}
}

// ---------------------------------------------------------------------------
// GuardedSseBody
// ---------------------------------------------------------------------------

/// Synthetic SSE error event sent to the client when a guardrail blocks content.
///
/// Encoded as a single `data: {...}\n\n` SSE frame.
fn guardrail_blocked_sse_bytes(body: Bytes) -> Bytes {
	let message = String::from_utf8_lossy(&body);
	let event = serde_json::json!({
		"error": {
			"type": "guardrail_blocked",
			"code": "guardrail_intervention",
			"message": message,
		}
	});
	Bytes::from(format!("data: {event}\n\n"))
}

type EvalFuture =
	Pin<Box<dyn Future<Output = (Vec<Box<dyn StreamingEvaluator>>, Option<Bytes>)> + Send + 'static>>;

/// Internal state machine for `GuardedSseBody`.
enum GuardedBodyState {
	/// Reading from upstream, holding frames until the eval threshold is reached.
	Buffering,
	/// Evaluating the current window asynchronously. `eof` records whether the
	/// upstream is already exhausted (this is the final evaluation).
	Evaluating { fut: EvalFuture, eof: bool },
	/// Yield held frames in order, then return to `Buffering` (or `Done` if `eof`).
	Flushing { queue: VecDeque<Bytes>, eof: bool },
	/// Send the synthetic error event then close.
	Blocked(Bytes),
	/// Done – no more frames.
	Done,
}

#[derive(Default)]
struct ResponseDelta {
	text: String,
	reasoning: String,
}

impl ResponseDelta {
	fn len(&self) -> usize {
		self.text.len() + self.reasoning.len()
	}

	fn append(&mut self, delta: Self) {
		self.text.push_str(&delta.text);
		self.reasoning.push_str(&delta.reasoning);
	}

	fn take_windows(&mut self, overlap: &mut Self) -> Vec<(ContentScope, String)> {
		let mut windows = Vec::new();
		// reasoning is message content, as on the buffered path
		for (scope, pending, tail) in [
			(
				ContentScope::Messages,
				&mut self.reasoning,
				&mut overlap.reasoning,
			),
			(ContentScope::Messages, &mut self.text, &mut overlap.text),
		] {
			if pending.is_empty() {
				continue;
			}
			let window = format!("{tail}{}", std::mem::take(pending));
			*tail = tail_chars(&window, OVERLAP_BYTES).to_string();
			windows.push((scope, window));
		}
		windows
	}
}

/// Reassembles streamed tool calls so tool-scoped guards see each call whole.
/// Frames are held while a call is open; completed calls are scanned with the
/// buffered path's visitors.
#[derive(Default)]
struct ToolCalls {
	/// Open Responses output items, by output index.
	responses: HashSet<u64>,
	/// Open Anthropic tool blocks by index, with their streamed `input` JSON.
	anthropic: HashMap<u64, (serde_json::Value, String)>,
	/// Completions call arguments by (choice, call index).
	completions: BTreeMap<(u64, u64), String>,
	done: Vec<(ContentScope, String)>,
}

impl ToolCalls {
	fn is_open(&self) -> bool {
		!self.responses.is_empty() || !self.anthropic.is_empty() || !self.completions.is_empty()
	}

	fn observe(&mut self, v: &serde_json::Value) {
		use serde_json::Value;
		let u64_at = |v: &Value, key: &str| v.get(key).and_then(Value::as_u64).unwrap_or_default();
		// message and reasoning items/blocks are windowed as text instead
		let is_tool_item = |item: &Value| {
			!matches!(
				item.get("type").and_then(Value::as_str),
				Some("message" | "reasoning" | "text" | "thinking" | "redacted_thinking")
			)
		};
		match v.get("type").and_then(Value::as_str) {
			Some("response.output_item.added") => {
				if v.get("item").is_some_and(is_tool_item) {
					self.responses.insert(u64_at(v, "output_index"));
				}
				return;
			},
			Some("response.output_item.done") => {
				self.responses.remove(&u64_at(v, "output_index"));
				let Some(item) = v.get("item").filter(|i| is_tool_item(i)) else {
					return;
				};
				match serde_json::from_value(item.clone()) {
					Ok(mut item) => self.scan(|f| {
						agent_llm::types::responses::visit_output_item_text(&mut item, &mut |t, s| {
							f(t.scope, s)
						})
					}),
					Err(_) => self.scan_raw(item),
				}
				return;
			},
			Some("content_block_start") => {
				if let Some(block) = v.get("content_block").filter(|b| is_tool_item(b)) {
					self
						.anthropic
						.insert(u64_at(v, "index"), (block.clone(), String::new()));
				}
				return;
			},
			Some("content_block_delta") => {
				if let Some((_, input)) = self.anthropic.get_mut(&u64_at(v, "index"))
					&& let Some(partial) = v
						.get("delta")
						.and_then(|d| d.get("partial_json"))
						.and_then(Value::as_str)
				{
					input.push_str(partial);
				}
				return;
			},
			Some("content_block_stop") => {
				if let Some((block, input)) = self.anthropic.remove(&u64_at(v, "index")) {
					self.finish_anthropic(block, input);
				}
				return;
			},
			_ => {},
		}
		if let Some(choices) = v.get("choices").and_then(Value::as_array) {
			for choice in choices {
				let idx = u64_at(choice, "index");
				let delta = choice.get("delta");
				for call in delta
					.and_then(|d| d.get("tool_calls"))
					.and_then(Value::as_array)
					.into_iter()
					.flatten()
				{
					let args = self
						.completions
						.entry((idx, u64_at(call, "index")))
						.or_default();
					for path in [["function", "arguments"], ["custom", "input"]] {
						if let Some(s) = call
							.get(path[0])
							.and_then(|c| c.get(path[1]))
							.and_then(Value::as_str)
						{
							args.push_str(s);
						}
					}
				}
				// legacy single function_call
				if let Some(s) = delta
					.and_then(|d| d.get("function_call"))
					.and_then(|c| c.get("arguments"))
					.and_then(Value::as_str)
				{
					self
						.completions
						.entry((idx, u64::MAX))
						.or_default()
						.push_str(s);
				}
				if choice.get("finish_reason").is_some_and(|r| !r.is_null()) {
					let calls: Vec<_> = self
						.completions
						.range((idx, 0)..=(idx, u64::MAX))
						.map(|(k, _)| *k)
						.collect();
					for k in calls {
						if let Some(args) = self.completions.remove(&k) {
							self.done.push((ContentScope::ToolInput, args));
						}
					}
				}
			}
			return;
		}
		if v.get("candidates").is_some()
			&& let Ok(mut chunk) = serde_json::from_value::<agent_llm::types::gemini::Response>(v.clone())
		{
			use agent_llm::types::ResponseType as _;
			self.scan(|f| chunk.visit_text_mut(&mut |t, s| f(t.scope, s)));
		}
	}

	fn finish_anthropic(&mut self, mut block: serde_json::Value, input: String) {
		if !input.is_empty() {
			match serde_json::from_str(&input) {
				Ok(parsed) => block["input"] = parsed,
				Err(_) => self.done.push((ContentScope::ToolInput, input)),
			}
		}
		let mut content = agent_llm::types::messages::Content {
			text: None,
			rest: block,
		};
		self.scan(|f| agent_llm::types::messages::visit_response_content_text(&mut content, f));
	}

	/// Flush calls the stream ended without closing.
	fn finish(&mut self) {
		for (_, args) in std::mem::take(&mut self.completions) {
			self.done.push((ContentScope::ToolInput, args));
		}
		for (_, (block, input)) in std::mem::take(&mut self.anthropic) {
			self.finish_anthropic(block, input);
		}
		self.responses.clear();
	}

	/// One window per scope; message text is windowed separately.
	fn scan(&mut self, visit: impl FnOnce(&mut dyn FnMut(ContentScope, &mut String))) {
		let mut input = Vec::new();
		let mut output = Vec::new();
		visit(&mut |scope, text| match scope {
			ContentScope::ToolInput => input.push(text.clone()),
			ContentScope::ToolOutput => output.push(text.clone()),
			_ => {},
		});
		for (scope, texts) in [
			(ContentScope::ToolInput, input),
			(ContentScope::ToolOutput, output),
		] {
			if !texts.is_empty() {
				self.done.push((scope, texts.join("\n")));
			}
		}
	}

	// items we cannot parse are scanned as raw JSON rather than skipped
	fn scan_raw(&mut self, item: &serde_json::Value) {
		self.done.push((ContentScope::ToolInput, item.to_string()));
	}
}

pin_project! {
	// An `http_body::Body` wrapper that implements windowed guardrail evaluation.
	pub struct GuardedSseBody {
		#[pin]
		inner: agent_http::RawBody,
		evaluators: Vec<Box<dyn StreamingEvaluator>>,
		eval_threshold: usize,
		buffer_limit: usize,
		held_frames: Vec<Bytes>,
		held_bytes: usize,
		pending_text: ResponseDelta,
		overlap_tail: ResponseDelta,
		// Only tracked when some guard is scoped to tool content.
		tool_calls: Option<ToolCalls>,
		sse_decoder: SseDecoder<Bytes>,
		decode_buffer: bytes::BytesMut,
		state: GuardedBodyState,
		// Owns the rate-limit logger; dropped only when this body is fully consumed,
		// so telemetry is recorded at the correct time.
		logger: Option<crate::llm::AmendOnDrop>,
	}
}

impl GuardedSseBody {
	/// Create a new `GuardedSseBody` with the default evaluation threshold.
	///
	/// * `inner` – the upstream SSE body.
	/// * `evaluators` – one evaluator per configured response guard.
	/// * `buffer_limit` – max bytes of held frames; reaching it forces an evaluation.
	/// * `logger` – rate-limit logger that must outlive the streaming response.
	// We do actually return Self; just wrapped in an http_body::Body. The annotation silences a false positive from clippy about that.
	#[allow(clippy::new_ret_no_self)]
	pub fn new(
		inner: agent_http::RawBody,
		evaluators: Vec<Box<dyn StreamingEvaluator>>,
		buffer_limit: usize,
		logger: Option<crate::llm::AmendOnDrop>,
	) -> agent_http::RawBody {
		Self::with_threshold(
			inner,
			evaluators,
			buffer_limit,
			logger,
			DEFAULT_EVAL_THRESHOLD,
		)
	}

	/// Like [`GuardedSseBody::new`] but with an explicit evaluation threshold.
	pub fn with_threshold(
		inner: agent_http::RawBody,
		evaluators: Vec<Box<dyn StreamingEvaluator>>,
		buffer_limit: usize,
		logger: Option<crate::llm::AmendOnDrop>,
		eval_threshold: usize,
	) -> agent_http::RawBody {
		let tool_calls = evaluators
			.iter()
			.any(|e| e.covers(ContentScope::ToolInput) || e.covers(ContentScope::ToolOutput))
			.then(ToolCalls::default);
		agent_http::RawBody::new(Self {
			inner,
			evaluators,
			eval_threshold,
			buffer_limit,
			held_frames: Vec::new(),
			held_bytes: 0,
			pending_text: ResponseDelta::default(),
			overlap_tail: ResponseDelta::default(),
			tool_calls,
			sse_decoder: SseDecoder::with_max_size(buffer_limit),
			decode_buffer: bytes::BytesMut::new(),
			state: GuardedBodyState::Buffering,
			logger,
		})
	}

	/// Parse the JSON payload of an SSE event.
	fn frame_json(frame: SseFrame<Bytes>) -> Option<serde_json::Value> {
		let SseFrame::Event(Event { data, .. }) = frame else {
			return None;
		};
		if data.as_ref() == b"[DONE]" {
			return None;
		}
		serde_json::from_slice(&data).ok()
	}

	/// Extract text and reasoning deltas from a parsed SSE event if present.
	fn extract_text_delta(v: &serde_json::Value) -> Option<ResponseDelta> {
		let str_at = |v: &serde_json::Value, key: &str| v.get(key)?.as_str().map(str::to_string);
		let mut out = ResponseDelta::default();
		// OpenAI Responses
		match v.get("type").and_then(|t| t.as_str()) {
			Some("response.output_text.delta") => {
				out.text = str_at(v, "delta")?;
				return Some(out);
			},
			Some("response.reasoning_text.delta" | "response.reasoning_summary_text.delta") => {
				out.reasoning = str_at(v, "delta")?;
				return Some(out);
			},
			_ => {},
		}
		// OpenAI completions.
		if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
			for delta in choices.iter().filter_map(|c| c.get("delta")) {
				out.text.extend(str_at(delta, "content"));
				out.reasoning.extend(str_at(delta, "reasoning"));
				out.reasoning.extend(str_at(delta, "reasoning_content"));
				for detail in delta
					.get("reasoning_details")
					.and_then(|d| d.as_array())
					.into_iter()
					.flatten()
				{
					let field = match detail.get("type").and_then(|t| t.as_str()) {
						Some("reasoning.text") => "text",
						Some("reasoning.summary") => "summary",
						_ => continue,
					};
					out.reasoning.extend(str_at(detail, field));
				}
			}
			return Some(out);
		}
		// Anthropic messages
		if let Some(delta) = v.get("delta").or_else(|| v.get("content_block")) {
			if let Some(text) = str_at(delta, "text") {
				out.text = text;
				return Some(out);
			}
			if let Some(thinking) = str_at(delta, "thinking") {
				out.reasoning = thinking;
				return Some(out);
			}
		}
		// Gemini
		if let Some(candidates) = v.get("candidates").and_then(|c| c.as_array()) {
			for part in candidates
				.iter()
				.filter_map(|c| c.get("content")?.get("parts")?.as_array())
				.flatten()
			{
				let Some(text) = part.get("text").and_then(|t| t.as_str()) else {
					continue;
				};
				if part.get("thought").and_then(|t| t.as_bool()) == Some(true) {
					out.reasoning.push_str(text);
				} else {
					out.text.push_str(text);
				}
			}
			return Some(out);
		}
		None
	}
}

impl http_body::Body for GuardedSseBody {
	type Data = Bytes;
	type Error = crate::http::Error;

	fn poll_frame(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
		let mut this = self.project();

		loop {
			match this.state {
				// -----------------------------------------------------------------
				// Flushing: yield held frames one at a time.
				// -----------------------------------------------------------------
				GuardedBodyState::Flushing { queue, eof } => {
					if let Some(frame) = queue.pop_front() {
						return Poll::Ready(Some(Ok(Frame::data(frame))));
					} else if *eof {
						*this.state = GuardedBodyState::Done;
						return Poll::Ready(None);
					} else {
						*this.state = GuardedBodyState::Buffering;
					}
				},
				// -----------------------------------------------------------------
				// Blocked: yield synthetic error event, then done.
				// -----------------------------------------------------------------
				GuardedBodyState::Blocked(body) => {
					let body = std::mem::take(body);
					*this.state = GuardedBodyState::Done;
					return Poll::Ready(Some(Ok(Frame::data(guardrail_blocked_sse_bytes(body)))));
				},
				// -----------------------------------------------------------------
				// Done: stream exhausted.
				// -----------------------------------------------------------------
				GuardedBodyState::Done => {
					return Poll::Ready(None);
				},
				// -----------------------------------------------------------------
				// Evaluating: poll the guardrail future for the current window.
				// -----------------------------------------------------------------
				GuardedBodyState::Evaluating { fut, eof } => match fut.as_mut().poll(cx) {
					Poll::Pending => return Poll::Pending,
					Poll::Ready((evaluators, blocked_body)) => {
						*this.evaluators = evaluators;
						if let Some(body) = blocked_body {
							this.held_frames.clear();
							*this.held_bytes = 0;
							*this.state = GuardedBodyState::Blocked(body);
						} else {
							let queue: VecDeque<Bytes> = this.held_frames.drain(..).collect();
							*this.held_bytes = 0;
							*this.state = GuardedBodyState::Flushing { queue, eof: *eof };
						}
					},
				},
				// -----------------------------------------------------------------
				// Buffering: read from upstream, holding frames until threshold.
				// -----------------------------------------------------------------
				GuardedBodyState::Buffering => {
					match this.inner.as_mut().poll_frame(cx) {
						Poll::Pending => return Poll::Pending,
						Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
						Poll::Ready(Some(Ok(frame))) => {
							let Some(data) = frame.data_ref() else {
								return Poll::Ready(Some(Ok(frame)));
							};

							let raw = data.clone();
							*this.held_bytes += raw.len();
							this.held_frames.push(raw.clone());

							this.decode_buffer.extend_from_slice(&raw);
							loop {
								match this.sse_decoder.decode(this.decode_buffer) {
									Ok(Some(sse_frame)) => {
										let Some(v) = GuardedSseBody::frame_json(sse_frame) else {
											continue;
										};
										if let Some(delta) = GuardedSseBody::extract_text_delta(&v) {
											this.pending_text.append(delta);
										}
										if let Some(tools) = this.tool_calls.as_mut() {
											tools.observe(&v);
										}
									},
									Ok(None) => break,
									Err(e) => {
										// Clear the buffer and reset the decoder so invalid bytes
										// don't accumulate across chunks and cause repeated errors.
										warn!("SSE decode error in streaming guardrail body, resetting decoder: {e}");
										this.decode_buffer.clear();
										*this.sse_decoder = SseDecoder::with_max_size(*this.buffer_limit);
										break;
									},
								}
							}

							let over_limit = *this.held_bytes >= *this.buffer_limit;
							let tools_open = this.tool_calls.as_ref().is_some_and(ToolCalls::is_open);
							// A tool call too large to hold cannot be evaluated whole.
							if over_limit
								&& tools_open
								&& this.evaluators.iter().any(|e| {
									(e.covers(ContentScope::ToolInput) || e.covers(ContentScope::ToolOutput))
										&& e.failure_mode() == FailureMode::FailClosed
								}) {
								warn!("streaming tool call exceeded the guardrail buffer, failing closed");
								this.held_frames.clear();
								*this.held_bytes = 0;
								*this.state = GuardedBodyState::Blocked(Bytes::from_static(FAIL_CLOSED_BODY));
								continue;
							}
							let tools_done = this.tool_calls.as_ref().is_some_and(|t| !t.done.is_empty());
							let ready =
								!tools_open && (tools_done || this.pending_text.len() >= *this.eval_threshold);
							if ready || over_limit {
								let mut windows = this.pending_text.take_windows(this.overlap_tail);
								if let Some(tools) = this.tool_calls.as_mut() {
									windows.append(&mut tools.done);
								}
								// Having a full buffer but nothing to evaluate implies that the
								// buffer is full of non-text frames (e.g. control frames or unsupported SSE formats that fail to decode).
								// In that case, flush the buffer as-is without evaluation, to avoid stalling on unprocessable content.
								if windows.is_empty() {
									let queue: VecDeque<Bytes> = this.held_frames.drain(..).collect();
									*this.held_bytes = 0;
									*this.state = GuardedBodyState::Flushing { queue, eof: false };
									continue;
								}
								let evaluators = std::mem::take(this.evaluators);
								let fut: EvalFuture = Box::pin(evaluate_windows(evaluators, windows));
								*this.state = GuardedBodyState::Evaluating { fut, eof: false };
							}
						},
						Poll::Ready(None) => {
							loop {
								match this.sse_decoder.decode_eof(this.decode_buffer) {
									Ok(Some(sse_frame)) => {
										let Some(v) = GuardedSseBody::frame_json(sse_frame) else {
											continue;
										};
										if let Some(delta) = GuardedSseBody::extract_text_delta(&v) {
											this.pending_text.append(delta);
										}
										if let Some(tools) = this.tool_calls.as_mut() {
											tools.observe(&v);
										}
									},
									Ok(None) => break,
									Err(e) => {
										warn!("SSE decode error at EOF in streaming guardrail body: {e}");
										this.decode_buffer.clear();
										break;
									},
								}
							}

							let mut windows = this.pending_text.take_windows(this.overlap_tail);
							if let Some(tools) = this.tool_calls.as_mut() {
								tools.finish();
								windows.append(&mut tools.done);
							}
							if windows.is_empty() {
								let queue: VecDeque<Bytes> = this.held_frames.drain(..).collect();
								*this.held_bytes = 0;
								*this.state = GuardedBodyState::Flushing { queue, eof: true };
								continue;
							}

							let evaluators = std::mem::take(this.evaluators);
							let fut: EvalFuture = Box::pin(evaluate_windows(evaluators, windows));
							*this.state = GuardedBodyState::Evaluating { fut, eof: true };
						},
					}
				},
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use http_body_util::BodyExt as _;

	use super::*;

	struct PassEvaluator;

	#[async_trait::async_trait]
	impl StreamingEvaluator for PassEvaluator {
		async fn evaluate(
			&mut self,
			_window: &str,
		) -> anyhow::Result<Option<StreamingGuardrailOutcome>> {
			Ok(None)
		}
	}

	struct BlockEvaluator;

	#[async_trait::async_trait]
	impl StreamingEvaluator for BlockEvaluator {
		async fn evaluate(
			&mut self,
			_window: &str,
		) -> anyhow::Result<Option<StreamingGuardrailOutcome>> {
			Ok(Some(StreamingGuardrailOutcome::Blocked(
				Bytes::from_static(b"blocked"),
			)))
		}
	}

	struct PatternEvaluator {
		pattern: regex::Regex,
	}

	#[async_trait::async_trait]
	impl StreamingEvaluator for PatternEvaluator {
		async fn evaluate(
			&mut self,
			window: &str,
		) -> anyhow::Result<Option<StreamingGuardrailOutcome>> {
			if self.pattern.is_match(window) {
				return Ok(Some(StreamingGuardrailOutcome::Blocked(
					Bytes::from_static(b"blocked"),
				)));
			}
			Ok(None)
		}
	}

	struct ErrorEvaluator {
		mode: crate::llm::policy::FailureMode,
	}

	#[async_trait::async_trait]
	impl StreamingEvaluator for ErrorEvaluator {
		fn failure_mode(&self) -> crate::llm::policy::FailureMode {
			self.mode
		}

		async fn evaluate(
			&mut self,
			_window: &str,
		) -> anyhow::Result<Option<StreamingGuardrailOutcome>> {
			Err(anyhow::anyhow!("simulated evaluator error"))
		}
	}

	fn sse_bytes(content: &str) -> Bytes {
		Bytes::from(format!("data: {}\n\n", content))
	}

	fn delta_bytes(text: &str) -> Bytes {
		sse_bytes(&format!(
			"{{\"choices\":[{{\"delta\":{{\"content\":\"{}\"}}}}]}}",
			text
		))
	}

	fn make_body(chunks: Vec<Bytes>) -> agent_http::RawBody {
		use std::convert::Infallible;

		use futures_util::stream;
		let stream = stream::iter(chunks.into_iter().map(Ok::<Bytes, Infallible>));
		agent_http::RawBody::from_stream(stream)
	}

	fn contains(haystack: &[u8], needle: &[u8]) -> bool {
		haystack.windows(needle.len()).any(|w| w == needle)
	}

	#[tokio::test]
	async fn test_pass_through() {
		let chunk = delta_bytes("hello");
		let done = sse_bytes("[DONE]");
		let body = make_body(vec![chunk.clone(), done.clone()]);

		let guarded = GuardedSseBody::new(body, vec![Box::new(PassEvaluator)], 1024 * 1024, None);

		let bytes = guarded.collect().await.unwrap().to_bytes();
		assert!(bytes.starts_with(&chunk));
	}

	#[tokio::test]
	async fn test_block() {
		let chunk = delta_bytes("bad content");
		let done = sse_bytes("[DONE]");
		let body = make_body(vec![chunk, done]);

		let guarded = GuardedSseBody::new(body, vec![Box::new(BlockEvaluator)], 1024 * 1024, None);

		let bytes = guarded.collect().await.unwrap().to_bytes();
		assert!(contains(&bytes, b"guardrail_blocked"));
		assert!(!contains(&bytes, b"bad content"));
	}

	fn pattern_evaluator(pattern: &str) -> PatternEvaluator {
		PatternEvaluator {
			pattern: regex::Regex::new(pattern).unwrap(),
		}
	}

	#[tokio::test]
	async fn test_regex_blocks_matching_response() {
		let chunk = delta_bytes("my SSN is 123-45-6789");
		let done = sse_bytes("[DONE]");
		let body = make_body(vec![chunk, done]);

		let guarded = GuardedSseBody::new(
			body,
			vec![Box::new(pattern_evaluator("SSN"))],
			1024 * 1024,
			None,
		);

		let bytes = guarded.collect().await.unwrap().to_bytes();
		assert!(contains(&bytes, b"guardrail_blocked"));
		assert!(!contains(&bytes, b"SSN"));
	}

	fn gemini_delta_bytes(text: &str, thought: &str) -> Bytes {
		sse_bytes(&format!(
			"{{\"candidates\":[{{\"content\":{{\"role\":\"model\",\"parts\":[{{\"text\":\"{}\",\"thought\":true}},{{\"text\":\"{}\"}}]}}}}]}}",
			thought, text
		))
	}

	#[tokio::test]
	async fn test_gemini_sse_text_is_evaluated() {
		let chunk1 = gemini_delta_bytes("my SSN", "planning the answer");
		let chunk2 = gemini_delta_bytes(" is 123-45-6789", "still planning");
		let body = make_body(vec![chunk1, chunk2]);

		let guarded = GuardedSseBody::new(
			body,
			vec![Box::new(pattern_evaluator("SSN is"))],
			1024 * 1024,
			None,
		);

		let bytes = guarded.collect().await.unwrap().to_bytes();
		assert!(contains(&bytes, b"guardrail_blocked"));
		assert!(!contains(&bytes, b"123-45-6789"));
	}

	fn gemini_candidates_bytes(candidates: serde_json::Value) -> Bytes {
		sse_bytes(&serde_json::json!({ "candidates": candidates }).to_string())
	}

	#[tokio::test]
	async fn test_gemini_sse_evaluates_every_candidate() {
		// candidateCount is client-controlled: the guard-relevant text sits in candidates[1]
		// behind a candidates[0] that only carries a thought part.
		let chunk = gemini_candidates_bytes(serde_json::json!([
			{ "content": { "role": "model", "parts": [{ "text": "planning", "thought": true }] } },
			{ "content": { "role": "model", "parts": [{ "text": "my SSN is 123-45-6789" }] } }
		]));
		let body = make_body(vec![chunk]);

		let guarded = GuardedSseBody::new(
			body,
			vec![Box::new(pattern_evaluator("SSN"))],
			1024 * 1024,
			None,
		);

		let bytes = guarded.collect().await.unwrap().to_bytes();
		assert!(contains(&bytes, b"guardrail_blocked"));
		assert!(!contains(&bytes, b"123-45-6789"));
	}

	#[tokio::test]
	async fn test_gemini_sse_scans_past_a_candidate_without_content() {
		// A candidate can carry only a finishReason; that must not end the scan.
		let chunk = gemini_candidates_bytes(serde_json::json!([
			{ "finishReason": "STOP" },
			{ "content": { "role": "model", "parts": [{ "text": "forbidden words" }] } }
		]));
		let body = make_body(vec![chunk]);

		let guarded = GuardedSseBody::new(
			body,
			vec![Box::new(pattern_evaluator("forbidden"))],
			1024 * 1024,
			None,
		);

		let bytes = guarded.collect().await.unwrap().to_bytes();
		assert!(contains(&bytes, b"guardrail_blocked"));
		assert!(!contains(&bytes, b"forbidden"));
	}

	fn text_delta(chunk: serde_json::Value) -> Option<Vec<String>> {
		GuardedSseBody::extract_text_delta(&chunk).map(|mut delta| {
			delta
				.take_windows(&mut ResponseDelta::default())
				.into_iter()
				.map(|(_, window)| window)
				.collect()
		})
	}

	#[test]
	fn test_extract_text_delta_matches_one_arm_per_chunk_shape() {
		assert_eq!(
			text_delta(serde_json::json!({ "type": "response.output_text.delta", "delta": "a" })),
			Some(vec!["a".to_string()])
		);
		assert_eq!(
			text_delta(serde_json::json!({ "choices": [{ "delta": { "content": "b" } }] })),
			Some(vec!["b".to_string()])
		);
		assert_eq!(
			text_delta(serde_json::json!({ "type": "content_block_delta", "delta": { "text": "c" } })),
			Some(vec!["c".to_string()])
		);
		assert_eq!(
			text_delta(serde_json::json!({
				"candidates": [
					{ "content": { "parts": [{ "text": "d" }] } },
					{ "content": { "parts": [{ "text": "e" }, { "text": "skip", "thought": true }] } }
				]
			})),
			Some(vec!["skip".to_string(), "de".to_string()])
		);
		assert_eq!(text_delta(serde_json::json!({ "usageMetadata": {} })), None);
	}

	#[tokio::test]
	async fn test_gemini_sse_evaluates_thought_parts() {
		let chunk = gemini_delta_bytes("all good", "forbidden");
		let body = make_body(vec![chunk.clone()]);

		let guarded = GuardedSseBody::new(
			body,
			vec![Box::new(pattern_evaluator("forbidden"))],
			1024 * 1024,
			None,
		);

		let bytes = guarded.collect().await.unwrap().to_bytes();
		assert!(!contains(&bytes, b"forbidden"));
		assert!(contains(&bytes, b"guardrail_blocked"));
	}

	#[rstest::rstest]
	#[case::responses(serde_json::json!({"type": "response.reasoning_text.delta", "delta": "forbidden"}))]
	#[case::responses_summary(serde_json::json!({"type": "response.reasoning_summary_text.delta", "delta": "forbidden"}))]
	#[case::completions(serde_json::json!({"choices": [{"delta": {"reasoning": "forbidden", "content": "fine"}}]}))]
	#[case::completions_reasoning_content(serde_json::json!({"choices": [{"delta": {"reasoning_content": "forbidden", "content": null}}]}))]
	#[case::completions_details(serde_json::json!({"choices": [{"delta": {"reasoning_details": [{"type": "reasoning.text", "text": "forbidden"}]}}]}))]
	#[case::completions_summary(serde_json::json!({"choices": [{"delta": {"reasoning_details": [{"type": "reasoning.summary", "summary": "forbidden"}]}}]}))]
	#[case::second_choice(serde_json::json!({"choices": [{"delta": {"content": "fine"}}, {"delta": {"reasoning_content": "forbidden"}}]}))]
	#[case::anthropic(serde_json::json!({"type": "content_block_delta", "delta": {"type": "thinking_delta", "thinking": "forbidden"}}))]
	#[case::anthropic_start(serde_json::json!({"type": "content_block_start", "content_block": {"type": "thinking", "thinking": "forbidden", "signature": "opaque"}}))]
	#[tokio::test]
	async fn reasoning_delta_is_blocked_before_forwarding(#[case] chunk: serde_json::Value) {
		let chunk = sse_bytes(&chunk.to_string());
		// Exercise partial SSE frames as well as reasoning-only responses at EOF.
		let split = chunk.len() / 2;
		let body = make_body(vec![chunk.slice(..split), chunk.slice(split..)]);
		let guarded = GuardedSseBody::new(
			body,
			vec![Box::new(pattern_evaluator("forbidden"))],
			1024 * 1024,
			None,
		);
		let bytes = guarded.collect().await.unwrap().to_bytes();
		assert!(contains(&bytes, b"guardrail_blocked"));
		assert!(!contains(&bytes, b"forbidden"));
	}

	#[rstest::rstest]
	#[case::reasoning(false)]
	#[case::answer(true)]
	#[tokio::test]
	async fn interleaved_reasoning_preserves_overlap(#[case] match_answer: bool) {
		let chunks: Vec<_> = [("credit", "fine"), (" card", "also fine")]
			.into_iter()
			.map(|(a, r)| {
				if match_answer {
					gemini_delta_bytes(a, r)
				} else {
					gemini_delta_bytes(r, a)
				}
			})
			.collect();
		// Check both a single window at EOF and a match spanning evaluation windows.
		for threshold in [4, DEFAULT_EVAL_THRESHOLD] {
			let guarded = GuardedSseBody::with_threshold(
				make_body(chunks.clone()),
				vec![Box::new(pattern_evaluator("credit card"))],
				1024 * 1024,
				None,
				threshold,
			);
			let bytes = guarded.collect().await.unwrap().to_bytes();
			assert!(contains(&bytes, b"guardrail_blocked"));
			assert!(!contains(&bytes, b" card"));
		}
	}

	#[tokio::test]
	async fn reasoning_and_answer_do_not_match_across_streams() {
		let guarded = GuardedSseBody::new(
			make_body(vec![gemini_delta_bytes("card", "credit")]),
			vec![Box::new(pattern_evaluator(r"credit\s*card"))],
			1024 * 1024,
			None,
		);
		let bytes = guarded.collect().await.unwrap().to_bytes();
		assert!(!contains(&bytes, b"guardrail_blocked"));
	}

	#[tokio::test]
	async fn opaque_reasoning_is_not_scanned() {
		let chunks = vec![
			sse_bytes(
				r#"{"type":"content_block_delta","delta":{"type":"signature_delta","signature":"forbidden"}}"#,
			),
			sse_bytes(
				r#"{"type":"content_block_start","content_block":{"type":"redacted_thinking","data":"forbidden"}}"#,
			),
			sse_bytes(
				r#"{"choices":[{"delta":{"reasoning_details":[{"type":"reasoning.encrypted","data":"forbidden"}]}}]}"#,
			),
		];
		let expected: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
		let guarded = GuardedSseBody::new(
			make_body(chunks),
			vec![Box::new(pattern_evaluator("forbidden"))],
			1024 * 1024,
			None,
		);
		assert_eq!(
			guarded.collect().await.unwrap().to_bytes().as_ref(),
			expected
		);
	}

	#[tokio::test]
	async fn test_regex_passes_non_matching_response() {
		let chunk = delta_bytes("hello world");
		let done = sse_bytes("[DONE]");
		let body = make_body(vec![chunk.clone(), done]);

		let guarded = GuardedSseBody::new(
			body,
			vec![Box::new(pattern_evaluator("SSN"))],
			1024 * 1024,
			None,
		);

		let bytes = guarded.collect().await.unwrap().to_bytes();
		assert!(bytes.starts_with(&chunk));
		assert!(!contains(&bytes, b"guardrail_blocked"));
	}

	#[tokio::test]
	async fn test_regex_accumulates_within_batch() {
		let chunk1 = delta_bytes("my credit");
		let chunk2 = delta_bytes(" card");
		let done = sse_bytes("[DONE]");
		let body = make_body(vec![chunk1, chunk2, done]);

		let guarded = GuardedSseBody::new(
			body,
			vec![Box::new(pattern_evaluator("credit card"))],
			1024 * 1024,
			None,
		);

		let bytes = guarded.collect().await.unwrap().to_bytes();
		assert!(contains(&bytes, b"guardrail_blocked"));
		assert!(!contains(&bytes, b"credit"));
	}

	#[tokio::test]
	async fn test_windowed_incremental_flush_then_block() {
		let chunk1 = delta_bytes("this part is fine");
		let chunk2 = delta_bytes("forbidden words here");
		let done = sse_bytes("[DONE]");
		let body = make_body(vec![chunk1.clone(), chunk2, done]);

		let guarded = GuardedSseBody::with_threshold(
			body,
			vec![Box::new(pattern_evaluator("forbidden"))],
			1024 * 1024,
			None,
			4,
		);

		let bytes = guarded.collect().await.unwrap().to_bytes();
		assert!(contains(&bytes, b"this part is fine"));
		assert!(!contains(&bytes, b"forbidden"));
		assert!(contains(&bytes, b"guardrail_blocked"));
	}

	#[tokio::test]
	async fn test_overlap_catches_boundary_spanning_pattern() {
		let chunk1 = delta_bytes("my credit");
		let chunk2 = delta_bytes(" card number");
		let done = sse_bytes("[DONE]");
		let body = make_body(vec![chunk1, chunk2, done]);

		let guarded = GuardedSseBody::with_threshold(
			body,
			vec![Box::new(pattern_evaluator("credit card"))],
			1024 * 1024,
			None,
			4,
		);

		let bytes = guarded.collect().await.unwrap().to_bytes();
		assert!(contains(&bytes, b"guardrail_blocked"));
		assert!(!contains(&bytes, b"card number"));
	}

	#[test]
	fn test_tail_chars_respects_utf8_boundaries() {
		let s = "héllo wörld";
		let t = tail_chars(s, 4);
		assert!(t.len() <= 4);
		assert!(s.ends_with(t));
		let s2 = "aé";
		assert_eq!(tail_chars(s2, 1), "");
		assert_eq!(tail_chars(s2, 2), "é");
	}

	struct ScopedEvaluator {
		pattern: regex::Regex,
		scope: ContentScope,
		mode: FailureMode,
	}

	#[async_trait::async_trait]
	impl StreamingEvaluator for ScopedEvaluator {
		fn failure_mode(&self) -> FailureMode {
			self.mode
		}

		fn covers(&self, scope: ContentScope) -> bool {
			scope == self.scope
		}

		async fn evaluate(
			&mut self,
			window: &str,
		) -> anyhow::Result<Option<StreamingGuardrailOutcome>> {
			Ok(
				self
					.pattern
					.is_match(window)
					.then(|| StreamingGuardrailOutcome::Blocked(Bytes::from_static(b"blocked"))),
			)
		}
	}

	fn scoped(scope: ContentScope) -> Vec<Box<dyn StreamingEvaluator>> {
		vec![Box::new(ScopedEvaluator {
			pattern: regex::Regex::new("forbidden").unwrap(),
			scope,
			mode: FailureMode::FailClosed,
		})]
	}

	fn json_frames(events: Vec<serde_json::Value>) -> Vec<Bytes> {
		events
			.into_iter()
			.map(|e| sse_bytes(&e.to_string()))
			.collect()
	}

	/// A model calls a tool with `{"cmd":"forbidden"}`, the arguments split mid-word.
	fn tool_call_stream(api: &str) -> Vec<serde_json::Value> {
		use serde_json::json;
		let (a, b) = (r#"{"cmd":"forb"#, r#"idden"}"#);
		match api {
			"completions" => {
				let args = |s: &str| json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": s}}]}}]});
				vec![
					json!({"choices": [{"index": 0, "delta": {"content": "running it"}}]}),
					args(a),
					args(b),
					json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}),
				]
			},
			"anthropic" => {
				let args = |s: &str| json!({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": s}});
				vec![
					json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "running it"}}),
					json!({"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "t1", "name": "run", "input": {}}}),
					args(a),
					args(b),
					json!({"type": "content_block_stop", "index": 1}),
				]
			},
			"responses" => {
				let item = |args: &str, status: &str| json!({"type": "function_call", "id": "fc1", "call_id": "c1", "name": "run", "arguments": args, "status": status});
				let args = |s: &str| json!({"type": "response.function_call_arguments.delta", "output_index": 1, "item_id": "fc1", "delta": s});
				vec![
					json!({"type": "response.output_text.delta", "delta": "running it"}),
					json!({"type": "response.output_item.added", "output_index": 1, "item": item("", "in_progress")}),
					args(a),
					args(b),
					json!({"type": "response.output_item.done", "output_index": 1, "item": item(&format!("{a}{b}"), "completed")}),
				]
			},
			"gemini" => vec![
				json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "running it"}]}}]}),
				json!({"candidates": [{"content": {"role": "model", "parts": [{"functionCall": {"name": "run", "args": {"cmd": "forbidden"}}}]}}]}),
			],
			_ => unreachable!(),
		}
	}

	#[rstest::rstest]
	#[tokio::test]
	async fn tool_input_guard_blocks_streamed_tool_call(
		#[values("completions", "anthropic", "responses", "gemini")] api: &str,
	) {
		// a tiny threshold would release the call fragment by fragment if it were windowed
		let body = make_body(json_frames(tool_call_stream(api)));
		let guarded =
			GuardedSseBody::with_threshold(body, scoped(ContentScope::ToolInput), 1024 * 1024, None, 1);
		let bytes = guarded.collect().await.unwrap().to_bytes();
		assert!(contains(&bytes, b"guardrail_blocked"), "{api}");
		assert!(!contains(&bytes, b"forb"), "{api}: partial call leaked");
		// message text before the call is not held behind it
		assert!(contains(&bytes, b"running it"), "{api}");
	}

	#[rstest::rstest]
	#[tokio::test]
	async fn messages_guard_ignores_tool_call(
		#[values("completions", "anthropic", "responses", "gemini")] api: &str,
	) {
		let body = make_body(json_frames(tool_call_stream(api)));
		let guarded = GuardedSseBody::new(body, scoped(ContentScope::Messages), 1024 * 1024, None);
		let bytes = guarded.collect().await.unwrap().to_bytes();
		assert!(!contains(&bytes, b"guardrail_blocked"), "{api}");
	}

	#[tokio::test]
	async fn tool_guard_ignores_message_text() {
		let body = make_body(vec![delta_bytes("forbidden"), sse_bytes("[DONE]")]);
		let guarded = GuardedSseBody::new(body, scoped(ContentScope::ToolInput), 1024 * 1024, None);
		let bytes = guarded.collect().await.unwrap().to_bytes();
		assert!(!contains(&bytes, b"guardrail_blocked"));
	}

	#[tokio::test]
	async fn oversized_tool_call_fails_closed() {
		// a large file write outgrows the buffer before the call completes
		let mut events = tool_call_stream("anthropic");
		events.truncate(3);
		let body = make_body(json_frames(events));
		let guarded = GuardedSseBody::new(body, scoped(ContentScope::ToolInput), 200, None);
		let bytes = guarded.collect().await.unwrap().to_bytes();
		assert!(contains(&bytes, b"guardrail_blocked"));
		assert!(!contains(&bytes, b"forb"));
	}

	#[tokio::test]
	async fn evaluate_window_fail_closed_blocks_on_error() {
		use crate::llm::policy::FailureMode;
		let mut evs: Vec<Box<dyn StreamingEvaluator>> = vec![Box::new(ErrorEvaluator {
			mode: FailureMode::FailClosed,
		})];
		assert_eq!(
			evaluate_window(&mut evs, ContentScope::Messages, "some text")
				.await
				.as_deref(),
			Some(&b"Content blocked by guardrail policy"[..])
		);
	}

	#[tokio::test]
	async fn evaluate_window_fail_open_passes_on_error() {
		use crate::llm::policy::FailureMode;
		let mut evs: Vec<Box<dyn StreamingEvaluator>> = vec![Box::new(ErrorEvaluator {
			mode: FailureMode::FailOpen,
		})];
		assert!(
			evaluate_window(&mut evs, ContentScope::Messages, "some text")
				.await
				.is_none()
		);
	}
}
