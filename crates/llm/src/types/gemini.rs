//! Inbound native Gemini `generateContent`/`streamGenerateContent`/`countTokens` requests.
//!
//! References:
//! - <https://ai.google.dev/api/generate-content>
//! - <https://ai.google.dev/api/tokens>
//! - <https://docs.cloud.google.com/vertex-ai/generative-ai/docs/model-reference/inference>
//!
//! Inbound requests are passthrough, so the request types here are deliberately minimal:
//! only the fields the gateway reads are typed (prompt guard walks `contents` and
//! `systemInstruction`; telemetry reads the `generationConfig` sampling params), and
//! everything else rides a `rest` flatten untouched. A field shape we got slightly wrong
//! can then never reject a request Google would accept. The complete typed request in
//! `types::vertex_gemini` is reserved for conversions, which construct it themselves.
//! The content tree (`Content`/`Part`) is shared with `types::vertex_gemini`.
//!
//! Request metadata the gateway needs (model and streaming) is carried in the URI
//! (`models/{model}:generateContent` vs `:streamGenerateContent`) rather than the body.

use agent_core::prelude::Strng;
use agent_core::strng;
use bytes::Bytes;
use itertools::Itertools;
use serde::{Deserialize, Deserializer, Serialize};

use crate::types::{
	ContentScope, NormalizedMessage, NormalizedMessagePart, OutputMessage, OutputMessagePart,
	RequestText, RequestVisitor, ResponseType, vertex_gemini as vg,
};
use crate::{
	AIError, InputFormat, LLMRequest, LLMRequestParams, LLMResponse, RequestType,
	SimpleChatCompletionMessage, logged_response_parsing, webhook,
};

/// Minimal inbound `generateContent` body; see the module docs for why only read fields
/// are typed. proto3 JSON accepts snake_case alongside camelCase field names, so the
/// multi-word fields carry `alias`es; re-serialization normalizes them to camelCase.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateContentRequest {
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub contents: Vec<vg::Content>,
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		alias = "system_instruction"
	)]
	pub system_instruction: Option<vg::Content>,
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		alias = "generation_config"
	)]
	pub generation_config: Option<GenerationConfig>,
	#[serde(flatten, default)]
	pub rest: serde_json::Value,
}

/// The `generationConfig` sampling parameters the gateway logs; everything else rides `rest`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerationConfig {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub temperature: Option<f32>,
	#[serde(default, skip_serializing_if = "Option::is_none", alias = "top_p")]
	pub top_p: Option<f32>,
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		alias = "frequency_penalty"
	)]
	pub frequency_penalty: Option<f32>,
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		alias = "presence_penalty"
	)]
	pub presence_penalty: Option<f32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub seed: Option<i64>,
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		alias = "max_output_tokens"
	)]
	pub max_output_tokens: Option<u32>,
	#[serde(flatten, default)]
	pub rest: serde_json::Value,
}

#[derive(Debug, Clone, Default)]
pub struct Request {
	/// Filled from the URI by the caller; never serialized into the wire body.
	pub model: Option<String>,
	/// Filled from the URI by the caller (`:streamGenerateContent`); there is no body flag.
	pub streaming: bool,
	pub inner: GenerateContentRequest,
}

impl<'de> Deserialize<'de> for Request {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		// `read_gemini_body_and_default_model` injects the resolved model into the body JSON — the
		// URI's, the backend pin, or whatever the operator's body mutations made of it — so keep
		// it, but take it out of the body: the passthrough `rest` flatten would otherwise forward
		// it upstream, where the path already carries the model and Vertex rejects the unknown
		// field.
		let mut body = serde_json::Value::deserialize(deserializer)?;
		let model = match body.as_object_mut().and_then(|obj| obj.remove("model")) {
			Some(serde_json::Value::String(model)) => Some(model),
			_ => None,
		};
		let inner = GenerateContentRequest::deserialize(body).map_err(serde::de::Error::custom)?;
		Ok(Request {
			model,
			streaming: false,
			inner,
		})
	}
}

/// Applies `f` to unsigned visible text parts in `content`, scanning
/// consecutive text parts as one run so guard patterns can span parts — matching how the other
/// request/response types expose text to prompt guard.
fn visit_content_text(content: &mut vg::Content, f: &mut dyn FnMut(&mut String)) {
	crate::types::scan_text_runs(
		&mut content.parts,
		"\n",
		|p| match p {
			vg::Part::Text(tp)
				if tp.thought != Some(true)
					&& tp.thought_signature.as_ref().is_none_or(String::is_empty)
					&& !crate::types::has_signature(&tp.rest) =>
			{
				Some(&mut tp.text)
			},
			_ => None,
		},
		|_| None,
		&[],
		f,
	);
}

fn visit_audio_transcription(
	rest: &mut serde_json::Value,
	f: &mut dyn FnMut(ContentScope, &mut String),
) {
	for field in ["audioTranscription", "audio_transcription"] {
		if let Some(transcript) = rest.get_mut(field) {
			crate::types::visit_json_at(transcript, &["text"], ContentScope::Messages, f);
			if let Some(serde_json::Value::Array(words)) = transcript.get_mut("words") {
				for word in words {
					crate::types::visit_json_at(word, &["word"], ContentScope::Messages, f);
				}
			}
		}
	}
}

// visit every part (that is represented in the typed SDK)
// unknown items should be logged for future review
// https://ai.google.dev/api/generate-content#Part
fn visit_part_text(part: &mut vg::Part, f: &mut dyn FnMut(ContentScope, &mut String)) {
	match part {
		vg::Part::Text(p) if p.thought == Some(true) => f(ContentScope::Messages, &mut p.text),
		// Visible text is scanned in runs by visit_content_text.
		vg::Part::Text(_) => {},
		vg::Part::FunctionCall(p) => {
			crate::types::visit_json_strings(&mut p.function_call.args, &mut |text| {
				f(ContentScope::ToolInput, text)
			});
		},
		// only scan the response, not IDs or `rest` which may contain multi-modal
		// things that are difficult to scan
		vg::Part::FunctionResponse(p) => {
			crate::types::visit_json_strings(&mut p.function_response.response, &mut |text| {
				f(ContentScope::ToolOutput, text)
			});
		},
		// only scan executable_code.code as other fields may contain
		// things like "language: PYTHON" that we shouldn't touch
		vg::Part::ExecutableCode(p) => {
			crate::types::visit_json_at(
				&mut p.executable_code,
				&["code"],
				ContentScope::ToolInput,
				f,
			);
		},
		// only scan code_execution_result.output as other fields may contain
		// things like "outcome: OUTCOME_OK" that we shouldn't touch
		vg::Part::CodeExecutionResult(p) => {
			crate::types::visit_json_at(
				&mut p.code_execution_result,
				&["output"],
				ContentScope::ToolOutput,
				f,
			);
		},
		vg::Part::ToolCall(p) => {
			crate::types::visit_json_at(&mut p.tool_call, &["args"], ContentScope::ToolInput, f);
		},
		vg::Part::ToolResponse(p) => {
			crate::types::visit_json_at(
				&mut p.tool_response,
				&["response"],
				ContentScope::ToolOutput,
				f,
			);
		},
		vg::Part::InlineData(p) => visit_audio_transcription(&mut p.rest, f),
		vg::Part::FileData(p) => visit_audio_transcription(&mut p.rest, f),
		vg::Part::Unknown(value) => {
			tracing::debug!(
				keys = value
					.as_object()
					.map(|o| o.keys().join(","))
					.unwrap_or_default(),
				"unrecognized part; not scanned by prompt guards"
			);
		},
	}
}

impl RequestType for Request {
	fn input_format() -> crate::InputFormat {
		crate::InputFormat::Gemini
	}
	fn body_is_json(&self) -> bool {
		true
	}

	fn model(&mut self) -> &mut Option<String> {
		&mut self.model
	}

	fn prepend_prompts(&mut self, prompts: Vec<SimpleChatCompletionMessage>) {
		prepend_prompts_helper(
			&mut self.inner.contents,
			&mut self.inner.system_instruction,
			prompts,
		);
	}

	fn append_prompts(&mut self, prompts: Vec<SimpleChatCompletionMessage>) {
		append_prompts_helper(
			&mut self.inner.contents,
			&mut self.inner.system_instruction,
			prompts,
		);
	}

	fn to_llm_request(&self, provider: Strng, tokenize: bool) -> Result<LLMRequest, AIError> {
		let model = strng::new(self.model.as_deref().unwrap_or_default());
		let input_tokens = if tokenize {
			Some(crate::tokenizer::num_tokens(
				&model,
				&self.get_messages_v2(),
				self
					.inner
					.rest
					.get("tools")
					.and_then(serde_json::Value::as_array)
					.into_iter()
					.flatten(),
			))
		} else {
			None
		};
		let gc = self.inner.generation_config.as_ref();
		Ok(LLMRequest {
			input_tokens,
			input_format: InputFormat::Gemini,
			cache_convention: crate::CacheTokenConvention::pending(),
			request_model: model,
			original_model: None,
			provider,
			streaming: self.streaming,
			params: LLMRequestParams {
				temperature: gc.and_then(|g| g.temperature).map(f64::from),
				top_p: gc.and_then(|g| g.top_p).map(f64::from),
				frequency_penalty: gc.and_then(|g| g.frequency_penalty).map(f64::from),
				presence_penalty: gc.and_then(|g| g.presence_penalty).map(f64::from),
				seed: gc.and_then(|g| g.seed),
				max_tokens: gc.and_then(|g| g.max_output_tokens).map(u64::from),
				encoding_format: None,
				dimensions: None,
				reasoning_effort: gc
					.and_then(|g| {
						g.rest
							.get("thinkingConfig")
							.or_else(|| g.rest.get("thinking_config"))
					})
					.and_then(|t| t.get("thinkingLevel").or_else(|| t.get("thinking_level")))
					.and_then(serde_json::Value::as_str)
					.and_then(crate::ReasoningEffort::parse),
			},
			prompt: Default::default(),
			provider_state: None,
		})
	}

	fn get_messages(&self) -> Vec<SimpleChatCompletionMessage> {
		get_messages_helper(&self.inner.contents, &self.inner.system_instruction)
	}

	fn get_messages_v2(&self) -> Vec<NormalizedMessage> {
		get_messages_v2_helper(&self.inner.contents, &self.inner.system_instruction)
	}

	fn to_value(&self) -> serde_json::Result<serde_json::Value> {
		serde_json::to_value(&self.inner)
	}

	fn visit_request_mut(&mut self, v: &mut dyn RequestVisitor) {
		if let Some(system) = &mut self.inner.system_instruction {
			v.message("system");
			let text_ref = ContentScope::SystemPrompt.into();
			for part in &system.parts {
				if part.has_signature()
					&& let vg::Part::Text(p) = part
				{
					v.signed_text(text_ref, &p.text);
				}
			}
			visit_content_text(system, &mut |text| v.text(text_ref, text));
		}
		for content in &mut self.inner.contents {
			v.message(match content.role.as_deref().unwrap_or("user") {
				"model" => "assistant",
				role => role,
			});
			for part in &mut content.parts {
				let reasoning = matches!(part, vg::Part::Text(p) if p.thought == Some(true));
				let signed = part.has_signature();
				if signed && let vg::Part::Text(p) = part {
					v.signed_text(
						RequestText {
							reasoning,
							in_content: true,
							..ContentScope::Messages.into()
						},
						&p.text,
					);
				} else {
					visit_part_text(part, &mut |scope, text| {
						let kind = RequestText {
							reasoning,
							in_content: reasoning,
							..scope.into()
						};
						if signed {
							v.signed_text(kind, text);
						} else {
							v.text(kind, text);
						}
					});
				}
			}
			let text_ref = ContentScope::Messages.into();
			visit_content_text(content, &mut |text| v.text(text_ref, text));
		}
	}
}

fn get_messages_v2_helper(
	contents: &[vg::Content],
	system: &Option<vg::Content>,
) -> Vec<NormalizedMessage> {
	let mut messages = system
		.as_ref()
		.map(|content| normalized_gemini_message(content, Some(strng::literal!("system"))))
		.into_iter()
		.collect::<Vec<_>>();
	messages.extend(
		contents
			.iter()
			.map(|content| normalized_gemini_message(content, None)),
	);
	messages
}

fn normalized_gemini_message(content: &vg::Content, role: Option<Strng>) -> NormalizedMessage {
	let role = role.unwrap_or_else(|| match content.role.as_deref() {
		Some("model") => strng::literal!("assistant"),
		Some(role) => strng::new(role),
		None => strng::literal!("user"),
	});
	let parts = content
		.parts
		.iter()
		.filter_map(|part| match part {
			vg::Part::Text(part) if part.thought == Some(true) => Some(NormalizedMessagePart::reasoning(
				serde_json::Value::String(part.text.clone()),
			)),
			vg::Part::Text(part) => Some(NormalizedMessagePart::text(strng::new(&part.text))),
			vg::Part::FunctionCall(part) => {
				let call = &part.function_call;
				Some(NormalizedMessagePart::tool_call(
					strng::new(call.id.as_deref().unwrap_or(&call.name)),
					strng::new(&call.name),
					call.args.clone(),
				))
			},
			vg::Part::FunctionResponse(part) => {
				let response = &part.function_response;
				Some(NormalizedMessagePart::tool_result(
					Some(strng::new(response.id.as_deref().unwrap_or(&response.name))),
					Some(strng::new(&response.name)),
					response.response.clone(),
					None,
				))
			},
			vg::Part::ExecutableCode(part) => Some(NormalizedMessagePart::tool_call(
				strng::literal!("code_execution"),
				strng::literal!("code_execution"),
				part.executable_code.clone(),
			)),
			vg::Part::CodeExecutionResult(part) => Some(NormalizedMessagePart::tool_result(
				Some(strng::literal!("code_execution")),
				Some(strng::literal!("code_execution")),
				part.code_execution_result.clone(),
				None,
			)),
			vg::Part::InlineData(_)
			| vg::Part::FileData(_)
			| vg::Part::ToolCall(_)
			| vg::Part::ToolResponse(_)
			| vg::Part::Unknown(_) => None,
		})
		.collect();
	NormalizedMessage { role, parts }
}

/// Inbound native Gemini `countTokens` body. Passthrough in both directions, so only the
/// fields the gateway reads are typed; the alternative `generateContentRequest` form and any
/// other field ride `rest`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CountTokensRequest {
	/// Comes from the URI, like the generateContent routes. `read_gemini_body_and_default_model`
	/// injects it into the body JSON, so it is captured by a typed field rather than landing in
	/// `rest`; it is never serialized back onto the wire, where the upstream path carries it.
	#[serde(default, skip_serializing)]
	pub model: Option<String>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub contents: Vec<vg::Content>,
	#[serde(
		default,
		skip_serializing_if = "Option::is_none",
		alias = "system_instruction"
	)]
	pub system_instruction: Option<vg::Content>,
	#[serde(flatten, default)]
	pub rest: serde_json::Value,
}

impl RequestType for CountTokensRequest {
	fn input_format() -> crate::InputFormat {
		crate::InputFormat::GeminiCountTokens
	}
	fn body_is_json(&self) -> bool {
		true
	}

	fn model(&mut self) -> &mut Option<String> {
		&mut self.model
	}

	fn prepend_prompts(&mut self, prompts: Vec<SimpleChatCompletionMessage>) {
		prepend_prompts_helper(&mut self.contents, &mut self.system_instruction, prompts);
	}

	fn append_prompts(&mut self, prompts: Vec<SimpleChatCompletionMessage>) {
		append_prompts_helper(&mut self.contents, &mut self.system_instruction, prompts);
	}

	fn to_llm_request(&self, provider: Strng, _tokenize: bool) -> Result<LLMRequest, AIError> {
		Ok(LLMRequest {
			// We never tokenize these, so always empty
			input_tokens: None,
			input_format: InputFormat::GeminiCountTokens,
			cache_convention: crate::CacheTokenConvention::pending(),
			request_model: strng::new(self.model.as_deref().unwrap_or_default()),
			original_model: None,
			provider,
			streaming: false,
			params: Default::default(),
			prompt: Default::default(),
			provider_state: None,
		})
	}

	fn get_messages(&self) -> Vec<SimpleChatCompletionMessage> {
		get_messages_helper(&self.contents, &self.system_instruction)
	}

	fn get_messages_v2(&self) -> Vec<NormalizedMessage> {
		get_messages_v2_helper(&self.contents, &self.system_instruction)
	}

	fn to_value(&self) -> serde_json::Result<serde_json::Value> {
		serde_json::to_value(self)
	}

	fn visit_request_mut(&mut self, _v: &mut dyn crate::types::RequestVisitor) {
		unimplemented!(
			"visit_text_mut is used for prompt guard; prompt guard is disabled for gemini countTokens."
		)
	}
}

/// Native Gemini `countTokens` response: forwarded as-is, parsed only for the token count.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CountTokensResponse {
	// proto3 JSON omits zero-valued fields, so an empty request comes back without the key.
	#[serde(default)]
	pub total_tokens: u64,
}

impl CountTokensResponse {
	pub fn translate_response(bytes: Bytes) -> Result<(Bytes, u64), AIError> {
		let resp: Self = serde_json::from_slice(&bytes).map_err(logged_response_parsing(&bytes))?;
		Ok((bytes, resp.total_tokens))
	}
}

fn get_messages_helper(
	contents: &[vg::Content],
	system_instruction: &Option<vg::Content>,
) -> Vec<SimpleChatCompletionMessage> {
	let mut out = Vec::new();
	if let Some(si) = system_instruction {
		let content = joined_text(si, '\n');
		if !content.is_empty() {
			out.push(SimpleChatCompletionMessage {
				role: strng::literal!("system"),
				content,
			});
		}
	}
	out.extend(contents.iter().map(|c| {
		let role = match c.role.as_deref() {
			Some("model") => strng::literal!("assistant"),
			Some(role) => strng::new(role),
			None => strng::literal!("user"),
		};
		SimpleChatCompletionMessage {
			role,
			content: joined_text(c, ' '),
		}
	}));
	out
}

fn prepend_prompts_helper(
	contents: &mut Vec<vg::Content>,
	system_instruction: &mut Option<vg::Content>,
	prompts: Vec<SimpleChatCompletionMessage>,
) {
	let (system, chat) = partition_system(prompts);
	if !system.is_empty() {
		let si = system_instruction.get_or_insert_default();
		si.parts
			.splice(0..0, system.into_iter().map(|p| text_part(&p.content)));
	}
	if !chat.is_empty() {
		contents.splice(0..0, chat.into_iter().map(content_from_message));
	}
}

fn append_prompts_helper(
	contents: &mut Vec<vg::Content>,
	system_instruction: &mut Option<vg::Content>,
	prompts: Vec<SimpleChatCompletionMessage>,
) {
	let (system, chat) = partition_system(prompts);
	if !system.is_empty() {
		let si = system_instruction.get_or_insert_default();
		si.parts
			.extend(system.into_iter().map(|p| text_part(&p.content)));
	}
	if !chat.is_empty() {
		contents.extend(chat.into_iter().map(content_from_message));
	}
}

/// Non-streaming native Gemini response: forwarded as-is (unknown fields ride the
/// `rest` flattens), parsed only to fill telemetry and serve response guardrails.
#[derive(Debug, Clone, Deserialize)]
#[serde(transparent)]
pub struct Response(pub vg::GenerateContentResponse);

impl ResponseType for Response {
	fn to_llm_response(&self, log_content: crate::LogContentFields) -> LLMResponse {
		let um = self.0.usage_metadata.as_ref();
		let counts = um.map(vg::UsageMetadata::counts);
		LLMResponse {
			input_tokens: counts.map(|c| c.0),
			output_tokens: counts.map(|c| c.1),
			total_tokens: counts.map(|c| c.2),
			reasoning_tokens: um.and_then(|u| u.thoughts_token_count),
			cached_input_tokens: um.and_then(|u| u.cached_content_token_count),
			service_tier: um
				.and_then(|u| u.service_tier.as_deref().or(u.traffic_type.as_deref()))
				.map(strng::new),
			provider_model: self.0.model_version.as_deref().map(strng::new),
			completion: log_content.completion.then(|| {
				self
					.0
					.candidates
					.iter()
					.map(|c| c.content.as_ref().map(candidate_text).unwrap_or_default())
					.collect()
			}),
			output_messages: if log_content.tool_calls {
				extract_output_messages(&self.0)
			} else {
				None
			},
			..Default::default()
		}
	}

	fn to_webhook_choices(&self) -> Vec<webhook::ResponseChoice> {
		self
			.0
			.candidates
			.iter()
			.map(|c| webhook::ResponseChoice {
				message: webhook::Message {
					role: strng::literal!("assistant"),
					content: strng::new(c.content.as_ref().map(candidate_text).unwrap_or_default()),
				},
			})
			.collect()
	}

	fn set_webhook_choices(&mut self, choices: Vec<webhook::ResponseChoice>) -> anyhow::Result<()> {
		if self.0.candidates.len() != choices.len() {
			anyhow::bail!("webhook response message count mismatch");
		}
		for (cand, wh) in self.0.candidates.iter_mut().zip(choices) {
			if let Some(content) = &mut cand.content {
				set_visible_text(content, &wh.message.content);
			}
		}
		Ok(())
	}

	fn serialize(&self) -> serde_json::Result<Vec<u8>> {
		serde_json::to_vec(&self.0)
	}

	fn visit_text_mut(&mut self, f: &mut dyn FnMut(crate::types::ResponseText, &mut String)) {
		for candidate in &mut self.0.candidates {
			if let Some(content) = &mut candidate.content {
				for part in &mut content.parts {
					let signed = part.has_signature();
					let mut visit =
						|scope, text: &mut String| f(crate::types::ResponseText { scope, signed }, text);
					if signed && let vg::Part::Text(p) = part {
						visit(ContentScope::Messages, &mut p.text);
					} else {
						visit_part_text(part, &mut visit);
					}
				}
				visit_content_text(content, &mut |text| f(ContentScope::Messages.into(), text));
			}
		}
	}
}

/// Visible (non-thought) text of a candidate, concatenated like the OpenAI translation does.
fn candidate_text(content: &vg::Content) -> String {
	content
		.parts
		.iter()
		.filter_map(|p| match p {
			vg::Part::Text(t) if t.thought != Some(true) => Some(t.text.as_str()),
			_ => None,
		})
		.collect()
}

/// Rewrite the visible text of a candidate: the first non-thought text part carries the new
/// text, later non-thought text parts are dropped; thought and non-text parts are untouched.
fn set_visible_text(content: &mut vg::Content, text: &str) {
	let mut replaced = false;
	content.parts.retain_mut(|p| match p {
		vg::Part::Text(t) if t.thought != Some(true) => {
			// Masking to "" drops the part instead of leaving `{"text":""}`.
			let keep = !replaced && !text.is_empty();
			replaced = true;
			if keep {
				t.text = text.to_string();
			}
			keep
		},
		_ => true,
	});
	// A tool-call-only candidate has no visible text.
	if !replaced && !text.is_empty() {
		content.parts.push(text_part(text));
	}
}

fn extract_output_messages(resp: &vg::GenerateContentResponse) -> Option<Vec<OutputMessage>> {
	let out: Vec<OutputMessage> = resp
		.candidates
		.iter()
		.filter_map(|cand| {
			let content = cand.content.as_ref()?;
			let calls: Vec<OutputMessagePart> = content
				.parts
				.iter()
				.filter_map(|p| match p {
					vg::Part::FunctionCall(fc) => Some(OutputMessagePart::ToolCall {
						id: strng::new(fc.function_call.id.as_deref().unwrap_or_default()),
						name: strng::new(&fc.function_call.name),
						arguments: fc.function_call.args.clone(),
					}),
					_ => None,
				})
				.collect();
			if calls.is_empty() {
				return None;
			}
			Some(OutputMessage {
				role: strng::literal!("assistant"),
				content: calls,
				finish_reason: cand.finish_reason.as_deref().map(strng::new),
			})
		})
		.collect();
	(!out.is_empty()).then_some(out)
}

fn partition_system(
	messages: Vec<SimpleChatCompletionMessage>,
) -> (
	Vec<SimpleChatCompletionMessage>,
	Vec<SimpleChatCompletionMessage>,
) {
	messages
		.into_iter()
		.partition(|m| m.role.as_str() == "system")
}

fn joined_text(content: &vg::Content, sep: char) -> Strng {
	let text = content
		.parts
		.iter()
		.filter_map(|p| match p {
			vg::Part::Text(t) => Some(t.text.as_str()),
			_ => None,
		})
		.fold(String::new(), |mut acc, s| {
			if !acc.is_empty() {
				acc.push(sep);
			}
			acc.push_str(s);
			acc
		});
	strng::new(&text)
}

fn content_from_message(m: SimpleChatCompletionMessage) -> vg::Content {
	let role = match m.role.as_str() {
		"assistant" => "model".to_string(),
		role => role.to_string(),
	};
	vg::Content {
		role: Some(role),
		parts: vec![text_part(&m.content)],
		rest: Default::default(),
	}
}

fn text_part(text: &str) -> vg::Part {
	vg::Part::Text(vg::TextPart {
		text: text.to_string(),
		thought: None,
		thought_signature: None,
		rest: Default::default(),
	})
}

#[cfg(test)]
mod tests {
	use serde_json::json;

	use super::*;

	fn request(body: serde_json::Value) -> Request {
		serde_json::from_value(body).expect("valid request")
	}

	#[test]
	fn deserialize_lifts_the_injected_model_out_of_the_body() {
		// The gateway injects the resolved model (URI, backend pin, or whatever the operator's body
		// mutations made of it) so the wrapper is where it must be read back from — but the wire
		// body has no such field and Vertex rejects unknown ones.
		let req = request(json!({
			"model": "gemini-2.5-flash",
			"contents": [{ "role": "user", "parts": [{ "text": "hi" }] }],
			"someNewTopLevelField": { "a": true }
		}));
		assert_eq!(req.model.as_deref(), Some("gemini-2.5-flash"));
		assert!(!req.streaming);
		assert_eq!(req.inner.contents.len(), 1);

		let out = serde_json::to_value(&req.inner).expect("serialize");
		assert!(
			out.get("model").is_none(),
			"the gateway-injected model must not reach the wire: {out}"
		);
		assert_eq!(out["someNewTopLevelField"], json!({ "a": true }));

		let bare = request(json!({ "contents": [] }));
		assert_eq!(bare.model, None);
	}

	#[test]
	fn snake_case_field_names_parse_like_camel_case() {
		// proto3 JSON accepts the original snake_case proto field names alongside camelCase;
		// both spellings must reach the typed fields (prompt guard, params) rather than
		// silently riding `rest`.
		let req = request(json!({
			"system_instruction": { "parts": [{ "text": "be brief" }] },
			"contents": [{ "role": "user", "parts": [
				{ "function_call": { "name": "f", "args": {} } },
				{ "inline_data": { "mime_type": "image/png", "data": "aGk=" } }
			] }],
			"generation_config": { "top_p": 0.5, "max_output_tokens": 100 }
		}));
		assert!(req.inner.system_instruction.is_some());
		assert!(matches!(
			req.inner.contents[0].parts[0],
			vg::Part::FunctionCall(_)
		));
		assert!(matches!(
			req.inner.contents[0].parts[1],
			vg::Part::InlineData(_)
		));
		let gc = req.inner.generation_config.as_ref().unwrap();
		assert_eq!(gc.top_p, Some(0.5));
		assert_eq!(gc.max_output_tokens, Some(100));
		// Nothing leaked into the catch-alls.
		assert_eq!(req.inner.rest, json!({}));
		assert_eq!(gc.rest, json!({}));
	}

	#[test]
	fn unread_fields_pass_through_regardless_of_shape() {
		// Only the fields the gateway reads are typed; a field we do not read must never be
		// able to fail parsing, even with a shape the current API docs would not predict.
		let raw = json!({
			"contents": [{ "role": "user", "parts": [{ "text": "hi" }] }],
			"labels": ["not", "a", "map"],
			"cachedContent": { "name": "cachedContents/abc" },
			"tools": "surprising-string"
		});
		let req = request(raw.clone());
		let out = serde_json::to_value(&req.inner).expect("serialize");
		assert_eq!(out["labels"], raw["labels"]);
		assert_eq!(out["cachedContent"], raw["cachedContent"]);
		assert_eq!(out["tools"], raw["tools"]);
	}

	#[test]
	fn get_messages_maps_system_instruction_and_contents() {
		let req = request(json!({
			"systemInstruction": { "parts": [{ "text": "be brief" }, { "text": "be kind" }] },
			"contents": [
				{ "role": "user", "parts": [{ "text": "hello" }, { "text": "there" }] },
				{ "role": "model", "parts": [{ "text": "hi!" }] },
				{ "parts": [{ "text": "and you?" }] }
			]
		}));
		let msgs = req.get_messages();
		assert_eq!(msgs.len(), 4);
		assert_eq!(msgs[0].role, "system");
		assert_eq!(msgs[0].content, "be brief\nbe kind");
		assert_eq!(msgs[1].role, "user");
		assert_eq!(msgs[1].content, "hello there");
		assert_eq!(msgs[2].role, "assistant");
		assert_eq!(msgs[2].content, "hi!");
		// Missing role defaults to user.
		assert_eq!(msgs[3].role, "user");
	}

	#[test]
	fn get_messages_and_prompt_enrichment_map_roles() {
		let body = json!({
			"contents": [
				{ "role": "user", "parts": [{ "text": "a" }] },
				{ "role": "model", "parts": [{ "text": "b" }] }
			]
		});
		let mut req = request(body.clone());
		let msgs = req.get_messages();
		assert_eq!(
			msgs.iter().map(|m| m.role.as_str()).collect::<Vec<_>>(),
			["user", "assistant"]
		);
		// Prompt enrichment maps the normalized assistant role back to model.
		req.append_prompts(vec![SimpleChatCompletionMessage {
			role: strng::literal!("assistant"),
			content: strng::literal!("c"),
		}]);
		assert_eq!(
			req
				.inner
				.contents
				.iter()
				.map(|c| c.role.as_deref().unwrap_or_default())
				.collect::<Vec<_>>(),
			["user", "model", "model"]
		);
	}

	#[test]
	fn masking_a_candidate_to_empty_drops_the_visible_text_part() {
		let mut resp = response(json!({
			"candidates": [{
				"content": { "role": "model", "parts": [
					{ "text": "internal reasoning", "thought": true },
					{ "text": "secret answer" },
					{ "functionCall": { "name": "f", "args": {} } }
				] },
				"finishReason": "STOP"
			}]
		}));
		let mut choices = resp.to_webhook_choices();
		choices[0].message.content = "".into();
		resp.set_webhook_choices(choices).expect("set choices");

		let out: serde_json::Value =
			serde_json::from_slice(&ResponseType::serialize(&resp).expect("serialize")).unwrap();
		assert_eq!(
			out["candidates"][0]["content"]["parts"],
			json!([
				{ "text": "internal reasoning", "thought": true },
				{ "functionCall": { "name": "f", "args": {} } }
			])
		);
	}

	#[test]
	fn masking_a_text_only_candidate_to_empty_leaves_no_parts() {
		let mut resp = response(json!({
			"candidates": [{
				"content": { "role": "model", "parts": [{ "text": "secret answer" }] },
				"finishReason": "STOP"
			}]
		}));
		let mut choices = resp.to_webhook_choices();
		choices[0].message.content = "".into();
		resp.set_webhook_choices(choices).expect("set choices");

		let out: serde_json::Value =
			serde_json::from_slice(&ResponseType::serialize(&resp).expect("serialize")).unwrap();
		// The same shape Google emits for a candidate it blocked itself.
		assert_eq!(
			out["candidates"][0],
			json!({ "content": { "role": "model" }, "finishReason": "STOP" })
		);
	}

	#[test]
	fn prepend_and_append_prompts_map_roles() {
		let mut req = request(json!({
			"contents": [{ "role": "user", "parts": [{ "text": "question" }] }]
		}));
		req.prepend_prompts(vec![
			SimpleChatCompletionMessage {
				role: strng::literal!("system"),
				content: strng::literal!("sys"),
			},
			SimpleChatCompletionMessage {
				role: strng::literal!("assistant"),
				content: strng::literal!("earlier answer"),
			},
		]);
		req.append_prompts(vec![SimpleChatCompletionMessage {
			role: strng::literal!("user"),
			content: strng::literal!("suffix"),
		}]);

		let si = req.inner.system_instruction.as_ref().unwrap();
		assert_eq!(si.parts.len(), 1);
		assert_eq!(req.inner.contents.len(), 3);
		assert_eq!(req.inner.contents[0].role.as_deref(), Some("model"));
		assert_eq!(req.inner.contents[2].role.as_deref(), Some("user"));
	}

	fn response(body: serde_json::Value) -> Response {
		serde_json::from_value(body).expect("valid response")
	}

	#[test]
	fn response_to_llm_response_extracts_usage_and_visible_completion() {
		let resp = response(json!({
			"candidates": [{
				"content": { "role": "model", "parts": [
					{ "text": "internal reasoning", "thought": true },
					{ "text": "hello" }
				] },
				"finishReason": "STOP"
			}],
			"usageMetadata": {
				"promptTokenCount": 10,
				"candidatesTokenCount": 5,
				"totalTokenCount": 17,
				"thoughtsTokenCount": 2,
				"cachedContentTokenCount": 3,
				"serviceTier": "flex"
			},
			"modelVersion": "gemini-2.5-flash"
		}));
		let llm = resp.to_llm_response(crate::LogContentFields {
			completion: true,
			tool_calls: true,
		});
		assert_eq!(llm.input_tokens, Some(10));
		// Output is normalized to candidates + thoughts (5 + 2), matching other providers.
		assert_eq!(llm.output_tokens, Some(7));
		assert_eq!(llm.total_tokens, Some(17));
		assert_eq!(llm.reasoning_tokens, Some(2));
		assert_eq!(llm.cached_input_tokens, Some(3));
		assert_eq!(llm.service_tier.as_deref(), Some("flex"));
		assert_eq!(llm.provider_model.as_deref(), Some("gemini-2.5-flash"));
		assert_eq!(llm.completion, Some(vec!["hello".to_string()]));
		assert!(llm.output_messages.is_none());
	}

	#[test]
	fn response_total_tokens_fall_back_to_prompt_plus_candidates() {
		let resp = response(json!({
			"usageMetadata": { "promptTokenCount": 4, "candidatesTokenCount": 6 }
		}));
		let llm = resp.to_llm_response(Default::default());
		assert_eq!(llm.total_tokens, Some(10));
	}

	#[test]
	fn response_serialize_preserves_unknown_fields() {
		let raw = json!({
			"candidates": [{
				"content": { "role": "model", "parts": [{ "text": "hi", "someNewPartField": 1 }] },
				"finishReason": "STOP",
				"someNewCandidateField": { "a": true }
			}],
			"usageMetadata": { "promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 2 },
			"someNewTopLevelField": "x"
		});
		let resp = response(raw.clone());
		let out: serde_json::Value =
			serde_json::from_slice(&ResponseType::serialize(&resp).expect("serialize")).unwrap();
		assert_eq!(out, raw);
	}

	#[test]
	fn response_webhook_masking_rewrites_visible_text_only() {
		let mut resp = response(json!({
			"candidates": [{
				"content": { "role": "model", "parts": [
					{ "text": "internal reasoning", "thought": true },
					{ "text": "secret answer" },
					{ "functionCall": { "name": "f", "args": {} } }
				] },
				"finishReason": "STOP"
			}]
		}));
		let mut choices = resp.to_webhook_choices();
		assert_eq!(choices.len(), 1);
		assert_eq!(choices[0].message.content, "secret answer");
		choices[0].message.content = strng::literal!("MASKED");
		resp.set_webhook_choices(choices).expect("set choices");

		let parts = &resp.0.candidates[0].content.as_ref().unwrap().parts;
		assert_eq!(parts.len(), 3);
		let vg::Part::Text(thought) = &parts[0] else {
			panic!("expected thought part first");
		};
		assert_eq!(thought.text, "internal reasoning");
		let vg::Part::Text(visible) = &parts[1] else {
			panic!("expected visible text part");
		};
		assert_eq!(visible.text, "MASKED");
		assert!(matches!(parts[2], vg::Part::FunctionCall(_)));
	}

	#[test]
	fn response_webhook_masking_leaves_tool_call_only_candidates_alone() {
		let body = json!({
			"candidates": [
				{ "content": { "role": "model", "parts": [{ "text": "secret" }] }, "finishReason": "STOP" },
				{ "content": { "role": "model", "parts": [
					{ "functionCall": { "name": "f", "id": "fc_1", "args": {} } }
				] }, "finishReason": "STOP" }
			]
		});
		let mut resp = response(body.clone());
		let mut choices = resp.to_webhook_choices();
		assert_eq!(choices[1].message.content, "");
		choices[0].message.content = strng::literal!("MASKED");
		resp.set_webhook_choices(choices).expect("set choices");

		let out: serde_json::Value =
			serde_json::from_slice(&ResponseType::serialize(&resp).expect("serialize")).unwrap();
		assert_eq!(
			out["candidates"][0]["content"]["parts"][0]["text"],
			"MASKED"
		);
		assert_eq!(
			out["candidates"][1], body["candidates"][1],
			"a tool-call-only candidate must not gain an empty text part"
		);
	}

	#[test]
	fn response_tool_calls_surface_as_output_messages() {
		let resp = response(json!({
			"candidates": [{
				"content": { "role": "model", "parts": [
					{ "functionCall": { "name": "get_weather", "id": "c1", "args": { "city": "Berlin" } } }
				] },
				"finishReason": "STOP"
			}]
		}));
		let llm = resp.to_llm_response(crate::LogContentFields {
			completion: false,
			tool_calls: true,
		});
		let messages = llm.output_messages.expect("output messages");
		assert_eq!(messages.len(), 1);
		let tool_calls = messages[0].tool_calls();
		assert_eq!(tool_calls.len(), 1);
		assert_eq!(tool_calls[0].name, "get_weather");
		assert_eq!(tool_calls[0].id, "c1");
		assert_eq!(tool_calls[0].arguments["city"], "Berlin");
	}

	#[test]
	fn to_llm_request_reports_gemini_format_and_uri_derived_fields() {
		let mut req = request(json!({
			"contents": [{ "role": "user", "parts": [{ "text": "hi" }] }],
			"generationConfig": { "temperature": 0.5, "topP": 0.9, "maxOutputTokens": 128, "seed": 7 }
		}));
		req.model = Some("gemini-2.5-flash".to_string());
		req.streaming = true;

		let llm = req
			.to_llm_request(strng::literal!("vertex"), false)
			.expect("llm request");
		assert_eq!(llm.input_format, InputFormat::Gemini);
		assert_eq!(llm.request_model, "gemini-2.5-flash");
		assert!(llm.streaming);
		assert_eq!(llm.params.temperature, Some(0.5f32 as f64));
		assert_eq!(llm.params.top_p, Some(0.9f32 as f64));
		assert_eq!(llm.params.max_tokens, Some(128));
		assert_eq!(llm.params.seed, Some(7));
	}

	fn count_tokens_request(body: serde_json::Value) -> CountTokensRequest {
		serde_json::from_value(body).expect("valid countTokens request")
	}

	#[test]
	fn count_tokens_request_strips_model_and_keeps_unknown_fields() {
		let mut req = count_tokens_request(json!({
			"model": "injected-by-the-gateway",
			"contents": [{ "role": "user", "parts": [{ "text": "hi" }] }],
			"generateContentRequest": {
				"model": "models/gemini-2.5-flash",
				"contents": [{ "role": "user", "parts": [{ "text": "hi" }] }],
				"tools": [{ "googleSearch": {} }]
			}
		}));
		assert_eq!(req.model.as_deref(), Some("injected-by-the-gateway"));

		*req.model() = Some("gemini-2.5-flash".to_string());
		let out: serde_json::Value = serde_json::to_value(&req).expect("serialize");
		assert!(
			out.get("model").is_none(),
			"the gateway-injected model must not reach the wire: {out}"
		);
		assert_eq!(
			out["generateContentRequest"]["tools"][0]["googleSearch"],
			json!({})
		);
		assert_eq!(out["contents"][0]["parts"][0]["text"], "hi");
	}

	#[test]
	fn count_tokens_request_reports_its_own_input_format() {
		let mut req = count_tokens_request(json!({
			"systemInstruction": { "parts": [{ "text": "be brief" }] },
			"contents": [{ "role": "user", "parts": [{ "text": "hi" }] }]
		}));
		*req.model() = Some("gemini-2.5-flash".to_string());

		let llm = req
			.to_llm_request(strng::literal!("vertex"), true)
			.expect("llm request");
		assert_eq!(llm.input_format, InputFormat::GeminiCountTokens);
		assert_eq!(llm.request_model, "gemini-2.5-flash");
		assert!(!llm.streaming);
		assert_eq!(llm.input_tokens, None);

		let msgs = req.get_messages();
		assert_eq!(msgs.len(), 2);
		assert_eq!(msgs[0].role, "system");
		assert_eq!(msgs[1].content, "hi");
	}

	#[test]
	fn count_tokens_request_enrichment_appends_contents() {
		let mut req = count_tokens_request(json!({
			"contents": [{ "role": "user", "parts": [{ "text": "hi" }] }]
		}));
		req.append_prompts(vec![SimpleChatCompletionMessage {
			role: strng::literal!("user"),
			content: strng::literal!("suffix"),
		}]);
		assert_eq!(req.contents.len(), 2);
		let out: serde_json::Value = serde_json::to_value(&req).expect("serialize");
		assert_eq!(out["contents"][1]["parts"][0]["text"], "suffix");
	}

	#[test]
	fn count_tokens_response_extracts_total_tokens() {
		let body = Bytes::from_static(
			br#"{"totalTokens":31,"totalBillableCharacters":96,"promptTokensDetails":[{"modality":"TEXT","tokenCount":31}]}"#,
		);
		let (out, count) = CountTokensResponse::translate_response(body.clone()).expect("parse");
		assert_eq!(count, 31);
		assert_eq!(
			out, body,
			"the countTokens response is passed through as-is"
		);
	}

	#[test]
	fn count_tokens_response_defaults_missing_total_to_zero() {
		let body = Bytes::from_static(br#"{"promptTokensDetails":[]}"#);
		let (_, count) = CountTokensResponse::translate_response(body).expect("parse");
		assert_eq!(count, 0);
	}
}
