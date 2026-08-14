pub mod bedrock;
pub mod completions;
pub mod count_tokens;
pub mod detect;
pub mod embeddings;
pub mod messages;
pub mod rerank;
pub mod responses;
pub mod vertex;
pub mod vertex_gemini;

use agent_core::prelude::Strng;
use agent_core::strng;
use serde::Serialize;

use crate::{AIError, LLMRequest, LLMResponse, apply};

pub enum ChatRequest {
	Completions(completions::Request),
	Messages(messages::Request),
	Responses(responses::Request),
}

pub(crate) fn thinking_budget_for_reasoning_effort(
	effort: &completions::typed::ReasoningEffort,
) -> Option<u64> {
	use completions::typed::ReasoningEffort;

	match effort {
		ReasoningEffort::None => None,
		ReasoningEffort::Minimal | ReasoningEffort::Low => Some(1024),
		ReasoningEffort::Medium => Some(2048),
		ReasoningEffort::High => Some(4096),
		ReasoningEffort::Xhigh => Some(8192),
		ReasoningEffort::Max => Some(16384),
	}
}

/// ResponseType is an abstraction over provider/endpoint specific response formats that enables
/// uniform policy enforcement and observability
pub trait ResponseType: Send + Sync {
	fn to_llm_response(&self, log_content: crate::LogContentFields) -> LLMResponse;
	fn to_webhook_choices(&self) -> Vec<crate::webhook::ResponseChoice>;
	fn set_webhook_choices(
		&mut self,
		resp: Vec<crate::webhook::ResponseChoice>,
	) -> anyhow::Result<()>;
	fn serialize(&self) -> serde_json::Result<Vec<u8>>;
	fn visit_text_mut(&mut self, f: &mut dyn FnMut(&mut String));
}

/// RequestType is an abstraction over provider/endpoint specific request formats that enables
/// uniform policy enforcement and observability
pub trait RequestType: Send + Sync {
	fn supports_model(&self) -> bool {
		true
	}
	fn body_is_json(&self) -> bool;
	fn model(&mut self) -> &mut Option<String>;
	fn prepend_prompts(&mut self, prompts: Vec<SimpleChatCompletionMessage>);
	fn append_prompts(&mut self, prompts: Vec<SimpleChatCompletionMessage>);
	fn to_llm_request(&self, provider: Strng, tokenize: bool) -> Result<LLMRequest, AIError>;
	fn get_messages(&self) -> Vec<SimpleChatCompletionMessage>;
	fn set_messages(&mut self, messages: Vec<SimpleChatCompletionMessage>);
	/// Write replacement text into existing messages in place, aligned with `get_messages` order;
	/// `None` leaves that message untouched. Unlike `set_messages`, non-text content and message
	/// fields survive. Default rebuilds via `set_messages` for types without an in-place impl.
	fn patch_messages(&mut self, patches: Vec<Option<String>>) {
		let mut messages = self.get_messages();
		for (m, patch) in messages.iter_mut().zip(patches) {
			if let Some(text) = patch {
				m.content = strng::new(&text);
			}
		}
		self.set_messages(messages);
	}
	fn to_value(&self) -> serde_json::Result<serde_json::Value>;
	fn visit_text_mut(&mut self, f: &mut dyn FnMut(&mut String));
}

/// Scan runs of consecutive text parts as one `sep`-joined string: `[t1, t2, img, t3]` scans
/// `"t1{sep}t2"` then `"t3"`. An edited run collapses into its last part (keeping its other
/// fields, e.g. `cache_control`); untouched runs pass through unchanged.
pub(crate) fn scan_text_runs<T>(
	parts: &mut Vec<T>,
	sep: &str,
	mut text_of: impl FnMut(&mut T) -> Option<&mut String>,
	f: &mut dyn FnMut(&mut String),
) {
	if let [part] = parts.as_mut_slice() {
		if let Some(text) = text_of(part) {
			f(text);
		}
		return;
	}

	let mut i = 0;
	while i < parts.len() {
		let mut joined = String::new();
		let mut end = i;

		// join until we hit non-text or the end of the list
		while let Some(text) = parts.get_mut(end).and_then(&mut text_of) {
			if end > i {
				joined.push_str(sep);
			}
			joined.push_str(text);
			end += 1;
		}
		if end == i {
			i += 1;
			continue;
		}

		// don't collapse the run into a single part if `f` wouldn't mutate it
		let original = joined.clone();
		f(&mut joined);
		if joined == original {
			i = end;
			continue;
		}

		// collapse the run's text into the last part, and remove the others
		if let Some(text) = text_of(&mut parts[end - 1]) {
			*text = joined;
		}
		parts.drain(i..end - 1);
		i += 1;
	}
}

/// Collapse a message's text parts into the last one (which keeps its other fields, mirroring
/// `scan_text_runs`) and write `text` into it; non-text parts stay in place. Cache breakpoint
/// keys (`carry_keys`) on removed parts are carried onto the survivor so masking does not
/// silently disable prompt caching. Returns false when there is no text part to write into.
pub(crate) fn collapse_text_parts_with<T>(
	parts: &mut Vec<T>,
	mut text_of: impl FnMut(&mut T) -> Option<&mut String>,
	mut rest_of: impl FnMut(&mut T) -> Option<&mut serde_json::Value>,
	carry_keys: &[&str],
	text: &str,
) -> bool {
	let text_idxs: Vec<usize> = (0..parts.len())
		.filter(|&i| text_of(&mut parts[i]).is_some())
		.collect();
	let Some((&survivor, drained)) = text_idxs.split_last() else {
		return false;
	};
	let mut carried = serde_json::Map::new();
	for &i in drained {
		if let Some(rest) = rest_of(&mut parts[i]) {
			for key in carry_keys {
				if let Some(v) = rest.get(*key) {
					carried.insert((*key).to_string(), v.clone());
				}
			}
		}
	}
	if let Some(t) = text_of(&mut parts[survivor]) {
		*t = text.to_string();
	}
	if !carried.is_empty()
		&& let Some(rest) = rest_of(&mut parts[survivor])
	{
		if !rest.is_object() {
			*rest = serde_json::Value::Object(Default::default());
		}
		if let Some(obj) = rest.as_object_mut() {
			for (k, v) in carried {
				obj.entry(k).or_insert(v);
			}
		}
	}
	for &i in drained.iter().rev() {
		parts.remove(i);
	}
	true
}

/// SimpleChatCompletionMessage is a simplified chat message
#[apply(schema!)]
#[derive(Eq, PartialEq, cel::DynamicType)]
pub struct SimpleChatCompletionMessage {
	/// Message role, such as "system", "user", or "assistant".
	pub role: Strng,
	/// Message text content.
	pub content: Strng,
}

/// ToolCall represents a single tool/function invocation surfaced for observability.
#[apply(schema!)]
#[derive(cel::DynamicType)]
pub struct ToolCall {
	pub id: Strng,
	pub name: Strng,
	#[cfg_attr(feature = "schema", schemars(with = "serde_json::Value"))]
	pub arguments: serde_json::Value,
}

/// A single content part within an output message, per the GenAI semantic conventions.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutputMessagePart {
	ToolCall {
		id: Strng,
		name: Strng,
		arguments: serde_json::Value,
	},
}

/// A structured output message for the `gen_ai.output.messages` semantic convention attribute.
#[derive(Debug, Clone, Serialize)]
pub struct OutputMessage {
	pub role: Strng,
	pub content: Vec<OutputMessagePart>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub finish_reason: Option<Strng>,
}

impl OutputMessage {
	pub fn tool_calls(&self) -> Vec<ToolCall> {
		self
			.content
			.iter()
			.map(|p| match p {
				OutputMessagePart::ToolCall {
					id,
					name,
					arguments,
				} => ToolCall {
					id: id.clone(),
					name: name.clone(),
					arguments: arguments.clone(),
				},
			})
			.collect()
	}
}

pub fn serialize_str<T: Serialize>(value: &T) -> Option<Strng> {
	serde_json::to_value(value).ok()?.as_str().map(Into::into)
}
