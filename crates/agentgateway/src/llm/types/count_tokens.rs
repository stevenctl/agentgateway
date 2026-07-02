use agent_core::prelude::Strng;
use agent_core::strng;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::llm::types::{RequestType, messages};
use crate::llm::{
	AIError, InputFormat, LLMRequest, SimpleChatCompletionMessage, conversion,
	logged_response_parsing,
};
use crate::proxy::httpproxy::PolicyClient;
use crate::store::BackendPolicies;
use crate::telemetry::metrics::{OutboundCallKind, OutboundCallSubtype};
use crate::types::agent::SimpleBackend;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Request {
	pub messages: Vec<messages::RequestMessage>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub model: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub system: Option<messages::TextBlock>,
	#[serde(flatten)]
	pub rest: serde_json::Map<String, serde_json::Value>,
}

impl Request {
	pub fn from_messages_request(req: &messages::Request) -> Self {
		Self {
			messages: req.messages.clone(),
			model: req.model.clone(),
			system: req.system.clone(),
			rest: count_tokens_rest_from_messages(req),
		}
	}
}

fn count_tokens_rest_from_messages(
	req: &messages::Request,
) -> serde_json::Map<String, serde_json::Value> {
	let mut rest = serde_json::Map::new();
	let Some(obj) = req.rest.as_object() else {
		return rest;
	};
	for key in ["tools", "tool_choice", "thinking"] {
		if let Some(value) = obj.get(key) {
			rest.insert(key.to_string(), value.clone());
		}
	}
	rest
}

impl RequestType for Request {
	fn model(&mut self) -> &mut Option<String> {
		&mut self.model
	}

	fn prepend_prompts(&mut self, prompts: Vec<SimpleChatCompletionMessage>) {
		messages::prepend_prompts_helper(&mut self.messages, &mut self.system, prompts);
	}

	fn append_prompts(&mut self, prompts: Vec<SimpleChatCompletionMessage>) {
		messages::append_prompts_helper(&mut self.messages, &mut self.system, prompts);
	}

	fn to_llm_request(&self, provider: Strng, _tokenize: bool) -> Result<LLMRequest, AIError> {
		let model = strng::new(self.model.as_deref().unwrap_or_default());
		Ok(LLMRequest {
			// We never tokenize these, so always empty
			input_tokens: None,
			compression: None,
			input_format: InputFormat::CountTokens,
			native_format: Some(crate::llm::custom::ProviderFormat::AnthropicTokenCount),
			cache_convention: crate::llm::CacheTokenConvention::pending(),
			request_model: model,
			provider,
			streaming: false,
			params: Default::default(),
			prompt: Default::default(),
			provider_state: None,
		})
	}

	fn get_messages(&self) -> Vec<SimpleChatCompletionMessage> {
		messages::get_messages_helper(&self.messages, &self.system)
	}

	fn set_messages(&mut self, _messages: Vec<SimpleChatCompletionMessage>) {
		unimplemented!(
			"set_messages is used for prompt guard; prompt guard is disable for token counting."
		)
	}

	fn to_anthropic(&self) -> Result<Vec<u8>, AIError> {
		serde_json::to_vec(&self).map_err(AIError::RequestMarshal)
	}

	fn to_bedrock_token_count(&self, headers: &::http::HeaderMap) -> Result<Vec<u8>, AIError> {
		conversion::bedrock::from_anthropic_token_count::translate(self, headers)
	}

	fn to_vertex(&self, provider: &crate::llm::vertex::Provider) -> Result<Vec<u8>, AIError> {
		let body = self.to_anthropic()?;
		provider.prepare_anthropic_count_tokens_body(body)
	}
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Response {
	#[serde(alias = "inputTokens")]
	pub input_tokens: u64,
}

impl Response {
	pub fn translate_response(bytes: Bytes) -> Result<(Bytes, u64), AIError> {
		let resp: Self = serde_json::from_slice(&bytes).map_err(logged_response_parsing(&bytes))?;
		Ok((bytes, resp.input_tokens))
	}
}

/// Headers to carry over from the (already backend-authed) inbound request to an
/// Anthropic-compatible count_tokens side call.
const ANTHROPIC_COUNT_TOKENS_HEADERS: [&str; 4] = [
	"x-api-key",
	"authorization",
	"anthropic-version",
	"anthropic-beta",
];

pub fn anthropic_count_tokens_headers(inbound: &::http::HeaderMap) -> ::http::HeaderMap {
	let mut headers = ::http::HeaderMap::new();
	for name in ANTHROPIC_COUNT_TOKENS_HEADERS {
		if let Some(v) = inbound.get(name) {
			headers.insert(::http::HeaderName::from_static(name), v.clone());
		}
	}
	if !headers.contains_key("anthropic-version") {
		headers.insert(
			::http::HeaderName::from_static("anthropic-version"),
			::http::HeaderValue::from_static("2023-06-01"),
		);
	}
	headers
}

/// Count a request's input tokens through a provider count_tokens endpoint. The request,
/// backend, and connector policies are prepared by the LLM provider from the same routing as
/// the public count_tokens route.
pub async fn count_input_tokens(
	client: &PolicyClient,
	req: crate::http::Request,
	backend: SimpleBackend,
	policies: BackendPolicies,
) -> anyhow::Result<u64> {
	let res = client
		.with_outbound(OutboundCallKind::Policy, OutboundCallSubtype::Compression)
		.call_with_explicit_policies(req, &backend, policies)
		.await?;
	let status = res.status();
	if status != ::http::StatusCode::OK {
		anyhow::bail!("count_tokens returned status {status}");
	}
	let lim = crate::http::response_buffer_limit(&res);
	let raw = crate::http::read_body_with_limit(res.into_body(), lim).await?;
	let (_, count) = Response::translate_response(raw)?;
	Ok(count)
}

#[cfg(test)]
mod tests {
	use super::*;

	// Anthropic count_tokens rejects extra inputs; the request must keep only accepted fields.
	#[test]
	fn from_messages_request_strips_disallowed_fields() {
		let req: messages::Request = serde_json::from_value(serde_json::json!({
			"model": "claude-x",
			"messages": [{ "role": "user", "content": "hi" }],
			"system": "be brief",
			"tools": [{ "name": "lookup", "input_schema": { "type": "object" } }],
			"tool_choice": { "type": "auto" },
			"thinking": { "type": "enabled", "budget_tokens": 1024 },
			"max_tokens": 1024,
			"stream": true,
			"metadata": { "user_id": "u1" }
		}))
		.unwrap();
		let count_req = Request::from_messages_request(&req);
		let body = serde_json::to_value(count_req).unwrap();
		let obj = body.as_object().unwrap();
		assert!(obj.contains_key("model") && obj.contains_key("messages"));
		assert!(obj.contains_key("system"));
		assert!(obj.contains_key("tools"));
		assert!(obj.contains_key("tool_choice"));
		assert!(obj.contains_key("thinking"));
		assert!(!obj.contains_key("max_tokens"));
		assert!(!obj.contains_key("stream"));
		assert!(!obj.contains_key("metadata"));
	}

	// The side call reuses backend-authed inbound headers and defaults the API version.
	#[test]
	fn anthropic_count_tokens_headers_copies_auth_and_defaults_version() {
		let mut inbound = ::http::HeaderMap::new();
		inbound.insert("x-api-key", ::http::HeaderValue::from_static("sk-ant-xxx"));
		inbound.insert("content-length", ::http::HeaderValue::from_static("42"));
		let out = anthropic_count_tokens_headers(&inbound);
		assert_eq!(out.get("x-api-key").unwrap(), "sk-ant-xxx");
		assert_eq!(out.get("anthropic-version").unwrap(), "2023-06-01");
		assert!(out.get("content-length").is_none());
	}
}
