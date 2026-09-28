use std::sync::Arc;

use bytes::Bytes;
use serde::Deserialize;
use serde_json::Value;

use super::{MAX_RESULT_BYTES, Root, api_path, usage};
use crate::http::{Method, Request, Response};
use crate::llm::catalog::ModelCatalog;
use crate::llm::types::{completions, messages, responses};
use crate::llm::{CacheTokenConvention, InputFormat, LLMInfo, ResponseType};

/// Logs the usage of each record in a batch result download proxied to the provider.
pub(super) struct Observation {
	provider: &'static str,
	artifact: String,
	catalog: Arc<ModelCatalog>,
	buffer: Vec<u8>,
	skipping: bool,
}

impl Observation {
	pub(super) fn for_request(
		req: &Request,
		provider: &'static str,
		catalog: Arc<ModelCatalog>,
	) -> Option<Self> {
		let (root, path) = api_path(req.uri().path())?;
		let download = req.method() == Method::GET
			&& match root {
				Root::Files => path.ends_with("/content"),
				Root::MessageBatches => path.ends_with("/results"),
				_ => false,
			};
		download.then(|| Self {
			provider,
			artifact: path.to_owned(),
			catalog,
			buffer: Vec::new(),
			skipping: false,
		})
	}

	pub(super) fn attach(self, response: Response) -> Response {
		if !response.status().is_success() {
			return response;
		}
		let (parts, body) = response.into_parts();
		Response::from_parts(parts, body.with_observer(self))
	}

	fn observe(&self, bytes: &[u8]) {
		let Ok(record) = serde_json::from_slice::<Value>(bytes) else {
			return;
		};
		if let Some(id) = record["custom_id"].as_str()
			&& let Some(info) = result_usage(&record, self.provider)
		{
			usage::log(&self.catalog, &self.artifact, id, &info);
		}
	}

	fn push(&mut self, bytes: &[u8]) {
		for part in bytes.split_inclusive(|byte| *byte == b'\n') {
			if !self.skipping {
				if self.buffer.len().saturating_add(part.len()) > MAX_RESULT_BYTES {
					self.buffer.clear();
					self.skipping = true;
				} else {
					self.buffer.extend_from_slice(part);
				}
			}
			if part.ends_with(b"\n") {
				if !self.skipping {
					self.observe(&self.buffer);
				}
				self.buffer.clear();
				self.skipping = false;
			}
		}
	}
}

impl agent_http::BodyObserver for Observation {
	fn on_frame(&mut self, frame: &http_body::Frame<Bytes>) {
		if let Some(bytes) = frame.data_ref() {
			self.push(bytes);
		}
	}
}

impl Drop for Observation {
	fn drop(&mut self) {
		if !self.skipping && !self.buffer.is_empty() {
			self.observe(&self.buffer);
		}
	}
}

fn result_usage(record: &Value, provider: &str) -> Option<LLMInfo> {
	let (body, input_format, cache_convention) = if provider == "anthropic" {
		(
			&record["result"]["message"],
			InputFormat::Messages,
			CacheTokenConvention::InputExcludesCache,
		)
	} else {
		let body = &record["response"]["body"];
		let format = if body["object"] == "response" {
			InputFormat::Responses
		} else {
			InputFormat::Completions
		};
		(body, format, CacheTokenConvention::InputIncludesCache)
	};
	let response = match input_format {
		InputFormat::Messages => messages::Response::deserialize(body)
			.ok()?
			.to_llm_response(Default::default()),
		InputFormat::Responses => responses::Response::deserialize(body)
			.ok()?
			.to_llm_response(Default::default()),
		_ => completions::Response::deserialize(body)
			.ok()?
			.to_llm_response(Default::default()),
	};
	if response.input_tokens.is_none() || response.output_tokens.is_none() {
		return None;
	}
	usage::info(response, input_format, cache_convention, provider)
}

#[cfg(test)]
mod tests {
	use serde_json::json;

	use super::*;
	use crate::http::Body;

	fn completion() -> Value {
		json!({"custom_id": "request-1", "response": {"status_code": 200, "body": {
			"id": "chatcmpl-1", "object": "chat.completion", "created": 1,
			"model": "gpt-4.1-mini", "choices": [],
			"usage": {"prompt_tokens": 1000, "completion_tokens": 100, "total_tokens": 1100,
				"prompt_tokens_details": {"cached_tokens": 400}}
		}}})
	}

	#[test]
	fn native_result_usage_preserves_cache_conventions() {
		let openai = result_usage(&completion(), "openai").unwrap();
		assert_eq!(openai.normalized_input_tokens(), Some(1000));
		assert_eq!(openai.response.cached_input_tokens, Some(400));
		let responses = json!({"custom_id": "request-2", "response": {"status_code": 200, "body": {
			"id": "resp-1", "object": "response", "status": "completed", "output": [], "model": "gpt-4.1-mini",
			"usage": {"input_tokens": 1000, "output_tokens": 100,
				"input_tokens_details": {"cached_tokens": 400},
				"output_tokens_details": {"reasoning_tokens": 20}}
		}}});
		let responses = result_usage(&responses, "openai").unwrap();
		assert_eq!(responses.response.cached_input_tokens, Some(400));
		assert_eq!(responses.response.reasoning_tokens, Some(20));
		let anthropic = json!({"custom_id": "request-1", "result": {"type": "succeeded", "message": {
			"id": "msg-1", "type": "message", "role": "assistant", "model": "claude-sonnet-4-6",
			"content": [], "stop_reason": "end_turn", "stop_sequence": null,
			"usage": {"input_tokens": 600, "output_tokens": 100, "cache_read_input_tokens": 400}
		}}});
		let anthropic = result_usage(&anthropic, "anthropic").unwrap();
		assert_eq!(anthropic.normalized_input_tokens(), Some(1000));
		assert_eq!(anthropic.response.output_tokens, Some(100));
		assert!(
			result_usage(
				&json!({"custom_id": "failed", "error": {"code": "invalid_request"}}),
				"openai"
			)
			.is_none()
		);
	}

	#[tokio::test]
	async fn observing_fragmented_download_preserves_bytes_and_trailers() {
		use http_body_util::StreamBody;
		let bytes = Bytes::from(format!("{}\n{}", completion(), completion()));
		let mut trailers = crate::http::HeaderMap::new();
		trailers.insert("x-checksum", "ok".parse().unwrap());
		let frames = vec![
			Ok::<_, std::convert::Infallible>(http_body::Frame::data(bytes.slice(..17))),
			Ok(http_body::Frame::data(bytes.slice(17..))),
			Ok(http_body::Frame::trailers(trailers.clone())),
		];
		let body = Body::new(StreamBody::new(futures::stream::iter(frames)));
		let req = ::http::Request::builder()
			.uri("/v1/files/file-1/content")
			.body(Body::empty())
			.unwrap();
		let observer = Observation::for_request(&req, "openai", ModelCatalog::empty()).unwrap();
		let observed = observer.attach(Response::new(body));
		let collected = http_body_util::BodyExt::collect(observed.into_body())
			.await
			.unwrap();
		assert_eq!(collected.trailers(), Some(&trailers));
		assert_eq!(collected.to_bytes(), bytes);
	}
}
