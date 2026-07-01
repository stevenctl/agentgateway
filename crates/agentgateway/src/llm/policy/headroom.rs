use ::http::header::CONTENT_TYPE;
use ::http::{HeaderValue, StatusCode};
use serde::{Deserialize, Serialize};

use crate::proxy::httpproxy::PolicyClient;
use crate::telemetry::metrics::{OutboundCallKind, OutboundCallSubtype};
use crate::types::agent::SimpleBackendReference;
use crate::*;

/// Request header that, when set to `true`, skips Headroom compression for that request.
pub const BYPASS_HEADER: &str = "x-headroom-bypass";

/// Request body for `POST /v1/compress`. `messages` is the raw provider-native message
/// array, forwarded verbatim so cache_control/image/tool blocks survive the round-trip.
/// `model` is a tokenizer/context-window hint, not a routing target.
#[derive(Debug, Serialize)]
struct CompressRequest<'a> {
	messages: &'a [serde_json::Value],
	#[serde(skip_serializing_if = "Option::is_none")]
	model: Option<&'a str>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CompressResponse {
	/// The compressed message array.
	pub messages: Vec<serde_json::Value>,
}

pub async fn compress(
	client: &PolicyClient,
	target: &SimpleBackendReference,
	messages: &[serde_json::Value],
	model: Option<&str>,
	buffer_limit: Option<crate::transport::BufferLimit>,
) -> anyhow::Result<CompressResponse> {
	let body_bytes = serde_json::to_vec(&CompressRequest { messages, model })?;
	let mut req = ::http::Request::builder()
		.uri("/v1/compress")
		.method(::http::Method::POST)
		.header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
		.body(http::Body::from(body_bytes))?;

	// big context might exceed default buffer limit on both the frontend and the call
	// to headroom, so we copy it here
	if let Some(lim) = buffer_limit {
		req.extensions_mut().insert(lim);
	}

	let res = Box::pin(
		client
			.with_outbound(OutboundCallKind::Policy, OutboundCallSubtype::Headroom)
			.call_reference(req, target),
	)
	.await?;

	let status = res.status();
	tracing::debug!(
		"headroom: /v1/compress model={:?} status={} ",
		model,
		status
	);

	let lim = http::response_buffer_limit(&res);
	let raw = http::read_body_with_limit(res.into_body(), lim).await?;

	if status != StatusCode::OK {
		anyhow::bail!("headroom /v1/compress returned status {status}");
	}
	Ok(serde_json::from_slice(&raw)?)
}

#[cfg(test)]
mod tests {
	use super::*;

	// A well-formed sidecar response parses into the message array.
	#[test]
	fn compress_response_parses_message_array() {
		let body = serde_json::json!({
			"messages": [{ "role": "user", "content": "hi" }],
			"tokens_before": 100, "tokens_after": 40
		});
		let parsed: CompressResponse = serde_json::from_value(body).unwrap();
		assert_eq!(parsed.messages.len(), 1);
	}

	// A `messages` that isn't an array is rejected at the boundary, not passed downstream.
	#[test]
	fn compress_response_rejects_non_array_messages() {
		let body = serde_json::json!({ "messages": "oops not an array" });
		assert!(serde_json::from_value::<CompressResponse>(body).is_err());
	}
}
