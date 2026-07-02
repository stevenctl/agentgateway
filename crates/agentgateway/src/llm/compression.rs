use std::sync::Arc;

use ::http::{HeaderValue, header};
use agent_core::strng;

use super::{
	AIProvider, CompressionInfo, InputFormat, Policy, ProviderState, RequestType, RouteType, custom,
	num_tokens_from_messages, policy,
};
use crate::http::{Body, Request, Response};
use crate::llm::types;
use crate::store::BackendPolicies;
use crate::types::agent::{ResourceName, SimpleBackend};
use tracing::debug;

impl AIProvider {
	// Ok((Some(_), _)) => compression was applied.
	// Ok((None, None)) => no compression was applied, including fail-open.
	// Err(_) => compression failed and fail-closed.
	pub(crate) async fn apply_compression(
		&self,
		policies: Option<&Policy>,
		backend_info: &crate::http::auth::BackendInfo,
		req: &mut dyn RequestType,
		parts: &mut ::http::request::Parts,
		original_format: InputFormat,
		native_format: Option<custom::ProviderFormat>,
	) -> Result<
		(
			Option<(Vec<u8>, Option<ProviderState>)>,
			Option<CompressionInfo>,
		),
		Response,
	> {
		let Some(hr) = policies.and_then(|p| p.headroom.as_ref()) else {
			return Ok((None, None));
		};
		// no need to compress the client doing counting, we want the original in that case
		if original_format == InputFormat::CountTokens {
			return Ok((None, None));
		}
		let (original, compression_info) = match hr.compress_request(backend_info, req, parts).await {
			policy::HeadroomOutcome::Bypass => return Ok((None, None)),
			policy::HeadroomOutcome::Failed(reason) => {
				return hr.fail(&reason).map(|body| (body, None));
			},
			policy::HeadroomOutcome::Compressed {
				original,
				compressed,
			} => {
				let compression_info = self.spawn_exact_count(hr, backend_info, req, parts);
				if let Err(e) = req.set_raw_messages(compressed) {
					return hr
						.fail(&format!("headroom returned unusable messages: {e}"))
						.map(|body| (body, None));
				}
				(original, compression_info)
			},
		};
		let model = req.model().clone().unwrap_or_default();
		match self.marshal_request(
			req,
			&parts.headers,
			original_format,
			native_format,
			&model,
			policies,
		) {
			Ok(marshaled) => Ok((Some(marshaled), compression_info)),
			Err(e) => {
				// revert so the fail-open marshal doesn't hit the same error
				let _ = req.set_raw_messages(original);
				hr.fail(&format!("compressed request failed to marshal: {e}"))
					.map(|body| (body, None))
			},
		}
	}

	pub(crate) fn spawn_exact_count(
		&self,
		hr: &policy::Headroom,
		backend_info: &crate::http::auth::BackendInfo,
		req: &mut dyn RequestType,
		parts: &::http::request::Parts,
	) -> Option<CompressionInfo> {
		if !hr.exact_measurement {
			return None;
		}
		let slot = Arc::new(std::sync::OnceLock::new());
		if let Some(count) = self.local_input_token_count(req) {
			let _ = slot.set(count);
			return Some(CompressionInfo {
				pre_compression_input_tokens: slot,
			});
		}
		let Some((side_req, backend, backend_policies)) =
			self.build_exact_count_call(req, &parts.headers)
		else {
			return None;
		};
		let client = crate::proxy::httpproxy::PolicyClient::new(backend_info.inputs.clone());
		tokio::spawn({
			let slot = slot.clone();
			async move {
				match types::count_tokens::count_input_tokens(&client, side_req, backend, backend_policies)
					.await
				{
					Ok(n) => {
						let _ = slot.set(n);
					},
					Err(e) => debug!("headroom: exact count_tokens failed: {e}"),
				}
			}
		});
		Some(CompressionInfo {
			pre_compression_input_tokens: slot,
		})
	}

	// we can use tiktoken to get real token counts for openai and copilot
	fn local_input_token_count(&self, req: &mut dyn RequestType) -> Option<u64> {
		let model = req.model().clone().unwrap_or_default();
		let supports_local_count = match self {
			AIProvider::OpenAI(_) | AIProvider::Copilot(_) => true,
			AIProvider::Azure(p) => !p.is_anthropic_model(Some(&model)),
			_ => false,
		};
		if !supports_local_count {
			return None;
		}
		num_tokens_from_messages(&model, &req.get_messages()).ok()
	}

	// the only way to get an exact count for antrhopic/claude is via their count_tokens endpoint
	pub(crate) fn build_exact_count_call(
		&self,
		req: &mut dyn RequestType,
		headers: &::http::HeaderMap,
	) -> Option<(Request, SimpleBackend, BackendPolicies)> {
		if !matches!(
			self,
			AIProvider::Anthropic(_)
				| AIProvider::Vertex(_)
				| AIProvider::Azure(_)
				| AIProvider::Bedrock(_)
		) {
			return None;
		}
		let model = req.model().clone().unwrap_or_default();
		if !self.supports_format(custom::ProviderFormat::AnthropicTokenCount, Some(&model)) {
			return None;
		}
		let count_req = req.to_count_tokens_request()?;
		let body = self
			.marshal_count_tokens_request(&count_req, headers, &model)
			.ok()?;
		let llm_info = count_req.to_llm_request(self.provider(), false).ok()?;

		let mut side_req = ::http::Request::builder()
			.method(::http::Method::POST)
			.uri("http://localhost/") // not an actual call we just use this to build the request
			.header(
				header::CONTENT_TYPE,
				HeaderValue::from_static("application/json"),
			)
			.body(Body::from(body))
			.ok()?;
		side_req
			.headers_mut()
			.extend(types::count_tokens::anthropic_count_tokens_headers(headers));
		self
			.setup_request(
				&mut side_req,
				RouteType::AnthropicTokenCount,
				Some(&llm_info),
				None,
				None,
				false,
			)
			.ok()?;

		let target = self.default_connector_target(RouteType::AnthropicTokenCount)?;
		let backend = SimpleBackend::Opaque(
			ResourceName::new(
				strng::literal!("_compression-count-tokens"),
				strng::literal!(""),
			),
			target,
		);
		let backend_policies = self.default_connector_policies()?;
		Some((side_req, backend, backend_policies))
	}
}
