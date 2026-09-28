use crate::llm::catalog::ModelCatalog;
use crate::llm::{CacheTokenConvention, InputFormat, LLMInfo, LLMRequest, LLMResponse};

/// Logs a batch record's usage with its cost at batch rates.
pub(super) fn log(catalog: &ModelCatalog, artifact: &str, record_id: &str, info: &LLMInfo) {
	let projection = catalog.project_batch(info);
	let cost = projection.cost.map(|cost| cost.total().to_string());
	tracing::info!(target: "batch", provider = %info.request.provider, artifact,
		record_id, model = info.response.provider_model.as_deref(),
		input_tokens = info.normalized_input_tokens(), output_tokens = info.response.output_tokens,
		cached_input_tokens = info.response.cached_input_tokens,
		cache_creation_input_tokens = info.response.cache_creation_input_tokens,
		cost = cost.as_deref(), cost_status = ?projection.status,
		"batch usage observed");
}

/// Usage of a batch record served by `provider`, priced by its response model.
pub(super) fn info(
	response: LLMResponse,
	input_format: InputFormat,
	cache_convention: CacheTokenConvention,
	provider: &str,
) -> Option<LLMInfo> {
	Some(LLMInfo::new(
		LLMRequest {
			input_tokens: None,
			input_format,
			cache_convention,
			request_model: response.provider_model.clone()?,
			provider: provider.into(),
			streaming: false,
			params: Default::default(),
			prompt: None,
			provider_state: None,
		},
		response,
	))
}
