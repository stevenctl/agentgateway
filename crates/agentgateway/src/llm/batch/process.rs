use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::{Endpoint, UpstreamError};
use crate::cel::RequestSnapshot;
use crate::http::jwt::Claims;
use crate::http::{HeaderMap, Request, SendDirectResponse};
use crate::llm::types::{completions, responses};
use crate::llm::{Policy, RequestType};
use crate::proxy::httpproxy::PolicyClient;
use crate::telemetry::log::{GuardrailLog, RequestLog};

/// The route's per-request LLM policies, applied to each request in a batch.
pub struct BatchPolicy {
	policy: Arc<Policy>,
	client: PolicyClient,
	headers: HeaderMap,
	claims: Option<Claims>,
	snapshot: Option<Arc<RequestSnapshot>>,
	log: Option<GuardrailLog>,
}

#[derive(Debug, thiserror::Error)]
#[error("request rejected by {guardrail} guardrail")]
pub(super) struct Rejected {
	pub(super) guardrail: &'static str,
	pub(super) response: SendDirectResponse,
}

impl BatchPolicy {
	pub fn new(
		policy: Option<&Arc<Policy>>,
		client: &PolicyClient,
		req: &Request,
		log: Option<&RequestLog>,
	) -> Option<Self> {
		let policy = policy.filter(|policy| policy.has_request_policies())?;
		Some(Self {
			policy: policy.clone(),
			client: client.clone(),
			headers: req.headers().clone(),
			claims: req.extensions().get::<Claims>().cloned(),
			snapshot: log.and_then(|log| log.request_snapshot.clone()),
			log: log.map(|log| log.guardrails.clone()),
		})
	}

	fn apply_value(&self, body: Value, model: Option<&str>) -> anyhow::Result<Value> {
		let body = with_model(body, model);
		Ok(
			self
				.policy
				.apply_request_body_mutations(body, self.snapshot.as_deref())?,
		)
	}

	/// Applies the policies to one request, as they would be applied if it were sent directly.
	async fn apply<T>(&self, body: Value, model: Option<&str>) -> anyhow::Result<Value>
	where
		T: RequestType + Serialize + DeserializeOwned,
	{
		let body = self.apply_value(body, model)?;
		let mut request: T = serde_json::from_value(body)?;
		self.policy.apply_model_alias(&mut request);
		self.policy.apply_prompt_enrichment(&mut request);
		if self.policy.has_request_guards() {
			self.guard(&mut request).await?;
		}
		Ok(serde_json::to_value(&request)?)
	}

	async fn apply_record(
		&self,
		endpoint: Endpoint,
		body: Value,
		model: Option<&str>,
	) -> anyhow::Result<Value> {
		match endpoint {
			Endpoint::ChatCompletions => self.apply::<completions::Request>(body, model).await,
			Endpoint::Responses => self.apply::<responses::Request>(body, model).await,
		}
	}

	async fn guard(&self, request: &mut dyn RequestType) -> anyhow::Result<()> {
		// Each call replaces the request's guardrail entries, so record them per batch instead.
		let entries = GuardrailLog::default();
		let rejection = self
			.policy
			.apply_prompt_guard(
				&self.client,
				request,
				&self.headers,
				self.claims.clone(),
				self.snapshot.as_deref(),
				self.log.as_ref().map(|_| &entries),
			)
			.await
			.map_err(|e| UpstreamError::new(format!("prompt guard failed: {e}")))?;
		if let Some(log) = &self.log
			&& let Some(entries) = entries.take()
		{
			log.mutate_or_default(|all| {
				for entry in entries {
					let seen = all
						.iter()
						.any(|e| e.phase == entry.phase && e.guard == entry.guard && e.action == entry.action);
					if !seen {
						all.push(entry);
					}
				}
			});
		}
		if let Some((response, guardrail)) = rejection {
			let response = SendDirectResponse::new(response).await?;
			return Err(
				Rejected {
					guardrail,
					response,
				}
				.into(),
			);
		}
		Ok(())
	}
}

/// Applies the route's policies to a request for `endpoint`, or only the backend's model when there
/// are none.
pub(super) async fn apply_record(
	policy: Option<&BatchPolicy>,
	endpoint: Endpoint,
	body: Value,
	model: Option<&str>,
) -> anyhow::Result<Value> {
	match policy {
		Some(policy) => policy.apply_record(endpoint, body, model).await,
		None => Ok(with_model(body, model)),
	}
}

fn with_model(mut body: Value, model: Option<&str>) -> Value {
	if let Some(model) = model {
		body["model"] = json!(model);
	}
	body
}
