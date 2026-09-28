use std::sync::Arc;

use agent_core::strng::Strng;
use anyhow::{Context, bail};
use bytes::Bytes;
use parking_lot::Mutex;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tokio_stream::wrappers::ReceiverStream;

use super::{MAX_RECORD_BYTES, Native, UpstreamError, upload};
use crate::cel::RequestSnapshot;
use crate::http::jwt::Claims;
use crate::http::{Body, BodyInspection, HeaderMap, Method, Request, SendDirectResponse};
use crate::llm::types::{completions, embeddings, messages, responses};
use crate::llm::{Policy, RequestType};
use crate::proxy::ProxyResponse;
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
		url: &str,
		body: Value,
		model: Option<&str>,
	) -> anyhow::Result<Value> {
		match url {
			"/v1/chat/completions" => self.apply::<completions::Request>(body, model).await,
			"/v1/responses" => self.apply::<responses::Request>(body, model).await,
			"/v1/embeddings" => self.apply::<embeddings::Request>(body, model).await,
			"/v1/messages" => self.apply::<messages::Request>(body, model).await,
			_ if self.policy.has_request_guards() || self.policy.prompts.is_some() => {
				bail!("batch records for {url} are not supported with request guards or prompts")
			},
			_ => {
				let mut body = self.apply_value(body, model)?;
				if let Some(alias) = body
					.get("model")
					.and_then(Value::as_str)
					.and_then(|model| self.policy.resolve_model_alias(model))
				{
					body["model"] = json!(alias);
				}
				Ok(body)
			},
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

/// Applies the route's policies to a request for `url`, or only the backend's model when there are
/// none.
pub(super) async fn apply_record(
	policy: Option<&BatchPolicy>,
	url: &str,
	body: Value,
	model: Option<&str>,
) -> anyhow::Result<Value> {
	match policy {
		Some(policy) => policy.apply_record(url, body, model).await,
		None => Ok(with_model(body, model)),
	}
}

fn with_model(mut body: Value, model: Option<&str>) -> Value {
	if let Some(model) = model {
		body["model"] = json!(model);
	}
	body
}

/// An error from processing a streamed request body, returned once the upstream call completes.
/// Dropping it stops the processing.
pub(super) struct DeferredError {
	error: Arc<Mutex<Option<anyhow::Error>>>,
	task: AbortHandle,
}

impl DeferredError {
	pub(super) fn take(&self) -> Option<ProxyResponse> {
		let error = self.error.lock().take()?;
		Some(super::into_proxy_response(error))
	}
}

impl Drop for DeferredError {
	fn drop(&mut self) {
		self.task.abort();
	}
}

struct Process {
	policy: Option<BatchPolicy>,
	model: Option<Strng>,
}

/// Applies the route's policies and the backend's model to a natively supported batch request
/// before it is proxied.
pub(super) async fn process_passthrough(
	native: Native,
	req: Request,
	policy: Option<BatchPolicy>,
	model: Option<Strng>,
) -> Result<(Request, Option<DeferredError>), ProxyResponse> {
	if req.method() != Method::POST || (policy.is_none() && model.is_none()) {
		return Ok((req, None));
	}
	let path = super::api_path(req.uri().path())
		.map(|(_, path)| path)
		.unwrap_or_default();
	let process = Process { policy, model };
	match (native, path) {
		(Native::OpenAI, "/v1/files") => {
			let (req, error) = stream_upload(req, process).map_err(super::into_proxy_response)?;
			Ok((req, Some(error)))
		},
		(Native::Anthropic, "/v1/messages/batches") => {
			Ok((buffer_message_batches(req, process).await?, None))
		},
		_ => Ok((req, None)),
	}
}

fn stream_upload(req: Request, process: Process) -> anyhow::Result<(Request, DeferredError)> {
	let (mut parts, body) = req.into_parts();
	let (multipart, boundary) = upload::multipart(&parts.headers, body)?;
	let (tx, rx) = mpsc::channel(2);
	let error = Arc::new(Mutex::new(None));
	let slot = error.clone();
	let task = tokio::spawn(async move {
		let mut sink = Reencode { process, tx };
		match upload::walk(multipart, &boundary, MAX_RECORD_BYTES, false, &mut sink).await {
			// The upstream failed or already responded; its own result is returned.
			Err(e) if e.is::<UpstreamClosed>() => {},
			Err(e) => {
				*slot.lock() = Some(e);
				// Fails the upstream body so the partial upload is discarded.
				let _ = sink
					.tx
					.send(Err(std::io::Error::other("batch upload rejected")))
					.await;
			},
			Ok(summary) if summary.records > 0 => {
				tracing::info!(target: "batch", provider = "openai", records = summary.records, bytes = summary.file_bytes, "batch upload processed");
			},
			Ok(_) => {},
		}
	});
	// Parts are re-emitted with the same boundary, but records may change length.
	parts.headers.remove(::http::header::CONTENT_LENGTH);
	let req = Request::from_parts(parts, Body::from_stream(ReceiverStream::new(rx)));
	Ok((
		req,
		DeferredError {
			error,
			task: task.abort_handle(),
		},
	))
}

#[derive(Debug, thiserror::Error)]
#[error("upstream closed")]
struct UpstreamClosed;

/// Re-encodes an upload for the provider, processing batch records.
struct Reencode {
	process: Process,
	tx: mpsc::Sender<Result<Bytes, std::io::Error>>,
}

impl Reencode {
	async fn send(&self, bytes: impl Into<Bytes>) -> anyhow::Result<()> {
		self
			.tx
			.send(Ok(bytes.into()))
			.await
			.map_err(|_| UpstreamClosed.into())
	}
}

impl upload::Sink for Reencode {
	async fn raw(&mut self, bytes: Bytes) -> anyhow::Result<()> {
		self.send(bytes).await
	}

	async fn record(&mut self, url: String, mut record: Map<String, Value>) -> anyhow::Result<()> {
		let body = record.remove("body").unwrap_or_default();
		let policy = self.process.policy.as_ref();
		let body = apply_record(policy, &url, body, self.process.model.as_deref()).await?;
		record.insert("body".to_owned(), body);
		let mut line = serde_json::to_vec(&record)?;
		line.push(b'\n');
		self.send(line).await
	}
}

async fn buffer_message_batches(req: Request, process: Process) -> Result<Request, ProxyResponse> {
	let (mut parts, mut body) = req.into_parts();
	let bytes = match body.inspect(crate::llm::DEFAULT_BUFFER_LIMIT).await {
		Ok(BodyInspection::Complete(bytes)) => bytes,
		Ok(BodyInspection::Partial(_)) => {
			return Err(ProxyResponse::DirectResponse(Box::new(
				crate::llm::model_router::request_body_too_large_response(),
			)));
		},
		Err(error) => return Err(super::into_proxy_response(error)),
	};
	let processed = process_message_batches(&process, &bytes)
		.await
		.map_err(super::into_proxy_response)?;
	parts.headers.remove(::http::header::CONTENT_LENGTH);
	Ok(Request::from_parts(parts, Body::from(processed)))
}

async fn process_message_batches(process: &Process, bytes: &[u8]) -> anyhow::Result<Bytes> {
	let mut body: Value = serde_json::from_slice(bytes)?;
	let requests = body
		.get_mut("requests")
		.and_then(Value::as_array_mut)
		.context("requests must be an array")?;
	let record_count = requests.len();
	for request in requests {
		let request = request
			.as_object_mut()
			.context("requests must be objects")?;
		let params = request
			.remove("params")
			.filter(Value::is_object)
			.context("params must be an object")?;
		let policy = process.policy.as_ref();
		let params = apply_record(policy, "/v1/messages", params, process.model.as_deref()).await?;
		request.insert("params".to_owned(), params);
	}
	tracing::info!(target: "batch", provider = "anthropic", records = record_count, "batch requests processed");
	Ok(serde_json::to_vec(&body)?.into())
}
