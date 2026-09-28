use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, bail, ensure};
use bytes::{Bytes, BytesMut};
use futures::stream::BoxStream;
use futures_util::{Stream, TryStreamExt, future};
use serde::Serialize;
use serde_json::{Map, Value, json};
use tokio_util::codec::{Decoder, FramedRead, LinesCodec, LinesCodecError};
use tokio_util::io::StreamReader;

use crate::http::auth::BackendAuth;
use crate::http::{Body, Method, Request, Response, StatusCode};
use crate::llm::catalog::ModelCatalog;
use crate::llm::model_router::llm_error_response;
use crate::llm::{AIProvider, RouteType};
use crate::proxy::httpproxy::PolicyClient;
use crate::proxy::{ProxyError, ProxyResponse};

mod bedrock;
mod process;
mod upload;
mod usage;

pub use bedrock::Config as BedrockConfig;
pub use process::BatchPolicy;

const MAX_RECORD_BYTES: usize = crate::llm::DEFAULT_BUFFER_LIMIT;
/// Result lines repeat the translated input alongside the output, so they can exceed the input
/// record limit.
const MAX_RESULT_BYTES: usize = 4 * MAX_RECORD_BYTES;

pub enum Batch<'a> {
	Bedrock(Box<bedrock::Backend<'a>>),
	Unavailable(&'static str),
}

#[derive(Clone, Copy)]
enum Root {
	Files,
	Uploads,
	Batches,
	MessageBatches,
}

impl Root {
	fn path(self) -> &'static str {
		match self {
			Root::Files => "/v1/files",
			Root::Uploads => "/v1/uploads",
			Root::Batches => "/v1/batches",
			Root::MessageBatches => "/v1/messages/batches",
		}
	}
}

pub fn classify<'a>(
	path: &str,
	provider: &'a AIProvider,
	policy: Option<&crate::llm::Policy>,
	route_type: RouteType,
	client: &'a PolicyClient,
	auth: Option<&BackendAuth>,
) -> Option<Batch<'a>> {
	let (root, _) = api_path(path)?;
	if policy.is_some_and(|policy| policy.has_explicit_route(path)) {
		return None;
	}
	let unsupported = |reason| {
		(!matches!(route_type, RouteType::Passthrough | RouteType::Detect))
			.then_some(Batch::Unavailable(reason))
	};
	match (provider, root) {
		(AIProvider::OpenAI(_), _) | (AIProvider::Anthropic(_), Root::Files | Root::MessageBatches) => {
			None
		},
		// TODO serve Anthropic message batches (/v1/messages/batches) from Bedrock batch inference
		(AIProvider::Bedrock(provider), Root::Files | Root::Batches) => match &provider.batch {
			Some(config) => Some(
				match bedrock::Backend::new(provider, config, client, auth) {
					Ok(backend) => Batch::Bedrock(Box::new(backend)),
					Err(reason) => Batch::Unavailable(reason),
				},
			),
			None => unsupported("Bedrock batch requires provider.bedrock.batch"),
		},
		_ => unsupported("provider does not support this batch API"),
	}
}

impl Batch<'_> {
	pub async fn handle(
		self,
		req: Request,
		policy: Option<BatchPolicy>,
	) -> Result<Response, ProxyResponse> {
		match self {
			Batch::Bedrock(backend) => route(&*backend, req, policy.as_ref())
				.await
				.map_err(into_proxy_response),
			Batch::Unavailable(reason) => {
				tracing::debug!(reason, "batch unavailable");
				Ok(unavailable())
			},
		}
	}
}

/// Whether `req` reads batch jobs or files, such as job status or result downloads.
pub fn is_read(req: &Request) -> bool {
	req.method() == Method::GET && api_path(req.uri().path()).is_some()
}

/// Returns the batch API root in `path` and the path from that root onward, without a trailing
/// slash.
fn api_path(path: &str) -> Option<(Root, &str)> {
	[
		Root::MessageBatches,
		Root::Files,
		Root::Uploads,
		Root::Batches,
	]
	.into_iter()
	.find_map(|root| {
		let start = path.find(root.path())?;
		let rest = &path[start + root.path().len()..];
		(rest.is_empty() || rest.starts_with('/')).then(|| (root, path[start..].trim_end_matches('/')))
	})
}

/// Serves the OpenAI batch API from a provider's batch jobs. IDs are exchanged without the OpenAI
/// `file-` and `batch-` prefixes.
trait Backend {
	type Upload;
	fn provider(&self) -> &'static str;
	/// The model every record runs on.
	fn model(&self) -> &str;
	fn catalog(&self) -> Arc<ModelCatalog>;
	async fn start_upload(&self, endpoint: Endpoint) -> anyhow::Result<Self::Upload>;
	async fn write_upload(
		&self,
		upload: &mut Self::Upload,
		record: InputRecord,
	) -> anyhow::Result<()>;
	/// Returns the file ID.
	async fn finish_upload(&self, upload: Self::Upload) -> anyhow::Result<String>;
	async fn abort_upload(&self, upload: Self::Upload);
	async fn create(&self, file_id: &str, endpoint: Endpoint) -> anyhow::Result<String>;
	async fn get(&self, batch_id: &str) -> anyhow::Result<Job>;
	async fn results(
		&self,
		batch_id: &str,
	) -> anyhow::Result<BoxStream<'static, anyhow::Result<ResultRecord>>>;
}

struct InputRecord {
	custom_id: String,
	endpoint: Endpoint,
	body: Value,
}

/// The OpenAI endpoint a batch targets.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Endpoint {
	ChatCompletions,
	Responses,
}

impl Endpoint {
	fn from_path(path: &str) -> Option<Self> {
		match path {
			"/v1/chat/completions" => Some(Endpoint::ChatCompletions),
			"/v1/responses" => Some(Endpoint::Responses),
			_ => None,
		}
	}

	fn path(self) -> &'static str {
		match self {
			Endpoint::ChatCompletions => "/v1/chat/completions",
			Endpoint::Responses => "/v1/responses",
		}
	}
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
	Validating,
	InProgress,
	Completed,
	Failed,
	Expired,
	Cancelling,
	Cancelled,
}

impl Status {
	fn has_results(self) -> bool {
		matches!(
			self,
			Status::Completed | Status::Expired | Status::Cancelled
		)
	}
}

struct Job {
	file_id: String,
	model: String,
	endpoint: Endpoint,
	status: Status,
	created_at: Option<i64>,
	total: u64,
	completed: u64,
	failed: u64,
	message: Option<String>,
}

struct ResultRecord {
	custom_id: String,
	usage: Option<crate::llm::LLMInfo>,
	outcome: Result<Value, RecordError>,
}

impl ResultRecord {
	/// A result line that couldn't be read or matched to its input record.
	fn invalid(custom_id: &str, message: &str, usage: Option<crate::llm::LLMInfo>) -> Self {
		Self {
			custom_id: custom_id.to_owned(),
			usage,
			outcome: Err(RecordError {
				code: "invalid_result".to_owned(),
				message: Value::String(message.to_owned()),
			}),
		}
	}
}

struct RecordError {
	code: String,
	message: Value,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
struct UpstreamError {
	status: Option<StatusCode>,
	message: String,
}

impl UpstreamError {
	fn new(message: String) -> Self {
		Self {
			status: None,
			message,
		}
	}
}

#[derive(Debug, thiserror::Error)]
#[error("unsupported batch endpoint")]
struct Unsupported;

fn ok_response(content_type: &'static str, body: impl Into<Body>) -> Response {
	let mut response = Response::new(body.into());
	response.headers_mut().insert(
		::http::header::CONTENT_TYPE,
		::http::HeaderValue::from_static(content_type),
	);
	response
}

fn unavailable() -> Response {
	let mut response = Response::new(Body::from("batch is not available for this backend"));
	*response.status_mut() = StatusCode::NOT_FOUND;
	response
}

/// A JSONL line, or why it couldn't be read.
type Line = Result<String, InvalidLine>;

#[derive(Debug, thiserror::Error)]
enum InvalidLine {
	#[error("line exceeds {0} bytes")]
	TooLong(usize),
	#[error("line is not UTF-8")]
	NotUtf8,
}

/// Yields unreadable lines as errors instead of ending the stream.
struct LineDecoder(LinesCodec);

impl LineDecoder {
	fn recover(
		&self,
		result: Result<Option<String>, LinesCodecError>,
	) -> Result<Option<Line>, LinesCodecError> {
		match result {
			Ok(line) => Ok(line.map(Ok)),
			Err(LinesCodecError::MaxLineLengthExceeded) => {
				Ok(Some(Err(InvalidLine::TooLong(self.0.max_length()))))
			},
			Err(LinesCodecError::Io(e)) if e.kind() == std::io::ErrorKind::InvalidData => {
				Ok(Some(Err(InvalidLine::NotUtf8)))
			},
			Err(e) => Err(e),
		}
	}
}

impl Decoder for LineDecoder {
	type Item = Line;
	type Error = LinesCodecError;

	fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Line>, LinesCodecError> {
		let result = self.0.decode(buf);
		self.recover(result)
	}

	fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Line>, LinesCodecError> {
		let result = self.0.decode_eof(buf);
		self.recover(result)
	}
}

/// Splits a byte stream into non-empty JSONL lines of at most `max` bytes.
fn lines<S, E>(stream: S, max: usize) -> impl Stream<Item = anyhow::Result<Line>>
where
	S: Stream<Item = Result<Bytes, E>>,
	E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
	let reader = StreamReader::new(stream.map_err(std::io::Error::other));
	FramedRead::new(reader, LineDecoder(LinesCodec::new_with_max_length(max)))
		.map_err(anyhow::Error::from)
		.try_filter(|line| future::ready(!matches!(line, Ok(line) if line.trim().is_empty())))
}

fn into_proxy_response(error: anyhow::Error) -> ProxyResponse {
	let error = match error.downcast::<process::Rejected>() {
		Ok(rejected) => {
			return ProxyError::GuardrailRejected {
				guardrail: rejected.guardrail,
				response: Box::new(rejected.response),
			}
			.into();
		},
		Err(error) => error,
	};
	let response = if error.is::<Unsupported>() {
		unavailable()
	} else if error.is::<upload::RecordTooLarge>() {
		crate::llm::model_router::request_body_too_large_response()
	} else if let Some(upstream) = error.downcast_ref::<UpstreamError>() {
		let status = match upstream.status {
			Some(
				status @ (StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND | StatusCode::TOO_MANY_REQUESTS),
			) => status,
			_ => StatusCode::BAD_GATEWAY,
		};
		llm_error_response(status, &upstream.message, "upstream_error")
	} else {
		llm_error_response(
			StatusCode::BAD_REQUEST,
			&error.to_string(),
			"invalid_request",
		)
	};
	ProxyResponse::DirectResponse(Box::new(response))
}

async fn route(
	backend: &impl Backend,
	req: Request,
	policy: Option<&BatchPolicy>,
) -> anyhow::Result<Response> {
	let method = req.method().clone();
	let path = api_path(req.uri().path()).ok_or(Unsupported)?.1.to_owned();
	let json = |body: Value| ok_response("application/json", body.to_string());
	if method == Method::POST && path == "/v1/files" {
		return Ok(json(upload_file(backend, req, policy).await?));
	}
	if method == Method::POST && path == "/v1/batches" {
		return Ok(json(create_batch(backend, req).await?));
	}
	if method == Method::GET {
		if let Some(id) = path.strip_prefix("/v1/batches/batch-") {
			return Ok(json(retrieve_batch(backend, id).await?));
		}
		let file = path
			.strip_prefix("/v1/files/file-")
			.and_then(|s| s.strip_suffix("/content"));
		if let Some(id) = file.and_then(|f| f.strip_prefix("output-")) {
			return download_results(backend, id, false).await;
		}
		if let Some(id) = file.and_then(|f| f.strip_prefix("errors-")) {
			return download_results(backend, id, true).await;
		}
	}
	Err(Unsupported.into())
}

async fn upload_file<B: Backend>(
	backend: &B,
	req: Request,
	policy: Option<&BatchPolicy>,
) -> anyhow::Result<Value> {
	let (parts, body) = req.into_parts();
	let multipart = upload::multipart(&parts.headers, body)?;
	let mut sink = WriteRecords {
		backend,
		policy,
		endpoint: None,
		upload: None,
		ids: HashSet::new(),
	};
	let summary = upload::walk(multipart, MAX_RECORD_BYTES, &mut sink)
		.await
		.and_then(|summary| {
			ensure!(summary.filename.is_some(), "missing file");
			ensure!(summary.batch, "purpose must be batch");
			Ok(summary)
		});
	// The purpose field may follow the file, so the upload is only completed once it is known.
	let (summary, upload) = match (summary, sink.upload) {
		(Ok(summary), Some(upload)) => (summary, upload),
		(summary, upload) => {
			if let Some(upload) = upload {
				backend.abort_upload(upload).await;
			}
			summary?;
			bail!("batch input is empty");
		},
	};
	let id = backend.finish_upload(upload).await?;
	tracing::info!(target: "batch", provider = backend.provider(), file_id = %id, records = summary.records, bytes = summary.file_bytes, "batch upload processed");
	Ok(json!({
		"id": format!("file-{id}"),
		"object": "file",
		"bytes": summary.file_bytes,
		"created_at": chrono::Utc::now().timestamp(),
		"filename": summary.filename,
		"purpose": "batch",
	}))
}

/// Writes batch records to the backend.
struct WriteRecords<'a, B: Backend> {
	backend: &'a B,
	policy: Option<&'a BatchPolicy>,
	// Set by the first record; every record must target it.
	endpoint: Option<Endpoint>,
	// Started on the first record.
	upload: Option<B::Upload>,
	ids: HashSet<String>,
}

impl<B: Backend> upload::Sink for WriteRecords<'_, B> {
	async fn record(&mut self, url: String, mut record: Map<String, Value>) -> anyhow::Result<()> {
		let endpoint = Endpoint::from_path(&url)
			.filter(|_| record.get("method").and_then(Value::as_str) == Some("POST"))
			.context("only POST /v1/chat/completions and /v1/responses records are supported")?;
		ensure!(
			*self.endpoint.get_or_insert(endpoint) == endpoint,
			"all records must target the same endpoint"
		);
		let custom_id = record
			.get("custom_id")
			.and_then(Value::as_str)
			.context("missing custom_id")?
			.to_owned();
		ensure!(
			!custom_id.is_empty() && custom_id.len() <= 128 && self.ids.insert(custom_id.clone()),
			"custom_id must be unique and 1-128 bytes"
		);
		let body = record.remove("body").unwrap_or_default();
		ensure!(body["stream"] != true, "batch streaming is unsupported");
		let body =
			process::apply_record(self.policy, endpoint, body, Some(self.backend.model())).await?;
		let upload = match &mut self.upload {
			Some(upload) => upload,
			None => self
				.upload
				.insert(self.backend.start_upload(endpoint).await?),
		};
		let record = InputRecord {
			custom_id,
			endpoint,
			body,
		};
		self.backend.write_upload(upload, record).await
	}
}

async fn create_batch(backend: &impl Backend, req: Request) -> anyhow::Result<Value> {
	let body: Value = serde_json::from_slice(&crate::http::read_req_body(req).await?)?;
	let endpoint = body["endpoint"]
		.as_str()
		.and_then(Endpoint::from_path)
		.context("batch endpoint must be /v1/chat/completions or /v1/responses")?;
	ensure!(
		body["completion_window"] == "24h",
		"completion_window must be 24h"
	);
	let file = body["input_file_id"]
		.as_str()
		.and_then(|id| id.strip_prefix("file-"))
		.context("invalid input_file_id")?;
	let id = backend.create(file, endpoint).await?;
	Ok(json!({
		"id": format!("batch-{id}"),
		"object": "batch",
		"endpoint": endpoint.path(),
		"input_file_id": body["input_file_id"],
		"completion_window": "24h",
		"status": Status::Validating,
		"created_at": chrono::Utc::now().timestamp(),
		"output_file_id": null,
		"error_file_id": null,
		"errors": null,
		"metadata": null,
		"request_counts": {"total": 0, "completed": 0, "failed": 0},
	}))
}

async fn retrieve_batch(backend: &impl Backend, id: &str) -> anyhow::Result<Value> {
	let job = backend.get(id).await?;
	let has_results = job.status.has_results();
	Ok(json!({
		"id": format!("batch-{id}"),
		"object": "batch",
		"endpoint": job.endpoint.path(),
		"input_file_id": format!("file-{}", job.file_id),
		"completion_window": "24h",
		"status": job.status,
		"created_at": job.created_at,
		"output_file_id": has_results.then(|| format!("file-output-{id}")),
		"error_file_id": has_results.then(|| format!("file-errors-{id}")),
		"request_counts": {
			"total": job.total,
			"completed": job.completed,
			"failed": job.failed,
		},
		"metadata": null,
		"errors": job.message.map(|message| json!({"object": "list", "data": [{"message": message}]})),
	}))
}

async fn download_results(
	backend: &impl Backend,
	id: &str,
	errors: bool,
) -> anyhow::Result<Response> {
	let id = id.to_owned();
	let catalog = backend.catalog();
	let artifact = format!("batch-{id}");
	let lines = backend.results(&id).await?.try_filter_map(move |record| {
		if record.outcome.is_err() == errors
			&& let Some(info) = &record.usage
		{
			usage::log(&catalog, &artifact, &record.custom_id, info);
		}
		future::ready(result_line(&id, record, errors))
	});
	Ok(ok_response("application/jsonl", Body::from_stream(lines)))
}

fn result_line(id: &str, record: ResultRecord, errors: bool) -> anyhow::Result<Option<Bytes>> {
	if record.outcome.is_err() != errors {
		return Ok(None);
	}
	let (response, error) = match record.outcome {
		Ok(body) => (
			json!({"status_code": 200, "request_id": null, "body": body}),
			Value::Null,
		),
		Err(error) => (
			Value::Null,
			json!({"code": error.code, "message": error.message}),
		),
	};
	let mut line = serde_json::to_vec(&json!({
		"id": format!("batch_req_{id}_{}", hex::encode(&record.custom_id)),
		"custom_id": record.custom_id,
		"response": response,
		"error": error,
	}))?;
	line.push(b'\n');
	Ok(Some(line.into()))
}

#[cfg(test)]
mod tests {
	use std::sync::Mutex;

	use futures_util::StreamExt;

	use super::*;

	#[derive(Default)]
	struct Fake {
		uploaded: Mutex<Vec<String>>,
		aborted: Mutex<bool>,
	}

	impl Backend for Fake {
		type Upload = Vec<String>;
		fn provider(&self) -> &'static str {
			"fake"
		}
		fn model(&self) -> &str {
			"m"
		}
		fn catalog(&self) -> Arc<ModelCatalog> {
			ModelCatalog::empty()
		}
		async fn start_upload(&self, _: Endpoint) -> anyhow::Result<Vec<String>> {
			Ok(Vec::new())
		}
		async fn write_upload(
			&self,
			upload: &mut Vec<String>,
			record: InputRecord,
		) -> anyhow::Result<()> {
			upload.push(record.custom_id);
			Ok(())
		}
		async fn finish_upload(&self, upload: Vec<String>) -> anyhow::Result<String> {
			*self.uploaded.lock().unwrap() = upload;
			Ok("f1".into())
		}
		async fn abort_upload(&self, _: Vec<String>) {
			*self.aborted.lock().unwrap() = true;
		}
		async fn create(&self, file_id: &str, _: Endpoint) -> anyhow::Result<String> {
			assert_eq!(file_id, "f1");
			Ok("b1".into())
		}
		async fn get(&self, batch_id: &str) -> anyhow::Result<Job> {
			assert_eq!(batch_id, "b1");
			Ok(Job {
				file_id: "f1".into(),
				model: "m".into(),
				endpoint: Endpoint::ChatCompletions,
				status: Status::Completed,
				created_at: Some(1),
				total: 2,
				completed: 1,
				failed: 1,
				message: None,
			})
		}
		async fn results(
			&self,
			batch_id: &str,
		) -> anyhow::Result<BoxStream<'static, anyhow::Result<ResultRecord>>> {
			assert_eq!(batch_id, "b1");
			let records = vec![
				Ok(ResultRecord {
					custom_id: "a".into(),
					usage: None,
					outcome: Ok(json!({"object": "chat.completion"})),
				}),
				Ok(ResultRecord {
					custom_id: "b".into(),
					usage: None,
					outcome: Err(RecordError {
						code: "400".into(),
						message: json!("bad request"),
					}),
				}),
			];
			Ok(futures::stream::iter(records).boxed())
		}
	}

	async fn call(
		fake: &Fake,
		method: Method,
		uri: &str,
		content_type: &str,
		body: &str,
	) -> Vec<Value> {
		let req = ::http::Request::builder()
			.method(method)
			.uri(uri)
			.header(::http::header::CONTENT_TYPE, content_type)
			.body(Body::from(body.to_owned()))
			.unwrap();
		let res = route(fake, req, None).await.unwrap();
		assert_eq!(res.status(), StatusCode::OK);
		let body = crate::http::read_body_with_limit(res.into_body(), 1 << 20)
			.await
			.unwrap();
		body
			.split(|b| *b == b'\n')
			.filter(|line| !line.is_empty())
			.map(|line| serde_json::from_slice(line).unwrap())
			.collect()
	}

	#[tokio::test]
	async fn round_trip() {
		let fake = Fake::default();
		let record = |id: &str| {
			json!({"custom_id": id, "method": "POST", "url": "/v1/chat/completions",
				"body": {"model": "m", "messages": [{"role": "user", "content": "hi"}]}})
		};
		// The purpose field follows the file.
		let records = format!("{}\n{}", record("a"), record("b"));
		let upload = upload::tests::multipart_body(&[("file", &records), ("purpose", "batch")]);
		let file = call(
			&fake,
			Method::POST,
			"/v1/files",
			"multipart/form-data; boundary=x",
			&upload,
		)
		.await;
		assert_eq!(file[0]["id"], "file-f1");
		assert_eq!(*fake.uploaded.lock().unwrap(), ["a", "b"]);

		let create = json!({"input_file_id": "file-f1", "endpoint": "/v1/chat/completions",
			"completion_window": "24h"});
		let batch = call(
			&fake,
			Method::POST,
			"/v1/batches",
			"application/json",
			&create.to_string(),
		)
		.await;
		assert_eq!(batch[0]["id"], "batch-b1");

		let batch = call(&fake, Method::GET, "/v1/batches/batch-b1", "", "").await;
		assert_eq!(batch[0]["status"], "completed");
		assert_eq!(batch[0]["output_file_id"], "file-output-b1");
		assert_eq!(batch[0]["error_file_id"], "file-errors-b1");

		let output = call(
			&fake,
			Method::GET,
			"/v1/files/file-output-b1/content",
			"",
			"",
		)
		.await;
		assert_eq!(output.len(), 1);
		assert_eq!(output[0]["custom_id"], "a");
		assert_eq!(output[0]["response"]["body"]["object"], "chat.completion");

		let errors = call(
			&fake,
			Method::GET,
			"/v1/files/file-errors-b1/content",
			"",
			"",
		)
		.await;
		assert_eq!(errors.len(), 1);
		assert_eq!(errors[0]["custom_id"], "b");
		assert_eq!(errors[0]["error"]["code"], "400");
	}

	#[tokio::test]
	async fn unreadable_lines_do_not_end_the_stream() {
		// Split across chunks so the long line is discarded after the limit is first hit.
		let chunks = [b"a\nxxxx".as_slice(), b"xxxxxx", b"x\n\xff\nb", b"\n"]
			.map(|chunk| Ok::<_, std::io::Error>(Bytes::copy_from_slice(chunk)));
		let lines: Vec<Line> = lines(futures::stream::iter(chunks), 4)
			.try_collect()
			.await
			.unwrap();
		assert!(matches!(
			lines.as_slice(),
			[
				Ok(a),
				Err(InvalidLine::TooLong(4)),
				Err(InvalidLine::NotUtf8),
				Ok(b)
			] if a == "a" && b == "b"
		));
	}

	#[tokio::test]
	async fn failed_upload_is_aborted() {
		let fake = Fake::default();
		let record =
			json!({"custom_id": "a", "method": "POST", "url": "/v1/chat/completions", "body": {}});
		// A repeated custom_id fails after the upload has started.
		let records = format!("{record}\n{record}");
		let upload = upload::tests::multipart_body(&[("purpose", "batch"), ("file", &records)]);
		let req = ::http::Request::builder()
			.method(Method::POST)
			.uri("/v1/files")
			.header(
				::http::header::CONTENT_TYPE,
				"multipart/form-data; boundary=x",
			)
			.body(Body::from(upload))
			.unwrap();
		assert!(route(&fake, req, None).await.is_err());
		assert!(*fake.aborted.lock().unwrap());
		assert!(fake.uploaded.lock().unwrap().is_empty());
	}
}
