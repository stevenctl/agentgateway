use std::sync::Arc;

use agent_core::strng;
use anyhow::{Context, bail, ensure};
use bytes::Bytes;
use futures::stream::BoxStream;
use futures_util::{StreamExt, TryStreamExt};
use http_body_util::BodyExt;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::{Endpoint, InputRecord, Job, RecordError, ResultRecord, Status, UpstreamError, usage};
use crate::http::auth::{AwsAuth, BackendAuth, BackendAuthKind};
use crate::http::{Body, Method, Response, StatusCode};
use crate::llm::{
	BedrockProvider, CacheTokenConvention, InputFormat, LLMInfo, LLMResponse, conversion, types,
};
use crate::proxy::httpproxy::PolicyClient;
use crate::telemetry::metrics::{OutboundCallKind, OutboundCallSubtype};
use crate::types::agent::{Backend as TargetBackend, BackendTrafficPolicy, ResourceName};
use crate::*;

const PREFIX: &str = "agentgateway-batch";
/// Records which endpoint an input file's records target.
const ENDPOINT_METADATA: &str = "x-amz-meta-agentgateway-endpoint";
/// S3 multipart parts must be at least 5 MiB, except the last.
const PART_BYTES: usize = 8 * 1024 * 1024;

#[apply(schema!)]
pub struct Config {
	/// S3 bucket in the provider's region. Objects use the agentgateway-batch/ prefix.
	pub bucket: String,
	/// IAM role Bedrock assumes to read input from and write output to the bucket.
	pub role_arn: String,
}

pub struct Backend<'a> {
	provider: &'a BedrockProvider,
	config: &'a Config,
	client: &'a PolicyClient,
	model: &'a str,
	auth: AwsAuth,
}

impl<'a> Backend<'a> {
	pub fn new(
		provider: &'a BedrockProvider,
		config: &'a Config,
		client: &'a PolicyClient,
		auth: Option<&BackendAuth>,
	) -> Result<Self, &'static str> {
		let model = provider
			.model_override
			.as_deref()
			.ok_or("Bedrock batch requires a configured model")?;
		let auth = match auth.and_then(|auth| auth.kind.as_ref()) {
			Some(BackendAuthKind::Aws(auth)) => auth.clone(),
			Some(_) => return Err("Bedrock batch requires AWS backend auth"),
			None => AwsAuth::Implicit {
				service_name: None,
				region: None,
				assume_role: None,
				source_credentials_cache: provider.source_credentials_cache.clone(),
				assume_role_cache: provider.assume_role_cache.clone(),
			},
		};
		Ok(Self {
			provider,
			config,
			client,
			model,
			auth,
		})
	}

	fn signing_auth(&self, service: Service) -> AwsAuth {
		let mut auth = self.auth.clone();
		match &mut auth {
			AwsAuth::ExplicitConfig {
				service_name,
				region,
				..
			}
			| AwsAuth::Implicit {
				service_name,
				region,
				..
			} => {
				*service_name = Some(service.name().to_owned());
				region.get_or_insert_with(|| self.provider.region.to_string());
			},
		}
		auth
	}
}

#[derive(Clone, Copy)]
enum Service {
	S3,
	Bedrock,
}

impl Service {
	fn name(self) -> &'static str {
		match self {
			Service::S3 => "s3",
			Service::Bedrock => "bedrock",
		}
	}
}

pub struct Upload {
	id: String,
	upload_id: String,
	part: Vec<u8>,
	etags: Vec<String>,
}

impl Upload {
	/// The object path for a request on this multipart upload, with `query` preceding `uploadId`.
	fn path(&self, query: &str) -> String {
		format!(
			"{}?{query}uploadId={}",
			input_key(&self.id),
			encode(&self.upload_id)
		)
	}
}

fn is_file_id(id: &str) -> bool {
	id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

fn input_key(file_id: &str) -> String {
	format!("/{PREFIX}/input/{file_id}.jsonl")
}

fn translate_input(record: InputRecord, provider: &BedrockProvider) -> anyhow::Result<Value> {
	let translated = match record.endpoint {
		Endpoint::ChatCompletions => {
			let request: types::completions::Request = serde_json::from_value(record.body)?;
			conversion::bedrock::from_completions::translate(&request, provider, None, None, None)?
		},
		Endpoint::Responses => {
			let request: types::responses::Request = serde_json::from_value(record.body)?;
			conversion::bedrock::from_responses::translate(&request, provider, None, None, None)?
		},
	};
	ensure!(
		translated.tool_name_map.is_empty() && translated.namespaces.is_empty(),
		"batch tools must use Bedrock-compatible names without namespaces"
	);
	let input: Value = serde_json::from_slice(&translated.body)?;
	Ok(json!({"recordId": hex::encode(record.custom_id), "modelInput": input}))
}

fn xml_value<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
	let start = xml.find(&format!("<{tag}>"))? + tag.len() + 2;
	let end = start + xml[start..].find(&format!("</{tag}>"))?;
	Some(&xml[start..end])
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JobResponse {
	job_name: String,
	model_id: String,
	status: String,
	submit_time: Option<chrono::DateTime<chrono::Utc>>,
	message: Option<String>,
	#[serde(default)]
	total_record_count: u64,
	#[serde(default)]
	success_record_count: u64,
	#[serde(default)]
	error_record_count: u64,
	input_data_config: JobInput,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JobInput {
	s3_input_data_config: S3Location,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct S3Location {
	s3_uri: String,
}

impl super::Backend for Backend<'_> {
	type Upload = Upload;

	fn provider(&self) -> &'static str {
		"aws.bedrock"
	}

	fn model(&self) -> &str {
		self.model
	}

	fn catalog(&self) -> Arc<crate::llm::catalog::ModelCatalog> {
		self.client.inputs.model_catalog.clone()
	}

	async fn start_upload(&self, endpoint: Endpoint) -> anyhow::Result<Upload> {
		let id = uuid::Uuid::new_v4().simple().to_string();
		let path = format!("{}?uploads", input_key(&id));
		let metadata = [(ENDPOINT_METADATA, endpoint_name(endpoint))];
		let response = self
			.send_with(Service::S3, Method::POST, &path, vec![], &metadata)
			.await?;
		let body = read_body(response).await?;
		let upload_id = std::str::from_utf8(&body)
			.ok()
			.and_then(|body| xml_value(body, "UploadId"))
			.ok_or_else(|| UpstreamError::new("s3 multipart upload returned no UploadId".into()))?
			.to_owned();
		Ok(Upload {
			id,
			upload_id,
			part: Vec::new(),
			etags: Vec::new(),
		})
	}

	async fn write_upload(&self, upload: &mut Upload, record: InputRecord) -> anyhow::Result<()> {
		serde_json::to_writer(&mut upload.part, &translate_input(record, self.provider)?)?;
		upload.part.push(b'\n');
		if upload.part.len() >= PART_BYTES {
			self.upload_part(upload).await?;
		}
		Ok(())
	}

	async fn finish_upload(&self, mut upload: Upload) -> anyhow::Result<String> {
		match self.complete_upload(&mut upload).await {
			Ok(()) => Ok(upload.id),
			Err(error) => {
				self.abort_upload(upload).await;
				Err(error)
			},
		}
	}

	async fn abort_upload(&self, upload: Upload) {
		let path = upload.path("");
		if let Err(error) = self.call(Service::S3, Method::DELETE, &path, vec![]).await {
			tracing::debug!(%error, "failed to abort batch upload");
		}
	}

	async fn create(&self, file_id: &str, endpoint: Endpoint) -> anyhow::Result<String> {
		ensure!(is_file_id(file_id), "invalid input_file_id");
		let input = self
			.send(Service::S3, Method::HEAD, &input_key(file_id), vec![])
			.await?;
		let stored = input
			.headers()
			.get(ENDPOINT_METADATA)
			.and_then(|value| value.to_str().ok())
			.unwrap_or(endpoint_name(Endpoint::ChatCompletions));
		ensure!(
			stored == endpoint_name(endpoint),
			"input file records do not target {}",
			endpoint.path()
		);
		let bucket = &self.config.bucket;
		// The job name records the endpoint so results can be returned in its format.
		let job_name = format!(
			"{file_id}-{}-{}",
			endpoint_name(endpoint),
			&uuid::Uuid::new_v4().simple().to_string()[..16]
		);
		let request = json!({
			"jobName": job_name,
			"modelId": self.model,
			"roleArn": self.config.role_arn,
			"modelInvocationType": "Converse",
			"timeoutDurationInHours": 24,
			"inputDataConfig": {"s3InputDataConfig": {"s3Uri": format!("s3://{bucket}{}", input_key(file_id))}},
			"outputDataConfig": {"s3OutputDataConfig": {"s3Uri": format!("s3://{bucket}/{PREFIX}/output/")}},
		});
		let created: Value = self
			.call_json(
				Service::Bedrock,
				Method::POST,
				"/model-invocation-job",
				serde_json::to_vec(&request)?,
			)
			.await?;
		// Keep the account and region in the batch ID.
		Ok(hex::encode(created["jobArn"].as_str().ok_or_else(
			|| UpstreamError::new("bedrock returned no jobArn".into()),
		)?))
	}

	async fn get(&self, batch_id: &str) -> anyhow::Result<Job> {
		Ok(self.lookup(batch_id).await?.0)
	}

	async fn results(
		&self,
		batch_id: &str,
	) -> anyhow::Result<BoxStream<'static, anyhow::Result<ResultRecord>>> {
		let (job, job_id) = self.lookup(batch_id).await?;
		ensure!(
			job.status.has_results() || matches!(job.status, Status::Failed),
			"batch results are not ready"
		);
		let key = format!("/{PREFIX}/output/{job_id}/{}.jsonl.out", job.file_id);
		let response = match self.send(Service::S3, Method::GET, &key, vec![]).await {
			// Stopped and expired jobs may not have written any output.
			Err(e) if e.status == Some(StatusCode::NOT_FOUND) => {
				return Ok(futures::stream::empty().boxed());
			},
			res => res?,
		};
		let model = job.model;
		let endpoint = job.endpoint;
		Ok(
			super::lines(
				response.into_body().into_data_stream(),
				super::MAX_RESULT_BYTES,
			)
			.map_ok(move |line| match line {
				Ok(line) => parse_result(&line, &model, endpoint),
				Err(error) => ResultRecord::invalid("", &format!("result {error}"), None),
			})
			.boxed(),
		)
	}
}

fn endpoint_name(endpoint: Endpoint) -> &'static str {
	match endpoint {
		Endpoint::ChatCompletions => "chat",
		Endpoint::Responses => "responses",
	}
}

/// Lines that can't be matched to an input record become `invalid_result` errors.
fn parse_result(line: &str, model: &str, endpoint: Endpoint) -> ResultRecord {
	let invalid = ResultRecord::invalid;
	let Ok(record) = serde_json::from_str::<Value>(line) else {
		return invalid("", "result line is not JSON", None);
	};
	let usage = result_usage(&record, model);
	let record_id = record["recordId"].as_str().unwrap_or_default();
	let Some(custom_id) = hex::decode(record_id)
		.ok()
		.and_then(|id| String::from_utf8(id).ok())
		.filter(|id| !id.is_empty())
	else {
		return invalid(record_id, "result has no gateway record ID", usage);
	};
	let error = &record["error"];
	let outcome = if error.is_null() {
		translate_output(&record["modelOutput"], model, endpoint).map_err(|e| RecordError {
			code: "translation_error".to_owned(),
			message: Value::String(e.to_string()),
		})
	} else {
		let code = &error["errorCode"];
		Err(RecordError {
			code: code
				.as_str()
				.map(str::to_owned)
				.unwrap_or_else(|| code.to_string()),
			message: error["errorMessage"].clone(),
		})
	};
	ResultRecord {
		custom_id,
		outcome,
		usage,
	}
}

fn result_usage(record: &Value, model: &str) -> Option<LLMInfo> {
	serde_json::from_value::<types::bedrock::TokenUsage>(record["modelOutput"]["usage"].clone())
		.ok()
		.and_then(|usage| {
			usage::info(
				LLMResponse {
					input_tokens: Some(usage.input_tokens as u64),
					output_tokens: Some(usage.output_tokens as u64),
					total_tokens: Some(usage.total_tokens as u64),
					cached_input_tokens: usage.cache_read_input_tokens.map(|v| v as u64),
					cache_creation_input_tokens: usage.cache_write_input_tokens.map(|v| v as u64),
					provider_model: Some(model.into()),
					..Default::default()
				},
				InputFormat::Completions,
				CacheTokenConvention::InputExcludesCache,
				"aws.bedrock",
			)
		})
}

fn translate_output(output: &Value, model: &str, endpoint: Endpoint) -> anyhow::Result<Value> {
	let output = Bytes::from(serde_json::to_vec(output)?);
	let translated = match endpoint {
		Endpoint::ChatCompletions => {
			conversion::bedrock::from_completions::translate_response(&output, model, None)?
		},
		Endpoint::Responses => {
			conversion::bedrock::from_responses::translate_response(&output, model, None, None)?
		},
	};
	Ok(serde_json::from_slice(&translated.serialize()?)?)
}

fn encode(value: &str) -> percent_encoding::PercentEncode<'_> {
	percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC)
}

impl Backend<'_> {
	async fn complete_upload(&self, upload: &mut Upload) -> anyhow::Result<()> {
		if !upload.part.is_empty() {
			self.upload_part(upload).await?;
		}
		let parts: String = upload
			.etags
			.iter()
			.enumerate()
			.map(|(i, etag)| {
				format!(
					"<Part><PartNumber>{}</PartNumber><ETag>{etag}</ETag></Part>",
					i + 1
				)
			})
			.collect();
		let body = format!("<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>");
		let path = upload.path("");
		let response = self
			.call(Service::S3, Method::POST, &path, body.into_bytes())
			.await?;
		// S3 can report a failed completion in a 200 response.
		ensure!(
			!String::from_utf8_lossy(&response).contains("<Error>"),
			UpstreamError::new(format!(
				"s3 multipart upload failed: {}",
				String::from_utf8_lossy(&response)
			))
		);
		Ok(())
	}

	async fn upload_part(&self, upload: &mut Upload) -> anyhow::Result<()> {
		let path = upload.path(&format!("partNumber={}&", upload.etags.len() + 1));
		let part = std::mem::take(&mut upload.part);
		let response = self.send(Service::S3, Method::PUT, &path, part).await?;
		let etag = response
			.headers()
			.get(::http::header::ETAG)
			.and_then(|etag| etag.to_str().ok())
			.ok_or_else(|| UpstreamError::new("s3 upload part returned no ETag".into()))?;
		upload.etags.push(etag.to_owned());
		Ok(())
	}

	async fn lookup(&self, batch_id: &str) -> anyhow::Result<(Job, String)> {
		let arn = String::from_utf8(hex::decode(batch_id).context("invalid batch ID")?)?;
		let (_, job_id) = arn
			.rsplit_once(":model-invocation-job/")
			.context("invalid batch ID")?;
		let job_id = job_id.to_owned();
		let job: JobResponse = self
			.call_json(
				Service::Bedrock,
				Method::GET,
				&format!("/model-invocation-job/{}", encode(&arn)),
				vec![],
			)
			.await?;
		let prefix = format!("s3://{}/{PREFIX}/input/", self.config.bucket);
		let file_id = job
			.input_data_config
			.s3_input_data_config
			.s3_uri
			.strip_prefix(&prefix)
			.and_then(|s| s.strip_suffix(".jsonl"))
			.context("job does not belong to this batch backend")?
			.to_owned();
		let status = match job.status.as_str() {
			"Submitted" | "Validating" => Status::Validating,
			"Scheduled" | "InProgress" => Status::InProgress,
			"Completed" | "PartiallyCompleted" => Status::Completed,
			"Failed" => Status::Failed,
			"Expired" => Status::Expired,
			"Stopping" => Status::Cancelling,
			"Stopped" => Status::Cancelled,
			other => bail!(UpstreamError::new(format!(
				"unknown Bedrock batch status: {other}"
			))),
		};
		let endpoint = match job.job_name.split('-').nth(1) {
			Some(name) if name == endpoint_name(Endpoint::Responses) => Endpoint::Responses,
			_ => Endpoint::ChatCompletions,
		};
		let job = Job {
			file_id,
			model: job.model_id,
			endpoint,
			status,
			created_at: job.submit_time.map(|t| t.timestamp()),
			total: job.total_record_count,
			completed: job.success_record_count,
			failed: job.error_record_count,
			message: job.message,
		};
		Ok((job, job_id))
	}

	async fn call_json<T: DeserializeOwned>(
		&self,
		service: Service,
		method: Method,
		path: &str,
		body: Vec<u8>,
	) -> anyhow::Result<T> {
		let bytes = self.call(service, method, path, body).await?;
		Ok(serde_json::from_slice(&bytes).map_err(|e| UpstreamError::new(e.to_string()))?)
	}

	async fn call(
		&self,
		service: Service,
		method: Method,
		path: &str,
		body: Vec<u8>,
	) -> Result<Bytes, UpstreamError> {
		let response = self.send(service, method, path, body).await?;
		read_body(response).await
	}

	async fn send(
		&self,
		service: Service,
		method: Method,
		path: &str,
		body: Vec<u8>,
	) -> Result<Response, UpstreamError> {
		self.send_with(service, method, path, body, &[]).await
	}

	/// Sends a signed request with additional headers, returning the response if it succeeded.
	async fn send_with(
		&self,
		service: Service,
		method: Method,
		path: &str,
		body: Vec<u8>,
		headers: &[(&'static str, &str)],
	) -> Result<Response, UpstreamError> {
		let region = &self.provider.region;
		let bucket = &self.config.bucket;
		let url = match service {
			// Virtual-hosted URLs fail TLS for bucket names containing dots.
			Service::S3 if bucket.contains('.') => {
				format!("https://s3.{region}.amazonaws.com/{bucket}{path}")
			},
			Service::S3 => format!("https://{bucket}.s3.{region}.amazonaws.com{path}"),
			Service::Bedrock => format!("https://bedrock.{region}.amazonaws.com{path}"),
		};
		// The signer buffers the body to hash it.
		let limit = body.len().max(crate::llm::DEFAULT_BUFFER_LIMIT);
		let mut request = ::http::Request::builder()
			.method(method)
			.uri(url)
			.header(
				"x-amz-content-sha256",
				hex::encode(crate::crypto::digest::sha256(&body)),
			)
			.extension(crate::transport::BufferLimit::new(limit));
		if matches!(service, Service::Bedrock) {
			request = request.header(::http::header::CONTENT_TYPE, "application/json");
		}
		for (name, value) in headers {
			request = request.header(*name, *value);
		}
		let request = request
			.body(Body::from(body))
			.map_err(|e| UpstreamError::new(e.to_string()))?;
		let policies = vec![
			BackendTrafficPolicy::BackendTLS(crate::http::backendtls::SYSTEM_TRUST.clone()),
			BackendTrafficPolicy::backend_auth(BackendAuthKind::Aws(self.signing_auth(service))),
		];
		let backend = TargetBackend::Dynamic(
			ResourceName::new(strng::literal!("_bedrock-batch"), strng::literal!("")),
			None,
		);
		let response = self
			.client
			.with_outbound(OutboundCallKind::Primary, OutboundCallSubtype::Llm)
			.call_with_explicit_policies_list(request, backend, policies)
			.await
			.map_err(|e| UpstreamError::new(e.to_string()))?;
		let status = response.status();
		if !status.is_success() {
			let body = read_body(response).await?;
			return Err(UpstreamError {
				status: Some(status),
				message: format!(
					"{} returned {status}: {}",
					service.name(),
					String::from_utf8_lossy(&body)
				),
			});
		}
		Ok(response)
	}
}

async fn read_body(response: Response) -> Result<Bytes, UpstreamError> {
	crate::http::read_body_with_limit(response.into_body(), crate::llm::DEFAULT_BUFFER_LIMIT)
		.await
		.map_err(|e| UpstreamError::new(e.to_string()))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn response_tools_must_round_trip_without_request_state() {
		let provider = serde_json::from_value(json!({"model":"model", "region":"us-west-2"})).unwrap();
		for (tool, valid) in [
			(
				json!({"type":"function", "name":"add", "parameters":{"type":"object","properties":{}}}),
				true,
			),
			(
				json!({"type":"namespace", "name":"math", "description":"Math tools", "tools":[
					{"type":"function", "name":"add", "parameters":{"type":"object","properties":{}}}
				]}),
				false,
			),
		] {
			let input = InputRecord {
				custom_id: "a".into(),
				endpoint: Endpoint::Responses,
				body: json!({"model":"model", "input":"Calculate", "tools":[tool]}),
			};
			assert_eq!(translate_input(input, &provider).is_ok(), valid);
		}
	}

	#[test]
	fn parses_results() {
		let success = json!({
			"recordId": hex::encode("a"),
			"modelInput": {},
			"modelOutput": {
				"output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
				"stopReason": "end_turn",
				"usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
				"metrics": {"latencyMs": 1},
			},
		});
		let record = parse_result(&success.to_string(), "m", Endpoint::ChatCompletions);
		assert_eq!(record.custom_id, "a");
		let body = record.outcome.ok().unwrap();
		assert_eq!(body["choices"][0]["message"]["content"], "hi");

		let record = parse_result(&success.to_string(), "m", Endpoint::Responses);
		let body = record.outcome.ok().unwrap();
		assert_eq!(body["object"], "response");
		assert_eq!(body["output"][0]["content"][0]["text"], "hi");

		let error = json!({
			"recordId": hex::encode("b"),
			"modelInput": {},
			"error": {"errorCode": 400, "errorMessage": "bad"},
		});
		let record = parse_result(&error.to_string(), "m", Endpoint::ChatCompletions);
		assert_eq!(record.custom_id, "b");
		let Err(error) = record.outcome else {
			panic!("expected an error record");
		};
		assert_eq!(error.code, "400");

		let invalid = json!({"recordId": hex::encode("c"), "modelOutput": {
			"usage": {"inputTokens": 5, "outputTokens": 2, "totalTokens": 7}
		}});
		let record = parse_result(&invalid.to_string(), "m", Endpoint::ChatCompletions);
		assert_eq!(record.custom_id, "c");
		assert_eq!(record.outcome.err().unwrap().code, "translation_error");
		assert_eq!(record.usage.unwrap().response.total_tokens, Some(7));

		// Unmatched lines keep their usage.
		let unmatched = json!({"recordId": "not-hex", "modelOutput": {
			"usage": {"inputTokens": 5, "outputTokens": 2, "totalTokens": 7}
		}});
		for (line, usage) in [(unmatched.to_string(), true), ("{".to_owned(), false)] {
			let record = parse_result(&line, "m", Endpoint::ChatCompletions);
			assert_eq!(record.outcome.err().unwrap().code, "invalid_result");
			assert_eq!(record.usage.is_some(), usage);
		}
	}
}
