use agentgateway::llm::batch::BedrockConfig;
use agentgateway::llm::{AIProvider, BedrockProvider, anthropic, bedrock, openai};
use agentgateway::types::local::LocalBackendPolicies;
use hyper_util::client::legacy::Client;

use crate::common::prelude::*;

const MODEL: &str = "us.anthropic.claude-haiku-4-5-20251001-v1:0";

fn bedrock_provider(model: Option<&str>, batch: Option<BedrockConfig>) -> AIProvider {
	let mut provider = BedrockProvider::new(bedrock::Provider {
		model_override: model.map(Into::into),
		region: "us-west-2".into(),
		guardrail_identifier: None,
		guardrail_version: None,
		endpoint_preference: Default::default(),
	});
	provider.batch = batch;
	AIProvider::Bedrock(provider)
}

fn bedrock_batch() -> Option<BedrockConfig> {
	Some(BedrockConfig {
		bucket: "my-batch-bucket".into(),
		role_arn: "arn:aws:iam::123456789012:role/Batch".into(),
	})
}

fn openai_provider(model: Option<&str>) -> AIProvider {
	AIProvider::OpenAI(openai::Provider {
		model_override: model.map(Into::into),
		moderation: None,
	})
}

fn anthropic_provider(model: Option<&str>) -> AIProvider {
	AIProvider::Anthropic(anthropic::Provider {
		model_override: model.map(Into::into),
	})
}

async fn setup(
	provider: AIProvider,
	policies: Option<Value>,
) -> (MockServer, TestBind, Client<MemoryConnector, Body>) {
	let mock = simple_mock().await;
	let mut provider = llm_named_provider(&mock, provider, false);
	provider.policies = policies.map(|p| serde_json::from_value::<LocalBackendPolicies>(p).unwrap());
	setup_llm_named_provider_mock(mock, provider, "{}")
}

fn guard(action: &str) -> Value {
	json!({"ai": {"promptGuard": {"request": [{
		"regex": {"action": action, "rules": [{"pattern": "SSN"}]},
		"rejection": {"status": 403},
	}]}}})
}

fn record(id: usize, content: &str) -> String {
	json!({"custom_id": id.to_string(), "method": "POST", "url": "/v1/chat/completions",
		"body": {"model": "m", "messages": [{"role": "user", "content": content}]}})
	.to_string()
}

fn upload(file: &[u8]) -> Vec<u8> {
	let mut body = b"--x\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nbatch\r\n\
		--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"in.jsonl\"\r\n\r\n"
		.to_vec();
	body.extend_from_slice(file);
	body.extend_from_slice(b"\r\n--x--\r\n");
	body
}

fn batch_upload(contents: &[&str]) -> Vec<u8> {
	let file: String = contents
		.iter()
		.enumerate()
		.map(|(i, content)| record(i, content) + "\n")
		.collect();
	upload(file.as_bytes())
}

async fn send_upload(io: Client<MemoryConnector, Body>, body: Vec<u8>) -> Response {
	RequestBuilder::new(Method::POST, "http://lo/v1/files")
		.header("content-type", "multipart/form-data; boundary=x")
		.body(body)
		.send(io)
		.await
		.unwrap()
}

#[tokio::test]
async fn bedrock_upload_is_guarded() {
	let provider = bedrock_provider(Some(MODEL), bedrock_batch());
	let (_mock, _bind, io) = setup(provider, Some(guard("reject"))).await;
	let res = send_upload(io, batch_upload(&["my SSN is 123"])).await;
	assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn native_upload_is_guarded() {
	let (_mock, _bind, io) = setup(openai_provider(None), Some(guard("mask"))).await;
	let res = send_upload(io, batch_upload(&["hello", "my SSN is 123"])).await;
	assert_eq!(res.status(), StatusCode::OK);
	let forwarded = read_body(res.into_body()).await.body;
	let forwarded = String::from_utf8_lossy(&forwarded);
	assert_eq!(forwarded.matches("custom_id").count(), 2);
	assert!(forwarded.contains("hello"));
	assert!(!forwarded.contains("SSN"));
}

#[tokio::test]
async fn native_upload_rejected_mid_stream() {
	let (mock, _bind, io) = setup(openai_provider(None), Some(guard("reject"))).await;
	let res = send_upload(io, batch_upload(&["hello", "my SSN is 123", "bye"])).await;
	assert_eq!(res.status(), StatusCode::FORBIDDEN);
	assert!(mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn native_upload_uses_backend_model() {
	let (_mock, _bind, io) = setup(openai_provider(Some("backend-model")), None).await;
	let res = send_upload(io, batch_upload(&["hello"])).await;
	assert_eq!(res.status(), StatusCode::OK);
	let forwarded = read_body(res.into_body()).await.body;
	assert!(String::from_utf8_lossy(&forwarded).contains(r#""model":"backend-model""#));
}

#[tokio::test]
async fn native_upload_applies_request_policies() {
	let policies = json!({"ai": {
		"modelAliases": {"m": "aliased"},
		"overrides": {"temperature": 0},
		"defaults": {"max_tokens": 16},
		"transformations": {"user": "llmRequest.messages[0].content"},
		"prompts": {"prepend": [{"role": "system", "content": "Be brief."}]},
	}});
	let (_mock, _bind, io) = setup(openai_provider(None), Some(policies)).await;
	let res = send_upload(io, batch_upload(&["hello", "goodbye"])).await;
	assert_eq!(res.status(), StatusCode::OK);
	let forwarded = read_body(res.into_body()).await.body;
	let forwarded = String::from_utf8_lossy(&forwarded);
	let records: Vec<Value> = forwarded
		.lines()
		.filter(|line| line.contains("custom_id"))
		.map(|line| serde_json::from_str(line).unwrap())
		.collect();
	assert_eq!(records.len(), 2);
	for (record, content) in records.iter().zip(["hello", "goodbye"]) {
		assert_eq!(record["body"]["model"], "aliased");
		assert_eq!(record["body"]["temperature"], 0.0);
		assert_eq!(record["body"]["max_tokens"], 16);
		assert_eq!(record["body"]["user"], content);
		assert_eq!(record["body"]["messages"][0]["content"], "Be brief.");
		assert_eq!(record["body"]["messages"][1]["content"], content);
	}
}

#[tokio::test]
async fn native_uploads_api_unavailable_with_guards() {
	let (mock, _bind, io) = setup(openai_provider(None), Some(guard("reject"))).await;
	let res = send_request(io, Method::POST, "http://lo/v1/uploads").await;
	assert_eq!(res.status(), StatusCode::NOT_FOUND);
	assert!(mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn anthropic_message_batches() {
	let body = json!({"requests": [{"custom_id": "a", "params": {
		"model": "m", "max_tokens": 16, "messages": [{"role": "user", "content": "my SSN is 123"}],
	}}]})
	.to_string();
	let send = |io| {
		let body = body.clone();
		async move {
			send_request_body(
				io,
				Method::POST,
				"http://lo/v1/messages/batches",
				body.as_bytes(),
			)
			.await
		}
	};

	let (mock, _bind, io) = setup(anthropic_provider(None), Some(guard("reject"))).await;
	assert_eq!(send(io).await.status(), StatusCode::FORBIDDEN);
	assert!(mock.received_requests().await.unwrap().is_empty());

	let (_mock, _bind, io) = setup(anthropic_provider(Some("backend-model")), None).await;
	let res = send(io).await;
	assert_eq!(res.status(), StatusCode::OK);
	let forwarded: Value = serde_json::from_slice(&read_body(res.into_body()).await.body).unwrap();
	assert_eq!(forwarded["requests"][0]["params"]["model"], "backend-model");
}

#[tokio::test]
async fn native_provider_passes_batch_paths_through() {
	let (_mock, _bind, io) = setup(openai_provider(None), None).await;
	for path in ["/v1/batches/batch_abc", "/v1/files/file-abc/content"] {
		let res = send_request(io.clone(), Method::GET, &format!("http://lo{path}")).await;
		assert_eq!(res.status(), StatusCode::OK);
		assert_eq!(read_body(res.into_body()).await.uri.path(), path);
	}
}

#[tokio::test]
async fn native_upload_without_processing_is_unchanged() {
	let (_mock, _bind, io) = setup(openai_provider(None), None).await;
	let body = upload(b"not JSONL: the provider validates an unprocessed upload");
	let res = send_upload(io, body.clone()).await;
	assert_eq!(res.status(), StatusCode::OK);
	assert_eq!(read_body(res.into_body()).await.body, body);
}

#[tokio::test]
async fn explicit_batch_route_overrides_detection() {
	let (_mock, _bind, io) = setup(
		openai_provider(None),
		Some(json!({"ai": {
			"routes": {"/v1/files": "passthrough"},
			"promptGuard": {"request": [{"regex": {"action": "reject", "rules": [{"pattern": "SSN"}]}}]}
		}})),
	)
	.await;
	let body = batch_upload(&["my SSN is 123"]);
	let res = send_upload(io, body.clone()).await;
	assert_eq!(res.status(), StatusCode::OK);
	assert_eq!(read_body(res.into_body()).await.body, body);
}

#[tokio::test]
async fn unsupported_batch_paths_are_not_completions() {
	let (mock, _bind, io) = setup(anthropic_provider(None), None).await;
	let res = send_request(io, Method::GET, "http://lo/v1/batches/batch_abc").await;
	assert_eq!(res.status(), StatusCode::NOT_FOUND);
	assert!(mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn bedrock_batch_availability() {
	let key_auth = json!({"backendAuth": {"key": {"value": "secret"}}});
	for (provider, policies) in [
		(bedrock_provider(Some(MODEL), None), None),
		(bedrock_provider(None, bedrock_batch()), None),
		(
			bedrock_provider(Some(MODEL), bedrock_batch()),
			Some(key_auth),
		),
	] {
		let (mock, _bind, io) = setup(provider, policies).await;
		let res = send_request(io, Method::GET, "http://lo/v1/batches/batch-abc").await;
		assert_eq!(res.status(), StatusCode::NOT_FOUND);
		assert!(mock.received_requests().await.unwrap().is_empty());
	}
}

#[tokio::test]
async fn configured_passthrough_is_kept_for_unsupported_provider() {
	let (_mock, _bind, io) = setup(
		anthropic_provider(None),
		Some(json!({"ai": {"routes": {"*": "passthrough"}}})),
	)
	.await;
	let res = send_request(io, Method::GET, "http://lo/v1/batches/batch-abc").await;
	assert_eq!(res.status(), StatusCode::OK);
	assert_eq!(
		read_body(res.into_body()).await.uri.path(),
		"/v1/batches/batch-abc"
	);
}
