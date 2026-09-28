use agentgateway::llm::batch::BedrockConfig;
use agentgateway::llm::{AIProvider, BedrockProvider, anthropic, bedrock};
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
