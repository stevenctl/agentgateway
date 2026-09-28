## LLM Batch Example

This example serves the OpenAI batch API (`/v1/files`, `/v1/batches`) from a Bedrock backend using Bedrock batch inference.

Other providers:

- OpenAI passes `/v1/files`, `/v1/batches`, and `/v1/uploads` through.
- Anthropic passes `/v1/files` and `/v1/messages/batches` through.
- Everything else, including Bedrock without `batch`, returns 404 unless the route is a passthrough route. A path listed explicitly in `ai.routes` skips batch handling entirely.

Request policies (defaults, overrides, transformations, model aliases, prompts, `promptGuard.request`) and the backend's model apply to each request in a batch as if it were sent directly. In CEL, `llmRequest` is each record's request body and `request` is the upload.

### Setup

Edit `config.yaml` with your model, region, bucket (same region), and role.

- Gateway credentials (the backend's AWS auth, or the default chain): `s3:GetObject`, `s3:PutObject`, and `s3:AbortMultipartUpload` on `agentgateway-batch/*`; `s3:ListBucket` on the bucket; `bedrock:CreateModelInvocationJob` and `bedrock:GetModelInvocationJob`; `iam:PassRole` on the role.
- Role (`roleArn`): trusted by `bedrock.amazonaws.com`, with model invoke access, `s3:GetObject` and `s3:PutObject` on `agentgateway-batch/*`, and `s3:ListBucket` on the bucket.

### Running

```sh
cargo run -- -f examples/llm-batch/config.yaml
./examples/llm-batch/test.sh
```

`test.sh` uploads 100 records (check your account's minimum records per job quota), creates a batch, polls it, and saves `output.jsonl` and `errors.jsonl`. Each input line is a `/v1/chat/completions` or `/v1/responses` request, and all lines in a file must target the same one:

```json
{"custom_id":"request-1","method":"POST","url":"/v1/chat/completions","body":{"model":"claude","messages":[{"role":"user","content":"Say hello"}],"max_tokens":128}}
```

### Limitations

- Records are limited to 32 MiB. When policies or a backend model apply, Anthropic batch requests are too.
- With request policies or a backend model, `/v1/uploads` returns 404.
- OpenAI policies run on file upload, not when submitting an existing file ID. Put `purpose` before the file for non-batch uploads; otherwise a batch-shaped first line classifies the file as a batch.
- Only file upload, batch creation/retrieval, and result download are supported. Listing, input-file retrieval/deletion, and batch cancellation aren't implemented; to cancel, stop the job in the Bedrock console.
- `custom_id` must be unique and 1–128 bytes, `stream` is rejected, and tools must use Bedrock-compatible names without namespaces.
- File IDs identify randomly generated object keys within the configured bucket. Batch IDs encode the job ARN. IDs aren't scoped to the client, and changing the region or bucket invalidates them.
- Grouped providers must share access to the same files and jobs (provider account, and Bedrock region/bucket). Client requests have no file/job affinity.
- Response guards don't apply to batch downloads.
- API key backend auth and request-derived AWS session tags or names aren't supported.
- Add S3 lifecycle rules for cleanup, including `AbortIncompleteMultipartUpload`.

### Cost observations

Result downloads emit `batch`-scope logs with record identity, model, token usage, and catalog-priced cost where explicit batch rates exist. Each download logs its own records, so repeated downloads repeat the observations. Usage is retained even when response translation fails.

Catalog entries can specify separate `batch.rates` and `batch.tiers`. Missing batch prices are reported as unpriced, not inferred from synchronous rates.

### Kubernetes

On an `AgentgatewayBackend`, configure `spec.ai.provider.bedrock.batch`:

```yaml
spec:
  ai:
    provider:
      bedrock:
        model: YOUR_BATCH_CAPABLE_MODEL
        region: us-west-2
        batch:
          bucket: my-bucket
          roleArn: arn:aws:iam::123456789012:role/AgentgatewayBedrockBatch
```
