## Headroom Context Compression Example

This example shows how to compress LLM request context through
[Headroom](https://github.com/headroomlabs-ai/headroom) before it
reaches the provider, attempting to reduce token usage on long-context
requests.

### Running the example

Start  Headroom. Use `--mode cache` so it freezes prior turns to keep
provider prefix-cache reuse intact:
```bash
headroom proxy --port 8787 --mode cache
```

> use `--mode token` to maximize raw compression instead. NOT recommended.
> Althought token compression goes way up, the actual cost will also likely
> skyrocket because the prefix cache general beats compression's cost savings.

Then run the gateway:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
cargo run -- -f examples/headroom/config.yaml
```

The `headroom` policy on the model points at the Headroom backend, and
`failureMode` dictates the behavior when there is a failure during compression.

```yaml
llm:
  models:
  - name: "*"
    provider: anthropic
    params:
      apiKey: "$ANTHROPIC_API_KEY"
    headroom:
      target:
        host: 127.0.0.1:8787
      # failureMode: failOpen   # failOpen (default) | failClosed
```

### Using with Claude Code

Claude Code accumulates a large, growing context,
and the gateway compresses it on every turn. Point Claude Code at the gateway
by setting its Anthropic base URL (see the [Claude Code integration
guide](https://agentgateway.dev/docs/standalone/main/integrations/llm-clients/claude-code/)),
then run it as usual:

```bash
export ANTHROPIC_BASE_URL=http://localhost:4000
claude -p "Hello"
```

With the sidecar in `--mode cache`, Headroom freezes prior turns so Anthropic's
prompt cache still hits and only the newest turn is compressed, long sessions
cost less without losing the cached-prefix discount. To confirm the gateway is
in the path, watch its logs (or Headroom's) while Claude Code runs; add `--mode
token` on the sidecar to maximize raw compression instead.

### Sending a raw request

To exercise compression without Claude Code, send a request whose messages
contain a large context block (compression only helps when there is enough to
compress. This uses `jq` to embed the bundled an arbitrary file to see if it
compresses:

```bash
curl http://localhost:4000/v1/messages \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d "$(jq -n --rawfile ctx examples/headroom/large-context.txt '{
    model: "claude-sonnet-4-5",
    max_tokens: 200,
    messages: [{
      role: "user",
      content: ("Here is some reference material:\n\n" + $ctx + "\n\nWhat are the key takeaways?")
    }]
  }')"
```

Send `x-headroom-bypass: true` on any request to skip compression for that
call. The gateway consumes this header; it is not forwarded to the provider.

### Large contexts

Request and sidecar-response bodies are subject to the frontend's
`maxBufferSize` (default 2MB). For contexts larger than that, raise
`frontendPolicies.http.maxBufferSize` on the bind; the gateway applies the same
limit when reading the sidecar's compressed response.
