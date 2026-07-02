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

### Cache-stable compression (recommended for cached providers)

By default the sidecar's compression is position-dependent: a message's
compressed bytes change as it ages (recency protection, adaptive ratios, and
stale-Read rewrites that alter *earlier* messages when a file is edited
*later*). On providers with prompt caching (Anthropic), every such byte change
invalidates the cached prefix from that point on — and cache reads are 10x
cheaper than fresh input, so busting the cache usually costs more than
compression saves.

Cache-stable mode makes `/v1/compress` a deterministic, prefix-stable
function: if a conversation extends a previous one, the compressed output is a
byte-identical extension of the previous compressed output, so the provider
cache keeps hitting. This is pure sidecar *startup* configuration — the
gateway stays stateless (no sticky routing needed) and the wire contract is
unchanged:

```bash
HEADROOM_MODE=cache \
HEADROOM_PROTECT_RECENT=0 \
HEADROOM_PROTECT_ANALYSIS_CONTEXT=0 \
HEADROOM_MIN_RATIO=0.75 \
HEADROOM_COMPRESS_MARKED_BLOCKS=1 \
headroom proxy --no-read-lifecycle
```

Keep `HEADROOM_NET_COST_POLICY` and `HEADROOM_SAVINGS_PROFILE` unset (both
reintroduce position-dependent behavior). `HEADROOM_MIN_RATIO` pins the
otherwise context-pressure-adaptive acceptance ratio to a constant.
`HEADROOM_COMPRESS_MARKED_BLOCKS` compresses `cache_control`-marked blocks at
first sight: clients like Claude Code move that marker forward every turn, and
skip-while-marked would flip the block's bytes one turn later — a guaranteed
prefix bust.

Trade-offs: stale/superseded Read rewriting is off (it is fundamentally
incompatible with prefix stability), and Read/Glob/Grep/Write/Edit outputs are
never compressed; Bash, WebFetch, and MCP tool outputs still compress fully.
Watch `cache_read_ratio` (below) to confirm the mode is working: it should
stay high across a long session and collapse if anything position-dependent
sneaks back in.

Enable `exactMeasurement` on the gateway's headroom policy to measure savings.
Without an exact provider pre-count, the gateway still forwards compressed
requests but does not emit savings telemetry for that request.

### Measuring compression and savings

Compressed-request savings are reported on the request log
(`agw.ai.headroom.*`) and as Prometheus counters
(`agw_headroom_saved_tokens`, `agw_headroom_saved_cost`) when exact
measurement succeeds:

- `input_tokens_before_compression` — exact provider token count of the
  *original* request, from a background `count_tokens` call. The call is free
  and runs off the hot path, but counts against the provider's count_tokens
  rate limit.
- `input_tokens_billed` — provider-billed context for the compressed request
  (fresh input + cache reads/writes), from the provider's usage block. Ground
  truth.
- `tokens_saved` — `count_tokens(original) - billed`, with both sides in the
  provider's tokenizer. If exact pre-count is unavailable, this field is not
  emitted.
- `saved_cost` — the request re-priced through the model cost catalog with the
  saved tokens added back **at the observed input/cache mix** (tier-aware),
  minus the actual cost. On a warm cached session saved tokens are valued
  mostly at the cache-read rate, not the fresh-input rate — this deliberately
  avoids the ~10x overstatement of flat-rate savings math. Requires a
  `modelCatalog` in the config.
- `cache_read_ratio` — cached fraction of billed context. **This is the
  compression-health signal**: on a long session it should stay high; if it
  collapses, compression is rewriting the cached prefix and likely costing
  more than it saves.

### Large contexts

Request and sidecar-response bodies are subject to the frontend's
`maxBufferSize` (default 2MB). For contexts larger than that, raise
`frontendPolicies.http.maxBufferSize` on the bind; the gateway applies the same
limit when reading the sidecar's compressed response.
