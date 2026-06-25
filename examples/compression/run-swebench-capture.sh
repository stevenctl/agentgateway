#!/usr/bin/env bash
# Capture TRUE (uncompressed) upstream request/response bodies from a
# mini-swe-agent SWE-bench run, for offline replay/tuning of ctxedit compression.
#
# Why mini-swe-agent: it makes the LLM calls from the HOST process (only bash runs
# in the task's Docker image), so litellm can point straight at a host-side
# capture proxy — no host.docker.internal hop. It uses structured tool-calling, so
# with an OpenAI model you get `role:tool` messages (completions walker path); with
# a Claude model you get `tool_result` blocks (anthropic walker path).
#
# Flow:
#   mini-swe-agent (host) --litellm--> capture_proxy(:CAP_PORT) --https--> provider
# Captures land in $CAPTURE_DIR/<provider>-NNN.{req,resp}.txt — exactly what the
# model receives. No gateway/compression in the loop: this is the true baseline
# corpus to iterate the walker+compressors against offline.
#
# Usage (run in YOUR terminal; needs your real key in the env):
#   OPENAI_API_KEY=sk-... ./run-swebench-capture.sh
#   COST_LIMIT=0.50 ./run-swebench-capture.sh                       # cheap smoke
#   INSTANCE=django__django-15629 ./run-swebench-capture.sh
#   MODEL=claude-sonnet-4-5 ./run-swebench-capture.sh               # anthropic path
#
# Prereqs: docker running; `mini` installed (uv tool install mini-swe-agent).
set -euo pipefail

REPO="/home/landow/solo/agentgateway"
SP="/tmp/claude-1000/-home-landow-solo-agentgateway/bd6db166-aacd-4026-8a39-17bf46bc916f/scratchpad"
export PATH="$HOME/.local/bin:$PATH"

INSTANCE="${INSTANCE:-pydata__xarray-4356}"
MODEL="${MODEL:-gpt-5}"
SUBSET="${SUBSET:-verified}"   # full | verified | lite
SPLIT="${SPLIT:-test}"
COST_LIMIT="${COST_LIMIT:-5}"  # USD; mini stops the run at this spend
CAP_PORT="${CAP_PORT:-8788}"
# Capture full tool output up to this many chars (mini's stock cap is 10k, which
# blind-clips the big logs we specifically want compression to handle). Head+tail
# keep = OUTPUT_KEEP/2 each beyond the threshold, guarding against runaway context.
OUTPUT_KEEP="${OUTPUT_KEEP:-100000}"

case "$MODEL" in
  gpt-*|o[0-9]*|openai/*) PROVIDER=openai;    UPSTREAM=api.openai.com;    KEY_ENV=OPENAI_API_KEY ;;
  claude*|anthropic/*)    PROVIDER=anthropic; UPSTREAM=api.anthropic.com; KEY_ENV=ANTHROPIC_API_KEY ;;
  *) echo "ERROR: unknown provider for model '$MODEL' (set PROVIDER/UPSTREAM manually)"; exit 1 ;;
esac

# --- preflight ---------------------------------------------------------------
docker info >/dev/null 2>&1 || { echo "ERROR: docker daemon not running (sudo systemctl start docker)"; exit 1; }
[ -n "${!KEY_ENV:-}" ] || { echo "ERROR: export $KEY_ENV before running"; exit 1; }
command -v mini-extra >/dev/null 2>&1 || { echo "ERROR: mini-swe-agent not installed (uv tool install mini-swe-agent)"; exit 1; }

# Resolve the package dir by globbing the install path — importing minisweagent
# prints a startup banner that would pollute a captured path.
MINI_PKG="$(ls -d /home/landow/.local/share/uv/tools/mini-swe-agent/lib/python*/site-packages/minisweagent 2>/dev/null | head -1)"
BASE_CFG="$MINI_PKG/config/benchmarks/swebench.yaml"
[ -s "$BASE_CFG" ] || { echo "ERROR: base swebench config not found at $BASE_CFG"; exit 1; }

CAPTURE_DIR="$SP/captures-mini-$INSTANCE"
rm -rf "$CAPTURE_DIR"; mkdir -p "$CAPTURE_DIR"

# --- capture proxy (plaintext in, HTTPS out, tees bodies) --------------------
echo ">> starting capture proxy (:$CAP_PORT -> https://$UPSTREAM), captures: $CAPTURE_DIR"
CAPTURE_DIR="$CAPTURE_DIR" python3 "$REPO/examples/compression/capture_proxy.py" \
  "$CAP_PORT" "$UPSTREAM" "$PROVIDER" >"$SP/capture-mini.log" 2>&1 & CAPPID=$!
trap 'kill $CAPPID 2>/dev/null' EXIT
for i in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$CAP_PORT/" && break || sleep 0.1; done
echo ">> capture proxy up (pid $CAPPID)"

# --- config override: capture FULL tool output ------------------------------
# Raise mini's 10k observation truncation so the real large logs reach the wire
# (compression's job is to shrink these intelligently, not blind-clip them).
HALF=$(( OUTPUT_KEEP / 2 ))
OVR="$SP/mini-capture-override.yaml"
cat >"$OVR" <<YAML
model:
  observation_template: |
    {% if output.exception_info -%}
    <exception>{{output.exception_info}}</exception>
    {% endif -%}
    <returncode>{{output.returncode}}</returncode>
    {% if output.output | length < $OUTPUT_KEEP -%}
    <output>
    {{ output.output -}}
    </output>
    {%- else -%}
    <output_head>
    {{ output.output[:$HALF] }}
    </output_head>
    <elided_chars>{{ output.output | length - $OUTPUT_KEEP }} characters elided</elided_chars>
    <output_tail>
    {{ output.output[-$HALF:] }}
    </output_tail>
    {%- endif -%}
YAML

# --- run one SWE-bench instance, LLM calls teed through the proxy ------------
TRAJ="$SP/mini-traj-$INSTANCE.json"
echo ">> mini-extra swebench-single: instance=$INSTANCE subset=$SUBSET/$SPLIT model=$MODEL cost_limit=\$$COST_LIMIT output_keep=$OUTPUT_KEEP"
mini-extra swebench-single \
  -i "$INSTANCE" --subset "$SUBSET" --split "$SPLIT" \
  -m "$MODEL" \
  -c "$BASE_CFG" -c "$OVR" \
  -c "model.model_kwargs.api_base=http://127.0.0.1:$CAP_PORT/v1" \
  -c "agent.cost_limit=$COST_LIMIT" \
  -o "$TRAJ" \
  --yolo || echo ">> (run ended non-zero — likely hit cost_limit or task finished; captures are still valid)"

# --- summary -----------------------------------------------------------------
echo ""
N=$(ls -1 "$CAPTURE_DIR"/*.req.txt 2>/dev/null | wc -l | tr -d ' ')
echo ">> captured $N request bodies in $CAPTURE_DIR"
if [ "$N" -gt 0 ]; then
  echo ">> largest captured request bodies:"
  ls -lS "$CAPTURE_DIR"/*.req.txt 2>/dev/null | head -5 | awk '{printf "   %10d  %s\n", $5, $NF}'
fi
echo ">> trajectory: $TRAJ"
