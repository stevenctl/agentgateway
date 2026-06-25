#!/usr/bin/env bash
# One shared agentgateway (compression on/off) + N parallel mini-swe-agent runs on
# the same SWE-bench instance. Gives multiple live trajectories with replication —
# some will reach the grep/diff/test turns where compression fires — so we can read
# accuracy + turn-inflation instead of a single noisy n=1.
#
# Only ONE gateway can run at a time (fixed mgmt ports), so the agents share it and
# hit it concurrently. Use COMPRESS=on vs COMPRESS=off (gateway passthrough) for A/B.
set -euo pipefail

REPO="/home/landow/solo/agentgateway"
SP="/tmp/claude-1000/-home-landow-solo-agentgateway/bd6db166-aacd-4026-8a39-17bf46bc916f/scratchpad"
export PATH="$HOME/.local/bin:$PATH"
GW="$REPO/target/debug/agentgateway"

INSTANCE="${INSTANCE:-pydata__xarray-4356}"
MODEL="${MODEL:-gpt-5}"
SUBSET="${SUBSET:-verified}"; SPLIT="${SPLIT:-test}"
N="${N:-3}"
COST_LIMIT="${COST_LIMIT:-2}"
OUTPUT_KEEP="${OUTPUT_KEEP:-100000}"
COMPRESS="${COMPRESS:-on}"
HEADROOM=true; GCF=false
[ "$COMPRESS" = off ] && HEADROOM=false
KEY_FILE="${KEY_FILE:-$SP/openai.key}"

docker info >/dev/null 2>&1 || { echo "ERROR: docker not running"; exit 1; }
[ -s "$KEY_FILE" ] || { echo "ERROR: gateway needs key at $KEY_FILE"; exit 1; }
MINI_PKG="$(ls -d /home/landow/.local/share/uv/tools/mini-swe-agent/lib/python*/site-packages/minisweagent 2>/dev/null | head -1)"
BASE_CFG="$MINI_PKG/config/benchmarks/swebench.yaml"

# kill any stale gateway holding mgmt ports
pkill -f "target/debug/agentgateway" 2>/dev/null || true
sleep 1

CFG="$SP/gw-parallel.yaml"
cat >"$CFG" <<YAML
llm:
  port: 3000
  policies:
    compression: { headroom: $HEADROOM, gcf: $GCF, simulate: false }
  models:
  - name: $MODEL
    provider: openai
    params:
      model: $MODEL
      apiKey: { file: $KEY_FILE }
YAML
echo ">> starting shared gateway (compress=$COMPRESS)"
RUST_LOG="info,agentgateway::llm::ctxedit=debug" LOCAL_XDS_PATH="$CFG" "$GW" \
  >"$SP/gw-parallel-$COMPRESS.log" 2>&1 & GWPID=$!
trap 'kill $GWPID 2>/dev/null' EXIT
for i in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:3000/" && break || sleep 0.2; done
echo ">> gateway up (pid $GWPID)"

HALF=$(( OUTPUT_KEEP / 2 ))
OVR="$SP/mini-parallel-override.yaml"
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

echo ">> launching $N parallel mini runs (compress=$COMPRESS, cost_limit=\$$COST_LIMIT each)"
pids=()
for i in $(seq 1 "$N"); do
  OPENAI_API_KEY="placeholder-gateway-injects-real-key" \
  mini-extra swebench-single \
    -i "$INSTANCE" --subset "$SUBSET" --split "$SPLIT" -m "$MODEL" \
    -c "$BASE_CFG" -c "$OVR" \
    -c "model.model_kwargs.api_base=http://127.0.0.1:3000/v1" \
    -c "agent.cost_limit=$COST_LIMIT" \
    -o "$SP/par-$COMPRESS-$i.json" \
    --yolo >"$SP/par-$COMPRESS-$i.log" 2>&1 &
  pids+=($!)
done
echo ">> waiting for $N runs (pids: ${pids[*]})"
for p in "${pids[@]}"; do wait "$p" || true; done

echo ""
echo "================= RESULTS (compress=$COMPRESS, N=$N) ================="
for i in $(seq 1 "$N"); do
  log="$SP/par-$COMPRESS-$i.log"
  laststep=$(grep -oE "step [0-9]+, \\\$[0-9.]+" "$log" 2>/dev/null | tail -1)
  submitted=$(grep -c "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT" "$log" 2>/dev/null || echo 0)
  echo "  run $i: ${laststep:-<no steps>}  submitted=$submitted"
done
echo ">> gateway compression (shared across all $N runs):"
grep -c "ctxedit compressed" "$SP/gw-parallel-$COMPRESS.log" 2>/dev/null | sed 's/^/   total fragments compressed: /'
awk '/ctxedit walk/ {r++; for(i=1;i<=NF;i++){if($i~/^compressed=/){split($i,a,"=");c+=a[2]}}} END{printf "   walk lines=%d, sum compressed=%d\n",r,c}' "$SP/gw-parallel-$COMPRESS.log" 2>/dev/null
echo ">> per-run trajectories: $SP/par-$COMPRESS-*.json"
