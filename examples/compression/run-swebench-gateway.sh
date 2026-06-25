#!/usr/bin/env bash
# Run mini-swe-agent on a SWE-bench instance THROUGH agentgateway with compression
# ON, to measure the end-to-end effect on accuracy + turn-inflation + total tokens
# vs the OFF baseline (mini straight to the provider).
#
# Path: mini-swe-agent (host) --litellm--> agentgateway:3000 (compresses) --> provider
# The gateway injects the real key (from the file); mini sends a placeholder.
# Same OUTPUT_KEEP as the OFF capture so the ONLY difference is gateway compression.
#
# Usage:
#   OPENAI_API_KEY ignored (gateway uses keyfile). Run in your terminal:
#   ./run-swebench-gateway.sh                       # headroom on, xarray-4356
#   HEADROOM=false GCF=true ./run-swebench-gateway.sh
#   COMPRESS=off ./run-swebench-gateway.sh          # gateway in path but no compression (A/B control)
set -euo pipefail

REPO="/home/landow/solo/agentgateway"
SP="/tmp/claude-1000/-home-landow-solo-agentgateway/bd6db166-aacd-4026-8a39-17bf46bc916f/scratchpad"
export PATH="$HOME/.local/bin:$PATH"
GW="$REPO/target/debug/agentgateway"

INSTANCE="${INSTANCE:-pydata__xarray-4356}"
MODEL="${MODEL:-gpt-5}"
SUBSET="${SUBSET:-verified}"
SPLIT="${SPLIT:-test}"
COST_LIMIT="${COST_LIMIT:-3}"
OUTPUT_KEEP="${OUTPUT_KEEP:-100000}"
COMPRESS="${COMPRESS:-on}"          # on => headroom; off => gateway passthrough (control)
HEADROOM="${HEADROOM:-true}"
GCF="${GCF:-false}"
[ "$COMPRESS" = off ] && { HEADROOM=false; GCF=false; }
KEY_FILE="${KEY_FILE:-$SP/openai.key}"

docker info >/dev/null 2>&1 || { echo "ERROR: docker not running"; exit 1; }
[ -s "$KEY_FILE" ] || { echo "ERROR: gateway needs the OpenAI key at $KEY_FILE"; exit 1; }
command -v mini-extra >/dev/null 2>&1 || { echo "ERROR: mini-swe-agent not installed"; exit 1; }
MINI_PKG="$(ls -d /home/landow/.local/share/uv/tools/mini-swe-agent/lib/python*/site-packages/minisweagent 2>/dev/null | head -1)"
BASE_CFG="$MINI_PKG/config/benchmarks/swebench.yaml"

# --- gateway (compression in the request path) -------------------------------
CFG="$SP/gw-swebench.yaml"
cat >"$CFG" <<YAML
llm:
  port: 3000
  policies:
    compression:
      headroom: $HEADROOM
      gcf: $GCF
      simulate: false
  models:
  - name: $MODEL
    provider: openai
    params:
      model: $MODEL
      apiKey:
        file: $KEY_FILE
YAML
echo ">> starting gateway (compress=$COMPRESS headroom=$HEADROOM gcf=$GCF) model=$MODEL"
RUST_LOG="info,agentgateway::llm::ctxedit=debug" LOCAL_XDS_PATH="$CFG" "$GW" \
  >"$SP/gw-swebench.log" 2>&1 & GWPID=$!
trap 'kill $GWPID 2>/dev/null' EXIT
for i in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:3000/" && break || sleep 0.2; done
echo ">> gateway up (pid $GWPID), log: $SP/gw-swebench.log"

# --- mini config: full tool output (match OFF baseline) ----------------------
HALF=$(( OUTPUT_KEEP / 2 ))
OVR="$SP/mini-gw-override.yaml"
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

# --- run mini through the gateway --------------------------------------------
TRAJ="$SP/mini-gw-traj-$INSTANCE-$COMPRESS.json"
echo ">> mini through gateway: instance=$INSTANCE model=$MODEL compress=$COMPRESS cost_limit=\$$COST_LIMIT"
OPENAI_API_KEY="placeholder-gateway-injects-real-key" \
mini-extra swebench-single \
  -i "$INSTANCE" --subset "$SUBSET" --split "$SPLIT" \
  -m "$MODEL" \
  -c "$BASE_CFG" -c "$OVR" \
  -c "model.model_kwargs.api_base=http://127.0.0.1:3000/v1" \
  -c "agent.cost_limit=$COST_LIMIT" \
  -o "$TRAJ" \
  --yolo || echo ">> (run ended non-zero — cost_limit or finished)"

# --- report: turns / cost / compression --------------------------------------
echo ""
echo "================= RESULT (compress=$COMPRESS) ================="
echo ">> agent steps/cost (last reported):"
grep -oE "step [0-9]+, \\\$[0-9.]+" "$SP/gw-swebench.log" 2>/dev/null | tail -1 | sed 's/^/   /'
echo ">> did it submit a patch?"
grep -c "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT" "$SP/gw-swebench.log" 2>/dev/null | sed 's/^/   submit markers: /'
echo ">> gateway walk activity (compression actually applied):"
awk '/ctxedit walk/ {reqs++; for(i=1;i<=NF;i++){if($i~/^walked=/){split($i,a,"=");w+=a[2]} if($i~/^eligible=/){split($i,a,"=");e+=a[2]} if($i~/^compressed=/){split($i,a,"=");c+=a[2]}}} END{printf "   requests=%d fragments_walked=%d eligible>=512B=%d compressed=%d\n",reqs,w,e,c}' "$SP/gw-swebench.log" 2>/dev/null
echo ">> trajectory: $TRAJ"
echo ">> compare to OFF baseline: 43 steps, \$0.50, completed (mini-traj-$INSTANCE.json)"
