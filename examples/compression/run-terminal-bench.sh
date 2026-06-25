#!/usr/bin/env bash
# Drive terminal-bench (Harbor) with a CLI agent, optionally routed through
# agentgateway so the context compressor runs on the way upstream.
#
# Usage:
#   ./run-terminal-bench.sh sim 1      # SIMULATE: real baseline cost + analyze-only
#                                      #   compression/cache report (no rewrite). Best
#                                      #   first run — answers "would it fire / bust cache"
#                                      #   without a live ON run.
#   HEADROOM=false GCF=true ./run-terminal-bench.sh sim 1  # simulate GCF instead of headroom
#   ./run-terminal-bench.sh off 1      # compression OFF baseline, 1 task
#   ./run-terminal-bench.sh on  1      # compression ON (actually rewrites), 1 task
#   ./run-terminal-bench.sh on  10     # compression ON, 10 tasks
#   AGENT=codex MODEL=gpt-5 ./run-terminal-bench.sh off 1
#                                      # Codex direct-to-OpenAI baseline, no gateway
#   CAPTURE=true ./run-terminal-bench.sh off 1
#                                      # record full upstream req/resp wire bodies to
#                                      #   $SP/captures-<agent>-<mode>/. Works for any
#                                      #   mode; slots capture_proxy on the gateway's
#                                      #   upstream leg (forces the gateway on, even
#                                      #   for codex/off). CAP_PORT overrides the port.
#
# Prereqs (do these once):
#   1. Docker daemon running:        sudo systemctl start docker
#   2. Claude/gateway keyfile:       echo -n "sk-ant-..." > "$SP/anthropic.key"
#      Codex direct keyfile/env:     echo -n "sk-..." > "$SP/openai.key"
#                                    or export OPENAI_API_KEY=sk-...
set -euo pipefail

MODE="${1:-sim}"         # sim | off | on
N_TASKS="${2:-1}"        # how many tasks
AGENT="${AGENT:-claude-code}" # claude-code | codex
DATASET="terminal-bench/terminal-bench-2"
REPO="/home/landow/solo/agentgateway"
GW="$REPO/target/debug/agentgateway"
SP="/tmp/claude-1000/-home-landow-solo-agentgateway/bd6db166-aacd-4026-8a39-17bf46bc916f/scratchpad"
export PATH="$HOME/.local/bin:$PATH"

case "$AGENT" in
  claude-code)
    MODEL="${MODEL:-claude-sonnet-4-6}" # Sonnet 4.0 was retired 2026-06-15; 4.6 is the stand-in
    PROVIDER="anthropic"
    KEY_FILE="${KEY_FILE:-$SP/anthropic.key}"
    KEY_ENV="ANTHROPIC_API_KEY"
    BASE_URL_ENV="ANTHROPIC_BASE_URL"
    ;;
  codex)
    MODEL="${MODEL:-gpt-5}"
    PROVIDER="openai"
    KEY_FILE="${KEY_FILE:-$SP/openai.key}"
    KEY_ENV="OPENAI_API_KEY"
    BASE_URL_ENV="OPENAI_BASE_URL"
    ;;
  *) echo "ERROR: AGENT must be claude-code or codex"; exit 1 ;;
esac

CAPTURE="${CAPTURE:-false}"
CAP_PORT="${CAP_PORT:-8788}"

USE_GATEWAY="${USE_GATEWAY:-true}"
if [ "$AGENT" = codex ] && [ "$MODE" = off ] && [ "${CODEX_DIRECT_OFF:-true}" = true ]; then
  USE_GATEWAY=false
fi
# Capture records the gateway's upstream leg, so it needs a host-side gateway hop
# to attach to. Force it on (overrides codex direct-to-OpenAI for off).
if [ "$CAPTURE" = true ] && [ "$USE_GATEWAY" = false ]; then
  echo ">> CAPTURE=true: forcing gateway on so capture_proxy can record the upstream leg"
  USE_GATEWAY=true
fi

if [ "$USE_GATEWAY" = false ] && [ "$MODE" != off ]; then
  echo "ERROR: USE_GATEWAY=false is only supported for mode=off"
  exit 1
fi

# --- preflight ----------------------------------------------------------------
docker info >/dev/null 2>&1 || { echo "ERROR: docker daemon not running (sudo systemctl start docker)"; exit 1; }
if [ "$USE_GATEWAY" = true ]; then
  [ -s "$KEY_FILE" ] || { echo "ERROR: write your $PROVIDER key to $KEY_FILE first"; exit 1; }
elif [ "$AGENT" = codex ]; then
  if [ -s "$KEY_FILE" ]; then
    export OPENAI_API_KEY="$(<"$KEY_FILE")"
  elif [ -z "${OPENAI_API_KEY:-}" ] && [ -z "${CODEX_AUTH_JSON_PATH:-}" ] && [ -z "${CODEX_FORCE_AUTH_JSON:-}" ]; then
    echo "ERROR: set OPENAI_API_KEY, CODEX_AUTH_JSON_PATH, CODEX_FORCE_AUTH_JSON, or write your OpenAI key to $KEY_FILE"
    exit 1
  fi
fi

# --- gateway config: sim | off | on ------------------------------------------
case "$MODE" in
  sim) HEADROOM="${HEADROOM:-true}"; SIMULATE=true  ;;   # true baseline cost + analyze-only report
  off) HEADROOM="${HEADROOM:-false}"; SIMULATE=false ;;   # plain uncompressed baseline
  on)  HEADROOM="${HEADROOM:-true}";  SIMULATE=false ;;   # actually rewrites requests
  *) echo "ERROR: mode must be sim|off|on"; exit 1 ;;
esac
GCF="${GCF:-false}"

# --- capture proxy: record the gateway's upstream leg -------------------------
# gateway:3000 -> 127.0.0.1:$CAP_PORT (capture_proxy, plaintext in / HTTPS out)
# -> real provider. Captures = exactly what hits the model (post-compression for
# on/sim, true baseline for off). Pointing the gateway at an http:// baseUrl makes
# the gateway->proxy hop plaintext; the proxy re-establishes TLS to the provider.
BASEURL_LINE=""
if [ "$CAPTURE" = true ]; then
  case "$PROVIDER" in
    anthropic) UPSTREAM_HOST="api.anthropic.com" ;;
    openai)    UPSTREAM_HOST="api.openai.com" ;;
    *) echo "ERROR: CAPTURE not supported for provider $PROVIDER"; exit 1 ;;
  esac
  CAPTURE_DIR="$SP/captures-$AGENT-$MODE"
  rm -rf "$CAPTURE_DIR"; mkdir -p "$CAPTURE_DIR"
  echo ">> starting capture proxy (:$CAP_PORT -> https://$UPSTREAM_HOST), captures: $CAPTURE_DIR"
  CAPTURE_DIR="$CAPTURE_DIR" python3 "$REPO/examples/compression/capture_proxy.py" \
    "$CAP_PORT" "$UPSTREAM_HOST" "$PROVIDER" >"$SP/capture-$MODE.log" 2>&1 & CAPPID=$!
  trap 'kill $CAPPID 2>/dev/null' EXIT
  for i in $(seq 1 50); do
    curl -s -o /dev/null "http://127.0.0.1:$CAP_PORT/" && break || sleep 0.1
  done
  BASEURL_LINE="      baseUrl: http://127.0.0.1:$CAP_PORT"
fi

CFG="$SP/gw-live-$MODE.yaml"
if [ "$USE_GATEWAY" = true ]; then
  cat >"$CFG" <<YAML
llm:
  port: 3000
  policies:
    compression:
      headroom: $HEADROOM
      gcf: $GCF
      simulate: $SIMULATE
  models:
  - name: $MODEL
    provider: $PROVIDER
    params:
      model: $MODEL
      apiKey:
        file: $KEY_FILE
$BASEURL_LINE
YAML

  # --- start gateway ------------------------------------------------------------
  echo ">> starting gateway (agent=$AGENT, provider=$PROVIDER, compression=$MODE) ..."
  RUST_LOG="${RUST_LOG:-info,agentgateway::llm::ctxedit=debug}" \
    LOCAL_XDS_PATH="$CFG" "$GW" >"$SP/gw-live-$MODE.log" 2>&1 & GWPID=$!
  trap 'kill $GWPID ${CAPPID:-} 2>/dev/null' EXIT
  for i in $(seq 1 50); do
    curl -s -o /dev/null "http://127.0.0.1:3000/" && break || sleep 0.2
  done
  echo ">> gateway up (pid $GWPID), log: $SP/gw-live-$MODE.log"
fi

# --- run harbor ---------------------------------------------------------------
# CLI agents forward provider base URLs into the container; the host-gateway
# overlay makes host.docker.internal resolvable there. When using the gateway,
# the API key is a placeholder because the gateway injects the real key.
HARBOR_EXTRA=()
if [ "$USE_GATEWAY" = true ]; then
  export "$KEY_ENV"="placeholder-gateway-injects-real-key"
  export "$BASE_URL_ENV"="http://host.docker.internal:3000"
  HARBOR_EXTRA+=(--extra-docker-compose "$REPO/examples/compression/harbor-host-gateway.yaml")
fi

JOBS_DIR="$SP/jobs-$AGENT-$MODE"
# Optional hard cost guard per task: MAX_BUDGET_USD=2 ./run-terminal-bench.sh sim 1
BUDGET_ARGS=()
if [ "$AGENT" = claude-code ]; then
  [ -n "${MAX_BUDGET_USD:-}" ] && BUDGET_ARGS+=(--ak "max_budget_usd=$MAX_BUDGET_USD")
  [ -n "${MAX_TURNS:-}" ]      && BUDGET_ARGS+=(--ak "max_turns=$MAX_TURNS")
elif [ -n "${MAX_BUDGET_USD:-}${MAX_TURNS:-}" ]; then
  echo "ERROR: MAX_BUDGET_USD/MAX_TURNS are claude-code-only in Harbor; unset them for AGENT=codex"
  exit 1
fi
# Cherry-pick a specific task with TASK=<name> (else run up to N_TASKS).
# -t wants a fully-qualified org/name ref; prepend the dataset org if omitted.
# e.g. TASK=log-summary-date-ranges ./run-terminal-bench.sh sim 1
if [ -n "${TASK:-}" ]; then
  case "$TASK" in */*) TASK_REF="$TASK" ;; *) TASK_REF="terminal-bench/$TASK" ;; esac
  SELECT_ARGS=(-t "$TASK_REF")
else
  SELECT_ARGS=(-l "$N_TASKS")
fi
echo ">> harbor run: $DATASET, agent=$AGENT, model=$MODEL, mode=$MODE, gateway=$USE_GATEWAY${TASK:+, task=$TASK}${MAX_BUDGET_USD:+, budget=\$$MAX_BUDGET_USD}"
harbor run \
  -d "$DATASET" \
  -a "$AGENT" \
  -m "$MODEL" \
  "${SELECT_ARGS[@]}" \
  -n 1 \
  -o "$JOBS_DIR" \
  "${BUDGET_ARGS[@]}" \
  "${HARBOR_EXTRA[@]}"

if [ "$USE_GATEWAY" = true ]; then
  echo ""
  echo ">> gateway compression activity (fragments compressed this run):"
  { grep -c "ctxedit compressed" "$SP/gw-live-$MODE.log" 2>/dev/null || true; } | sed 's/^/   fragments compressed: /'
  grep -i "ctxedit compressed" "$SP/gw-live-$MODE.log" 2>/dev/null | tail -5 || true
  # Per-request walk accounting (one `ctxedit walk` line per request). Proves the
  # walker ran and shows eligibility even when 0 fragments compressed — i.e.
  # distinguishes "nothing compressible" from "walker never reached".
  echo ">> walker activity (did the compressor get reached, and what did it see?):"
  awk '
    /ctxedit walk/ {
      reqs++
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^walked=/)     { split($i, a, "="); w += a[2] }
        if ($i ~ /^eligible=/)   { split($i, a, "="); e += a[2] }
        if ($i ~ /^compressed=/) { split($i, a, "="); c += a[2] }
      }
    }
    END {
      printf "   requests=%d  fragments_walked=%d  eligible>=512B=%d  compressed=%d\n", reqs, w, e, c
    }
  ' "$SP/gw-live-$MODE.log" 2>/dev/null || true
fi

if [ "$CAPTURE" = true ]; then
  echo ""
  echo ">> captured upstream wire bodies (post-compression req/resp pairs):"
  CAPTURE_DIR="$SP/captures-$AGENT-$MODE"
  echo "   dir: $CAPTURE_DIR"
  echo "   pairs: $(ls "$CAPTURE_DIR"/*.req.txt 2>/dev/null | wc -l | tr -d ' ')"
  ls -lh "$CAPTURE_DIR" 2>/dev/null | tail -6 || true
fi

echo ""
echo ">> billed-token metrics (from Harbor $AGENT trajectories):"
python3 "$REPO/examples/compression/aggregate_metrics.py" "$JOBS_DIR" "$MODE"

if [ "$USE_GATEWAY" = true ] && [ "$MODE" = sim ]; then
  echo ""
  echo ">> SIMULATION report (would compression fire? would it bust the cache?):"
  python3 "$REPO/examples/compression/summarize_simulation.py" "$SP/gw-live-sim.log"
fi
