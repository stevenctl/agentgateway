#!/usr/bin/env bash
set -euo pipefail

url=http://localhost:3000

jq -cn 'range(100) | {custom_id: tostring, method: "POST", url: "/v1/chat/completions", body: {model: "claude", messages: [{role: "user", content: "Say hello"}], max_tokens: 16}}' > input.jsonl

file=$(curl -fsS "$url/v1/files" -F purpose=batch -F file=@input.jsonl | jq -r .id)
batch=$(curl -fsS "$url/v1/batches" -H 'Content-Type: application/json' \
  -d "{\"input_file_id\":\"$file\",\"endpoint\":\"/v1/chat/completions\",\"completion_window\":\"24h\"}" | jq -r .id)
echo "Submitted $batch"

while true; do
  curl -fsS "$url/v1/batches/$batch" > batch.json
  status=$(jq -r .status batch.json)
  echo "$status"
  case "$status" in
    completed) break ;;
    failed|expired|cancelled) cat batch.json; exit 1 ;;
  esac
  sleep 30
done

curl -fsS "$url/v1/files/$(jq -r .output_file_id batch.json)/content" > output.jsonl
curl -fsS "$url/v1/files/$(jq -r .error_file_id batch.json)/content" > errors.jsonl
echo 'Results saved to output.jsonl and errors.jsonl'
