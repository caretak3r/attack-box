#!/usr/bin/env bash
# Local live-server smoke test. Builds the release binary, starts all three
# personas on loopback with New Relic disabled, and checks each persona and
# its streaming format. It makes no request to any non-loopback host.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
pid=""
cleanup() {
	if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
		kill -TERM "$pid"
		wait "$pid" || true
	fi
	rm -rf "$work"
}
trap cleanup EXIT

openai_port=${SMOKE_OPENAI_PORT:-18080}
vllm_port=${SMOKE_VLLM_PORT:-18000}
ollama_port=${SMOKE_OLLAMA_PORT:-18434}

fail() {
	echo "smoke: FAIL: $*" >&2
	echo "--- service log (last 20 lines) ---" >&2
	tail -n 20 "$work/attackbox.log" >&2 || true
	exit 1
}

echo "smoke: building release binary"
(cd "$root" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -X main.version=smoke' -o "$work/attackbox" ./cmd/attackbox)

ATTACKBOX_NR_DISABLED=true \
	ATTACKBOX_OPENAI_ADDR="127.0.0.1:$openai_port" \
	ATTACKBOX_VLLM_ADDR="127.0.0.1:$vllm_port" \
	ATTACKBOX_OLLAMA_ADDR="127.0.0.1:$ollama_port" \
	ATTACKBOX_HOLD_SILENT=1s ATTACKBOX_IDLE_INTERVAL=200ms ATTACKBOX_MAX_STREAM=5s \
	ATTACKBOX_SHUTDOWN_TIMEOUT=3s \
	"$work/attackbox" >"$work/attackbox.log" 2>&1 &
pid=$!

for _ in $(seq 1 50); do
	if "$work/attackbox" -healthcheck "http://127.0.0.1:$openai_port/health" 2>/dev/null; then
		break
	fi
	sleep 0.1
done
"$work/attackbox" -healthcheck "http://127.0.0.1:$openai_port/health" || fail "openai listener did not become healthy"

c() { curl -sS --max-time 15 --noproxy '*' "$@"; }
json='Content-Type: application/json'
expect() { # name, needle, haystack
	[[ "$3" == *"$2"* ]] || fail "$1: missing '$2' in: ${3:0:300}"
	echo "smoke: ok   $1"
}

o="http://127.0.0.1:$openai_port"
v="http://127.0.0.1:$vllm_port"
l="http://127.0.0.1:$ollama_port"

expect "openai models" '"object":"list"' "$(c "$o/v1/models")"
expect "openai chat json" '"object":"chat.completion"' \
	"$(c -H "$json" -H 'Authorization: Bearer sk-smoke-not-a-real-key' -d '{"model":"qwen3:8b","messages":[{"role":"user","content":"hello"}]}' "$o/v1/chat/completions")"
expect "openai chat sse" 'data: [DONE]' \
	"$(c -N -H "$json" -d '{"model":"qwen3:8b","stream":true,"messages":[{"role":"user","content":"hello"}]}' "$o/v1/chat/completions")"
# Default pacing holds the first byte for the jittered first-token delay.
ttfb=$(c -o /dev/null -w '%{time_starttransfer}' -H "$json" -d '{"model":"qwen3:8b","stream":true,"messages":[{"role":"user","content":"hello"}]}' "$o/v1/chat/completions")
awk -v t="$ttfb" 'BEGIN { exit !(t >= 0.2 && t < 5) }' || fail "openai first byte after ${ttfb}s; want paced 0.2-5s"
echo "smoke: ok   paced first token (${ttfb}s)"
expect "openai responses sse" 'event: response.completed' \
	"$(c -N -H "$json" -H 'Authorization: Bearer sk-smoke-responses-not-a-real-key' -d '{"model":"qwen3:8b","stream":true,"input":"hello"}' "$o/v1/responses")"
expect "openai unknown model" '"code":"model_not_found"' \
	"$(c -H "$json" -d '{"model":"nope","messages":[{"role":"user","content":"hi"}]}' "$o/v1/chat/completions")"
# A genuine reply to the registration gate: the same history plus the field the
# gate asked for, on its own credential so no other request shares the session.
fu='Authorization: Bearer sk-smoke-followup-not-a-real-key'
c -o /dev/null -H "$json" -H "$fu" -d '{"model":"qwen3:8b","messages":[{"role":"user","content":"hello"}]}' "$o/v1/chat/completions"
expect "openai follow-up reply" '"object":"chat.completion"' \
	"$(c -H "$json" -H "$fu" -d '{"model":"qwen3:8b","metadata":{"client_model":"acme/coder-2.1"},"messages":[{"role":"user","content":"hello"}]}' "$o/v1/chat/completions")"
expect "vllm version" '"version"' "$(c "$v/version")"
expect "vllm metrics" 'vllm:' "$(c "$v/metrics")"
expect "vllm openapi" '"/invocations"' "$(c "$v/openapi.json")"
# The third generation request of the anonymous session gets the behavioral
# gate. One of the ten gates answers 429 with Retry-After. A client then sends
# the request again, and so does this step.
vllm_sse() { c -N -H "$json" -d '{"model":"qwen3:8b","stream":true,"prompt":"hello"}' "$v/v1/completions"; }
retried=""
out=$(vllm_sse) || fail "vllm streaming transport failed"
if [[ "$out" == *'"type":"TooManyRequests"'* ]]; then
	echo "smoke: note retry gate answered first; sending the request again"
	retried=1
	sleep 1 # The fixed retry gate advertises Retry-After: 1.
	out=$(vllm_sse) || fail "vllm streaming transport failed"
fi
expect "vllm completions sse" 'data: [DONE]' "$out"
expect "ollama root" 'Ollama is running' "$(c "$l/")"
expect "ollama tags" '"models"' "$(c "$l/api/tags")"
expect "ollama chat ndjson" '"done":true' \
	"$(c -N -d '{"model":"qwen3:8b","messages":[{"role":"user","content":"hello"}]}' "$l/api/chat")"
expect "ollama generate" '"done":true' \
	"$(c -d '{"model":"qwen3:8b","prompt":"hello","stream":false}' "$l/api/generate")"
expect "ollama embed" '"embeddings"' "$(c -d '{"model":"qwen3:8b","input":"hello"}' "$l/api/embed")"
expect "ollama delete no-op" '200' "$(c -o /dev/null -w '%{http_code}' -X DELETE -d '{"model":"qwen3:8b"}' "$l/api/delete")"

kill -TERM "$pid"
wait "$pid" || fail "service exited non-zero after SIGTERM"
pid=""

log=$(cat "$work/attackbox.log")
expect "log stopped event" '"action":"stopped"' "$log"
expect "log edge events" '"stream":"edge"' "$log"
expect "log request capture" '"direction":"request"' "$log"
expect "log response capture" '"direction":"response"' "$log"
expect "log sse response body" 'data: [DONE]' "$(grep '"direction":"response"' "$work/attackbox.log")"
request_summary=$(grep '"direction":"request"' "$work/attackbox.log" | grep '"parse_state":"ok"' | grep '"input_fp_scope":"full"' || true)
expect "log parsed request fingerprint" '"input_fp":"hmac256:' "$request_summary"
for field in capture_state declared_bytes observed_bytes captured_bytes body_utf8_replaced redactions; do
	expect "log request $field" "\"$field\":" "$request_summary"
done
stopped=$(grep '"action":"stopped"' "$work/attackbox.log" || true)
expect "log graceful shutdown" '"forced":false' "$stopped"
expect "log local drops" '"local_dropped_total":0' "$stopped"
for field in persona_version policy_version redaction_version fp_epoch fp_scope; do
	expect "log request $field" "\"$field\":" "$request_summary"
	expect "log stopped $field" "\"$field\":" "$stopped"
done
expect "log probe stream" '"stream":"probe"' "$log"
expect "log probe nonce" '"nonce":"' "$(grep '"stream":"probe"' "$work/attackbox.log")"
expect "log follow-up attribution" '"followup":"register-model"' "$(grep '"stream":"probe"' "$work/attackbox.log")"
# The second attempt above is valid only after the retry gate, not after another 429.
[[ -z "$retried" ]] || expect "log retry gate" '"probe_id":"retry"' "$(grep '"stream":"probe"' "$work/attackbox.log")"
for m in requests probes sessions probe_followups request_bytes response_bytes session_duration_seconds; do
	expect "metric attackbox.$m" "\"name\":\"attackbox.$m\"" "$log"
done
[[ "$log" != *"sk-smoke-not-a-real-key"* ]] || fail "raw bearer token in log"
echo "smoke: ok   bearer token redacted"
echo "smoke: PASS"
