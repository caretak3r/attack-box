# Synthetic attack checks

Use this check before public ingress opens. It sends ten fixed requests to one loopback listener. It does not execute commands, scan ports, use real credentials, follow redirects, or contact a public target.

Source: `/Users/rohit/attack-box/cmd/attackbox-scenarios/main.go`.
Tests: `/Users/rohit/attack-box/cmd/attackbox-scenarios/main_test.go`.

## Boundaries

The default target is `https://127.0.0.1:8443`. Only HTTP or HTTPS origins with loopback IP literals are accepted. DNS names, credentials in URLs, query strings, fragments, and base paths are rejected. The client ignores proxy environment variables. TLS verification is on by default. `-self-signed` disables certificate verification for this loopback client only. HTTP is available for a local test listener.

Requests run in order. Each request has a 20-second deadline. The full run has a 120-second deadline. The largest request is 1,048,577 bytes. Each response is limited to 2 MiB plus one detection byte. Output contains hashes and lengths, not response bodies. The output file must not exist; it is created with mode `0600`.

The check targets the OpenAI persona and model `qwen3:8b`. Other personas can omit the expected response ID header. A changed model list or request body limit requires a separate reviewed fixture change. Do not treat a failed check as a successful attack.

## Cases and expected evidence

| Case | Expected response | Evidence to check |
| --- | --- | --- |
| `models` | 200; nonempty model list | Request metadata and full JSON response |
| `standard-json` | 200; nonempty choices | Request and response body hashes |
| `prompt-injection` | 200; nonempty choices | Instruction override text and invented secret `TEST_ONLY_NEVER_VALID_42` |
| `tool-request` | 200; nonempty choices | Requested shell command preserved as text; no command execution |
| `fake-credential` | 200; nonempty choices | Invalid token in raw request metadata; credential fingerprint in ordinary logs |
| `traversal-path` | 404; JSON error | Exact encoded URI in raw metadata; normalized path can differ in ordinary logs |
| `unknown-mcp` | 404; JSON error | JSON-RPC `tools/list` request on an unknown route |
| `malformed-json` | 400; JSON error | Exact incomplete JSON body |
| `sse` | 200; SSE content type and final `[DONE]` | Complete response segments, final manifest, exact response hash |
| `oversized` | 413; JSON error | Exactly 1 MiB captured request prefix; incomplete manifest with `body_limit` reason |

The oversized case intentionally cannot produce a complete request-body reconstruction. The client submits 1 MiB plus one byte; the service captures only the allowed 1 MiB prefix. The manifest must state this limit. A complete manifest for that request is a failure.

Each case uses a distinct user agent, `attackbox-synthetic-RUN_ID-SCENARIO`, plus `X-Attackbox-Research-Run` and `X-Attackbox-Research-Scenario` headers. These labels are untrusted input. They do not authenticate traffic, exclude it from alerts, or prove its origin. Each case uses a separate responder session to avoid repeated-run probe state changing the expected response.

## Local candidate gate

Run from `/Users/rohit/attack-box`:

```sh
cd /Users/rohit/attack-box
GOTOOLCHAIN=go1.25.11 go test -race -count=1 -v ./cmd/attackbox-scenarios
GOTOOLCHAIN=go1.25.11 go vet ./cmd/attackbox-scenarios
```

The integration test starts the real HTTP handler with raw evidence capture enabled. It invokes the full CLI, checks all ten responses, then reconstructs each request and response from captured segments. It verifies segment order, offsets, hashes, byte totals, completion flags, response IDs, encoded URI, research headers, and the fake credential. It also verifies that ordinary events contain the readable research marker. Separate tests check destination restrictions, redirects, response limits, self-signed TLS, and exclusive output creation.

To retain local test evidence, use a new absolute directory:

```sh
cd /Users/rohit/attack-box
ATTACKBOX_SCENARIO_TEST_REPORT_DIR=/tmp/attackbox-scenario-local-001 GOTOOLCHAIN=go1.25.11 go test -race -count=1 -v ./cmd/attackbox-scenarios
```

The test writes `/tmp/attackbox-scenario-local-001/results.json` and `/tmp/attackbox-scenario-local-001/local-events.json`. These files prove local handler capture only. They are not New Relic delivery receipts. `/tmp/attackbox-scenario-local-001/local-events.json` uses the internal event schema; do not pass it to the New Relic export reconstruction command.

## Closed-ingress host check

First confirm that the reviewed raw-evidence service and shipper are installed and healthy. The earlier `c44e2cb` host build does not provide the new raw-evidence capture. A 200 response from that build does not establish raw logging readiness.

Build a Linux binary from the reviewed candidate, then copy it to a temporary path on the host through the existing SSH access. Keep public ingress closed. Run it on that host:

```sh
/tmp/attackbox-scenarios -target https://127.0.0.1:8443 -self-signed -run-id preflight-001 -output /tmp/attackbox-preflight-001.jsonl
```

The default endpoint passes through the local proxy. Do not expose a new port for this check. Keep `/tmp/attackbox-preflight-001.jsonl` as the response manifest. A second run needs a new file and run ID. Remove the temporary binary after the check.

Exit 0 means all response checks passed. A timeout, wrong status, missing server ID, invalid response envelope, incomplete SSE terminator, or response size limit returns exit 1. Configuration errors return exit 2. The command always writes `logging_verified: false`: only independent evidence checks can establish logging and delivery.

`response_id` is the complete `X-Request-Id` header. `log_request_id` is the first 16 hexadecimal characters after `req_`, matching the server log schema. Compare the response manifest with logs by this server-assigned ID. Do not use the research label as a trusted correlation key.

## New Relic evidence gate

Select the correct New Relic account and sensor. Find ordinary events for the run:

```sql
FROM Log SELECT count(*), uniqueCount(request_id)
WHERE `service.name` = 'attackbox'
  AND sensor_id = 'REPLACE_SENSOR_ID'
  AND user_agent LIKE 'attackbox-synthetic-preflight-001-%'
FACET stream SINCE 15 minutes ago LIMIT MAX
```

Expect ten distinct request IDs across the full result. Transcripts and probe records apply only to inference cases; do not expect every stream for every request. Use the IDs in `/tmp/attackbox-preflight-001.jsonl` to check all ten, including errors and the oversized request. Substitute one ID below:

```sql
FROM Log SELECT *
WHERE `service.name` = 'attackbox'
  AND sensor_id = 'REPLACE_SENSOR_ID'
  AND request_id = 'REPLACE_LOG_REQUEST_ID'
SINCE 15 minutes ago LIMIT MAX
```

Export all matching rows for that request. Check export row limits and pagination. A partial export cannot prove complete delivery. Store the result as `/tmp/attackbox-nr-request.json`. Reconstruct the complete request and response with the existing verifier:

```sh
cd /Users/rohit/attack-box
go run ./cmd/attackbox-evidence -input /tmp/attackbox-nr-request.json -request-id REPLACE_LOG_REQUEST_ID -kind request_body -output /tmp/attackbox-rebuilt-request.bin
go run ./cmd/attackbox-evidence -input /tmp/attackbox-nr-request.json -request-id REPLACE_LOG_REQUEST_ID -kind response_body -output /tmp/attackbox-rebuilt-response.bin
shasum -a 256 /tmp/attackbox-rebuilt-request.bin /tmp/attackbox-rebuilt-response.bin
wc -c /tmp/attackbox-rebuilt-request.bin /tmp/attackbox-rebuilt-response.bin
```

Use new paths for each request. Match both byte counts and SHA-256 values to the response manifest. For `oversized`, request reconstruction must reject the incomplete capture; inspect its `body_limit` manifest and verify the complete response instead. For `fake-credential`, also reconstruct `request_metadata` and confirm the deliberately invalid Authorization value. The raw header representation uses base64-encoded byte strings.

Record the first time each request is visible in New Relic and the manifest `started_at` time. Their difference gives an observed end-to-end visibility bound, including request duration and query delay. It is not a precise ingest latency metric. Missing events, missing segments, hash errors, and unbounded delay must block public rollout.

If tracing is enabled, check that the same request has a `trace.id` and that its corresponding span is present. Check Infrastructure host metrics and collector freshness separately. These text-only scenarios should not execute a shell or produce real outbound attack traffic; absence of a Falco execution alert or egress block is expected. They do not validate host compromise detection, packet capture, collector outage recovery, or all attack classes.
