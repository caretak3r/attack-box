# Telemetry security review — d5a7316

Scope: `internal/telemetry` and the telemetry-facing responder boundaries at commit `d5a7316dd2eb0fcb679af78fa00a36d211d1c914`, compared with `implementation_plan.md` and `research/new-relic.md`. HTTP/deployment findings are intentionally excluded. This was a read-only source review; no build or test commands were run.

## Findings

### 1. High — Common credential forms in request bodies survive the only text scrubber

**Evidence:** `internal/telemetry/redact.go:34-38` and `internal/telemetry/redact.go:138-154` recognize only Bearer tokens of at least eight characters, `sk-` keys of at least sixteen trailing characters, and line-oriented `Cookie:`/`Set-Cookie:` values. Ordinary forms such as `{"password":"hunter2"}`, `{"access_token":"..."}`, `{"api_key":"..."}`, `Basic dXNlcjpwYXNz`, a short `Bearer abc`, and JSON-shaped cookie fields do not match and are returned unchanged. The comment at `redact.go:130-137` expressly concedes that other shapes pass through. There is no backstop in either `internal/telemetry/newrelic.go:167-187` or `internal/telemetry/sink.go:105-113`; both accept the resulting body for delivery.

This violates the no-real-operator-secrets rule (`implementation_plan.md:31`). A client that includes a real password, access token, or non-OpenAI API key in a captured prompt can have that value retained in local JSON logs and sent to New Relic. This needs structured-field scrubbing plus broader secret handling, not reliance on clients obeying the request not to submit credentials.

### 2. Medium — Header sanitization preserves credential-bearing Referers and unrecognized authorization fields

**Evidence:** the allow/deny logic at `internal/telemetry/redact.go:22-36` has no match for names such as `X-Authorization`, `Authentication`, `X-Auth`, or `X-Credential`. They fall through to the raw-value branch at `redact.go:96-117`. The same branch also preserves up to 512 runes of `Referer`; a URL such as `https://example.test/callback?access_token=...` is therefore considered log-safe without its query being sanitized.

The output is explicitly intended to be the log-safe header map, so these values propagate as ordinary event attributes. This is contrary to the requirement to retain only keyed HMAC fingerprints for `Authorization` “and similar credentials” (`implementation_plan.md:126`) and to avoid real operator secrets (`implementation_plan.md:31`). Credential classification must cover aliases/suffixes, and URL-valued informational headers need userinfo/query credential scrubbing.

### 3. Medium — Responder declarations retain and return raw credentials

**Evidence:** `internal/responder/responder.go:135-141` redacts only email-shaped text and truncates to 256 bytes. `declare` then applies that function to arbitrary `metadata.client`, `status`, `operator`/`operator_alias`, `client_model`, and OpenAI `user` values at `responder.go:145-179`. For example, `metadata.client={"name":"x","token":"raw-secret"}` is stringified and retained with `raw-secret` intact; a bearer/API key in `user` is likewise intact. These values are returned in telemetry-facing `Decision.Declarations` (`responder.go:54-61`, `responder.go:82`) and may also persist in `Session.Declarations` (`internal/responder/session.go:68`). The 32-declaration session cap does not sanitize the per-request `Decision` output.

Excluding only the exact `metadata.credential` field is insufficient against hostile clients. This creates another raw-secret route into declaration telemetry and retains the secret in memory despite `implementation_plan.md:31`. Declaration values need the same credential policy as bodies, including nested `metadata.client` values, before they cross the responder boundary.

### 4. Medium — The shipper cannot enforce the ingest-only New Relic key boundary

**Evidence:** `internal/telemetry/newrelic.go:87-90` checks only that `LicenseKey` is nonempty. No key type, documented ingest-key shape, or known privileged-key prefix is rejected before the value is installed as the `Api-Key` header at `newrelic.go:477-483`.

The design requires an additional **Ingest - License** key and explicitly prohibits User, NerdGraph, and query keys on the decoy (`implementation_plan.md:223-226`); the research identifies the documented ingest license key as a 40-character hex value and contrasts it with full-access User keys (`research/new-relic.md:56-68`). As implemented, accidentally configuring a User/query key starts normally instead of failing closed. On the assumed-compromised host, that configuration error changes an ingest-spam credential into potential account/data compromise. At minimum, known non-ingest formats should be rejected and the documented ingest shape enforced.

### 5. Medium — 429 retries ignore New Relic's Retry-After instruction

**Evidence:** `internal/telemetry/newrelic.go:443-471` always sleeps the configured backoff (one and two seconds by default), while `try` at `newrelic.go:475-498` reduces a 429 to a boolean and never reads `Retry-After`. Thus a 429 with `Retry-After: 60` receives further POSTs after roughly one and three seconds, then the batch is marked lost.

`research/new-relic.md:133-164` specifically documents 429 handling through `Retry-After`. The fixed-delay text in `implementation_plan.md:202` conflicts with that guidance and should be revised. Ignoring the server instruction worsens rate limiting and predictably discards telemetry before the permitted retry time. The retry path should parse seconds and HTTP-date forms, apply a bounded maximum, and retain cancellation.

### 6. Medium — Heartbeats can be delayed past the power-off threshold or dropped with attack traffic

**Evidence:** one goroutine performs queue intake, synchronous log/metric POSTs, retries, and heartbeat production in `internal/telemetry/newrelic.go:275-320`. While `flushLogs`/`flushMetrics` and their POSTs are running, the heartbeat ticker is not serviced. Each default POST can consume three ten-second attempts plus one/two-second sleeps (`newrelic.go:118-129`, `newrelic.go:443-498`), and `postAll` invokes multiple POSTs sequentially when a batch exceeds the payload budget. Several slow posts can therefore block heartbeat production for more than the plan's two-minute power-off threshold (`implementation_plan.md:259`).

When the heartbeat case finally runs, it calls the ordinary lossy `Emit` path (`newrelic.go:299-301`); a full attacker-filled queue drops the heartbeat log just like any other chunk (`newrelic.go:167-185`). The gauge does not make the required heartbeat log reliable. Dedicate an independent scheduler/delivery path or prioritize heartbeat items so load and retry stalls cannot create a false loss-of-signal shutdown.

### 7. Medium — Count/Gauge calls after Close are accepted but silently stranded

**Evidence:** `Close` claims to stop intake at `internal/telemetry/newrelic.go:255-273`, and log `Emit` checks `n.closed`. Metric intake at `newrelic.go:198-218` has no corresponding closed check. A `Count` or `Gauge` racing after the final map swap, or called after `n.done` closes, can create/update `n.series` and return normally. No worker remains to flush it, and neither `Dropped` nor `Lost` is incremented.

This silently loses shutdown-window security metrics and makes the drop statistics incomplete. Metric intake needs the same close synchronization and late-call accounting as logs, including the race with the final `flushMetrics` map swap.

### 8. Medium — JSONLog and Multi violate the nonblocking Sink contract

**Evidence:** the interface requires implementations not to block the request path (`internal/telemetry/sink.go:10-14`). `JSONLog.Emit` synchronously chunks and writes every event (`sink.go:105-113`), and `write` performs `json.Encoder.Encode` directly on the supplied `io.Writer` while holding a mutex (`sink.go:137-144`). There is no queue, timeout, or drop policy. `Multi` invokes each sink sequentially (`sink.go:20-38`), so a slow JSON writer also prevents subsequent sinks from receiving the event.

A stalled filesystem/writer therefore stalls request processing and can serialize all callers behind `JSONLog.mu`, despite the package's backpressure contract. Either make the local sink asynchronous with explicit bounded-drop behavior or narrow the interface contract and keep blocking sinks off the request path.

### 9. Low — Empty and weak redactor HMAC keys are accepted

**Evidence:** `internal/telemetry/redact.go:47-58` accepts any byte slice, including nil, empty, and very short keys, and uses it directly for credential fingerprints. `internal/telemetry/redact_test.go:69` and `redact_test.go:75-78` explicitly exercise nil and short keys, so this is accepted behavior rather than an unreachable state.

With an empty or known key, anyone who obtains a fingerprint can compute candidates independently, enabling dictionary confirmation and cross-rebuild correlation rather than a secret keyed fingerprint. Require a cryptographically random minimum-length key at construction; do not silently turn a missing key into a public hash.

### 10. Low — Retried-then-successful failed POSTs never reach Errors or ingest_errors_total

**Evidence:** `Stats.Errors` is documented as counting failed POSTs (`internal/telemetry/newrelic.go:43-48`). In `post`, an error followed by a successful retry returns immediately after incrementing `Sent` (`newrelic.go:453-460`). `n.errs` is incremented only by `fail` (`newrelic.go:501-507`), which runs solely after terminal failure/cancellation. `TestRetryRecovers` at `newrelic_test.go:367-384` codifies the zero-error result.

Consequently transient 429/5xx/transport failures disappear from both `LastError` and `attackbox.telemetry.ingest_errors_total`, hiding retry pressure from the monitoring path. Count each failed attempt separately from `Lost`, which should remain terminal-item accounting.

### 11. Low — Percent-encoding bypasses endpoint key rejection and literal-only error scrubbing

**Evidence:** `internal/telemetry/newrelic.go:145-153` rejects a URL only when the raw string contains the literal key. A URL containing the same key with one or more percent-encoded characters passes, including in `RawQuery`, despite the header-only requirement. Transport errors wrap the request URL at `newrelic.go:475-489`, while `fail` at `newrelic.go:501-504` removes only the unencoded literal key.

A malformed/custom endpoint can therefore put the ingest key in the request target and potentially expose its escaped form through `LastError`/`OnError`, contrary to `implementation_plan.md:202`. Reject credential query parameters and compare decoded URL components; scrub both raw and escaped forms before reporting errors.

## Coverage and checked controls

Reviewed all production and test files in `internal/telemetry`, plus responder `Request`/`Decision`/`Declaration`/`Session` boundaries and classification/probe output types. Also compared the credential, heartbeat, payload, and alerting requirements in both supplied documents.

Checked without an additional finding: redirects are disabled; non-loopback plaintext HTTP is rejected; the default client has a ten-second timeout; the key is normally sent only in `Api-Key`; response draining is capped at 64 KiB; JSON POSTs are gzip-compressed and packed to the default 900,000-byte uncompressed budget; queue/series caps and metric-label filtering exist; chunking is rune-safe; responder session IDs are randomly generated and the caller-derived session key is not returned as `Decision.SessionID`.
