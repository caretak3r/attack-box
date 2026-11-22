# New Relic hardening review

Read-only review of the current working tree. No build or test commands were run.

## Verified remaining issues

### 1. Medium — JSONLog can still stall request processing and prevent New Relic fan-out

**Locations:** `internal/telemetry/sink.go:14-19`, `internal/telemetry/sink.go:28-39`, `internal/telemetry/sink.go:111-119`, `internal/telemetry/sink.go:144-151`; `cmd/attackbox/main.go:130-151`.

`JSONLog.Emit` synchronously calls `json.Encoder.Encode` while holding `JSONLog.mu`. `Multi` invokes sinks sequentially, and `newApp` installs `telemetry.Multi{a.local, nr}`, so the blocking local writer runs first on the request path. A writer that stops returning blocks every caller serialized on `mu` and prevents the New Relic sink from receiving the event. Because no write returns an error in that state, neither `Errors` nor `OnError` observes it.

The revised comments acknowledge synchronous writes, but they do not implement finding 8's alternative of narrowing the contract **and keeping blocking sinks off the request path**, nor the requirement that request processing not stall silently.

**Regression test:** Add a writer whose `Write` waits on a channel and a recording second sink. For `Emit`, `Count`, and `Gauge`, invoke `Multi` with the blocking JSONLog first and assert that the call has bounded backpressure (or an explicit counted drop) and that the second sink still receives the item. Release the writer during cleanup. Also run two concurrent JSONLog calls to cover the mutex serialization.

### 2. Medium — Nested percent-encoding still bypasses endpoint credential rejection and error scrubbing

**Locations:** `internal/telemetry/newrelic.go:186-226`, `internal/telemetry/newrelic.go:663-673`.

`containsKey` tries the raw URL and only one `PathUnescape`/`QueryUnescape` pass. Encoding a key character as `%2530` therefore decodes to `%30`, not `0`, and the configured key is not detected. The endpoint is accepted with the escaped credential in its request target. `fail` subsequently removes only the literal, case-sensitive key, so transport errors can retain the case-folded, singly escaped, or doubly escaped key in `LastError` and `OnError`.

Validation also remains value-specific: URLs such as `https://example.test/log?api_key=another-secret` or with `token`/`password` query parameters are accepted even though finding 11 calls for credential query parameters to be rejected and the design requires header-only authentication.

**Regression tests:**

- Extend `TestEncodedKeyInURLRejected` with a doubly encoded form of `testKey` in both `LogURL` and `MetricURL`, and with credential-shaped query names carrying a value other than the configured key. Assert construction fails.
- Add `TestFailureScrubsEscapedKey`: return a transport error containing the request URL (or call `fail` directly) with raw, singly encoded, doubly encoded, and case-folded key forms; assert none survives in `LastError` or the `OnError` error.

### 3. Low — Retried-then-successful POST failures still do not reach operational ingest-error telemetry

**Locations:** `internal/telemetry/newrelic.go:77-88`, `internal/telemetry/newrelic.go:464-474`, `internal/telemetry/newrelic.go:582-613`; `cmd/attackbox/main.go:277-288`.

On a transient failure followed by success, `post` increments only `Retries` and then returns on the successful attempt. `Errors`, `LastError`, and `OnError` are unchanged. The only metric emitted is `attackbox.telemetry.ingest_errors_total` from `n.errs`, and the application's final `stopped` record includes `nr_errors` but not `nr_retries`. Thus the new in-memory `Retries` counter leaves the recovered failure invisible to New Relic alerts and normal process logs, which is the remaining impact described by finding 10.

`TestRetryRecovers` at `internal/telemetry/newrelic_test.go:367-384` and the assertion at `internal/telemetry/newrelic_test.go:636` currently codify `Errors == 0` after a recovered 429 rather than checking the required failed-attempt accounting.

**Regression test:** Make the first log POST return 429 and the next return 202. After `Close`, assert `Sent > 0`, `Lost == 0`, and the chosen public failed-attempt counter is one; for the contract in finding 10, assert `Errors == 1`. Decode the final metric POST and assert `attackbox.telemetry.ingest_errors_total == 1`. Add an application-level assertion that the recovered failure is represented in the final local record or an emitted retry/error metric, not only in `Stats.Retries`.

### 4. Low — Retry scheduling can exceed MaxRetryAfter and count a canceled retry that never ran

**Location:** `internal/telemetry/newrelic.go:599-609`.

The cap is applied only inside `if after > wait`. With `Backoff = []time.Duration{2 * time.Second}`, `MaxRetryAfter = 100 * time.Millisecond`, and `Retry-After: 1`, `after <= wait`, so the code sleeps for two seconds. This contradicts the documented cap on a 429 wait and the plan's "larger of that step and Retry-After, capped by MaxRetryAfter" behavior. The normal defaults do not trigger this edge; a custom backoff and cap do.

The same block increments `Retries` before waiting. If `Close(ctx)` cancels that wait, no subsequent POST occurs, but `Retries` still increases despite being documented as counting attempts that were retried.

**Regression tests:**

- Add a 429-then-202 case where the configured backoff exceeds both a positive Retry-After value and `MaxRetryAfter`; assert the second attempt occurs within the cap.
- Return 429 with a long Retry-After, start `Close` with a short deadline, and assert prompt cancellation, one actual POST, and `Retries == 0`.

## Coverage summary

Reviewed `internal/telemetry/newrelic.go`, `sink.go`, `redact.go`, their current tests, `cmd/attackbox/main.go`, `config.go`, `main_test.go`, findings 3-11 in `research/telemetry-security.md`, `research/new-relic.md`, `research/main-review.md`, `SECURITY_FIXES.md`, and the relevant implementation-plan requirements.

No remaining issue was found in the requested ingest-key shape checks, independent heartbeat delivery under a full queue/stalled ordinary worker, post-Close metric synchronization and drop accounting, random replacement of short redactor keys, Retry-After seconds/HTTP-date parsing and context cancellation, or the current command-side startup cleanup, resource caps, secret-mode checks, final stop/error handling, and healthcheck userinfo rejection. Finding 3's responder implementation was outside this assigned file scope. Known stale key-fixture failures were not treated as findings.
