# Attack Box Main Lifecycle Review

Review date: 2026-11-21  
Scope: `/Users/rohit/attack-box/cmd/attackbox/main.go`, `config.go`  
Focus: Listener binding, cleanup, TLS/proxy assumptions, signal/context, NR flush, error propagation, healthcheck SSRF, secret handling, config bounds

---

## BLOCKING

### 1. Partial listener bind leaves NR background work running (main.go:189-194)

**Severity:** P1 — partial startup leaves background goroutines running  
**Evidence:**

```go
188:		if err != nil {
189:			a.closeListeners()
190:			if a.nr != nil {
191:				ctx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
192:				_ = a.nr.Close(ctx)  // ← error discarded
193:				cancel()
194:			}
```

**Failure scenario:** Second listener bind fails after NR is created. `closeListeners()` closes the first listener, then `nr.Close(ctx)` is called with a timeout. If NR.Close returns an error (e.g., flush incomplete, context deadline exceeded), that error is silently discarded. The background flush goroutine in NewRelic may still be running, retrying HTTP posts, holding queue memory, and logging errors through `OnError`.

**Risk:** Process exits with "listener bind failed" but leaves telemetry background work active. On a container orchestrator restart loop, these orphaned goroutines accumulate.

**Fix:** Return the NR close error joined with the bind error:
```go
if a.nr != nil {
    ctx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
    nrErr := a.nr.Close(ctx)
    cancel()
    return nil, errors.Join(fmt.Errorf("%s listener %s: %w", l.persona, l.addr, err), nrErr)
}
```

---

### 2. Config allows unbounded resource limits (config.go:109-112)

**Severity:** P1 — memory exhaustion via environment variables  
**Evidence:**

```go
109:		maxSessions:       num("MAX_SESSIONS", 10000),
110:		maxBody:           int64(num("MAX_BODY_BYTES", 1<<20)),
111:		maxPerSource:      num("MAX_PER_SOURCE", 8),
112:		maxInFlight:       num("MAX_IN_FLIGHT", 256),
```

The `num()` helper (lines 79-90) validates positive but has no upper bound. `strconv.Atoi` returns int, so on 64-bit systems values up to ~9e18 are accepted.

**Failure scenario:** An operator sets `ATTACKBOX_MAX_SESSIONS=100000000`. The responder allocates `10,000 * <session size>` on first use; the LRU may never evict under moderate load. With 10M sessions at ~500 bytes each (conservative), that's 5 GB baseline before any request bodies or response buffers.

**Risk:** Misconfiguration or malicious environment causes immediate OOM, defeating the decoy's availability goal. Plan section "Implementation status" mentions "bounded LRU store (default 10,000 sessions)" but nowhere caps the env override.

**Fix:** Add sanity caps in `num()` or per-use:
```go
if c.maxSessions > 100_000 {
    errs = append(errs, errors.New("ATTACKBOX_MAX_SESSIONS: max 100000"))
}
if c.maxInFlight > 10_000 {
    errs = append(errs, errors.New("ATTACKBOX_MAX_IN_FLIGHT: max 10000"))
}
```

---

### 3. Secret file read with no permission check (config.go:181)

**Severity:** P2 — world-readable secret defeats deployment isolation  
**Evidence:**

```go
180:	if c.secretFile != "" {
181:		b, err := os.ReadFile(c.secretFile)
182:		switch {
183:		case err != nil:
184:			errs = append(errs, fmt.Errorf("ATTACKBOX_SECRET_FILE: %v", err))
185:		case len(b) < minSecret:
186:			errs = append(errs, fmt.Errorf("ATTACKBOX_SECRET_FILE: need at least %d bytes, got %d", minSecret, len(b)))
187:		default:
188:			c.secret = b
189:		}
190:	}
```

**Failure scenario:** Operator writes secret to `/var/secrets/attackbox.key` with mode 0644 (default touch/echo). Any process on the decoy, including sandbox-escaped attacker or a co-tenant container, can read it. The secret derives session keys, embed seeds and redaction keys; with it an attacker can:
- Forge session fingerprints to bypass rate limits
- Reverse redacted credential fingerprints via rainbow table
- Predict embedding outputs

Plan rule 5: "Accepted-loss secrets only." The session/embed secret is *not* a network credential, but losing it breaks session isolation and fingerprint unlinkability.

**Fix:** Stat the file and require owner-only read (0600 or 0400):
```go
if c.secretFile != "" {
    info, err := os.Stat(c.secretFile)
    if err != nil {
        errs = append(errs, fmt.Errorf("ATTACKBOX_SECRET_FILE: %v", err))
    } else if info.Mode().Perm()&0077 != 0 {
        errs = append(errs, fmt.Errorf("ATTACKBOX_SECRET_FILE: permissions %#o too open; use 0600", info.Mode().Perm()))
    } else {
        b, rerr := os.ReadFile(c.secretFile)
        // ... existing length check
    }
}
```

---

## NON-BLOCKING

### 4. NR "stop" event sent before Close, may be lost (main.go:251-254)

**Severity:** P2 — final lifecycle event unreliable  
**Evidence:**

```go
249:	attrs := map[string]any{}
250:	var nrErr error
251:	a.runtime("stop", "ok", nil)
252:	if a.nr != nil {
253:		flushCtx, cancelFlush := context.WithTimeout(context.Background(), a.cfg.shutdownTimeout)
254:		nrErr = a.nr.Close(flushCtx)
```

**Failure scenario:** The "stop" event is emitted to the queue at line 251, then `nr.Close()` starts its flush. If the queue already has 10,000 events (the default cap), "stop" is immediately dropped. Even if queued, Close has only `shutdownTimeout` (default 15s) to drain; partial flush loses it.

**Impact:** Logs show "start" but no "stop". Alerts keyed on lifecycle pairs (uptime, restart count) become unreliable. The final "stopped" event (line 267) goes to local JSON only and is never ingested.

**Fix direction:** Emit "stop" to local only, or emit it early in the shutdown sequence before servers stop (before line 235) so NR has the full grace period to flush it.

---

### 5. Lost-event error message assumes non-empty LastError (main.go:259)

**Severity:** P3 — misleading error message  
**Evidence:**

```go
258:		if nrErr == nil && (st.Lost > 0 || st.Dropped > 0) {
259:			nrErr = fmt.Errorf("new relic: %d lost, %d dropped; last error: %s", st.Lost, st.Dropped, st.LastError)
260:		}
```

**Failure scenario:** Events are lost/dropped due to queue overflow (Dropped) or successful retries that exhausted the retry budget (Lost), but the last HTTP attempt succeeded (200 OK). `st.LastError` is empty. The error message reads: `new relic: 50 lost, 100 dropped; last error: ` (trailing space, no details).

**Fix:** Guard the LastError inclusion:
```go
msg := fmt.Sprintf("new relic: %d lost, %d dropped", st.Lost, st.Dropped)
if st.LastError != "" {
    msg += "; last error: " + st.LastError
}
nrErr = errors.New(msg)
```

---

### 6. Healthcheck URL validation trusts url.Hostname() (main.go:95-98)

**Severity:** P3 — SSRF defense-in-depth gap  
**Evidence:**

```go
90:func healthcheck(raw string) error {
91:	u, err := url.Parse(raw)
92:	if err != nil || u.Scheme != "http" {
93:		return errors.New("want an http:// loopback URL")
94:	}
95:	switch u.Hostname() {
96:	case "127.0.0.1", "::1", "localhost":
97:	default:
98:		return errors.New("only loopback hosts are allowed")
```

**Known edge cases:**
1. `url.Hostname()` strips `[]` brackets, so `http://[::1@evil.com]/` becomes `::1@evil.com`, which the switch rejects — safe.
2. Credentials in the URL (`http://user:pass@127.0.0.1/`) are not rejected; `u.User != nil` is never checked.
3. Kubernetes liveness probes commonly use `http://127.0.0.1:8080/health`; the user/pass case is theoretical unless an operator pastes a malicious URL from logs (Plan rule 8: "Do not paste ... URLs from logs into ... a browser").

**Risk:** Low — the binary itself can't exfiltrate credentials (no other network code path uses them), but failing fast on unexpected URL structure is better hygiene.

**Fix:**
```go
if u.User != nil {
    return errors.New("credentials in healthcheck URL are not supported")
}
```

---

### 7. Shutdown timeout not validated against stream duration (config.go:119,124-126)

**Severity:** P3 — config incoherence  
**Evidence:**

```go
115:		maxStream:         dur("MAX_STREAM", 180*time.Second),
...
119:		shutdownTimeout:   dur("SHUTDOWN_TIMEOUT", 15*time.Second),
...
124:	if c.holdSilent > c.maxStream {
125:		errs = append(errs, errors.New("ATTACKBOX_HOLD_SILENT must not exceed ATTACKBOX_MAX_STREAM"))
126:	}
```

**Gap:** `holdSilent` is validated against `maxStream`, but `shutdownTimeout` is not. If `shutdownTimeout < maxStream`, in-flight streams are forcibly closed before their natural end. Plan section "HTTP personas" (line 212): "Holds ... capped by `MaxStreamDuration` (180 s)". A 15s shutdown timeout cuts a 180s hold at 15s, logging `hold_result: client_closed` even though the server initiated the close.

**Impact:** Telemetry mislabels server-initiated closes as client behavior. Test `TestShutdownCutsHolds` (main_test.go:433-454) validates that shutdown *does* cut holds, so this is known behavior. The gap is that nothing warns the operator that `ATTACKBOX_SHUTDOWN_TIMEOUT=5s` will never let a hold complete.

**Fix:** Warn but don't error (some deployments may want fast shutdown):
```go
if c.shutdownTimeout < c.maxStream {
    errs = append(errs, fmt.Errorf("ATTACKBOX_SHUTDOWN_TIMEOUT (%v) is less than MAX_STREAM (%v); in-flight holds will be cut", c.shutdownTimeout, c.maxStream))
}
```

Or: document that `shutdownTimeout >= maxStream` is required for clean hold telemetry, then validate it as an error.

---

## OBSERVED STRENGTHS

1. **Listener bind-before-serve** (main.go:129-199): `newApp` binds every listener before returning, so port conflicts fail at startup, not mid-serve. Plan requirement met.

2. **TLS/reverse-proxy separation** (main.go:90-114): Healthcheck correctly probes only the local HTTP listener (no TLS). The plan's public 443 TLS termination happens at the edge proxy (not in this binary). No assumption that the app listener has TLS.

3. **Signal/context cancellation hygiene** (main.go:74, 231-233, 235): Uses `signal.NotifyContext` for SIGINT/SIGTERM. Shutdown uses a *new* `context.Background()` with its own timeout (line 235), not the canceled parent context. This is correct: allows the shutdown sequence its full grace period even if the triggering signal has a short deadline.

4. **Lost-event propagation** (main.go:258-268): `run()` checks NR stats and treats `Lost > 0 || Dropped > 0` as an error, returned via `errors.Join`. The exit code reflects delivery failure, not just listener failure. Plan requirement met.

5. **Healthcheck SSRF core restrictions** (main.go:95-98, 102): Hostname whitelist + scheme check + redirect blocking + 3s timeout. The binary cannot be trivially used to probe external hosts.

6. **Secret fallback** (config.go:194-198): If no secret file is provided, generates a random 32-byte secret. Session keys remain unpredictable across restarts (but sessions don't survive restart, so this is correct per the stateless design).

7. **Config validation coverage** (config.go:121-126, 173-178): Checks instance label format, NR key vs disabled flag conflicts, duration positivity, holdSilent <= maxStream. Errors accumulate and are reported together (line 191).

---

## SUMMARY

**Blocking:** 3 findings — partial cleanup leaves NR running (P1), unbounded config allows OOM (P1), secret file permissions unchecked (P2).  
**Non-blocking:** 4 findings — stop event timing (P2), error message formatting (P3), healthcheck URL edge case (P3), shutdown vs stream timeout incoherence (P3).  
**Strengths:** Bind-before-serve, signal handling, lost-event propagation, SSRF core defenses, config validation structure.

**Next:** Address P1/P2 before first deployment. P3 findings are polish but not deployment blockers.
