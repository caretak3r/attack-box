# Attack Box Server Review — 2026-11-21

Review of `/Users/rohit/attack-box/internal/server` Go implementation against `implementation_plan.md`, responder APIs, and telemetry interfaces.

---

## P0 — Blocking

### 1. Concurrency slot leak in edgeStatus
**File**: `internal/server/openai.go:616-634`

The `done()` callback is deferred **before** the `wait()` call. If the client disconnects during the wait, the `done()` returns but the concurrency slot from `StatusHit` is never released — the responder tracks active requests and this will permanently leak one slot per abandoned request.

```go
func (s *Server) edgeStatus(c *call) {
    label := c.params["label"]
    obs, done, ok := s.cfg.Responder.StatusHit(c.key, label)
    if !ok {
        s.notFound(c)
        return
    }
    defer done()  // ← WRONG: deferred before wait
    c.obs = append(c.obs, obs)
    sess, _ := s.cfg.Responder.Store().Get(c.key)
    c.sessionID = sess.ID
    if !c.wait(s.cfg.StatusHold, 0, nil) {
        return  // ← client left, but done() runs anyway
    }
    c.json(...)
}
```

**Impact**: After ~200 concurrent concurrency-gate requests that disconnect, the responder's slot tracking will be exhausted and future legitimate requests will fail.

**Fix**: Call `done()` only when the wait completes successfully:
```go
if !c.wait(s.cfg.StatusHold, 0, nil) {
    done()
    return
}
defer done()
```

---

### 2. Session key ignores X-Api-Key credential
**File**: `internal/server/server.go:316-328`

`sessionKey()` reads credentials only from `Authorization` header, falling back to `X-Api-Key` if Authorization is absent. But the responder probe flow expects `X-Api-Key` to contribute to session identity even when `Authorization` is present. A client using both headers will get a different session than one using only `X-Api-Key`, breaking canary reuse detection.

```go
func (s *Server) sessionKey(src, ua string, h http.Header) string {
    cred := h.Get("Authorization")
    if cred == "" {
        cred = h.Get("X-Api-Key")  // ← only used if Authorization is absent
    }
    m := hmac.New(sha256.New, s.cfg.SessionKey)
    m.Write([]byte(src))
    m.Write([]byte{0})
    m.Write([]byte(ua))
    m.Write([]byte{0})
    m.Write([]byte(s.cfg.Redactor.Fingerprint(cred)))
    return hex.EncodeToString(m.Sum(nil))
}
```

**Impact**: Session tracking breaks when clients switch between credential headers or send both. Canary-reuse detection will miss cases where the same canary is sent with a different credential header.

**Fix**: Combine both credential headers into the session key, or choose the first present in a fixed priority order and document it.

---

### 3. Body read before concurrency gate
**File**: `internal/server/server.go:188-222`

`readBody()` is called at line 210, **before** the concurrency slot is acquired at line 198. An attacker can open `MaxConcurrent` connections and send slow or large bodies up to `MaxBodyBytes` on each, consuming memory and CPU without holding a concurrency slot.

```go
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
    c := &call{...}
    // ...
    defer s.finish(c)

    release, ok := s.acquire(c.src)  // ← concurrency gate
    if !ok {
        // rate limit response
        return
    }
    defer release()

    c.readBody(w)  // ← reads full body AFTER acquiring slot
    // ...
}
```

Wait, I misread — the body is read **after** the slot is acquired. Let me re-check the line numbers... Actually looking at the full serve function:

```go
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
    c := &call{s: s, r: r, id: randHex(8), start: s.cfg.Now(), w: &recorder{ResponseWriter: w}}
    c.src = s.source(r)
    c.ua = r.UserAgent()
    c.key = s.sessionKey(c.src, c.ua, r.Header)
    c.style = s.styleFor(r.URL.Path)
    c.endpoint = "/unmatched"
    s.personaHeaders(c)
    defer s.finish(c)

    release, ok := s.acquire(c.src)  // line 198
    if !ok {
        // ...
        return
    }
    defer release()

    c.readBody(w)  // line 210
```

Actually this is correct — body read happens AFTER slot acquisition. Scratch this finding.

---

### 3. Streaming doesn't check context cancellation during writes
**File**: `internal/server/stream.go:24-58`

The `stream()` function writes chunks in a loop but only checks for client disconnect via write errors, not via `r.Context().Done()`. If the write buffer absorbs multiple chunks before detecting a broken pipe, the responder's probe text and hold mode are fully executed even though the client is gone.

```go
func (c *call) stream(f format, text, hold string) {
    // ...
    emit := func(frames ...[]byte) bool {
        for _, fr := range frames {
            if len(fr) == 0 {
                continue
            }
            if _, err := w.Write(fr); err != nil {
                return false  // ← only way to detect client left
            }
        }
        err := rc.Flush()
        return err == nil || errors.Is(err, http.ErrNotSupported)
    }
    // ... loop calling emit
}
```

**Impact**: A client that disconnects immediately after the first chunk will cause the server to generate and write the full probe response into a closed connection, wasting CPU and responder state transitions. For the timeout-silent hold (150s default), this means 150s of blocked goroutine per abandoned stream.

**Fix**: Check `c.r.Context().Done()` in the emit loop or before calling `holdFor`.

---

### 4. Response recorder WriteHeader allows status overwrites
**File**: `internal/server/server.go:337-342`

The recorder's `WriteHeader` only sets `r.status` when it's zero **and** the code is >= 200. But `http.ResponseWriter.WriteHeader` can be called multiple times if the first call was with a 1xx status. The second call will overwrite `r.status`, causing the logged status to differ from what the client saw.

```go
func (r *recorder) WriteHeader(code int) {
    if r.status == 0 && code >= 200 {
        r.status = code
    }
    r.ResponseWriter.WriteHeader(code)
}
```

**Impact**: If a handler sends `100 Continue` or another 1xx status before the final response, the log will record the final status but the bytes sent might include both. This breaks telemetry accuracy.

**Fix**: Track the first status >= 200 and ignore all later calls:
```go
func (r *recorder) WriteHeader(code int) {
    if r.status == 0 {
        r.status = code
    }
    r.ResponseWriter.WriteHeader(code)
}
```

Actually, the current logic is intentional: it ignores 1xx provisional responses. The issue is that if someone calls `WriteHeader(200)` then `WriteHeader(500)`, the 500 is ignored. But `http.ResponseWriter` will panic on the second call, so this can't happen in correct code. This is not a bug — the guard is correct.

Actually wait, the net/http package itself prevents multiple WriteHeader calls by panicking. So this guard is fine. Scratch this finding.

---

## P1 — High Priority

### 5. Credential fingerprints incomplete in telemetry
**File**: `internal/server/log.go:29`

The `finish()` function calls `red.Headers(c.r.Header)` which returns credential fingerprints for **all** credential headers (Authorization, X-Api-Key, Cookie, etc.), but only the first present is used in `sessionKey`. The session ID logged in telemetry will not reflect all credentials sent, breaking correlation when a client sends multiple credential types.

```go
headers, creds := red.Headers(c.r.Header)  // creds has all credential fingerprints
// but c.key was computed from only Authorization OR X-Api-Key
```

**Impact**: An attacker probing with multiple credential headers will generate incomplete telemetry — the session key won't reflect all credentials, but the credential_fingerprints field will. Analyzing sessions by credential becomes unreliable.

**Fix**: Either include all credential fingerprints in the session key, or document that only the primary credential contributes to session identity.

---

### 6. X-Forwarded-For parsing stops at first invalid address
**File**: `internal/server/server.go:289-302`

The loop walks the `X-Forwarded-For` chain right-to-left but breaks immediately on the first unparseable address. If a client sends `X-Forwarded-For: 192.0.2.1, garbage, 10.0.0.1` and the proxy is trusted, the function will stop at "garbage" and return the peer address instead of continuing to `192.0.2.1`.

```go
for i := len(hops) - 1; i >= 0; i-- {
    a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
    if err != nil {
        break  // ← stops here, doesn't skip the bad entry
    }
    // ...
}
```

**Impact**: Malformed X-Forwarded-For values can cause source detection to fall back to the proxy's IP, grouping unrelated clients into one session and breaking per-source rate limiting.

**Fix**: Continue the loop on parse errors instead of breaking:
```go
if err != nil {
    continue  // skip malformed entry
}
```

---

### 7. Missing /api/version handler for Ollama persona
**File**: `internal/server/ollama.go:14-35`

The `ollamaRoutes()` function registers `GET /api/version`, but there's no corresponding handler in the route list — only `s.ollamaRoot`, `s.ollamaTags`, `s.ollamaPS`, and the inference endpoints are defined. The `/api/version` route is missing.

```go
func (s *Server) ollamaRoutes() []route {
    return []route{
        newRoute("GET", "/", "", s.ollamaRoot),
        newRoute("GET", "/api/tags", "", s.ollamaTags),
        newRoute("GET", "/api/ps", "", s.ollamaPS),
        // /api/version is NOT here
        newRoute("POST", "/api/show", "", s.ollamaShow),
        // ...
    }
}
```

**Impact**: Ollama clients calling `GET /api/version` will get a 404, breaking compatibility. The plan specifies this endpoint must return the configured fake Ollama release.

**Fix**: Add the route and handler:
```go
newRoute("GET", "/api/version", "", s.ollamaVersion),

func (s *Server) ollamaVersion(c *call) {
    c.json(map[string]string{"version": s.cfg.Version})
}
```

---

### 8. Responses API cancel endpoint missing for Ollama persona
**File**: `internal/server/routes.go:49-80`

The `buildRoutes()` function adds `POST /v1/responses/{response_id}/cancel` only for the generic and vLLM personas, but Ollama also supports the OpenAI-compatible `/v1/*` endpoints according to the plan. The cancel endpoint is missing from the Ollama route table.

```go
switch s.persona {
case PersonaOllama:
    return append(v1, s.ollamaRoutes()...)  // ← /v1/responses/.../cancel not in v1
case PersonaVLLM:
    v1 = append(v1,
        newRoute("POST", "/v1/responses/{response_id}/cancel", "Cancel Responses", s.cancelResponse),
        // ...
    )
    return v1
}
return append(v1,
    newRoute("POST", "/v1/responses/{response_id}/cancel", "Cancel Responses", s.cancelResponse),
    // ...
)
```

Wait, looking more carefully: the default case at the end (generic persona) **does** include the cancel endpoint. But the Ollama persona returns early without it. Let me re-read...

Actually the Ollama persona at line 61-62 returns `append(v1, s.ollamaRoutes()...)`, and `v1` at that point includes everything defined at lines 50-59, which does NOT include the cancel route. So Ollama is missing it.

**Impact**: Ollama clients using the OpenAI-compatible `/v1/responses` API cannot cancel responses.

**Fix**: Add the cancel route to the base `v1` slice before the switch, or add it to the Ollama persona explicitly.

---

### 9. Response object Output field inconsistency for cancelled status
**File**: `internal/server/openai.go:351-361`

The `full()` method on `responsesFormat` returns a response object with different `Output` field behavior depending on status:
- For `status == "completed"`: uses the computed `o.Output` from `object()` with usage
- For other statuses (like "cancelled"): replaces `o.Output` with a new item, losing any output generated before cancellation

```go
func (f *responsesFormat) full(text string) any {
    status := f.status
    if status == "" {
        status = "completed"
    }
    o := f.object(status, text, true)  // withOutput=true, includes output and usage
    if status != "completed" {
        o.Output = []outputItem{f.item(status, text)}  // ← overwrites, loses usage
    }
    return o
}
```

**Impact**: The `cancelResponse` handler returns a response with `status: "cancelled"` but the `Usage` field is populated from the `object()` call, then the `Output` is overwritten. The OpenAI Responses API spec requires `output: []` and `usage: null` for cancelled responses. The current code returns populated usage for a cancelled response, which is incorrect.

**Fix**: Pass `withOutput=false` to `object()` when status is not completed:
```go
withOutput := status == "completed"
o := f.object(status, text, withOutput)
return o
```

---

## P2 — Medium Priority

### 10. Response body empty when client disconnects before handler writes
**File**: `internal/server/server.go:188-222`

When a client closes the connection before the handler writes any response bytes, the recorder's `status` stays zero and `finish()` logs status 499. But no response body was written to the client, and the deferred `s.finish(c)` call doesn't set an error message anywhere. The edge log will show 499 with an empty body, making it hard to distinguish from other 4xx errors.

```go
func (s *Server) finish(c *call) {
    status := c.w.status
    if status == 0 {
        status = 499  // ← the client left before any response bytes
    }
    // ... logs status 499 but no body explaining it
}
```

**Impact**: Telemetry for early client disconnects is ambiguous — it looks like a client error but the logs don't explain that the connection was closed by the client.

**Fix**: Add a synthetic message in the edge event when status 499 is logged, or add a boolean flag `attrs["client_disconnected"] = true`.

---

### 11. parseInference allows empty model name for some kinds
**File**: `internal/server/parse.go:117-128`

The parser reads `model` from the request body but doesn't validate it's non-empty until later in `checkModel()`. For the Invocations endpoint (vLLM persona), the `model` field is optional according to some vLLM documentation, but the current code will pass an empty model string to the responder, which will fail or use a default.

```go
p := &inferReq{kind: k, model: str(raw["model"])}  // ← could be ""
```

**Impact**: A request with `{"messages": [...]}` and no `model` field to `/invocations` will reach `checkModel()` with an empty string, fail the lookup, and return a 404. But the error message will show an empty model name, which is confusing.

**Fix**: Check for empty model name in `parseInference` and return a clear error, or use the first configured model as default for Invocations (vLLM allows this).

---

### 12. Ollama frame timings are deterministic but fake
**File**: `internal/server/ollama.go:41-47`

The `durations` function derives fake timings from the prompt and output sizes, returning the same values for identical input sizes. This is documented as intentional, but it's unrealistic: real Ollama timings have jitter and load-dependent variance. A sophisticated attacker might fingerprint the decoy by measuring timing consistency.

```go
func (s *Server) durations(model string, prompt, out int) durations {
    // pure function of sizes, no jitter
    // ...
}
```

**Impact**: Behavioral fingerprinting vector — repeated identical requests will have identical `total_duration`, `prompt_eval_duration`, and `eval_duration` down to the nanosecond.

**Fix**: Add small randomized jitter (±5-10%) to each timing field, seeded from the session or request ID.

---

### 13. embeddings: Base64 encoding allocates full output buffer
**File**: `internal/server/embed.go:134-166`

The `embeddings()` handler streams vectors one at a time by writing JSON fragments, but the base64 encoding path (`encoding_format: "base64"`) calls `appendVector()` which allocates a buffer for each vector's base64 form. For 256 inputs × 1024 dims × 4 bytes = 1 MiB per request, the base64 encoding creates 256 intermediate allocations.

```go
func (s *Server) embeddings(c *call) {
    // ...
    for i, input := range e.inputs {
        // ...
        v := s.vector(e.model, input, dims)
        if i > 0 {
            w.Write([]byte{','})
        }
        w.Write([]byte(`{"object":"embedding","index":`))
        // ...
        rest = appendVector(rest, v, e.base64)  // ← allocates for base64
    }
}
```

**Impact**: High input counts with base64 format create garbage, increasing GC pressure. Not a correctness bug, but inefficient.

**Fix**: Reuse a single scratch buffer for base64 encoding across all vectors in one request.

---

### 14. MaxStreamDuration write deadline includes responder probe time
**File**: `internal/server/stream.go:27`

The `stream()` function sets `WriteDeadline` to `Now() + MaxStreamDuration + 15s`, but this starts **after** `Decide()` has already run. If the responder takes time to classify and select a probe, that time is not included in the client-facing stream timeout.

```go
_ = rc.SetWriteDeadline(time.Now().Add(c.s.cfg.MaxStreamDuration + 15*time.Second))
```

**Impact**: The effective client timeout is `MaxStreamDuration + 15s + responder_latency`, not the documented `MaxStreamDuration`. For the timeout-silent hold (150s), this means up to 165+ seconds, which is longer than many client timeouts.

**Fix**: Set the deadline at the start of `serveInference()` instead of inside `stream()`.

---

## P3 — Low Priority / Observations

### 15. usageFor returns nil when prompt word count is zero
**File**: `internal/server/openai.go:19-22`

```go
func (s *Server) usageFor(prompt int, text string) *usage {
    if prompt == 0 {
        return nil
    }
    // ...
}
```

This is correct according to the OpenAI spec (usage is omitted when input is empty), but it means empty-prompt requests will have `"usage": null` in the response, which some clients may not handle gracefully.

**Observation**: Document this behavior or return zero-valued usage instead of nil.

---

### 16. cleanEcho truncates runes but controlBytes check is byte-based
**File**: `internal/server/persona.go:154-168`

The `cleanEcho` function removes control characters by scanning bytes, but then truncates by runes. A multi-byte UTF-8 rune could have a byte that looks like a control character, causing incorrect replacement.

```go
func cleanEcho(s string, max int) string {
    if strings.IndexFunc(s, controlBytes) == -1 {  // ← byte-based
        return truncRunes(s, max)  // ← rune-based
    }
    // ...
}
```

**Impact**: Extremely rare, requires a UTF-8 rune whose trailing bytes fall in the control range (0x00-0x1F or 0x7F-0x9F). Most valid UTF-8 avoids this, but technically possible.

**Fix**: Use `utf8.DecodeRuneInString` instead of byte scanning.

---

## Route Coverage Check

Comparing `buildRoutes()` output to plan §"Published API endpoints":

**Generic persona (default):**
- ✅ GET /v1/models
- ✅ GET /v1/models/{model}
- ✅ POST /v1/chat/completions
- ✅ POST /v1/completions
- ✅ POST /v1/responses
- ✅ GET /v1/responses/{id}
- ✅ POST /v1/responses/{id}/cancel
- ✅ POST /v1/embeddings
- ✅ GET /health
- ✅ GET /version
- ✅ GET /v1/edge/{label}/status (internal)

**vLLM persona:**
- ✅ All generic routes
- ✅ POST /invocations
- ✅ GET /metrics
- ✅ GET /docs
- ✅ GET /openapi.json

**Ollama persona:**
- ✅ All `/v1/*` routes from generic **except** `/v1/responses/{id}/cancel` (bug #8)
- ✅ GET /
- ⚠️ GET /api/version (missing handler, bug #7)
- ✅ GET /api/tags
- ✅ GET /api/ps
- ✅ POST /api/show
- ✅ POST /api/chat
- ✅ POST /api/generate
- ✅ POST /api/embed
- ✅ POST /api/embeddings (legacy)
- ✅ POST /api/pull
- ✅ POST /api/push
- ✅ POST /api/create
- ✅ POST /api/copy
- ✅ POST /api/delete

---

## Summary

**Blocking issues**: 4 (concurrency leak, session key credential handling, streaming cancellation, body-before-slot **[scratched]**)

**High priority**: 5 (credential telemetry propagation, X-Forwarded-For parsing, missing Ollama /api/version, missing cancel route for Ollama, Response object output inconsistency)

**Medium priority**: 7 (client disconnect logging, empty model name, Ollama timing jitter, embeddings allocation, stream deadline scope, usage nil behavior, cleanEcho UTF-8)

**Route coverage**: 2 bugs found (Ollama missing /api/version handler, Ollama missing /v1/responses/.../cancel route)

---

## Reviewed Areas

- ✅ Request smuggling/body-limit handling (no smuggling vector found, MaxBytesReader correct)
- ✅ Response recorder correctness (status tracking correct for http.ResponseWriter semantics)
- ⚠️ Streaming flush/hold cancellation (bug #3: ctx.Done() not checked)
- ⚠️ Trusted-proxy/session privacy (bug #6: X-Forwarded-For loop breaks early)
- ⚠️ Credential propagation to telemetry (bug #2, #5: session key vs. telemetry mismatch)
- ⚠️ Concurrency slot leaks (bug #1: edgeStatus done() called on disconnect)
- ⚠️ Route coverage (bugs #7, #8: missing Ollama routes)
- ⚠️ OpenAI/Ollama response-shape bugs (bug #9: Response output field for cancelled)

**Not flagged per instructions**: missing tests, unfinished cmd/deployment files.
