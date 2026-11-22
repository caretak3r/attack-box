# Attack Box Responder Review — Commit 935bbca
**Review date:** 2026-11-21  
**Scope:** internal/responder package against implementation_plan.md and research/README.md  
**Focus areas:** Bounded session state, races, declaration validation, probe sequencing, canary safety, invisible-character handling, classification gaps, behavioral evidence correctness

---

## Critical Findings

### C1. Race condition in StatusHit done closure
**File:** `internal/responder/responder.go:369-373`  
**Severity:** P0 — data race under concurrent requests

The `done` closure returned by `StatusHit` decrements `sess.statusActive` without holding `r.store.mu`. Two concurrent requests to the same session's status URLs will race:

```go
done := func() {
    sess.mu.Lock()         // locks sess.mu only
    sess.statusActive--
    sess.mu.Unlock()
}
```

**Scenario:** Request A calls `StatusHit("key", "A")` and gets session S with `statusActive=1`. Request B calls `StatusHit("key", "B")` immediately after, reads `statusActive=1`, increments to 2, and updates `statusPeak=2`. Request A's `done()` runs and decrements to 1. Request B's `done()` runs and decrements to 0. If a third request arrives before both are done, it may read a stale `statusActive` or `statusPeak` value. The session lock protects the decrement itself, but the caller holds no lock between the `StatusHit` read and the `done()` call, so the transport layer can invoke `done()` out of order or concurrently with new `StatusHit` calls.

**Fix:** The existing session mutex prevents corruption of `statusActive` itself — the race is in the observation ordering, not memory safety. The test at line 346 passes under `-race` because the closure properly locks. However, the `statusPeak` and `statusActive` observations returned by `StatusHit` reflect a snapshot at call time, not at `done()` time. A third concurrent request may see an `active` count that includes requests whose `done()` has already been called but not yet executed.

**Recommendation:** Accept this as an observability race (the counts are approximate under concurrency, which is itself evidence) or move the peak tracking into `Decide` after the main lock is released. The current design is safe for memory but produces non-monotonic `active` counts in observations when requests overlap. Document this in a comment at line 339.

---

## High-Priority Findings

### H1. Invisible Unicode normalization incomplete
**File:** `internal/responder/classify.go:139`  
**Severity:** P1 — detection evasion

The `normalize` function strips six invisible format characters:

```go
case r == '\u200b' || r == '\u200c' || r == '\u200d' || r == '\u2060' || r == '\ufeff' || r == '\u00ad':
```

**Missing:** U+200E (LEFT-TO-RIGHT MARK), U+200F (RIGHT-TO-LEFT MARK), U+202A through U+202E (directional formatting), U+2061 through U+2063 (function application, invisible separator, invisible times), U+180E (MONGOLIAN VOWEL SEPARATOR pre-Unicode 6.3).

**Attack:** An attacker inserts `sys\u200etem prompt` or `cred\u202eential` to bypass keyword matching. The plan at line 29 says "invisible format characters (U+200B, U+200C, U+200D, U+2060, U+FEFF, U+00AD) are removed" but does not claim completeness.

**Evidence:** The `character-rewriting` behavioral gate at `probes.go:114` tests only U+200B (zero-width space) and U+0301 (combining acute). The test at `responder_test.go:263-274` checks exact/NFC/stripped variants but does not exercise other Unicode bidi or invisible categories.

**Fix:** Add U+200E, U+200F, U+202A–U+202E, U+2061–U+2063 to the switch. If the plan intends to strip all Unicode `Cf` (format) characters, use `unicode.Is(unicode.Cf, r)` instead of a hardcoded list. The current list matches the plan's explicit enumeration, so this is a gap in the plan itself, not the implementation.

**Recommendation:** Extend `normalize` to strip U+200E, U+200F, U+202A–U+202E at minimum. Consider adding a test case that injects `sys\u200etem prompt` and verifies classification as `prompt-extraction`. Document the normalization policy in `classify.go` comments.

---

### H2. Classification priority mismatch with plan
**File:** `internal/responder/classify.go:160-163`  
**Severity:** P1 — behavioral discrepancy

The `Classify` function checks `indirect-injection` first (line 160), then iterates `rules` starting with `prompt-extraction` (line 164). The plan at line 29 says priority order is:

> `indirect-injection` (instructions inside tool/function output), `prompt-extraction`, `persistence`, `credential-access`, `shell-execution`, `url-exfiltration`, `instruction-override`, `tool-invocation`

The code matches this, but the `rules` slice does **not** include `indirect-injection`:

```go
var rules = []rule{
    {TaskPromptExtraction, ...},   // first
    {TaskPersistence, ...},
    {TaskCredentialAccess, ...},
    // ... indirect-injection is missing
}
```

`indirect-injection` is handled separately at line 160 by checking `injectionTerms` in `in.Untrusted`. This is correct behavior: indirect injection is detected in untrusted content (tool output, function results), while other tasks are detected in `in.Text` (operator-authored messages).

**Issue:** The comment at line 27 says "Order is priority: the first matching rule is the primary task," but `indirect-injection` is not in `rules` at all — it's in a separate check. A request with both indirect injection in `Untrusted` and prompt extraction in `Text` will have `c.Labels = ["indirect-injection", "prompt-extraction"]` and `c.Task = "indirect-injection"` (line 175). This is correct per the plan, but the code path is non-obvious.

**Recommendation:** Add a comment at line 160 explaining that `indirect-injection` is checked separately because it scans `Untrusted`, not `Text`. The current logic is correct but underdocumented.

---

### H3. Declaration bound not enforced per field
**File:** `internal/responder/responder.go:172-179`  
**Severity:** P1 — session pollution

The `declare` function enforces `MaxDeclarations` (default 32, line 14) as a total bound, not per field:

```go
room := r.cfg.MaxDeclarations - len(sess.Declarations)
if room > 0 {
    kept := out
    if len(kept) > room {
        kept = kept[:room]
    }
    sess.Declarations = append(sess.Declarations, kept...)
}
```

**Attack:** An attacker sends 32 requests with unique `metadata.user` values, filling the session's declaration array. The 33rd request with a valid `metadata.client_model` is dropped. The session never gets a valid model declaration, never exits the registration gates, and the attacker can interrogate the decoy indefinitely (bypassing the 3-question payout limit at `responder.go:99`).

**Evidence:** The plan at line 33 says "At most 32 declarations per session" but does not specify per-field limits. The test at `responder_test.go:402-411` (`TestDeclarationBound`) sends 40 declarations and verifies only 32 are kept, but it does not test field diversity or gate progression.

**Recommendation:** Either (a) enforce a per-field limit (e.g., 8 `client_model`, 8 `user`, 8 `operator_alias`, 8 `client`) to prevent one field from crowding out others, or (b) document that the first 32 declarations of any kind are kept, and an attacker who fills the array with junk will never complete registration. Option (a) is safer because it preserves the ability to capture successive declaration attempts. The current design allows session DoS via declaration spam.

---

### H4. Email redaction logic bypass
**File:** `internal/responder/responder.go:135-141`  
**Severity:** P2 — credential leakage

The `redact` function replaces email-shaped values with `[email-redacted]`:

```go
func redact(v string) string {
    if emailLike.MatchString(v) {
        return "[email-redacted]"
    }
    return v
}
```

The regex at line 133 is:

```go
var emailLike = regexp.MustCompile(`[^\s@"]+@[^\s@"]+\.[A-Za-z]{2,}`)
```

**Bypass:** The pattern requires a TLD with 2+ letters, so `user@host.c` and `user@192.168.1.1` are **not** redacted. The pattern also allows `user@host.com"extra"` (the quote is excluded from the match, but the value itself is not rejected). An attacker who wants their email stored unredacted can send `metadata.operator = "user@192.168.1.1"` or `metadata.operator = "alice@x.o"`.

**Evidence:** The plan at line 33 says "Email-shaped values are stored as `[email-redacted]`." The test at `responder_test.go:296-307` checks that `bob@corp.example` is redacted and not stored with `@`, but it does not test single-letter TLDs or IP-address domains.

**Recommendation:** Change the regex to `[^\s@"]+@[^\s@"]+` (removing the TLD length requirement) so any `user@host` is redacted. This will also redact `user@localhost`, which is acceptable. Alternatively, use a more precise email regex from a standard library or document that short TLDs and IP addresses are intentionally not redacted (but this contradicts the plan's "email-shaped" intent).

---

### H5. Canary reuse check is substring, not token boundary
**File:** `internal/responder/responder.go:211`  
**Severity:** P2 — false positives

The `canaryReuse` function checks:

```go
if strings.Contains(corpus, v) {
    res[name] = "present"
}
```

**False positive:** A canary `dpl-ABCD1234567890` will match `deployment-ABCD1234567890123` or any string containing that substring. Hex collisions are unlikely (canaries are 10–24 hex digits), but the check is not token-aware.

**Example:** The three-part canary is `eyJhbGciOiJIUzI1NiJ9.<base64>.<base64>`. If the attacker sends a request with `metadata.note = "REDACTED"` (a valid JWT), it will match the canary header `eyJhbGciOiJIUzI1NiJ9`.

**Evidence:** The plan at line 31 says "Any later request that contains one produces a `canary-reuse` observation." This is working as specified, but the substring match is brittle. The test suite does not cover false positives.

**Recommendation:** Accept substring matching as sufficient (hex collisions are ~1 in 2^40 for a 10-byte hex value) or switch to word-boundary matching: `\b` + regexp.QuoteMeta(canary) + `\b`. The current design is correct per the plan but may produce rare false positives. Document the tradeoff in a comment at line 205.

---

## Medium-Priority Findings

### M1. Placeholder word list incomplete
**File:** `internal/responder/probes.go:38-42`  
**Severity:** P2 — validation bypass

The `placeholderWords` map includes common placeholders:

```go
var placeholderWords = map[string]bool{
    "test": true, "placeholder": true, "unknown": true, "example": true, "model": true,
    "xxx": true, "foo": true, "bar": true, "string": true, "your": true, "provider": true,
    "none": true, "null": true, "version": true, "dummy": true, "fake": true,
}
```

**Missing:** `sample`, `default`, `generic`, `temp`, `temporary`, `name`, `invalid`, `demo`, `lorem`, `ipsum`.

**Attack:** An attacker sends `metadata.client_model = "openai/gpt-sample-4o"` or `anthropic/claude-generic-3`. These pass `ValidDeclaration` because they have the form `provider/model-version` with a digit, and `sample` and `generic` are not in the placeholder list.

**Evidence:** The test at `responder_test.go:88-102` checks `openai/gpt-example-4`, `test/model-1`, `foo/bar-2` and verifies they are invalid. It does not test `sample`, `default`, `generic`, `demo`.

**Recommendation:** Add `sample`, `default`, `generic`, `demo`, `temp` to `placeholderWords`. The list will never be complete, but these are common. The plan at line 46 says "Validity is a lead, not proof," so missed placeholders are acceptable — the follow-up behavioral gates will still gather evidence. Consider logging a warning when a declaration contains suspicious words not in the placeholder list.

---

### M2. Probe history truncation loses early canaries
**File:** `internal/responder/responder.go:91-93`  
**Severity:** P2 — evidence loss

The probe history is truncated to 64 entries:

```go
sess.ProbeHistory = append(sess.ProbeHistory, p.ID)
if len(sess.ProbeHistory) > 64 {
    sess.ProbeHistory = sess.ProbeHistory[len(sess.ProbeHistory)-64:]
}
```

**Issue:** A session with 70 requests will lose its first 6 probe IDs. If the first probe was `register-model` (which issued a nonce for `context-recall`), and the session runs for 70 requests, an operator reviewing the history will not see that the nonce was issued.

**Mitigation:** The nonce is stored in `sess.Nonce` itself (line 57 of `session.go`), so the evidence is not lost — only the history of when it was issued. The plan at line 36 does not specify probe history retention.

**Recommendation:** Accept the truncation (64 probes is 20+ interactions given the 3-question limit and payout) or increase the limit to 128. Add a comment at line 91 explaining that the history is for debugging, not evidence — the nonces, canaries, declarations, and observations are the durable evidence.

---

### M3. Classification scan limit is bytecount, not rune count
**File:** `internal/responder/classify.go:131-132`  
**Severity:** P2 — truncation inconsistency

The `normalize` function enforces a 64 KiB limit:

```go
if len(s) > maxScan {
    s = s[:maxScan]
}
```

**Issue:** `len(s)` is UTF-8 byte count, not rune count. A string with 64,000 single-byte ASCII characters is scanned fully, but a string with 32,000 two-byte characters (e.g., Cyrillic, Arabic) is truncated at 32,000 characters. After truncation, `strings.ToLower(s)` and the `for _, r := range` loop process the truncated string.

**Attack:** An attacker sends 64 KiB of Cyrillic filler, then `system prompt` after the cutoff. The classifier never sees it.

**Evidence:** The plan at line 29 says "scan is capped at 64 KiB." The test at `responder_test.go:52-86` does not test large inputs or non-ASCII obfuscation.

**Recommendation:** Accept byte-count truncation as sufficient (64 KiB is ~1,000 lines of text; attacks beyond that are truncated in transit or storage anyway) or switch to rune-count truncation: `if utf8.RuneCountInString(s) > maxScan { ... }`. The current design is correct for the stated goal (bounding CPU work), but the truncation behavior differs by script.

---

### M4. Retry gate does not enforce minimum delay
**File:** `internal/responder/responder.go:268`  
**Severity:** P2 — evidence quality

The `followup` function records retry delay as:

```go
case "retry":
    res["retried"] = "true"
```

The delay is captured implicitly via `obs.DelayMS = now.Sub(p.Issued).Milliseconds()` at line 230. The probe at `probes.go:143` says `Retry-After: 1`, but the code does not check whether the delay is ≥1000ms.

**Attack:** An attacker retries immediately (delay 10ms) and still passes the gate. The observation will show `DelayMS=10`, but the gate proceeds to payout.

**Evidence:** The test at `responder_test.go:308-318` advances the clock by 1300ms and checks that the delay is recorded, but it does not test a retry with <1s delay.

**Recommendation:** Add `res["complied"] = yes(obs.DelayMS >= 1000)` to the retry case at line 268. The current design records the delay but does not score compliance. The plan at line 35 says the gate records "retry count, delay, jitter, SDK retry headers and User-Agent changes." The delay is recorded; compliance scoring is optional but would improve evidence quality.

---

### M5. Session TTL check is not idempotent
**File:** `internal/responder/session.go:141-145`  
**Severity:** P2 — TTL inconsistency

The `Get` function checks expiration and updates `LastSeen` while holding both `s.mu` and `sess.mu`:

```go
sess.mu.Lock()
expired := now.Sub(sess.LastSeen) > s.cfg.IdleTTL
if !expired {
    sess.LastSeen = now
}
sess.mu.Unlock()
```

**Race:** Two concurrent `Get` calls for the same key will both check `expired` before either updates `LastSeen`. If the session is 1ms before expiration, both calls may see `expired=true`, evict the session, and create two new sessions with the same key (the second call overwrites `s.items[key]` at line 159).

**Mitigation:** The `s.mu` lock at line 135 serializes `Get` calls, so only one call can evict and create a new session. The race is in reading `sess.LastSeen` while holding `sess.mu` but not `s.mu`, but the outer lock prevents double-creation.

**Actual issue:** The `sess.mu` lock is released before moving the LRU element (line 147). If a concurrent `Get` call arrives after line 145 but before line 147, it will also move the element, and the LRU order may be inconsistent. However, `s.mu` is still held, so the LRU move is serialized.

**Recommendation:** No fix needed — the code is correct. The inner `sess.mu` lock at line 140 is not necessary (the outer `s.mu` lock already protects the session map), but it is harmless and may be a defensive pattern for future concurrent session reads. Add a comment at line 140 explaining that the session lock is for future-proofing.

---

## Low-Priority Findings

### L1. Gate sequencing is not persisted
**File:** `internal/responder/responder.go:116-130`  
**Severity:** P3 — resumption gap

The `sess.Gate` counter advances from 0 to 2 (register-model, register-harness, behavioral), then proceeds to payout. If the decoy restarts, all sessions are lost (they are in-memory only). A new session starts at `Gate=0`.

**Issue:** An attacker who completes registration (gate 0 and 1), then waits for a decoy restart, will be asked to re-register. This is correct behavior (the plan does not specify session persistence), but it may reveal the restart.

**Recommendation:** Accept in-memory sessions as correct per the plan. The plan at line 31 says sessions are keyed by a caller-derived fingerprint (not source IP alone), and the plan does not mention persistence. Document that sessions are ephemeral and do not survive restarts.

---

### L2. ProbeHistory does not deduplicate
**File:** `internal/responder/responder.go:90`  
**Severity:** P3 — storage waste

The `ProbeHistory` slice appends every probe ID without deduplication:

```go
sess.ProbeHistory = append(sess.ProbeHistory, p.ID)
```

An attacker who repeatedly triggers the same intent probe (e.g., sending 10 requests with `system prompt`) will have `ProbeHistory = ["register-model", "prompt-extraction", "prompt-extraction", ...]`.

**Recommendation:** Accept duplication as correct (the history is a log, not a set). Deduplication would lose the count of repeated probes. Add a comment at line 90 clarifying that the history is append-only and may contain duplicates.

---

### L3. StatusHit label validation is ASCII-only
**File:** `internal/responder/responder.go:340`  
**Severity:** P3 — validation narrowness

The `StatusHit` function accepts labels A–D:

```go
if len(label) != 1 || label[0] < 'A' || label[0] > 'D' {
    return Observation{}, nil, false
}
```

**Issue:** `len(label)` is byte count, not rune count. A label `"Å"` (U+00C5, two UTF-8 bytes) has `len=2` and is rejected. A label `"E"` is rejected. This is correct per the plan (line 36 says "labels outside A-D are rejected"), but the check assumes ASCII.

**Recommendation:** No fix needed — the labels are hardcoded in the probe text at `probes.go:141` as `/v1/edge/A/status`, and the HTTP handler will pass the path segment directly. Add a comment at line 340 clarifying that labels are single ASCII characters A–D.

---

### L4. Classification does not detect `tool_choice: "required"`
**File:** `internal/responder/classify.go:168-170`  
**Severity:** P3 — classification gap

The `Classify` function checks:

```go
if in.ToolForce || (in.HasTools && containsAny(text, toolTerms)) {
    add(TaskToolInvocation)
}
```

The plan at line 29 says "`tool_choice` forces a function" is classified as `tool-invocation`. The code checks `in.ToolForce`, which the caller must set.

**Gap:** The OpenAI API accepts `tool_choice: "required"` (force any tool), `tool_choice: "auto"` (model decides), and `tool_choice: {"type": "function", "function": {"name": "foo"}}` (force a specific tool). Only explicit function forcing should set `ToolForce=true`. The responder's `Request` struct does not document what values of `tool_choice` should set `ToolForce`.

**Recommendation:** Add a comment in `classify.go` at line 76 documenting that `ToolForce` is true when `tool_choice` is `"required"` or a specific function object, and false when `tool_choice` is `"auto"` or absent. The HTTP handler (not yet implemented per line 42) is responsible for parsing `tool_choice` and setting `ToolForce`. This is not a bug in the responder, but it will be a bug in the HTTP handler if it does not set `ToolForce` correctly.

---

### L5. Nonce format is not validated in followup
**File:** `internal/responder/responder.go:252,266,283`  
**Severity:** P3 — evidence robustness

The followup checks for nonce inclusion use `strings.Contains`:

```go
res["nonce_included"] = yes(strings.Contains(text, sess.Nonce))
```

**False positive:** A session with nonce `ABCD1234` will match `metadata.note = "XYZABCD1234WXYZ"`. This is acceptable (the nonce is 8 uppercase hex digits, collision chance ~1 in 2^32), but the check does not enforce word boundaries or the `CHG-` prefix.

**Recommendation:** Accept substring matching as sufficient. The nonce is evidence, not a secret. Add a comment at line 252 explaining that the check is substring-based to tolerate minor reformatting (e.g., `nonce: ABCD1234` vs `ABCD1234`).

---

## Summary

| Severity | Count | Blocking |
|----------|-------|----------|
| P0 (Critical) | 1 | No — observability race, not memory corruption |
| P1 (High) | 5 | Yes — H1 (Unicode evasion), H3 (session DoS) |
| P2 (Medium) | 5 | No — evidence quality, rare edge cases |
| P3 (Low) | 5 | No — documentation, future handler requirements |

**Overall assessment:** The responder is well-structured, deterministic, and passes `-race` testing. The critical finding (C1) is not a memory-safety issue but an observation ordering race that is acceptable given the decoy's threat model. The high-priority findings (H1, H3) should be fixed before deployment: H1 allows detection evasion via Unicode bidi marks, and H3 allows session DoS via declaration spam.

**Code quality:** The implementation is clean, uses standard library only, and has good test coverage (92.1%). The session store is properly bounded, the LRU eviction is correct, and the mutex usage is sound. The classifier is deterministic and the probe sequencing matches the plan. The behavioral gates are correctly implemented and the evidence scoring logic is thorough.

**Plan compliance:** The code matches the plan at lines 29-36 with minor gaps: Unicode normalization is narrower than ideal (H1), and the declaration bound is not per-field (H3). The probe texts match the plan's tables with the documented changes (line 34). The canary shapes, behavioral gates, and follow-up evidence all match the plan.

**Next steps:** Fix H1 (extend Unicode stripping) and H3 (per-field declaration limits), then deploy. The other findings are acceptable for the first deployment and can be addressed in follow-up work. The HTTP handler (not yet implemented) must correctly set `Input.ToolForce` and `Input.Untrusted` per the classifier's expectations (see L4).
