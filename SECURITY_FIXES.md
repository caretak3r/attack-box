# Required Security Corrections

Read `research/responder-review.md` and `research/telemetry-security.md` before finalizing the build.

## Responder

1. H1: normalize U+200E/U+200F and U+202A–U+202E in the classifier, with regression tests.
2. H3: bound declarations per field (reviewer suggests eight each), not only by a shared total.
3. Sanitize declaration values, including nested `metadata.client`, before they enter session state or telemetry.

## Telemetry

1. High: redact JSON credential fields, Basic/Bearer forms, API-key aliases and cookie-shaped fields in request/response bodies; add adversarial regression tests.
2. Medium: redact credential-bearing header aliases and Referer userinfo/query secrets.
3. Medium: reject known non-ingest New Relic key formats and require the documented ingest-key shape at configuration time.
4. Medium: honor bounded `Retry-After` seconds and HTTP-date values on 429.
5. Medium: make heartbeat scheduling/delivery independent of slow POST retries and attacker-filled queues.
6. Medium: reject/account for metric intake after Close; make the Sink contract and local JSON writer behavior agree so request processing cannot stall silently.
7. Review Low findings: strong random redactor keys, count transient failed POST attempts, and reject/scrub raw or escaped credentials in endpoint URLs.

## HTTP server snapshot

The host triaged `research/server-review.md` against the live source. Several reported blockers were false or referred to code added while the review ran:

- `edgeStatus` already uses `defer done()`, so its responder slot is released on every return, including disconnects. Do not change this based on the review's incorrect leak claim.
- `wait()` already selects on request context cancellation, including silent/idle holds. Add a context check to the streaming frame loop as defense in depth, but do not describe holds as uncancellable.
- `/api/version` is registered to `s.version` and has a test. Generic and vLLM cancel routes exist; stateless Ollama Responses does not need the same stateful behavior.
- The fixed Authorization-then-X-Api-Key session-key priority is deliberate. Document and test it rather than combining credentials blindly; combining them does not make header switching stable either.
- Validate malformed X-Forwarded-For handling with a security test and keep the trusted-proxy behavior explicit.

Remaining action: add streaming frame-loop cancellation, XFF malformed-input and disconnect regression tests, and verify cancelled Responses against the selected client contract. Do not implement the review's false route/leak findings.

## Protocol fidelity

Read `research/protocol-review.md` and fix all ten client-visible mismatches with contract tests: streamed `usage:null`, multi-prompt completion choices, Responses required fields/logprobs/usage details, cancelled nested item status, token-array embedding cardinality/counts, Ollama unload reason, `/api/create` non-streaming JSON and `/api/copy` success body. If a deliberately emulated older release differs, gate that behavior explicitly by persona version and document it; do not silently ignore the current contract.

## Runtime defaults

`cmd/attackbox/config.go` currently defaults `ATTACKBOX_OPENAI_ADDR` to `:8080`, which binds every interface and contradicts the private-application-listener design. Change the development default to `127.0.0.1:8080`; deployment must explicitly set the intended public or container address. Add a test proving the zero-configuration listener is loopback-only.
