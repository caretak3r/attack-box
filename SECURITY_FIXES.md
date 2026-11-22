# Required Security Corrections

Read `research/responder-review.md`, `research/telemetry-security.md`, and `REMAINING_WORK.md` before finalizing the build. The latter is the authoritative remaining-deliverables checklist beyond the security findings below.

## Responder

1. DONE: H1: normalize U+200E/U+200F and U+202A–U+202E in the classifier, with regression tests.
2. DONE: H3: bound declarations per field (reviewer suggests eight each), not only by a shared total.
3. DONE: Sanitize declaration values, including nested `metadata.client`, before they enter session state or telemetry.

## Telemetry

1. DONE: High: redact JSON credential fields, Basic/Bearer forms, API-key aliases and cookie-shaped fields in request/response bodies; add adversarial regression tests.
2. DONE: Medium: redact credential-bearing header aliases and Referer userinfo/query secrets.
3. DONE: Medium: reject known non-ingest New Relic key formats and require the documented ingest-key shape at configuration time.
4. DONE: Medium: honor bounded `Retry-After` seconds and HTTP-date values on 429.
5. DONE: Medium: make heartbeat scheduling/delivery independent of slow POST retries and attacker-filled queues.
6. DONE: Medium: reject/account for metric intake after Close; make the Sink contract and local JSON writer behavior agree so request processing cannot stall silently.
7. DONE: Review Low findings: strong random redactor keys, count transient failed POST attempts, and reject/scrub raw or escaped credentials in endpoint URLs.
8. DONE: All 11 findings in `research/secret-review.md` are closed in `internal/secret`. Only complete `[redacted]` or `[redacted:hmac256:<16 hex>]` markers and exact decoy canary shapes (including the JWT canary) are kept. Credential names are canonicalized (camelCase, acronyms, `\u` and percent escapes). JSON credential values of every type are redacted by structure, and nonsecret JSON is kept byte for byte. Cookie, PEM, quoted env/YAML, Bearer, empty-user Basic and URL userinfo shapes are covered. Fingerprints that do not match `hmac256:<16 hex>` are discarded. Fuzzing found two more defects, and both are fixed with regression tests: a JSON quote desync hid a later credential key, and a cookie name inside a cookie value broke idempotence. Each regex pass now runs once per input. The server cuts the body to `MaxLogBody` before it scrubs it, which removes a 1 MiB CPU-amplification path. A linear-scaling test runs in the default gate (`-race` on `internal/secret`: 6 s, was 116.617 s). Free-text limits are listed in `implementation_plan.md`.
9. `research/new-relic-hardening-review.md`: keep blocking JSONLog writers off the request path (or use bounded async/drop behavior), reject nested-escaped and arbitrary credential query parameters, scrub escaped keys in errors, expose recovered failed attempts in shipped metrics, cap custom backoff correctly, and count retries only when a subsequent POST actually runs.

## HTTP server snapshot

The host triaged `research/server-review.md` against the live source. Several reported blockers were false or referred to code added while the review ran:

- `edgeStatus` already uses `defer done()`, so its responder slot is released on every return, including disconnects. Do not change this based on the review's incorrect leak claim.
- `wait()` already selects on request context cancellation, including silent/idle holds. Add a context check to the streaming frame loop as defense in depth, but do not describe holds as uncancellable.
- `/api/version` is registered to `s.version` and has a test. Generic and vLLM cancel routes exist; stateless Ollama Responses does not need the same stateful behavior.
- The fixed Authorization-then-X-Api-Key session-key priority is deliberate. Document and test it rather than combining credentials blindly; combining them does not make header switching stable either.
- Validate malformed X-Forwarded-For handling with a security test and keep the trusted-proxy behavior explicit.

Remaining action: add streaming frame-loop cancellation, XFF malformed-input and disconnect regression tests, and verify cancelled Responses against the selected client contract. Do not implement the review's false route/leak findings.

## Protocol fidelity

DONE: all ten mismatches are fixed and covered by `internal/server/protocol_test.go` (each test fails against the previous code). The OpenAI `usage:null` chunk behavior is gated to the `openai` persona, because vLLM and Ollama omit the key; this is documented in `implementation_plan.md`. Original item: read `research/protocol-review.md` and fix all ten client-visible mismatches with contract tests: streamed `usage:null`, multi-prompt completion choices, Responses required fields/logprobs/usage details, cancelled nested item status, token-array embedding cardinality/counts, Ollama unload reason, `/api/create` non-streaming JSON and `/api/copy` success body. If a deliberately emulated older release differs, gate that behavior explicitly by persona version and document it; do not silently ignore the current contract.

## Runtime defaults

`cmd/attackbox/config.go` currently defaults `ATTACKBOX_OPENAI_ADDR` to `:8080`, which binds every interface and contradicts the private-application-listener design. DONE: the development default is now `127.0.0.1:8080`, a test proves it is loopback-only, and a wildcard and a specific address on the same port are rejected as a conflict; deployment must explicitly set the intended public or container address. Add a test proving the zero-configuration listener is loopback-only.

Also address the validated findings in `research/main-review.md`:

1. DONE: On partial-listener startup failure, join/report `nr.Close` errors rather than discarding them; prove cleanup with a failing listener and fake NR intake.
2. DONE: Put safe upper bounds on `MAX_SESSIONS`, `MAX_IN_FLIGHT`, `MAX_PER_SOURCE` and `MAX_BODY_BYTES` to reject operator configurations that trivially exhaust memory.
3. DONE: Require secret files to be private to the service account (reject group/other-readable files) and test permissive modes.
4. DONE: Emit the final runtime stop event before closing NR with a reliable local record, and handle empty `LastError` without malformed error text.
5. DONE: Reject userinfo in healthcheck URLs and validate/document the relationship between shutdown and stream timeouts.

## Deployment acceptance

When writing the Ubuntu deployment, treat `research/ubuntu-hardening.md` as leads and enforce these boundaries:

1. Default is preflight/dry-run. Require explicit `--apply`; require both `--disable-ssh` and `--console-confirmed` before masking SSH or changing cloud-init. Preserve a rollback copy of firewall configuration.
2. Block metadata before Docker starts and prove container egress cannot bypass host policy through Docker's FORWARD/DOCKER-USER path. Test DNS/NTP/New Relic allowances and denied destinations from inside gVisor, not only from the host.
3. Do not add Watchtower, automatic `docker compose pull`, unverified image tags or automatic reboots by default. Pin verified image versions/digests at deployment and make upgrades an explicit rebuild.
4. Use pinned DNS resolvers; do not force DNS-over-TLS unless the script actually configures and verifies it. Keep the initial package-bootstrap path working before locking egress.
5. Falco must not give the bait container Docker socket access. If host Falco needs privileged access, isolate it from the bait and document that residual host-monitoring privilege and kernel/eBPF support checks.
6. Keep writable state bounded and explicit; read-only root filesystem plus approved tmpfs/log paths only. Never mount host SSH, cloud, kube, AWS or Docker credentials.
7. Follow `research/ubuntu-validation.md`: no `--net-raw` by default, no cron reboot loophole, no automatic image pulls, and no assumption that `DOCKER-USER` exists under Docker's native nftables backend. Validate both Docker firewall backends and test the exact Log/Metric API endpoints from inside gVisor.
