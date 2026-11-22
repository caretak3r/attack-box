# Improve Attack Box: security intelligence and response quality

Date: 2026-11-22. Source baseline: `584a658`.

Implementation direction: Go runtime services. Architecture and setup documentation are required deliverables for each service change. This revision incorporates the owner's direction and an adversarial review of I01–I14 and C01–C17.

Purpose: collect reliable evidence about attacks against an internet-facing fake agentic service. Identify methods, payload families, exploit attempts, tool abuse, and changes in attack sequences. Generate coherent responses that let an interaction continue without giving the service real execution or network access.

This document proposes improvements. It does not authorize a deployment, a new data contract, or a new model provider. Track implementation in Beads. The priorities below describe value and dependency order; they are not claims that the features exist.

## Recommendation

Build a controlled observation service around a deterministic simulator. Prepare discovery routing with public ingress closed. Verify evidence collection, response consistency, and containment before opening the intended ports. Add deeper agent protocols only after the existing personas produce useful, reproducible observations.

Optimize for **distinct, well-supported attack sequences per operating day**, not request count or conversation length. A thousand copies of one scanner request are one payload family with a frequency measurement. A fake success response is not evidence that an exploit works against a real product.

For this measure, a supported sequence has retained request evidence, ordered server observations, capture-quality flags, and a reviewed technique hypothesis. Deduplicate with a versioned family rule. Report incomplete candidates separately. Distinctness is an analysis decision, not an attacker-supplied ID. Report the numerator with reachable sensor-hours, received traffic, sampling opportunity, and loss intervals. Do not use the measure alone to choose a response policy: random mutations can inflate novelty, and longer conversations can consist only of sensor-induced replies.

Retain the current separation between the bait and the host shipper. Retain bounded memory, disk, request bodies, response duration, and queues. Do not add a real shell, external fetcher, package installer, browser, or attacker-supplied tool execution to improve realism.

## Go service boundaries and documentation contract

Keep runtime implementation in the existing Go module at `/Users/rohit/attack-box/go.mod`. Use the repository's declared Go version and build tools. Prefer the standard library and existing packages. Do not replace existing infrastructure software merely to make every process Go. Shell remains appropriate for provisioning; Python remains appropriate for the existing official-client test harness. Neither should become the new production response or analysis service.

| Component | Current or proposed | Responsibility and boundary |
|---|---|---|
| Go bait | Exists: `/Users/rohit/attack-box/cmd/attackbox/main.go` | Public protocol handling, bounded scenario state, deterministic response plans, redacted local observations. No new outbound connections or real tools. |
| Go shipper and stdin adapters | Exist: `/Users/rohit/attack-box/cmd/attackbox-shipper/main.go` | Authenticated local producers, bounded admission and durable queue, New Relic delivery. The host ingest key stays here. Keep analysis out of this trusted delivery path. |
| Go analysis job | Proposed; not implemented | Consume approved redacted exports in a separate analysis environment, outside the decoy and the operator's Mac. Produce bounded payload families, candidate links, and reports. Start with a batch command, not an always-on public API, broker, or new database. |
| Response generator | Deterministic code exists; typed planner is proposed | Remain a Go package inside the bait. Do not introduce a network service for ordinary response generation. I14 is an optional offline experiment, not an implicit model-service dependency. |

Document the current and proposed architecture in `/Users/rohit/attack-box/docs/architecture.md`. Document supported setup and operations in `/Users/rohit/attack-box/docs/operator.md`. Each implementation change must update both where applicable, including binary and service names, protocol/schema versions, inputs/outputs, trust boundaries, identities, secrets, network policy, storage, resource bounds, shutdown, loss behavior, and recovery. List every actual flag/environment variable with its default and validation rule. Mark planned settings as planned; do not publish commands for nonexistent binaries or options.

A service is not ready when it merely compiles. Its setup must be reproducible from a clean supported host, with preflight, private validation, public exposure, health checks, restart, rollback/rebuild, and containment verification. Document test evidence and remaining deployment-only gates. Changing Go service boundaries or data contracts requires a concrete implementation design, not a hidden consequence of a documentation edit.

## Current foundation and limits

The current implementation already has three API personas, streaming, local response templates, bounded session state, credential scrubbing, request and response capture, six telemetry streams, a host shipper, and a durable delivery queue. Reuse these components.

| Observation from current source | Consequence |
|---|---|
| `/Users/rohit/attack-box/compose.yaml:60` disables vLLM and Ollama. Published proxy ports bind to loopback at line 193. | The supplied configuration does not expose the intended discovery services. |
| `/Users/rohit/attack-box/internal/responder/responder.go:147` selects an intent probe or a registration sequence. | General requests can receive registration questions instead of plausible task responses. |
| `/Users/rohit/attack-box/internal/responder/probes.go:69` and subsequent cases disclose simulated operations. | The current research probes can reveal the sensor and influence later behavior. This is a design choice, not an execution vulnerability. |
| `/Users/rohit/attack-box/internal/responder/classify.go:31` defines fixed keyword rules. | Labels are useful leads. They do not establish exploit validity or distinguish all encoded and multi-turn attacks. |
| `/Users/rohit/attack-box/internal/server/parse.go:166` counts tool definitions. `/Users/rohit/attack-box/internal/server/openai.go:133` returns a text completion. | Accepting a tools field does not provide a coherent tool-call lifecycle. |
| `/Users/rohit/attack-box/internal/server/log.go:277` bounds and redacts captured text. | The retained body is a transformed, sometimes partial observation. It is not the original wire payload. |
| `/Users/rohit/attack-box/internal/shipper/record.go:104` restricts streams by producer role. | New evidence types must preserve authenticated provenance and admission limits. |

## Priority order

Effort: S = one bounded change; M = several related changes; L = a new subsystem or protocol. Risk means implementation risk. Confidence refers to the cited current limitation, not to predicted attacker engagement.

| ID | Priority | Improvement | Effort | Risk | Confidence |
|---|---|---|---|---|---|
| I01 | P0 | Expose and verify the discovery profile | M | Medium | High |
| I02 | P0 | Record evidence provenance and collection limits | M | Medium | High |
| I03 | P0 | Correct follow-up and canary attribution | M | Medium | High |
| I04 | P1 | Separate passive responses from active probes | M | Medium | High |
| I05 | P1 | Add coherent simulated task and resource state | L | High | High |
| I06 | P1 | Make tool, JSON, and streaming behavior consistent | L | High | High |
| I07 | P1 | Classify attack methods with evidence and uncertainty | M | Medium | High |
| I08 | P1 | Build a bounded payload and indicator collection | M | Medium | High |
| I09 | P1 | Group related sessions into candidate campaigns | M | Medium | High |
| I10 | P1 | Capture edge rejections and exploitation attempts | M | Medium | High |
| I11 | P1 | Produce useful intelligence views and loss accounting | M | Medium | High |
| I12 | P1 | Add replay and adversarial response evaluation | M | Low | High |
| I13 | P2 | Add isolated agent-protocol scenarios | L | High | High |
| I14 | P2 | Evaluate optional language generation offline | M | High | High |

### I01 — Expose and verify the discovery profile

**Evidence:** `/Users/rohit/attack-box/compose.yaml:60`, `/Users/rohit/attack-box/compose.yaml:193`, `/Users/rohit/attack-box/docker/nginx/nginx.conf:64`, and `/Users/rohit/attack-box/deploy/nftables/attackbox.nft`.

Provide an explicit deployment profile for public TCP 11434 (Ollama), 8000 (vLLM), and 443 (generic HTTPS). Keep port 80 optional and redirect it to public 443, not 8443. Route each port to its own persona. Keep the underlying OpenAI listener private. Update the provider firewall, host filtering, proxy routing, startup checks, and operator guide together.

Use one consistent product version and model catalog per persona. The shared commercial-model list in `/Users/rohit/attack-box/compose.yaml:64` should not automatically become the advertised local-model catalog on all ports. Pin profile metadata to tested protocol fixtures. Do not advertise a real vulnerability as confirmed merely because a banner names an affected version.

**Accept when:** an independent test host reaches each intended API, receives the correct models and response format, and cannot reach management ports. The same deployed sandbox cannot initiate internet or metadata connections. Log the active ports, profile version, and observation interval. Syntax-only Compose tests do not meet this gate.

Test IPv4 and IPv6 separately, including direct access that bypasses the proxy. Bind any forwarded identity or correlation metadata to the configured proxy peer, not to the whole container subnet. Validate the closed-ingress build first; opening public ingress is the final deployment action. Recovery uses a tested provider-console path.

### I02 — Record provenance and collection limits

**Evidence:** `/Users/rohit/attack-box/internal/telemetry/event.go`, `/Users/rohit/attack-box/internal/server/log.go:78`, `/Users/rohit/attack-box/internal/server/log.go:277`, and `/Users/rohit/attack-box/internal/shipper/record.go`.

Add a versioned evidence contract. Each observation needs sensor ID, deployment ID, process boot ID, producer role, request ID, event time, ingest time, persona version, response-policy version, and redaction version. Keep attacker-declared identity separate from server-assigned identity. Do not accept provenance fields from request metadata.

Record capture state explicitly: complete within the accepted limit, body limit exceeded, log prefix only, parse failure, unsupported content, sampled out, or queue loss. Record captured bytes separately from declared content length. Mark the full byte count as unknown when the server stops reading. The current oversized-request fingerprint covers the retained request prefix once the request-body limit is reached; do not label it a full original-payload hash.

Keep separate fingerprints for the observed input bytes, redacted content, and normalized analysis representation. Use keyed hashes for sensitive input correlation. Record key epochs and transformation versions. A digest of redacted content proves consistency of that content, not authenticity of the request or sender. Shipper roles establish local producer identity, not integrity after host-root compromise.

Record evidence stages separately: observed by the process, admitted to a queue, written to the socket, committed to the shipper queue, accepted by the remote API, and verified available for analysis. `/Users/rohit/attack-box/internal/telemetry/spool.go` uses a one-way protocol; a successful socket write does not acknowledge durable receipt. Do not claim end-to-end durability from the disk queue alone. If durable producer receipts are added, specify bounded retransmission, receiver acknowledgement after disk commit, and replay identity before changing the wire contract.

Reconcile producer boot/sequence ranges and cumulative counters at each available stage. Reserve bounded health-report capacity separately from payload records. Counter reports can themselves be lost; after saturation followed by a crash, mark the unreconciled interval and missing count unknown. Never infer zero loss from the absence of a drop event. Use off-host receipt times and expected deployment manifests to detect gaps. Host-root compromise can forge local events, counters, keys, and heartbeats; external receipt proves receipt, not truth. Mark the affected interval suspect and retain already-received evidence outside the decoy's deletion authority.

Use monotonic durations for local ordering and UTC times for cross-system comparison. Record clock quality and restart boundaries. Do not repair uncertain cross-host order by inventing timestamps. A rejected schema version must produce a protected aggregate rejection signal; it must not silently disappear from the denominator.

**Accept when:** partial requests, invalid UTF-8, redaction expansion, chunked events, replayed delivery, and queue overflow preserve honest completeness flags where records survive. Saturation followed by producer termination before its next heartbeat produces an unknown-loss interval, not a zero-loss report. Unknown schema versions fail with a bounded reason. New attributes survive shipper validation without silent loss. Existing producer-role isolation tests remain green.

### I03 — Correct follow-up and canary attribution

**Evidence:** `/Users/rohit/attack-box/internal/responder/responder.go:252` checks canaries against the full corpus. `/Users/rohit/attack-box/internal/responder/responder.go:279` scores many follow-ups against accumulated request text. Only some branches use the latest reply.

Score the new reply after the relevant probe, not material copied from earlier turns. Record the probe request ID, issue time, expected reply channel, and reply request ID. For full-history clients, identify a bounded message delta or record an ambiguous-history result. Do not credit a client for an argv array, nonce, URL, or content hash that appeared before the probe.

Track probe delivery separately from probe selection: selected, partially sent, fully sent, or unknown. The responder currently marks a pending probe before the HTTP path sends it. Do not credit an earlier concurrent request as a reply to an undelivered probe. Bytes written establish server-side delivery progress; they do not prove that the client consumed the response.

Keep a bounded issuance record with session, probe ID, state version, response digest, expected reply type, and expiry. All client-supplied history is a claim. Matching a nonce or copied assistant response shows possession of text, not who generated it or whether it was obeyed. Invented, reordered, expired, or conflicting history must not create a verified follow-up. When the API lacks a reliable turn reference, record ambiguity instead of forcing a match. Probe slots need request-specific identities; one mutable pending slot cannot correctly attribute overlapping exchanges.

Record canary states separately: issued, present in returned history, newly echoed, placed in a requested destination, presented back as a credential, and independently observed at an owned receiver. Presence in a prompt is not exfiltration. Cross-session correlation must use an explicit issuance record and bounded retention; do not expose a global token lookup to clients. Match only issued synthetic tokens, not every token with a similar shape.

An owned callback receiver is optional and requires a separate deployment decision. Do not fetch an attacker destination or direct a client to contact a third party to test a canary. Even a callback can come from a researcher, security scanner, preview service, or replay; retain those alternatives. A public synthetic-token prefix is never a redaction exemption. Only an exact currently issued synthetic value can receive that treatment, with a bounded issuance registry.

**Accept when:** replaying the issued response produces no new compliance or exfiltration finding. A new client reply produces one deduplicated observation. Tests cover changed message order, truncated history, tool messages, retries, concurrent requests, disconnect before delivery, and overlapping streams. A claimed action and an observed action remain distinct.

### I04 — Separate passive responses from active probes

**Evidence:** `/Users/rohit/attack-box/internal/responder/responder.go:129` and `/Users/rohit/attack-box/internal/responder/probes.go` implement bounded counter-probes. This supports fingerprint experiments but does not provide a passive comparison group.

Keep the existing counter-probe policy. Add a passive policy that gives coherent, bounded task responses without immediately asking for the client model, harness, or operator alias. Add a third policy only if needed: a small number of intent-specific follow-ups after the client expresses a concrete objective.

Assign policy once per session with a stable seed. Record assignment before the first response. Set a probe budget and stop repeated questioning. Keep response policy separate from attack labels so that a classifier update does not silently change the experiment. Record statements introduced by the sensor and exclude them from evidence of independently initiated attacker behavior.

Use server-controlled assignment; request fields cannot select a treatment. Record repeated session creation, assignment churn, and cross-cohort campaign links. An attacker can still create sessions until a preferred cohort appears. Treat observed results as selection-biased when that occurs. Include sessions that stop immediately; do not compare only successful continuations. Hold exposure period, persona, and scenario mix constant where possible. Do not change the policy online to maximize apparent engagement or novelty.

**Accept when:** the same seed gives the same assignment; benign baseline prompts do not enter registration gates in passive mode; repeated requests do not switch cohorts. Compare continuation rate, unique methods, evidence completeness, and resource cost by cohort. Group correlated traffic when comparing results. Do not treat sessions from one campaign as independent experiments.

### I05 — Add coherent simulated task and resource state

**Evidence:** `/Users/rohit/attack-box/internal/responder/session.go` stores gates and canaries. `/Users/rohit/attack-box/internal/responder/probes.go:152` releases a fixed payout. There is no general simulated workspace with consistent resource operations.

Add a small catalog of synthetic scenarios: document retrieval, deployment assistant, code assistant, and internal support agent. Each scenario has an immutable fixture plus a bounded per-session overlay. Model fake files, jobs, tool results, permissions, and resource versions as data. Never map a requested path to the host filesystem. Never interpret a submitted command through a shell.

Use an explicit transition function: current state + validated intent → new state + response plan + observation. A simulated write must affect a later simulated read. A rejected write must not appear as successful. A completed job must keep the same identifier and result. Keep separate sessions isolated. Limit objects, bytes, history depth, operations, and idle lifetime.

Only server-owned state and retained issuance records authorize transitions. Client-supplied assistant messages, tool results, role names, response IDs, model declarations, and campaign links cannot grant permissions or rewrite history. Match a permitted continuation to a session-scoped outstanding operation, then validate its fields. Client tool output remains client-reported data even when its call ID matches. Unknown or expired IDs produce the persona's not-found or conflict result. Unverifiable histories can be recorded without becoming authoritative state.

Serialize state transitions per session. Assign a monotonically increasing state version within a server-assigned boot/session epoch. Validate and commit one complete transition before emitting its response. Store the response plan and commit observation atomically with the in-memory transition. Never hold the state lock while pacing or writing a stream. Order requests by server admission; reject an explicit stale-version precondition instead of overwriting newer state.

Cancellation before commit leaves state unchanged. Cancellation or disconnect after commit stops delivery but does not roll back the simulated mutation. Keep both outcomes. A documented idempotency key is scoped to session, operation, epoch, and TTL. The same key and normalized arguments returns the recorded outcome without another mutation; the same key with different arguments returns conflict. Without a key, do not infer exactly-once execution from matching text. After restart, use a new epoch and refuse stale handles; do not pretend volatile state survived. Campaign correlation never restores authorization.

Make unknown behavior plausible and explicit in the protocol: unsupported operation, missing resource, or a bounded clarification. Do not claim that an external system was contacted. Internally tag every generated result as simulated, even when a passive response does not repeat a simulation banner to the client.

**Accept when:** multi-turn fixtures preserve state, permission boundaries, and stable identifiers across JSON and streaming responses. Forged assistant success, invented tool output, and foreign IDs cannot modify state. Deterministic schedules cover conflicting writes, stale versions, duplicate retries, changed-body retries, cancellation before and after commit, and restart. Each response references its committed state version. Interleaved sessions cannot read each other's objects. Path traversal, command substitution, and URLs remain inert data.

### I06 — Make tool, JSON, and streaming behavior consistent

**Evidence:** `/Users/rohit/attack-box/internal/server/parse.go:166` counts tools. `/Users/rohit/attack-box/internal/server/openai.go:121` ends text output with `stop`. `/Users/rohit/attack-box/internal/server/openai.go:690` wraps JSON-mode output in fixed fields.

Create a typed response plan with text, structured output, simulated tool activity, usage, finish reason, and terminal state. Render all protocol envelopes from this plan. Validate supported tool names and argument shapes. Preserve tool-call IDs and result association. Distinguish client-provided tool output from a server-generated simulated result.

Support a bounded, documented subset of structured-output schemas. Validate required properties, enums, types, and nesting. Reject unsupported schemas in the persona's normal error format; do not return a different object while claiming schema compliance. Bound schema size, recursion, string length, and output size.

Pin a capability matrix for each advertised profile: supported routes, sampling parameters, output limits, structured formats, model management, tool behavior, and error cases. Honor supported parameters or return a profile-correct rejection. Do not silently accept a one-token limit while emitting an unbounded answer. Use one token-accounting method for budgeting, usage, and finish reason; an estimate is internally labeled as an estimate. Restrict schemas to local data: no external references, executable validators, unbounded regular expressions, or network resolution.

Validate the response plan before the first byte is sent. Keep one terminal protocol event. A failure after emission starts follows that protocol's error/termination rule; do not append a fresh JSON fallback to a partial SSE or NDJSON stream. Cap amplification by output bytes and frame count as well as time. Identical semantic replay requires the same initial state, policy, profile, accepted parameters, and seed; identical prompt text alone is insufficient.

Keep simulated tools internal to the fake service by default. A response that emits a real client-side tool call can cause the connecting client to execute it. Do not turn captured attacker instructions into executable client tool calls. Any interoperability scenario that requires tool-call output must use explicitly permitted inert operations and a separate review.

**Accept when:** official-client tests check parsed content and finish reasons, not only HTTP status. Streamed and non-streamed outputs represent the same result. Tool fragments reconstruct valid arguments. Cancellation ends emission. Token limits, retries, unsupported fields, and partial streams have consistent terminal states. No fallback emits an unvalidated action.

### I07 — Classify attack methods with evidence and uncertainty

**Evidence:** `/Users/rohit/attack-box/internal/responder/classify.go:31` uses a fixed priority list and `/Users/rohit/attack-box/internal/server/parse.go` reduces input to operator and untrusted text.

Keep fast rules on the request path. Move deeper classification to a bounded analysis stage. Separate intent, technique, entry surface, target resource, obfuscation, and observed outcome. Preserve message role, tool-result origin, content-part index, and extraction offset. A generic URL or the word “shell” is not enough to establish malicious intent.

Cover direct and indirect injection, role spoofing, instruction extraction, credential requests, command and code execution attempts, SSRF and metadata probes, data collection and exfiltration intent, persistence attempts, memory poisoning, tool-description poisoning, unauthorized delegation, resource exhaustion, and ordinary scanner traffic. Keep an unknown class. Map supported labels to a pinned OWASP or MITRE taxonomy version; do not invent technique IDs.

Decode only recognized text encodings under strict depth, byte, and expansion limits. Record each transform. Preserve the retained redacted representation alongside the derived form. Detect multilingual and split-turn candidates without treating decoding or translation as proof. Record classifier version, matched evidence, confidence, and analyst corrections. Never execute a payload to classify it.

Apply scrubbing again after each material decoding or extraction step and before any persistence, export, fixture promotion, or generator input. Encoded credentials can become visible only after the initial scrub. Retain keyed correlation and structural features without logging the newly decoded secret. Mark fields removed by redaction so that absence is not mistaken for an absent attack feature. Preserve raw-message role as a client claim separately from verified source provenance. Distinguish the observed request representation from wire bytes; HTTP libraries and proxies can normalize input before capture.

**Accept when:** a labeled corpus includes benign security discussion, ambiguous requests, encoded text, tool output, long context, multilingual text, and mixed attacks. Report precision and recall per class. Hold out whole payload families and time periods. Report abstentions. New rules must not silently relabel historical data without a new analysis version.

### I08 — Build a bounded payload and indicator collection

**Evidence:** `/Users/rohit/attack-box/internal/server/log.go` captures redacted bodies and `/Users/rohit/attack-box/internal/telemetry/event.go` chunks them. These records do not yet form a curated payload corpus or indicator index.

Create inert corpus records for retained payloads. Keep first and last observed times, occurrence count, persona, entry surface, campaign candidates, capture completeness, redaction version, exact retained-content hash, normalized-family hash, and representative request IDs. Keep the original retained representation; never replace it with only a normalized variant. Name normalization collisions explicitly.

Separate candidate discovery from reviewed promotion. Random padding, copied exploit names, or a fresh hash cannot automatically become a new technique. Bound candidate rate, per-source admission, corpus bytes, representative count, and analyst queue size. Reserve a random baseline sample with a recorded inclusion probability independent of inferred family or campaign, plus protected health capacity. Campaign-based fairness alone fails when the attacker creates many campaign candidates. Report candidate rejections and the remaining sampling opportunity; no finite sample guarantees retention of every rare attack.

Extract candidate domains, IP addresses, URLs, requested filesystem paths, command structure, package names, repository references, claimed CVEs, and submitted artifact hashes. Preserve context and source location. Distinguish attacker-supplied indicators from canaries and fixture values. A URL supplied by a client is an observed string, not confirmed attacker infrastructure. Validate an alleged CVE against the vendor advisory before assigning a vulnerability label.

Do not fetch submitted URLs, resolve arbitrary domains, follow redirects, install referenced packages, or execute collected content. Import published attack collections only as versioned, inert fixtures with source, license, retrieval date, and content digest. If binary or archive upload capture is added, cap bytes and keep opaque data quarantined; do not unpack it on the bait or analyst workstation.

Keep redacted evidence as the default. Any unredacted archive needs a separate retention and access decision. A durable spool is a delivery buffer, not a research archive. New archive storage is an explicit architecture choice.

**Accept when:** duplicate payloads group predictably, meaningful mutations remain available, canaries are excluded from external-indicator exports, and transformations are reproducible. Floods cannot exhaust storage. Exports remain inert when rendered. Retention expiry removes the intended records and records the deletion event without retaining their sensitive contents.

### I09 — Group sessions into candidate campaigns

**Evidence:** `/Users/rohit/attack-box/internal/server/server.go:370` derives sessions from source IP, user agent, and credential fingerprint. `/Users/rohit/attack-box/internal/responder/session.go` uses bounded in-memory sessions.

Retain local session identity. Emit explicit reset, idle-expiry, and capacity-eviction observations so that a broken sequence is not mistaken for client abandonment. Add a separate analysis-only campaign hypothesis using several independent signals: payload family, ordered routes, timing, requested targets, safe header features, client protocol behavior, and issued-canary reuse. Record each contributing signal and the rule version. Use source IP or ASN only as context. Shared NAT, proxies, copied scanners, and deliberate imitation make identity claims unreliable.

Count independent evidence sources, not just feature count. An attacker can copy a payload, route sequence, target, and canary together. A single bridge observation must not merge two established clusters through automatic transitive closure. Keep weighted, reversible links with evidence IDs, alternative explanations, expiry, and analyst decisions. Bound candidate comparisons, cluster membership, and link fan-out. Offline correlation must not mutate online session ownership, state, admission, or cohort selection.

Keep model and harness declarations as claims. Score a candidate model or harness only against known reference clients and held-out behavior. Return unknown when evidence is weak or conflicting. Do not infer a person's identity, location, or intent from an address or writing style.

**Accept when:** fixtures demonstrate both false-merge and false-split cases. Rotated credentials and addresses can form a weak candidate link without changing session isolation. A shared source IP does not force a merge. Analysts can inspect, reject, and split hypotheses. Cluster revisions do not overwrite source observations.

### I10 — Capture edge rejections and exploitation attempts

**Evidence:** `/Users/rohit/attack-box/internal/server/server.go:206` logs requests that reach the handler. Rejections before that handler need a different producer. `/Users/rohit/attack-box/docker/nginx/nginx.conf:14` writes access records to local files; it does not define a structured redacted edge-to-shipper contract.

Collect bounded metadata for TLS handshake failures, invalid HTTP, oversized headers, proxy body-limit rejection, unsupported content types, timeouts, and scans of unknown paths. Capture these at the layer that observes them. Join proxy and application records with a server-generated request ID. Overwrite client-supplied correlation headers at the trusted edge.

The current proxy request log can include raw query text and other client-supplied fields. Define a scrubbed structured format before forwarding it. Do not duplicate raw credentials into an edge log while the application log redacts them. A new edge producer needs its own authenticated role and limits; do not permit the bait to claim host or proxy observations.

Add inert fixtures for common application-exploit shapes: traversal, template injection, unsafe deserialization probes, command injection, upload attempts, and protocol confusion. Record the targeted route, supplied technique, and response. Keep emulator acceptance, actual process failure, and independently observed host activity separate. Do not equate a 200 response with exploitation.

Include scans for debug/admin routes, model inventory changes, model deletion or replacement, and unauthenticated resource consumption. Retain unmatched and rejected traffic as candidates, not automatic attacks. Expose only intentionally simulated routes. Keep the actual proxy and HTTP parser patched; do not reproduce request-smuggling or parser vulnerabilities for fidelity. Any extra edge sensor requires measured overhead and its own privilege boundary.

**Accept when:** tests rejected by the proxy and tests rejected by the application both produce correctly attributed evidence. Raw secrets and terminal control sequences do not reach analyst output. Body absence is explicit. Noise quotas protect host-health and rare-event telemetry. No HTTP-parser vulnerability is added for realism.

### I11 — Produce useful intelligence views and loss accounting

**Evidence:** `/Users/rohit/attack-box/newrelic/queries.md:13` contains `count(*WHERE`, an invalid query fragment. The same section treats missing attack-event streams as producer failure. Quiet egress or Falco streams can be legitimate. Existing queue and replay behavior must remain visible in analysis.

Build views for: new payload families; first observed techniques; multi-stage session timelines; changes in target routes; candidate campaigns; canary transitions; response-policy comparison; and collection health. Show both raw volume and deduplicated observations. Separate sensor-generated content, known test traffic, and observed client content.

Report denominators: exposed hours, reachable services, received requests, accepted requests, retained bodies, classified requests, dropped records, incomplete chunks, and sampled events. Separate planned probe delays from capacity rejection and unexpected failure. Record sampling policy and probability. Preserve representative novel payloads under a bounded budget; do not let a high-volume campaign consume every evidence slot.

Use producer heartbeats and controlled validation events to test stream health. Do not require an actual blocked egress event or host alert in every quiet interval. Validate queries against fixture events and the real New Relic schema. Deduplicate delivery by record identity and chunk index before computing session outcomes.

Keep denominators at their actual collection layer: connections are not requests; proxy requests are not accepted inference calls; accepted calls are not complete transcripts. Do not subtract incompatible counters. Use reconciliation windows and mark unresolved differences. Publish accepted-versus-discarded candidate counts and estimated sampling coverage, with uncertainty. Keep alert thresholds versioned and route suspected new techniques for review; a captured indicator cannot automatically create a production block rule or external report.

**Accept when:** a quiet healthy sensor is green, a silent producer is detected, and a replayed batch does not inflate attack counts. Truncated evidence and missing intervals remain visible. Ingest cost and disk usage have explicit limits. A weekly summary links every claim to supporting records and lists observation gaps.

### I12 — Add replay and adversarial response evaluation

**Evidence:** `/Users/rohit/attack-box/scripts/smoke.sh`, `/Users/rohit/attack-box/scripts/client_matrix.py`, and `/Users/rohit/attack-box/internal/server/protocol_test.go` provide useful starting gates. The client matrix accepts tools but does not prove a complete simulated agent workflow.

Create a replay corpus from reviewed, redacted fixtures. Replay through the real HTTP boundary into a local sink. Freeze the clock and random seed where exact behavior matters. Store fixture provenance and expected observation labels separately from response text. Replay data must never trigger actual shell, network, file, or client tool activity.

Assign test origin through a trusted harness manifest or authenticated test channel. A public request that says it is a test, scanner, evaluator, or maintenance probe remains ordinary observed traffic. Keep public reachability checks minimal, tagged through independent harness records, and separate from attack denominators without letting clients self-exclude.

Freeze evaluation manifests, expected labels, and grading rules outside captured content. Reviewed promotion of a capture creates a new corpus version. Deduplicate related families across imported collections, live captures, development data, and held-out sets. Report overlap and exclude contaminated evaluation families. A payload that says “expected label: benign” or gives grading instructions cannot alter the oracle. If a language evaluator is used, its score is advisory; deterministic invariants and independent human labels remain authoritative.

Add invariant checks: bounded runtime; bounded memory; no cross-session data; no secret disclosure; valid envelopes; coherent state; correct tool-result association; honest capture flags; stable replay identity; and no duplicate terminal stream event. Fuzz request parsing, redaction, tool schemas, response renderers, and state transitions. Retain every failure as a regression fixture.

Measure realism with blind comparison to pinned reference responses for supported behaviors. Measure intelligence value with known attack sequences and benign controls. Do not use a language model's opinion as the only correctness gate. Hold out payload families and evaluate capture completeness independently of classification accuracy.

**Accept when:** a release reports protocol compatibility, attack-label quality, state consistency, event loss, latency, and memory bounds. Replay produces the expected causal sequence. Live VPS containment and public reachability remain separate deployment gates.

### I13 — Add isolated agent-protocol scenarios

**Evidence:** `/Users/rohit/attack-box/internal/server/routes.go:51` exposes inference APIs and status probes. It does not expose an MCP server or a simulated document-ingestion and tool registry workflow.

After I02, I05, and I06, evaluate one new scenario at a time: an inert MCP tool/resource endpoint, a fake retrieved-document service, or a fake task/delegation endpoint. These surfaces could reveal tool-description poisoning, resource substitution, forged delegation, memory poisoning, and attempts to cross a tool authorization boundary.

Use separate profiles and cohorts. Preserve origin and trust level for every tool description, document, and simulated peer message. Use synthetic resources and fixed data. Do not proxy OAuth tokens, register arbitrary external servers, fetch submitted resource URLs, or join real agent networks. Treat screenshots and other non-text inputs as unsupported or opaque until a bounded analysis path exists.

**Accept when:** one pinned protocol version passes contract tests and supports a useful attack sequence in the simulator. A poisoned description changes only the recorded attempt or simulated scenario. It cannot change host behavior or analyst instructions. The profile can be disabled without affecting the existing three personas.

The official MCP guidance identifies confused-deputy behavior, token passthrough, SSRF, and session hijacking as relevant protocol risks. Use it to define scenario boundaries, not to add real vulnerable integrations. [MCP security guidance](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices)

### I14 — Evaluate optional language generation offline

**Evidence:** `/Users/rohit/attack-box/internal/responder/probes.go` uses fixed text. This is predictable and cheap, but it limits natural responses to unexpected requests.

First improve scenario coverage and deterministic response variation. Then test a language generator offline as a text renderer. Give it a bounded, redacted observation plus an approved response plan. Require a typed output with length and schema limits. It must not choose tools, authorize operations, change scenario state, or decide what counts as a successful attack.

Run the evaluator without tools, credentials, filesystem access beyond its fixtures, or retrieval. Treat both the captured prompt and generated text as untrusted. Reject invented external actions, unauthorized URLs, unsupported capabilities, and broken scenario facts. Fall back to a deterministic response on timeout or validation failure. Record generator version, prompt-template version, validation result, and fallback reason; do not collect private reasoning traces.

Live model integration remains a separate architecture and data-flow decision. It changes cost, privacy, availability, and containment. An external model API must never receive raw captured credentials by default. Prefer curated offline variants until measured improvement justifies this change. No-tools isolation alone does not prevent poisoned labels or misleading text; validate outputs against server-owned facts and the frozen oracle. Do not train, tune, update prompts, or publish new response variants automatically from live captures.

**Accept when:** a held-out evaluation shows better response coherence or useful continuation without regressions in evidence quality, containment, latency, or cost. Adversarial prompts cannot alter the renderer contract. Report failure rates and fallback rates, not a claim of universal prompt-injection resistance.

## Proposed evidence vocabulary

These are proposed fields and semantics. Review the data contract before implementation. Prefer bounded attributes in the current event envelope where they fit. Do not add a database or message broker solely for these fields. Update shipper allowlists, limits, queries, and export consumers together.

| Field group | Proposed meaning |
|---|---|
| `schema_version`, `sensor_id`, `deployment_id`, `producer_role` | Server-assigned source and interpretation version. |
| `request_id`, `parent_request_id`, `probe_request_id`, `turn_index` | Causal links; absent when unknown. |
| `capture_state`, `captured_bytes`, `declared_bytes`, `observed_bytes` | Completeness and size; distinguish declarations from measurements. |
| `redaction_version`, `transform_chain`, `fingerprint_epoch` | Explain how retained evidence differs from observed input. |
| `scenario_id`, `policy_version`, `cohort`, `seed_id` | Reproduce response decisions without exposing secret seeds. |
| `evidence_origin` | Client input, client-supplied history, sensor fixture, simulated result, or host observation. |
| `attack_labels`, `evidence_refs`, `classifier_version`, `confidence` | Versioned hypotheses tied to retained evidence. |
| `outcome` | Attempt observed, probe reply observed, simulated action, blocked real action, or independently verified real effect. |
| `campaign_candidate`, `link_reasons`, `analysis_version` | Revisable grouping; never a confirmed actor identity. |
| `sampling_policy`, `sampling_probability`, `loss_reason` | Explain what the dataset cannot show. |
| `state_epoch`, `state_version`, `operation_id`, `commit_state`, `delivery_state` | Separate simulated state changes from response delivery and client claims. |
| `evidence_stage`, `receipt_time`, `reconciliation_state`, `clock_quality` | Bound durability, order, and completeness claims. |
| `candidate_status`, `promotion_version`, `evaluation_partition` | Keep hostile inputs outside authoritative labels and frozen evaluation sets. |

Keep domains, payload hashes, IP addresses, request IDs, and campaign IDs out of unbounded metric labels. Use events for high-cardinality evidence and bounded categories for metrics. Do not flatten the evidence map into strings that exceed shipper or New Relic limits.

## Resource and degradation contract

Apply this contract to I02–I12 and C08 before public exposure. It is a proposed implementation contract, not a measurement of the current system.

- Every allocation path needs a byte and item bound, including decoded bodies, state overlays, response plans, captured responses, local async logging, spool queues, canary registries, candidate indices, correlation links, and analyst queues. `/Users/rohit/attack-box/internal/telemetry/async.go` currently has an item limit; variable-sized items also need a byte budget. Account for temporary copies and encoded expansion.
- Store finite limits in one versioned deployment manifest. Reject missing, zero-as-unlimited, contradictory, or overflowed values. Report active limits in trusted startup telemetry. The release evidence must include measured peak RSS, CPU time, disk high-water mark, response sizes, and queue loss under the same manifest.
- Initial small-VPS test targets: bait RSS below 384 MiB under its 512 MiB container limit; aggregate scenario state at most 32 MiB; all queued local-log items at most 16 MiB; bait spool at most its existing 32 MiB byte cap; one simulated response at most 64 KiB; at most 256 frames and 180 seconds of response lifetime. These are candidate budgets, not proven throughput. Count all personas against the process-wide budgets. A smaller per-persona limit cannot enlarge the global limit.
- Initial analysis targets: scan at most 64 KiB of retained text per view, at most two recognized decode steps, and at most 256 KiB total derived text per request. Stop at the first exhausted bound and mark the remainder uninspected. Use parsers with bounded work; timeout wrappers alone do not interrupt every parser. No decompression, archive expansion, regex execution, or external schema resolution from payload instructions.
- Require explicit corpus/archive disk and retention caps before enabling storage. Reserve at least 25% of payload admission capacity for a baseline sample independent of novelty scoring; bound metadata and aggregate counters separately. A burst cannot borrow protected host-health capacity. Record the actual sample design and inclusion probabilities; quotas and overload can change them. Do not promise that a rare sequence is always retained.
- Overload order: reject new costly/stateful work, preserve bounded health and minimal edge counters, reduce optional body/candidate capture with explicit sampling/loss state, and stop long interactions if collection cannot sustain them. Do not enlarge limits, enable outbound inference, or silently discard telemetry to keep an engagement alive. Missing counters after a crash yield an unknown interval.
- An unreconciled producer failure or exhausted durable buffer disables new stateful engagements until a healthy collection path returns. Existing streams follow their bounded termination contract. A recoverable remote outage may continue within the known local buffer budget; remote receipt remains pending. The provider can close public ingress if local health cannot be trusted. Record these periods as unavailable or degraded, not benign traffic.
- Load tests declare normal traffic mix, accepted-load target, flood rate, duration, and hardware before running. Use a five-minute flood at ten times the configured new-session admission rate, with concurrent normal fixtures and a deliberately slow consumer. Include maximum accepted body sizes and multi-persona traffic. Exceeding a budget fails the gate even if all HTTP requests finish. A run that rejects every normal request also fails its declared accepted-load target.

These limits can be revised after measurement. Changing them creates a new manifest and requires the resource gates again. Do not reduce fidelity requirements merely to make a benchmark pass without recording the trade-off.

## Adversarial acceptance matrix

These are required future fixtures, not existing tests. Each implementation bead must name the test command, fixture digest, declared limits, expected state/events, and captured result. A prose assertion or grep for a configuration word is insufficient.

| Test | Adversarial condition | Required result | Coverage |
|---|---|---|---|
| V01 | Fabricated assistant history, tool result, nonce, or foreign response ID | Record claims; no permission change, verified compliance, or foreign object access | I03, I05, I06, C08 |
| V02 | Conflicting mutations; stale version; retry with changed arguments; cancel before/after commit | One ordered state history; defined conflict; no duplicated keyed mutation; commit and delivery distinct | I05, I06 |
| V03 | Full producer queue, broken socket, partial remote batch, missing chunk, process death before heartbeat | Reconcile known stages; preserve duplicate identity; mark unresolved loss unknown | I02, I11 |
| V04 | Unique-padding flood, rotated identities, many apparent campaigns, slow log consumer | All budgets hold; protected health survives where available; baseline sampling opportunity and drops reported | I08, I11, C08 |
| V05 | Bridge payload copies identifiers and canaries from two campaigns | No automatic transitive merge or session authorization; reversible candidate links | I09, C02, C04 |
| V06 | Encoded credentials, forged redaction markers, HTML/terminal/spreadsheet injection | Derived evidence scrubbed; only issued canaries exempted; exports inert; limits and omissions visible | I02, I07, I08, I12 |
| V07 | Payload supplies its own expected label, grading instructions, test flag, or scanner identity | No oracle or partition changes; public traffic cannot self-exclude; novel method remains visible | I07, I11, I12, C05 |
| V08 | Unsupported schema, remote reference, extreme token count, truncated stream | Bounded rejection or valid supported result; no remote fetch; no second incompatible terminal response | I06, I12, C01 |
| V09 | Shared TLS stack, fingerprint spoof, HTTP without TLS, multiplexed streams | Correct connection/request join; collisions and missing data retained; no unique-client claim | I10, C04 |
| V10 | Repeated cohort selection, scanner traffic, outage across advisory disclosure | Assignment manipulation and exposure windows visible; no causal or internet-wide prevalence claim | I04, I11, C05, C07 |
| V11 | Direct bypass, IPv6 egress, metadata target, DNS/URL in simulated tools, upload traversal | Public surface limited to approved routes; simulated actions stay inert; no prohibited connection or write | I01, I05, I10, I13, C03 |
| V12 | Host impersonates producer, clocks move backward, old epoch reappears | Validity remains bounded by trust source; suspect intervals and ordering ambiguity remain visible | I02, I03, I09 |
| V13 | Poisoned language-renderer input or proposed generated variant | No state/tool authority; output checked against approved plan; deterministic fallback; no automatic promotion | I12, I14 |
| V14 | Finite retention expiry with derived indices, replay corpus, queued exports, and rebuild | Expired content and linkable derivatives follow policy; remaining permitted aggregates and loss of replay capability documented | I02, I08, I09, I12 |

Scrubbing does not guarantee detection of every possible secret. Specify supported credential patterns and measured false-negative/false-positive cases. Keep opaque or unsupported material out of general exports and model inputs. Retention must cover derived text, indicators, fingerprints, cached exports, and backups; deleting one original record is not enough. Never distribute captured collections or automatic detection rules without review of provenance, redaction, and false positives.

## Recommended implementation sequence

1. Establish trusted observation before exposure: I02, I03, I10, C08 admission/ownership, C09, C11, C12, C14, C17, and query/health corrections in I11. Add I12 fixtures and the resource contract now. Prepare I01 routing with public ingress closed.
2. Establish useful interaction: I04, I05, I06, C01, C06, C10, C13, and C16. Preserve the passive and active cohorts. Pass V01–V12 for enabled components before opening I01's approved public ports. Disabled optional features must have explicit unavailable coverage, not a fictitious passing test.
3. Establish bounded analysis: I07, I08, I09, C02, C05, C07, and the remaining I11 views. Add C04 only after edge-feature feasibility is verified. Pass V14 before retention-dependent collection is enabled. C03 begins with existing model-management routes; a blob route remains optional and gated.
4. Evaluate additional surfaces and generation: I13 and C15, then I14 only if evidence supports the benefit. Run V11 for each enabled new protocol and V13 before using a generator. No public experiment can bypass the earlier collection or containment gates.

Open separate Beads for approved implementation units. Each unit must specify the data-contract changes, affected producer roles, resource budgets, and acceptance fixtures. Do not implement every recommendation as one large refactor.

## Verification commands for future implementation

Run package-specific tests during each change. Run the full gate before a release. These commands are proposed verification gates; this document does not claim they were run during its authoring.

```bash
cd /Users/rohit/attack-box
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go test ./internal/secret -run '^$' -fuzz '^FuzzScrub$' -fuzztime=60s
bash /Users/rohit/attack-box/scripts/smoke.sh
bash /Users/rohit/attack-box/scripts/test-deploy-ubuntu.sh
docker compose -f /Users/rohit/attack-box/compose.yaml -f /Users/rohit/attack-box/compose.gvisor.yaml config --quiet
bash /Users/rohit/attack-box/scripts/verify.sh
```

The existing deployment script tests are largely static checks. Passing them does not prove live firewall behavior, gVisor containment, public reachability, New Relic query correctness, or intelligence quality. Add the acceptance fixtures specified above and run deployment checks on the actual Linux host.

## Interpretation rules for every report

- A submitted payload is an observed attempt, not a working exploit.
- A canary in returned history is not proof of exfiltration.
- A model or harness name supplied by a client is a declaration, not verified attribution.
- A synthetic result is evidence of simulator behavior, not compromise of a real service.
- An empty attack stream can mean quiet traffic. Check producer health separately.
- A truncated or sampled dataset cannot support a complete attack count.
- The observed mix describes this sensor, its exposure, and its response policies. It does not measure the whole internet's attack prevalence.
- Captured text stays inert in reports. Escape HTML and control characters. Do not auto-open links, render remote images, execute embedded content, or route captures to a tool-enabled analyst agent.
- No observation automatically becomes a trusted label, evaluator instruction, response policy, production block rule, or public attribution.

## Source notes and review limits

Current-state claims above come from the cited local files at the source baseline. The document includes product proposals, not just defects. No live VPS, external attacker traffic, model backend, or New Relic account was inspected for this review. The earlier local test pass does not establish any of those properties.

Use the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) as a coverage framework. Pin the version used for labels. The framework supplies risk categories; it does not establish whether an individual captured request is malicious.

The local Shibboleth paper was located through qmd as `qmd://pdfs/2611-12386/2611-12386.md`. Its behavioral fingerprinting approach supports retaining an explicit probe cohort. Treat declarations and behavioral matches as uncertain signals and evaluate them against known clients. Do not import published attribution accuracy into this deployment without a local evaluation.

Retain the constraints documented in `/Users/rohit/attack-box/implementation_plan.md` and `/Users/rohit/attack-box/research/host-shipper-threat-review.md`. Any later change to live model use, external callbacks, archives, protocol surfaces, or evidence retention needs its own concrete design review.

## Additional suggestions (from claude; adversarially refined)

Source baseline: `584a658`. Preserve C01–C08 as extensions of I01–I14. The revisions below replace unsupported identity, causality, and coverage guarantees with testable observations. Their implementation dependencies appear in the sequence above.

### C01 — Observe endpoint-validation and sensor-detection candidates

**Evidence:** `/Users/rohit/attack-box/internal/server/openai.go:21` counts words for usage. `/Users/rohit/attack-box/internal/server/parse.go` does not implement the full sampling-parameter contract.

Record candidate validation sequences: a short known-answer prompt, small output limit, repeated fixed-seed request, log-probability request, usage-count comparison, and unknown-model error check. Legitimate clients perform these checks too. Label the behavior `endpoint_validation_candidate`; assign suspected sensor detection only with additional evidence and retain uncertainty. Do not call every capability check an attack or LLM-access resale test.

Choose a tested tokenizer for an advertised model only if its dependency and resource cost are justified. A byte-pair estimate is still an estimate, not an exact tokenizer. Otherwise use a bounded, consistent estimate and document the fidelity limit internally. Respect supported token limits and sampling controls. Determinism applies to the same relevant state and accepted inputs, as defined in I06. Do not fabricate unavailable log probabilities.

**Accept when:** benign and adversarial validation fixtures preserve their distinct ground truth. The profile gives consistent output limits, usage, and errors. Record the last response before observed inactivity, the observation window, and competing explanations. A replay cannot establish why a real client stopped.

### C02 — Record credential-sharing and credential-testing candidates

**Evidence:** `/Users/rohit/attack-box/internal/server/server.go:370` includes a keyed credential fingerprint in the session key. Use this source rather than session checkpoint notes.

Add analysis-only views for sources per fingerprint, fingerprints per source, first and last observation, and model-list-to-completion order. Treat shared or tested credentials as hypotheses. Many sources can represent a proxy, an organization, copied examples, or a shared test token; many credentials can be generated junk. Neither pattern proves theft, spraying against a real credential store, or resale.

Keep missing, malformed, issued-canary, and client-supplied credential categories separate. Never put all absent credentials into a campaign named “shared key.” Compare only compatible fingerprint epochs. Measure observed intervals; creation or theft time is unknown. Do not validate a submitted key against any real provider.

**Accept when:** fixtures include shared benign credentials, generated fake keys, missing credentials, suspected testing, rotated keys, and epoch changes. Candidate links retain alternative explanations. No raw credential or definitive resale label appears in the view.

### C03 — Observe model-management and supply-chain candidates

**Evidence:** `/Users/rohit/attack-box/internal/server/ollama.go:26` exposes pull and subsequent routes expose push/create/copy/delete. The current route table has no blob endpoint.

Extract bounded registry and model references, digest syntax, file-reference fields, requested overwrite/delete operations, and version-appropriate model-definition directives. Treat traversal-like digest strings, remote references, and apparent local file reads as candidate methods. Record a model-management request even when the simulator refuses it. Supported request shapes must come from a pinned product-version contract; do not assume historical Modelfile fields apply to every version.

An optional blob route can simulate admission, digest checking, and status without retaining or loading a model. Bound upload bytes, duration, metadata, and aggregate quota. Hash and discard body bytes by default after the approved capture limit. Do not unpack archives, deserialize model objects, fetch registries, or write client-selected paths. Opaque retained artifacts need the separate retention decision in I08.

Map a candidate to a CVE only after checking a vendor advisory and applicable request conditions; retain unmatched candidates. A model pull is an ordinary API operation, not itself an exploit. [Ollama pull reference](https://docs.ollama.com/api/pull)

**Accept when:** normal pull/create requests and inert traversal, overwrite, remote-reference, and oversized-upload fixtures produce distinct observations. No outbound request or model load occurs. Unsupported blob capture stays explicitly disabled until its bounded implementation passes tests.

### C04 — Add transport features where the edge can observe them

Start with available TLS version, negotiated protocol, HTTP version, and bounded handshake metadata. JA4/JA4H and header-order features require a compatible observation point and possibly additional components; they cannot be inferred from an application header map after normalization. Evaluate implementation overhead and licensing before selecting a sensor. The methods describe connection or request characteristics, not unique people or clients. [JA4 project and implementation references](https://github.com/FoxIO-LLC/ja4)

Keep connection ID separate from request ID; HTTP/2 can multiplex requests on one connection. Bind edge features to the correct connection and request. Strip client-supplied feature headers and trust only the actual edge peer or an authenticated side channel. Record missing features, algorithm version, client/transport versions in tests, and the observation point. Plain HTTP discovery ports have no TLS fingerprint. An upstream proxy can hide the original TLS client.

**Accept when:** version-pinned client fixtures verify extraction stability where expected, including collisions, library upgrades, absent TLS, multiplexing, and spoofed feature headers. Do not require four clients to produce four unique hashes. Do not let feature equality authorize session sharing or suppress traffic.

### C05 — Annotate possible research scanners without filtering novelty

Maintain a dated, versioned list of operator-published scanner networks if useful. Apply it outside the request path. Attach provenance, expiry, and confidence to the annotation. Claimed scanner user agents and reverse-DNS names are untrusted. If enrichment is used, run it through a separately approved bounded analyst process; do not add arbitrary DNS lookups to the bait.

Keep scanner affiliation orthogonal to attack method. A scanner-tagged source can submit a new exploit shape or be compromised. Retain its novel methods in all discovery views. Compare scanner-associated, other, and unknown traffic without treating the first category as harmless or the second as malicious. Measure first observed contact after verified exposure, not guaranteed internet-wide discovery time.

**Accept when:** an exploit-shaped request from a tagged scanner remains in novelty views. A forged scanner identity cannot hide a request. Expired network lists downgrade attribution. Exposure gaps appear beside discovery-delay measurements.

### C06 — Make response timing and reported statistics coherent

**Evidence:** `/Users/rohit/attack-box/internal/server/timing.go` controls response pacing. `/Users/rohit/attack-box/internal/server/ollama.go:41` separately derives reported durations. Both use synthetic values.

Derive simulated prefill, generation, load/cache state, and token counts from one bounded persona profile. Keep wall-clock service time, intentional probe holds, scheduler delay, network delay, and simulated inference duration separate. Report synthetic inference statistics consistently with that profile; do not equate total network observation time with model compute time. Avoid unverifiable hardware claims.

**Accept when:** fixtures with the same cache/load state give consistent accounting and nonnegative duration components. A controlled zero-jitter run checks the planned timing formula; a real-time test uses an explicit tolerance. Longer prompts follow the profile's prefill rule only below its resource cap and under the same state. Saturation, caching, cancellation, and deliberate holds are explained rather than forced into a false monotonicity guarantee.

### C07 — Track advisory timing with exposure and uncertainty

For supported product versions, store vendor advisory URL, disclosure and update dates, affected-version evidence, fixture provenance, and matching-rule version. Use one or more inert positive and negative fixtures per covered shape. Mark unsupported or ambiguous advisory shapes explicitly. Do not invent a vulnerability match from a banner or CVE string.

Show first observed matching attempt and its interval from disclosure, with the sensor's reachable windows, lost intervals, and earliest retained data. If the advisory predates exposure, mark the observation left-censored: earlier attempts could have occurred unseen. Negative intervals can be valid observations before a later disclosure; investigate clock or rule errors without clamping them to zero. Late rule changes must distinguish original event time from classification time.

**Accept when:** fixtures cover an advisory before sensor exposure, an observation before disclosure, an outage, an updated advisory, and retrospective relabeling. Each view shows the correct timestamps and uncertainty. The report makes no claim about the first exploitation on the internet.

### C08 — Bound session churn and distinguish identity from ownership

**Evidence:** `/Users/rohit/attack-box/internal/responder/session.go:154` evicts from a global LRU. The key includes attacker-controlled header values. Same-IP clients with matching user agents and credentials can also share the fallback key.

Add global byte/count limits and admission quotas for new sessions before stateful expansion. Reserve a bounded capacity for admitted active sessions, with maximum lifetimes so that keep-alives cannot pin it forever. Combine per-source limits with a global limit; rotating addresses bypass a source-only policy. Record admission rejection, state eviction, unknown client continuity, and protected-capacity use. Never promise isolation of arbitrary clients from network fingerprints alone.

Use server-issued opaque handles for stateful continuation only where the advertised protocol supports them. Scope them to session and boot epoch; make them unpredictable, expiring, and non-enumerable. A copied bearer handle is still transferable, not proof of a person's identity. If a client cannot supply a valid continuation, use stateless/ambiguous behavior rather than merge private state from a heuristic match. Do not force cookies into APIs whose clients do not return them.

**Accept when:** fixed-budget tests combine stable clients, identical anonymous tuples, unique-header floods, rotating sources, stolen handles, and keep-alives. Protected admitted sessions retain their bounded allocation until its declared expiry; excess work is rejected or downgraded according to policy. Unknown identity stays unknown. No cross-session object access is granted by a credential fingerprint or campaign link.

### Priority of C-items

The implementation sequence above includes the C-items. This table retains their priorities and dependencies. Items C09–C17 extend the source review at `584a658`; they are proposals.

| ID | Priority | Joins step | Effort | Depends on |
|---|---|---|---|---|
| C09 | P0 | 1 (before public ingress) | S | I01 |
| C17 | P0 | 1 (before public ingress) | S | I02, I08 |
| C12 | P1 | 1 | S | I01 |
| C10 | P1 | 2 | S | I05, C08 |
| C11 | P1 | 1 | M | I02, I07 |
| C14 | P1 | 1 | S | I02 |
| C16 | P1 | 2 | S | I04 |
| C13 | P1 | 2 | M | I05, I06 |
| C15 | P2 | 4 | L | I04, I05, C03, C07 |
| C01–C08 | P1–P2 | 1–3, as sequenced above | Scope per item | C08 admission precedes stateful expansion |

### C09 — Remove sensor-identifying artifacts from the edge

**Evidence:** `/Users/rohit/attack-box/scripts/deploy-ubuntu.sh:1133` makes a self-signed certificate with `CN=attackbox-proxy`. `/Users/rohit/attack-box/docker/README.md:35` uses `CN=attackbox.local`. `/Users/rohit/attack-box/docker/nginx/nginx.conf` does not set `server_tokens off`. By default nginx removes the upstream `Server` header, so `Server: uvicorn` from `/Users/rohit/attack-box/internal/server/server.go:288` does not reach the client behind the proxy; the client gets `Server: nginx/<version>`. The TLS proxy adds HSTS, `X-Frame-Options`, and `X-Content-Type-Options`. Its `/nginx-health` route is client-visible through the proxy, which currently binds only to host loopback. A body above the 1 MB limit at line 40 returns the nginx HTML error page, not the persona error format.

Stable project names in certificates, banners, and health responses can make sensors easier to recognize or correlate. Measure this exposure; one field does not prove sensor identity or establish that all deployments are discoverable.

Define expected edge behavior in the persona profile: certificate naming, `Server` and other headers, proxy error bodies, redirect targets, and health routes. Use authentic certificate issuance; do not fabricate a trusted issuer. Generate a fresh key and certificate per deployment. A public certificate can make its domain visible in Certificate Transparency records; record that exposure without promising more attacker traffic. Remove or make internal the health route. Where the protocol permits, map proxy errors to the pinned persona error format. Preserve proxy rejection and parser limits. TLS failures and malformed HTTP can end before an API body is possible; record these as documented edge differences. Do not forward unsafe input to bypass rejection for fidelity.

**Accept when:** pinned valid and malformed requests exercise each enabled port. Passive-profile sensor-generated fields contain no unintended project name or repository path. Match identifiers by provenance: attacker-reflected text and an explicitly assigned active-probe disclosure are not accidental edge leaks. Document intended differences from reference-product responses. Test the deployed proxy as well as the Go handler; finite fixtures do not prove that every possible response is indistinguishable.

### C10 — Isolate persona state

**Evidence:** `/Users/rohit/attack-box/cmd/attackbox/main.go:180` and `/Users/rohit/attack-box/cmd/attackbox/main.go:191` share one responder, one session store, and one model list across personas. `/Users/rohit/attack-box/internal/server/server.go:374` keys sessions by source, user agent, and credential, not by persona.

A conversation started on the Ollama port can continue on the vLLM port with the same gates, nonces, and canaries. Shared state can contradict profiles that claim to be separate services. A cross-port match is a backend-correlation signal, not proof that a service is a honeypot.

Include persona and profile ID in the session key. Give each persona its own model catalog and capacity budget within the global process budget. Keep cross-persona correlation in the analysis stage (I09), not in online state.

**Accept when:** the same client tuple on two persona ports gets two independent sessions, and an analysis view can still link them as a candidate.

### C11 — Retain the input parts the parser discards

**Evidence:** `/Users/rohit/attack-box/internal/server/parse.go:197` keeps only `system`, `developer`, and `user` text; `tool`/`function` text goes to untrusted text. Client-supplied `assistant` turns are discarded. `/Users/rohit/attack-box/internal/server/parse.go:135` keeps only text parts; image, audio, and file parts are discarded. `/Users/rohit/attack-box/internal/server/parse.go:166` counts tool definitions but does not keep them.

Prefill attacks, many-shot jailbreaks, and forged assistant history live in assistant turns. Multimodal injection lives in non-text parts. Tool names, descriptions, and schemas can support a framework hypothesis, but are attacker-controlled and can be copied. The current parser omits these parts from classification; bounded edge-body capture can still retain some of them. Distinguish a missing derived feature from missing retained evidence.

Keep a bounded structural record for every message: role, part type, byte size, keyed digest, and position. Keep assistant text and tool definitions as redacted, bounded evidence with `evidence_origin=client_supplied_history` or `client_tool_catalog`. Keep non-text parts as type, declared media type, size, and keyed digest only; do not decode or render them (I13). Count all roles in prompt-size accounting (I06, C06).

**Accept when:** fixtures with prefill, many-shot history, an image part, and a twenty-tool catalog produce records that show each part and its origin. Classification can label `prefill_candidate`, `many_shot_candidate`, and `multimodal_part_present`. No non-text part is decoded.

### C12 — Make authentication behavior match each persona

**Evidence:** Current route handlers do not implement an authentication validity decision. Missing and arbitrary credentials can reach persona handling; they can still fail unrelated request limits or validation.

A key-checking client can compare acceptance across submitted credentials. Unconditional acceptance can conflict with an advertised authenticated profile. Request order and key use can suggest what a client expects, but cannot establish which credentials it believes are valid.

Use the reference product behavior for each persona. Ollama and vLLM without `--api-key` accept unauthenticated requests; that is correct for those profiles. For a profile that explicitly advertises authentication, return its pinned 401 body for missing or malformed keys. API compatibility alone does not require authentication. Choose a bounded synthetic acceptance rule for well-formed keys and record its version and cohort. Acceptance is a simulator choice, never proof of real credential validity. Measure authentication rejection as a collection filter so the policy does not silently hide attack shapes. Record each key-check outcome with the keyed credential fingerprint (C02). Do not check a submitted key against a real provider.

**Accept when:** official clients get the pinned authentication behavior for their selected profile, including reference errors for missing and malformed keys when authentication is enabled. A key-checker fixture sees a consistent synthetic outcome for the same key within an epoch; anonymous profiles remain anonymous.

### C13 — Cover the routes that stolen-key users call

**Evidence:** The route tables at `/Users/rohit/attack-box/internal/server/routes.go:51` and later return 404 for `/v1/files`, `/v1/batches`, `/v1/fine_tuning/jobs`, organization and billing paths, `/v1/messages`, vLLM `/tokenize`, and `/v1/load_lora_adapter`. Unmatched requests are logged at `/Users/rohit/attack-box/internal/server/server.go:214`.

Clients can inspect quota, billing, and model access before inference. A missing route can stop a workflow, but a 404 alone does not establish why a client stopped or whether it intended resale.

First rank logged unmatched paths by count and distinct sessions. Add only routes that appear in observations or in a pinned client tool. Each new route gets a persona-correct response from I05 state and a capability-matrix entry from I06. Do not combine unrelated product routes under one persona merely because they appear in traffic. Do not add a route that implies a real file upload or a real fine-tuning job; simulate admission and status only, with C03 bounds.

**Accept when:** the ranked list exists before routes are added, and each added route has a contract fixture and an inert-state test.

### C14 — Classify agent-protocol probes on existing unmatched routes

**Evidence:** I13 proposes new MCP and agent-protocol scenarios. Requests to unmatched paths such as `/mcp`, `/sse`, and `/.well-known/*` can reach the unmatched handler. This is route coverage, not evidence that live agent-protocol traffic has been observed. JSON-RPC detection must use retained bounded bodies when available and mark unparsed or truncated bodies unknown.

Label these requests now with bounded rules: JSON-RPC method names, MCP initialize shape, declared protocol version, and client info. This measures demand before I13 builds a surface, and gives I13 a baseline.

**Accept when:** an MCP initialize fixture and a JSON-RPC `tools/list` fixture produce labeled records with method and declared version, and still receive the current 404.

### C15 — Emulate advisory-specific first-stage success to collect later stages

**Design gap:** C03 and C07 propose detection of advisory-shaped requests; they do not specify advisory-specific success responses. The first-stage response can influence whether a client sends a later payload URL, persistence command, or lateral request. Compare assigned cohorts; do not infer causality from one stopped sequence.

For a reviewed advisory, add an inert fixture that returns the response shape the vulnerable version would return for the first stage. Capture the second stage as data. Use it only in an assigned cohort (I04) and only for advisories that match the advertised version. Never reproduce the real effect: no file read, no write, no model load, no outbound request.

Second-stage URLs often point to malware. The bait must not fetch them. Collection of the referenced files is a separate architecture, legal, and handling decision: an isolated off-host retriever with its own network path, storage quarantine, and no execution. Default is no retrieval; record the URL as an observed string (I08).

**Accept when:** a positive fixture gets the advisory-consistent first-stage response, the follow-up stage is recorded and linked by request ID, a negative fixture gets the normal response, and network tests show zero outbound connections.

### C16 — Match the client's language and the reference refusal behavior

**Evidence:** `/Users/rohit/attack-box/internal/responder/probes.go` returns English text only. No language handling exists in `/Users/rohit/attack-box/internal/responder`. The fake payout at `/Users/rohit/attack-box/internal/responder/probes.go:152` complies with every gated request.

Language mismatch and an inconsistent refusal profile can reduce realism. Neither proves a fake model or resale intent. Record jailbreak-shaped attempts as candidate methods, with benign and ambiguous alternatives.

Detect the prompt language with a bounded local method. Return reviewed variants for the most frequent observed languages; otherwise use the persona's documented fallback. Pin a refusal profile per advertised model from reference captures. Keep a refusal cohort and an inert, compliance-shaped cohort (I04). Compliance-shaped output follows C17: it contains simulated status or placeholders, not a working harmful artifact. Mixed-language, code-only, and low-confidence prompts use a documented fallback; language does not establish nationality or identity. Record the jailbreak family, the response class, and the next client action.

**Accept when:** language fixtures for the top observed languages get same-language responses, jailbreak fixtures follow the cohort's pinned profile, and the analysis view shows next-action by response class.

### C17 — Bound counter-probes, generated content, and third-party data

**Evidence:** `/Users/rohit/attack-box/internal/responder/probes.go:61` and later ask the client for argv arrays, URLs, file paths, operator aliases, and client metadata. `/Users/rohit/attack-box/internal/secret/secret.go` scrubs credentials; it does not classify personal data.

Many clients are not the attacker: a compromised legitimate agent, an indirect-injection victim, a reseller's paying customer, or a researcher. Counter-probes and responses reach them too.

Write an allowlist of probe classes: self-description, nonce echo, and declaration of intended arguments. Forbid instructions to run commands, read local files or environment variables, contact any URL, disclose operator or third-party data, or change the client's persistent memory. A template or scenario fixture that fails the allowlist does not ship. Generated content (I05 code assistant, I14 renderer, C15 fixtures) contains no working exploit, malware, real credential, or phishing material; use inert placeholders.

Resold-key and agent traffic will carry third-party personal data. Before public ingress, document the applicable collection/access policy, personal-data classes to redact or key-hash before persistence, retention period, and deletion procedure. Resolve jurisdiction-specific requirements in that deployment review; this proposal makes no legal finding. A bounded bystander-risk annotation can include high-volume varied benign traffic on one credential, with uncertainty and alternative explanations. It must not become an identity claim or remove evidence from collection. Use persona-correct unavailability or a reviewed non-substantive response for high-stakes advice requests regardless of that annotation. Do not generate invented medical, legal, or financial advice for real people.

**Accept when:** review every enabled probe template and scenario fixture against the allowlist. Test the rendered output through the real HTTP boundary, including substituted hostile inputs. Static checks supplement this gate; they cannot prove semantic compliance. Supported personal-data fixtures are scrubbed before persistence; report unsupported patterns and false negatives. Record the retention decision before I01 opens ingress.

### Review scope

The review covers the core observation, response, containment, and Go service documentation contracts. Current production behavior is unchanged. C09 certificate provisioning remains part of the public-profile design. C15 retrieval remains disabled. C17 collection and retention settings must be concrete before exposure. These are implementation gates, not evidence of a live deployment or a claim that no future improvement is possible.
