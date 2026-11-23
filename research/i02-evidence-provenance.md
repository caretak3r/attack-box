# I02 — Evidence provenance and collection limits: contract proposal

Date: 2026-11-22. Source baseline: `c44e2cb`. Bead: `[internal reference removed]`. Topic: `/Users/rohit/attack-box/IMPROVE.md`, section I02.

Status: **revision 3, approved by the owner on 2026-11-22.** The owner approved the three decisions in section 8: contract version 1 as written, both renames, and both new shipper settings. Implementation follows section 4. Revision 3 includes the corrections from four rounds of independent design review (section 9).

## 1. Purpose

Make each record say where it came from, how complete it is, and how far it got. Make loss visible as a number or as "unknown", never as an implied zero.

The design keeps the bait and shipper separation, the six streams, producer-role isolation, and every existing bound. It adds no database, no broker, no new process, and no new network path. It applies to the spool deployment. Direct mode, where the bait holds a New Relic key, is for development only and gets the bait-assigned attributes only.

## 2. Current state

| Area | Fact | Source |
|---|---|---|
| Wire record | `Record{ID "<boot>-<seq>", Event or Metric}`. `boot` is 8 random bytes per process. `seq` advances on every call, drops included. No version field. `put` builds the line and its size by hand. | `internal/telemetry/spool.go:32-36`, `:238-265` |
| Protocol | One-way. The spool never reads the socket. A successful write means the kernel took the bytes. | `internal/telemetry/spool.go:93-101` |
| Admission | `Admit` is the only strict decoder of a record. A new top-level field fails with reason `json`. New keys inside `attrs` pass the structural limits. The drain decodes loosely. | `internal/shipper/record.go:157-170`, `:315`, `cmd/attackbox-shipper/drain.go:131-132` |
| Shipper-assigned attributes | `source` (verified role), `record_id`, `boot`, `seq`, and the flags `timestamp_clamped`, `reserved_attrs_removed`, `attrs_truncated`, `fields_truncated`. The reserved list also protects the fixed fields. | `internal/shipper/record.go:145-155`, `:275-292` |
| Time | `timestamp` is the producer clock. Outside −24 h / +5 min the shipper overwrites it. The producer value is lost. No ingest time is recorded. | `internal/shipper/record.go:275-292` |
| Rejections | Counted by reason in `RoleStats.Rejected`, with `Lines`, `Oversize`, `Duplicates`, `Gaps`, `Queued`, `QueueFull`. In memory only; not shipped. Three rejected lines in a row close the connection. | `internal/shipper/ingest.go:24`, `:114-129` |
| Producer boots | A high-water mark for the last 8 boots of a role, evicted by recency. `mark` runs before the durable append. A shipper restart forgets the marks. | `internal/shipper/ingest.go:25`, `:169-172`, `:430-453`, `:528-559` |
| Shipper heartbeat | One log item and one metric every 30 s, posted directly, one attempt, not through the durable queue. No rejection, gap or duplicate count. | `internal/telemetry/newrelic.go:566-595`, `cmd/attackbox-shipper/main.go:181-199` |
| Heartbeat queries | 14 query lines in `newrelic/` read the heartbeat stream. 13 filter `source = 'shipper'`. None filters on `action`. | `newrelic/alerts/critical-alerts.yaml:11`, `newrelic/queries.md:25` |
| Bait heartbeat | Every 30 s through the same spool queue as payload: `queue_len`, `queue_bytes`, `dropped_total`, `errors_total`, `reconnects`. A full queue drops the heartbeat too. | `internal/telemetry/spool.go:473-476` |
| Final record | The bait emits `stopped` and then closes the spool. The heartbeat can still fire between the two. The counters in `stopped` are a snapshot. | `cmd/attackbox/main.go:329-335`, `:345-363` |
| Durable queue | An item over a role or total cap is dropped and counted for the role, after admission. Role caps are 60 / 20 / 20 percent. | `internal/shipper/queue.go:760-826`, `internal/shipper/ingest.go:365-382` |
| Body capture | `body_bytes` is the count of bytes read, at most 1 MiB. A read error other than the size limit is ignored. A rate-limited request is answered before any read. The log keeps at most 128 KiB after redaction. | `internal/server/log.go:33-91`, `:295-310`, `internal/server/server.go:210-254`, `:310-318` |
| Fingerprints | `body_fingerprint` exists only when the log body is cut, over the bytes that were read. `body_sha256` is computed at the last hop over the redacted text. | `internal/server/log.go:78-84`, `internal/telemetry/event.go:94-95` |
| Redaction | The scrubber returns text only. Every replacement goes through one internal marker function; its fallback marker `[redacted]` is written without the fingerprint callback, so the callback alone cannot count every replacement. Invalid UTF-8 is replaced later, by the JSON encoder, with no mark. | `internal/secret/secret.go:252-275`, `internal/telemetry/spool.go:259-265` |
| Fingerprint key | Derived from `ATTACKBOX_SECRET_FILE`. Random per process when the file is absent. No record says which key was used. | `cmd/attackbox/config.go:48-51`, `internal/telemetry/redact.go:44-67` |
| Gate | The environment check compares only the bait `config.go` with `implementation_plan.md`. | `scripts/verify.sh:228-252` |

Hazard outside this topic, bead `[internal reference removed]`: the drain retries every delivery error, permanent ones included, and delivers nothing behind it.

## 3. Proposed contract, version 1

### 3.1 Wire record

`Record` gains the top-level integer `v`. Every producer writes `1`. The shipper accepts only versions that it supports. Any other value, an absent value included, is rejected with reason `schema_version`.

All producers use `telemetry.Spool`, so one change covers the bait and both adapters. Records already in the durable queue stay valid across an upgrade and a rollback, because the drain decodes loosely.

Rollout rule: the bait and the shipper restart together, from one release. A bait that is older than its shipper loses every record, and the shipper closes its connection after three lines. That loss is counted as `rejected_schema_version`. No compatibility mode exists, because nothing is deployed.

### 3.2 Shipper-assigned provenance

No producer can set these names. The shipper removes them from producer `attrs` and sets `reserved_attrs_removed`.

| Attribute | Where | Meaning |
|---|---|---|
| `schema_version` | each event | The accepted `v`. |
| `source`, `record_id`, `boot`, `seq` | each event | Unchanged. `source` is the producer role. |
| `request_id` | each request event | Unchanged. The server assigns it at random. A client request ID appears only inside `headers`. |
| `ingest_ts` | each event | Shipper clock at admission, Unix milliseconds. Stored in the queue, so a replay keeps it. |
| `producer_ts` | event, only when `timestamp_clamped` is true | The producer time that the shipper replaced, Unix milliseconds. |
| `sensor_id` | New Relic common attribute, logs and metrics | New shipper setting `ATTACKBOX_SENSOR_ID`. Default: the host name in lower case. Rule: `^[a-z0-9][a-z0-9._-]{0,62}$`. |
| `deployment_id` | New Relic common attribute, logs and metrics | New shipper setting `ATTACKBOX_DEPLOYMENT_ID`. Default: `unset`. Same rule. The operator changes it for each rebuild. |
| `shipper_boot` | shipper-owned records only | 16 hex characters, random for each shipper process. |

### 3.3 Bait-assigned provenance

The bait sets these on every event that it emits. One map feeds two places: the spool configuration, which also covers the spool's own heartbeat, and a sink wrapper for the local log. They are not set on metrics. The shipper removes these names from records of the other roles.

| Attribute | Meaning |
|---|---|
| `persona_version`, `policy_version`, `redaction_version` | Integers. Constants in the package that owns the behaviour. A test pins each constant to a digest of fixed inputs and outputs, so a behaviour change without a version change fails the test. |
| `fp_epoch` | 8 hex characters derived from the fingerprint key. Fingerprints compare only inside one epoch. |
| `fp_scope` | `configured` only when the bait read `ATTACKBOX_SECRET_FILE` and the redactor kept the derived key; `boot` in every other case. The value comes from what the redactor did, not from the setting. |

Values that the client declares stay where they are: inside `headers`, `declarations`, `model`, `query`. No request field can set a provenance attribute.

### 3.4 Capture state

These attributes are on the edge request event and the edge response event only. Transcript and probe events hold text that the sensor wrote.

| Attribute | Values and meaning |
|---|---|
| `capture_state` | `none` (no body), `complete`, `log_prefix` (the full body was read; the record keeps a prefix), `body_limit_exceeded` (the server stopped reading; the total size is unknown), `read_error` (the read ended with an error; the record keeps what arrived), `not_read` (the server answered before it read the body). A response uses `none`, `complete` or `log_prefix` only. |
| `parse_state` | Request only. `ok`, `failed`, `not_attempted`. The name `unsupported` is reserved for C11. |
| `declared_bytes` | Request only. Present only when the client sent a `Content-Length` header. This is a claim. |
| `observed_bytes` | Request only. Bytes that the server read. It replaces `body_bytes`. It is a lower bound with `body_limit_exceeded` and `read_error`. A response keeps `response_bytes`, which is exact. |
| `captured_bytes` | Bytes of body text in this record, after all transforms. |
| `body_utf8_replaced` | True when the retained part held invalid UTF-8. |
| `redactions` | Number of replacements that the scrubber made in the part that it scanned. A marker in the text with `redactions` = 0 is client text. |
| `body_limit_exceeded`, `body_truncated` | Unchanged. |

Transform order, fixed for `redaction_version` 1: cut the raw body to the scan window, replace invalid UTF-8, redact, cut to the log limit on a rune boundary, then digest and chunk at the last hop. The log limit applies to the final text.

The two attributes are independent. `capture_state` comes from the read alone. `parse_state` comes from the handler alone. The server response does not change: a handler still runs after a read error, as it does today.

| Read outcome | `capture_state` |
|---|---|
| The server answered before the read (rate limit) | `not_read` |
| No body | `none` |
| Read to the end, all of it in the record | `complete` |
| Read to the end, the record keeps a prefix | `log_prefix` |
| The size limit stopped the read | `body_limit_exceeded` |
| Another read error or a client abort | `read_error` |

| Handler action | `parse_state` |
|---|---|
| No handler decoded the body (rate limit, unknown route, wrong method, status 413, a route with no body parser) | `not_attempted` |
| A handler decoded the body | `ok` |
| A handler tried to decode the body and failed, an empty body included | `failed` |

Combinations that exist today and must stay visible: an unknown route with a body over the limit gives status 404 with `body_limit_exceeded` and `not_attempted`; an empty body on a parsing route gives `none` with `failed`; a read error on a parsing route gives `read_error` with `ok` or `failed`.

A lost record carries no state. Loss is reported by the counters in 3.6. The name `sampled_out` is reserved; no sampling exists.

### 3.5 Fingerprints

| Attribute | Covers | Keyed |
|---|---|---|
| `input_fp` | The body bytes that the server read. Present for every non-empty request body. It replaces `body_fingerprint`. | Yes |
| `input_fp_scope` | `full`, or `prefix` with `body_limit_exceeded` and `read_error`. | — |
| `body_sha256` | The retained, redacted text. Unchanged. It proves that chunks belong together. It proves nothing about the sender. | No |
| `norm_fp`, `norm_version` | Reserved for I08. Not emitted in version 1. | — |

### 3.6 Stages and loss accounting

Stage names, in order: `observed` (the bait built the event), `queued` (the spool took it; a dropped event still uses a `seq`), `written` (the kernel took the bytes), `admitted` (the shipper validated it), `committed` (synced to the durable queue), `accepted` (New Relic accepted every chunk), `available` (a reader confirmed it). Version 1 does not implement `available`.

A record that is visible in New Relic passed `committed` and `accepted`. For records that are not visible, counters carry the evidence. In version 1 these counters stop at `committed`: `loss` covers the stages `observed` to `committed` only, and each boot row says so with `loss_scope = committed`. The stage `accepted` is not reconciled for each boot. A boot can read `none_known` while the drain is stuck and New Relic holds nothing; the shipper heartbeat (`queue_backlog_bytes`) shows that state, not the boot row.

**Bait side.** `bait_heartbeat` and `stopped` carry the cumulative counters `written_total`, `dropped_total`, `oversize_total`, `lost_total`, `resent_total`, `errors_total`, `reconnects`, `local_dropped_total` and `uptime_ms`. The record's own `seq` is the count of events and metrics so far. Two rules make these records reliable:

- Reserved capacity. Four records and 64 KiB of the spool queue accept only heartbeat and lifecycle records. Payload cannot fill that part. Order in the queue does not change. For a queue smaller than the default, the reserve is the smaller of 4 records and a quarter of the record limit, and the smaller of 64 KiB and a quarter of the byte limit; a queue of fewer than 4 records has no reserve.
- Last record. The bait stops the spool heartbeat before it builds `stopped`. `stopped` then has the highest `seq` of the boot.

**Shipper side.** Each 30 s the shipper sends one extra POST on the direct heartbeat path, with at most 40 rows and one attempt. A lost report is replaced by the next one, because every row is repeated. The rows are on the heartbeat stream with `source = 'shipper_accounting'`, so the 13 existing queries that filter `source = 'shipper'` do not see them.

| Row (`action`) | One row for | Content |
|---|---|---|
| `ingest_stats` | each role | `role`, `shipper_boot`, `lines`, `oversize`, `rejected_total`, one `rejected_<reason>` for each non-zero reason, `duplicates`, `gaps`, `queued`, `queue_full`, `boots_unreported`, `rows_omitted`. |
| `producer_boot` | each tracked boot | `role`, `boot`, `shipper_boot`, `first_seq`, `last_seq`, `final_seq`, `admitted`, `missing`, `rejected`, `queue_refused`, `duplicates`, `reported_dropped`, `reported_at_seq`, `max_skew_ms`, `clamped`, `last_ingest_ts`, `state`, `loss`, `loss_scope`, `loss_reason`, `lost`. |

Definitions for one boot inside one shipper process:

- `admitted`: records that passed admission and the duplicate check, counted only after the durable append of their batch returned. `missing = last_seq − first_seq + 1 − admitted`.
- `rejected`: lines that the shipper refused on a connection of this boot. `queue_refused`: admitted records that the durable queue refused. The append reports refusals for each boot.
- `reported_dropped`: the `dropped_total` in the latest counter record of the boot, at `reported_at_seq`. It is a producer claim.
- `stopped` carries `forced = true` when the graceful shutdown of the bait failed. Handlers can then still emit after `stopped`, and the spool drops those records without a trace.
- `state`: `open`; `clean_end` (`stopped` was admitted, it is the highest `seq`, it is not forced, and the append of its batch returned); `unclean_end` (another boot of the role arrived first); `silent` (no record for the idle timeout, 2 minutes).
- `loss` is `pending` while the boot is open. A final value needs a clean end and `first_seq` = 1:
  - `none_known`: `missing`, `queue_refused` and `reported_dropped` are all 0.
  - `known`: `missing` equals `rejected` plus `reported_dropped`. Then `lost` = `missing` + `queue_refused`.
  - `unknown`: every other case.
- `loss_reason`: `none`, `unclean_end`, `silent`, `prefix_unseen`, `post_stop`, `forced_stop`, `counter_mismatch`, `append_error`, `evicted`. An append error stops the shipper; the row of that boot is `unknown` with `append_error` if a report still goes out.

Bounds: at most 8 tracked boots for each role, the existing limit. An ended boot is reported for 20 more intervals. A boot that is evicted before its final row gets a row with `loss = unknown` and `loss_reason = evicted`, and that row is also reported for 20 intervals. At most 2 evicted rows wait for each role; more are counted in `boots_unreported`. The largest report is 3 `ingest_stats` rows, 24 tracked boots and 6 evicted rows: 33 rows, under the limit of 40. If a later change breaks that sum, rows are kept in this order: `ingest_stats`, final `unknown` rows, other final rows, open rows; the rest are counted in `rows_omitted`. The durable queue format and its roles do not change.

Limits that stay: producer counters are claims inside a verified role. A host-root compromise can forge all of them. The adapters send no counters, so their boots end as `unknown`.

### 3.7 Clocks and restarts

Order inside one producer boot comes from `seq`. Comparison across systems uses `timestamp` and `ingest_ts`. The shipper invents no order. Clock quality is recorded as `timestamp_clamped` with `producer_ts` on a record, and as `max_skew_ms` and `clamped` on the boot row. `uptime_ms` shows a wall-clock jump between two heartbeats. A new `boot` is a producer restart. A new `shipper_boot` is a restart of the delivery path, and the first accounting POST goes out at start.

## 4. Implementation units

Sequential. One new implementer session for each unit. The full gate must pass after each unit.

| Unit | Scope | Main files |
|---|---|---|
| U1 | `v` in the line and in its size formula; `schema_version`, `ingest_ts`, `producer_ts`; reserved names for all roles and bait-only names for the other roles; `sensor_id`, `deployment_id`; both settings in `docs/operator.md` and `implementation_plan.md`; every test fixture that passes through `Admit` | `internal/telemetry/spool.go`, `internal/shipper/record.go`, `cmd/attackbox-shipper/config.go`, `cmd/attackbox-shipper/main.go`, tests in `internal/shipper`, `cmd/attackbox-shipper`, `cmd/attackbox`, `internal/server/capture_test.go` |
| U2 | Capture and parse state, sizes, `input_fp`, UTF-8 order, redaction count, the three versions with pin tests, `fp_epoch`, `fp_scope`, the stamp | `internal/server/log.go`, `internal/server/server.go`, `internal/server/openai.go`, `internal/secret/secret.go`, `internal/telemetry/redact.go`, `internal/telemetry/spool.go`, `cmd/attackbox/main.go` |
| U3 | Bait counters, reserved capacity, last record; boot tracking; the accounting POST | `internal/telemetry/spool.go`, `internal/shipper/ingest.go`, `internal/telemetry/newrelic.go`, `cmd/attackbox-shipper/main.go`, `cmd/attackbox/main.go` |
| U4 | Independent review and corrections | — |
| U5 | Architecture and operator documents, plan, New Relic text, smoke assertions, remove I02 from `IMPROVE.md` | `docs/`, `newrelic/`, `scripts/smoke.sh` |

## 5. Acceptance tests

Each line is one test or one table case. Test command for each unit: `go test -race -count=1 ./...`, then `bash scripts/verify.sh`.

| I02 clause | Test |
|---|---|
| Partial request | Body over the limit: `capture_state=body_limit_exceeded`, `input_fp_scope=prefix`, `declared_bytes` larger than `observed_bytes`, status 413. Client abort: `read_error`. Rate limit: `not_read`. |
| Capture and parse tables | One case for each row of both tables in 3.4, and one case for each of the three named combinations. No response status changes. |
| Invalid UTF-8 | `body_utf8_replaced=true`; the shipped body is valid UTF-8 and inside the log limit; `body_sha256` matches the shipped text. |
| Redaction expansion | A body inside the limit that grows past it after redaction: `capture_state=log_prefix`, `body_truncated=true`, `redactions` above 0. |
| Forged marker | A body with marker text and no credential: `redactions=0`. |
| Chunked event | Every chunk carries the same capture attributes and `record_id`. |
| Replayed delivery | After an uncertain recovery, the second delivery has the same `record_id`, `ingest_ts` and capture attributes. |
| Queue overflow | A full durable queue with a clean end: `queue_refused` above 0, `loss=known`, `lost` equals the refused count. Never `none_known`. |
| Saturation, then producer death | Fill the bait queue after the last heartbeat, end the connection with no `stopped`, pass the idle timeout: `loss=unknown`. The stale `reported_dropped` does not produce `known`. |
| Saturated queue keeps health records | With the payload part of the queue full, the next heartbeat is queued and carries the new `dropped_total`. |
| Record after `stopped` | `loss=unknown`, `loss_reason=post_stop`. |
| Forced stop | A graceful shutdown that fails: `stopped` carries `forced=true`; the row reports `loss=unknown`, `loss_reason=forced_stop`. |
| Append before final state | A tick between admission and the durable append reports `pending`, not a final value. A refusal is credited to the correct boot. |
| Eviction | A ninth boot evicts the oldest: a row with `loss_reason=evicted` that is repeated for 20 intervals, also after one failed POST. |
| Accounting POST | All rows in one POST; the largest report (33 rows) fits; a failed POST leaves the loop on schedule; 13 existing heartbeat queries do not match the new rows. |
| Loss scope | With a drain that delivers nothing, a clean boot still reports `none_known`, and the row carries `loss_scope=committed`. |
| Fingerprint scope | A key that the redactor replaces gives `fp_scope=boot`. |
| Unknown schema version | `v` absent, 0 and 2 are rejected with reason `schema_version`; `ingest_stats` shows `rejected_schema_version`. |
| New attributes survive | Each new attribute is present after `Admit` and in the New Relic item of a maximum-size record, with no cut. |
| Role isolation | The existing isolation tests pass with no change to their assertions. An adapter record with a bait-only name loses it. |
| Provenance forgery | Request metadata with provenance names changes no envelope attribute. A producer that sends a reserved name loses it and gets `reserved_attrs_removed`. |
| Clock | A clamped record keeps `producer_ts`. `max_skew_ms` reports the largest difference seen for the boot. |

## 6. Not in version 1

- Durable producer receipts. The spool protocol stays one-way.
- The stage `available`, and gap detection from outside the host. Both need a New Relic account.
- Reconciliation of the stage `accepted` for each boot. It needs the acknowledged position of the durable queue for each boot, and bead `[internal reference removed]` first.
- Marking an interval as suspect after a host compromise. Evidence that New Relic already holds is outside the decoy's deletion authority, because the ingest key cannot delete. The mark itself is an analysis action.
- `norm_fp`. It belongs to I08.
- Sampling.
- The versioned deployment manifest of the resource contract.
- A change to `scripts/deploy-ubuntu.sh` to set `ATTACKBOX_DEPLOYMENT_ID`. It follows as its own unit, after coordination with the Vultr launch work.
- Any change to an NRQL condition, threshold, or alert name. `newrelic/queries.md:25` counts heartbeat rows by `source` and will show the new source value.
- The contract in direct mode.

## 7. Risks

- Rename cost. `body_bytes` has no reference outside the source. `body_fingerprint` has one document and one test. The New Relic artifacts use neither.
- Attribute count. An edge request event gains about 16 attributes. The New Relic item path limits extra attributes and marks a cut (`internal/telemetry/newrelic.go:617-631`).
- CPU. `input_fp` is one HMAC-SHA256 over at most 1 MiB for each request. Today it runs only when the log body is cut.
- U1 changes many test fixtures. The assertions must stay; only the record version is added.
- The scrubber changes to return a count. Its fuzz test and corpus must pass unchanged.
- Version constants depend on discipline. The pin tests catch changes that the fixed inputs exercise, and no others.

## 8. Decisions for the owner

1. Approve contract version 1 as written in section 3.
2. Approve the two renames: `body_bytes` to `observed_bytes`, and `body_fingerprint` to `input_fp`.
3. Approve two new shipper settings: `ATTACKBOX_SENSOR_ID` and `ATTACKBOX_DEPLOYMENT_ID`.

## 9. Log

- 2026-11-22: host read the evidence path and wrote revision 1. A broad read-only mapping worker (session `226a191f-0ef4-47f2-b3ee-306776a17dbf`) stopped with "Autocompact is thrashing" and produced no report; its task was too wide.
- 2026-11-22: independent design review of revision 1, Sonnet session `e7227fb8-80d0-4a7d-b4fb-75d3575d4210`, review text `/tmp/[internal reference removed]-design-review.md`. Verdict "I02 DESIGN: NOT PASS": 1 blocker, 11 major, 5 minor. The host checked the findings against the source and accepted all of them. Revision 2 changes:
  - B1 blocker: the loss rule now counts `queue_refused` and `rejected`; `none_known` needs all of them at 0.
  - B2, B3: `stopped` is made the last record; `missing` and the reconciliation identity are defined.
  - B4, B17: eviction gives a final row; waiting rows are bounded.
  - B5, B6: one bounded accounting POST; the rows use `source = 'shipper_accounting'`, so no existing query changes.
  - B7: the line assembly, the fixture files and the rollout rule are stated.
  - B8: the stamp covers the spool's own records; direct mode is out of the contract.
  - B9: `not_read` and `read_error`, the path table, the `declared_bytes` rule, the response values.
  - B10, B11: the transform order; the scrubber returns the count.
  - B12: `request_id`, clocks and restarts, reserved bait capacity, and the host-compromise item are placed.
  - B13, B14, B16: bait-only names are removed from other roles; `fp_scope` follows the secret file; the gate compares the plan, not the operator document.
- 2026-11-22: re-review of revision 2 by the same reviewer session (total cost $2.29, review text `/tmp/[internal reference removed]-design-rereview.md`). Verdict "I02 DESIGN: NOT PASS": no blocker, four new major findings, B14 not fixed. The host accepted all five. Revision 3 changes:
  - N1: a record counts as `admitted` only after its batch is appended; final states wait for that append; `append_error` added.
  - N2: `stopped` carries `forced`; a forced stop gives `unknown`.
  - N3: evicted rows repeat for 20 intervals; 2 wait for each role; the row limit is 40 with a stated order.
  - N4: `capture_state` and `parse_state` are independent tables; no response changes; the three real combinations are named.
  - B14: `fp_scope` follows what the redactor did.
- 2026-11-22: third round, same reviewer session (total cost $2.45, review text `/tmp/[internal reference removed]-design-rereview2.md`). N1 to N4 and B14 fixed. Verdict "I02 DESIGN: NOT PASS" for one major finding, M1: `none_known` read as "no loss" while the counters stop at `committed`. The host accepted it. Revision 3 now states the scope in 3.6, adds `loss_scope`, a test, and an item in section 6.
- 2026-11-22: fourth round, same reviewer session (total cost $2.72, review text `/tmp/[internal reference removed]-design-rereview3.md`). M1 fixed, no new finding. Verdict "I02 DESIGN: PASS".
- 2026-11-22: the owner approved section 8 through the approval form (answers: contract "approve", renames "yes", settings "yes"). Unit U1 starts.
