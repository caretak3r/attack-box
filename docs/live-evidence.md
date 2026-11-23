# Live attack evidence and New Relic monitoring


## Capture contract

`ATTACKBOX_FULL_EVIDENCE=true` is the process default and is set in `/Users/rohit/attack-box/compose.yaml`. It adds an unredacted application capture to the existing readable, redacted context logs. Set it to `false` to stop this additional capture. Restart the bait after a setting change.

The capture includes submitted body bytes, parsed request headers, the request URI, request trailers, response header snapshots, and response bytes accepted by the HTTP writer. Submitted credentials remain in this evidence. Server secret files and the New Relic license key are not capture inputs. Keep the New Relic key in the host shipper; do not place it in the bait.

| Record | When emitted | What it establishes |
|---|---|---|
| `request_metadata` | Handler entry | Method, URI, parsed headers, host, protocol, declared length, peer |
| `request_body` | Coalesced reads, with a 250 ms flush timer | Bytes within the accepted request-body limit |
| `request_trailers` | End of body read | Parsed trailers; complete only after successful EOF |
| `request_received` | End of body read | Readable, redacted preview before a long response finishes |
| `response_metadata` | First final response header | Application header snapshot and status |
| `response_body` | Coalesced writer output, with a 250 ms flush timer | Bytes accepted by the writer, including streamed output |
| `manifest` | End of each captured component | Byte count, segment count, whole hash, completeness and reason |

All capture records use `stream=edge`, `action=capture`, and the request ID. A data segment carries `evidence_kind`, `evidence_segment`, `evidence_offset`, `evidence_bytes`, and `evidence_sha256`. A manifest carries `evidence_target`, `evidence_segments`, `evidence_bytes`, `evidence_sha256`, `evidence_complete`, and `evidence_reason`. `evidence_version=1` and `evidence_scope=application` identify this format.

Each segment contains at most 12 KiB of source bytes. Short reads and writes are coalesced with a 250 ms flush timer; completion flushes the remainder immediately. This limits log amplification from byte-at-a-time input. Its body is `base64:` followed by standard base64. This preserves binary data, invalid UTF-8 and credential strings through JSON transport. Parsed header values and URI fields are also stored as byte slices inside the metadata JSON. Metadata key order and HTTP header order are not wire evidence.

The exporter divides each event body into at most 3,500-character `body_chunk` fields. Each chunk retains `record_id`, `body_sha256`, `chunk_index`, and `chunk_count`. New Relic's `message` is a fixed action label. It does not contain attacker JSON that could be parsed as trusted attributes. Existing body queries must use `body_chunk`; `message` no longer holds the body.

## Completeness boundaries

Full evidence means exact recovery of the captured application bytes. It does not mean unlimited input or lossless packet capture.

- The default request-body limit remains 1 MiB. A request above the limit retains the accepted prefix and has an incomplete `body_limit` manifest. Changing `ATTACKBOX_MAX_LOG_BODY` affects readable summaries only, not raw capture.
- A read failure emits `read_error`. A rejected request whose body was not read emits an incomplete `body_not_read` manifest. Do not treat these as empty complete requests.
- A response manifest reports `writer_accepted`, not proof that the client received every byte. Write errors, interrupted streams and shutdown produce incomplete evidence.
- HTTP parsing has already occurred. Header casing/order, TLS records, transfer framing and requests rejected by nginx or Go before the handler are outside this capture. The host/edge collector work remains necessary.
- Queues remain bounded. Capture does not bypass admission, source byte-rate limits, queue budgets or New Relic limits. The producer socket protocol still has no fsync receipt. A crash, overload or outage can lose records. Hashes and manifests reveal missing or changed parts; an absent manifest is unknown, not complete.
- A privileged or compromised producer can forge its own evidence. Hashes verify consistency; the shipper's authenticated source fields establish the collection role, not attacker identity or successful exploitation.

The bait now waits for tracked handlers to emit final evidence before closing sinks. Compose gives the process 90 seconds before SIGKILL. With the current 15-second setting, HTTP shutdown, handler completion, remote drain and local drain each have a bounded phase. If this setting increases, increase container grace beyond the combined bound. Close public ingress first: new requests rejected by the shutdown wrapper are not full captures.

## Near-real-time delivery

The Go shipper reads up to 200 records and exports them in byte-bounded batches immediately. It does not wait to fill a batch. An empty queue is checked every 100 ms. Each uncompressed request stays below the configured 900,000-byte target. The direct developer mode flushes every second. Production uses the host spool and durable shipper.

A durable batch is acknowledged only after all its log and metric POSTs succeed. Partial acceptance retains the full batch for replay. Log IDs and chunk hashes permit duplicate removal. Count metrics can repeat after a crash or partial acceptance; use distinct evidence records for research counts. Count deltas use deterministic one-second UTC windows derived from their stored event time.

`export_lag_ms` measures event time to the export attempt. `export_attempt_at_ms` records that attempt time. These fields do not measure vendor indexing delay. A bad record, authentication error or backend outage can still hold the ordered queue; watch backlog and source-specific loss counters. A healthy heartbeat alone does not prove evidence delivery.

Operational target: under the measured normal campaign load, attempt export within two seconds of capture. Validate the actual VPS, transport and account separately. The dashboard refreshes every 30 seconds; use the Logs view for continuous inspection if the account provides it. Do not promise sub-second account visibility from local timing tests.

New Relic limits log POSTs to 1 MB and stores only a limited number of characters in ordinary string fields. It can discard old timestamps. Chunking and bounded requests address transport limits; remote parsing, retention and drop rules still require a canary check. [Log API requirements](https://docs.newrelic.com/docs/logs/log-api/introduction-log-api/)

## Watch and recover evidence

Import `/Users/rohit/attack-box/newrelic/dashboards/attackbox-overview.json` after replacing account placeholders as described in `/Users/rohit/attack-box/newrelic/README.md`. Filter by `sensor_id` and `deployment_id` to select one campaign. The three pages show live traffic, evidence/forensics, and delivery health. Missing values mean no data, not a healthy zero.

For one request, export all capture rows, including manifests. New Relic result limits can truncate a query export. Use narrow time/request filters and verify that the export includes every chunk. A table showing a complete manifest alone does not prove that all its segments arrived.

```sql
FROM Log SELECT *
WHERE `service.name` = 'attackbox' AND source = 'bait'
  AND stream = 'edge' AND action = 'capture'
  AND request_id = 'REPLACE_REQUEST_ID'
SINCE 1 hour ago LIMIT MAX
```

The Go recovery tool accepts a flat New Relic JSON array or NDJSON export. It also accepts individual log objects with nested `attributes`. It does not accept the complete Log API `common`/`logs` transport envelope.

```bash
cd /Users/rohit/attack-box
go run /Users/rohit/attack-box/cmd/attackbox-evidence \
  -input /Users/rohit/attack-box/capture-export.ndjson \
  -request-id REPLACE_REQUEST_ID \
  -kind request_body \
  -output /Users/rohit/attack-box/request-capture.bin
```

Valid kinds: `request_body`, `response_body`, `request_metadata`, `response_metadata`, `request_trailers`. The tool requires schema version 1, base64 encoding and application scope on each selected row. It checks chunk hashes, segment hashes, offsets, counts, the whole-capture hash, and a complete manifest. It rejects gaps, conflicting copies and incomplete captures before creating output. It creates a new file with mode `0600`; it will not overwrite a file or print captured bytes to the terminal. Limits: 64 MiB input, 16 MiB decoded data, 1 MiB per exported record, and 32,768 parts.

The local review page is `/Users/rohit/attack-box/.lavish/live-watch.html`. Open [the interactive preview](http://127.0.0.1:4387/session/d605c6b2261d2061) to inspect all 45 widgets, exact queries and synthetic traffic scenarios. It uses the existing project review theme. It is not connected to New Relic. Browser checks covered desktop and 390-pixel mobile layouts, tab changes, search, keyboard session drilldown and inert payload display. The New Relic dashboard retains New Relic's native visual style.

