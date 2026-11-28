# Live attack evidence collection


## Capture contract

`ATTACKBOX_FULL_EVIDENCE=true` is the process default and is set in `/Users/rohit/attack-box/compose.yaml`. It adds an unredacted application capture to the existing readable, redacted context logs. Set it to `false` to stop this additional capture. Restart the bait after a setting change.

The capture includes submitted body bytes, parsed request headers, the request URI, request trailers, response header snapshots, and response bytes accepted by the HTTP writer. Submitted credentials remain in this evidence. Server secret files are not capture inputs.

The bait skips all telemetry (edge events, evidence records, and OpenTelemetry spans) for its own health checks: requests from loopback addresses, or requests with User-Agent `attackbox-hostcollector/1` from private addresses. These probes still serve normal responses. Other traffic from private addresses keeps full telemetry.

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

The shipper writes records to local JSONL files. Each line is a complete JSON record. The shipper divides large event bodies into at most 3,500-character `body_chunk` fields for compatibility. Each chunk retains `record_id`, `body_sha256`, `chunk_index`, and `chunk_count`. Existing queries must use `body_chunk`.

## Completeness boundaries

Full evidence means exact recovery of the captured application bytes. It does not mean unlimited input or lossless packet capture.

- The default request-body limit remains 1 MiB. A request above the limit retains the accepted prefix and has an incomplete `body_limit` manifest. Changing `ATTACKBOX_MAX_LOG_BODY` affects readable summaries only, not raw capture.
- A read failure emits `read_error`. A rejected request whose body was not read emits an incomplete `body_not_read` manifest. Do not treat these as empty complete requests.
- A response manifest reports `writer_accepted`, not proof that the client received every byte. Write errors, interrupted streams and shutdown produce incomplete evidence.
- HTTP parsing has already occurred. Header casing/order, TLS records, transfer framing and requests rejected by nginx or Go before the handler are outside this capture. The host/edge collector work remains necessary.
- Queues remain bounded. Capture does not bypass admission, source byte-rate limits, or queue budgets. The producer socket protocol still has no fsync receipt. A crash, overload or outage can lose records. Hashes and manifests reveal missing or changed parts; an absent manifest is unknown, not complete.
- A privileged or compromised producer can forge its own evidence. Hashes verify consistency; the shipper's authenticated source fields establish the collection role, not attacker identity or successful exploitation.

The bait waits for tracked handlers to emit final evidence before closing sinks. Compose gives the process 90 seconds before SIGKILL. With the current 15-second setting, HTTP shutdown, handler completion, and local drain each have a bounded phase. If this setting increases, increase container grace beyond the combined bound. Close public ingress first: new requests rejected by the shutdown wrapper are not full captures.

## Local file delivery

The Go shipper reads up to 200 records and writes them to local JSONL files immediately. It does not wait to fill a batch. An empty queue is checked every 100 ms. Each file write stays below the configured byte target. Production uses the host spool and durable shipper.

A durable batch is acknowledged only after file writes succeed. Partial acceptance retains the full batch for replay. Record IDs and chunk hashes permit duplicate removal. Count metrics can repeat after a crash or partial acceptance; use distinct evidence records for research counts. Count deltas use deterministic one-second UTC windows derived from their stored event time.

`export_lag_ms` measures event time to the write attempt. `export_attempt_at_ms` records that attempt time. A bad record or I/O error can hold the ordered queue; watch backlog and source-specific loss counters. A healthy heartbeat alone does not prove evidence writes succeeded.

Operational target: under measured normal campaign load, write evidence within two seconds of capture. Validate the actual VPS and filesystem separately. Do not promise sub-second file visibility from local timing tests.

## Watch and recover evidence

The live dashboard reads evidence files from the host (via SSH) or from the local archive. Filter by `sensor_id` and `deployment_id` to select one campaign. The panels show live traffic, evidence/forensics, and collection health. Missing values mean no data, not a healthy zero.

For one request, extract all capture rows from the evidence files, including manifests. Use `jq` or DuckDB to filter and export. Verify that the export includes every chunk. A complete manifest alone does not prove that all its segments were written.

```bash
# Using jq to filter one request from shipper events file
jq -c 'select(.record.stream == "edge" and .record.action == "capture" and .record.request_id == "REPLACE_REQUEST_ID")' \
  /var/lib/attackbox-evidence/shipper/events-YYYYMMDD.jsonl > capture-export.ndjson
```

The Go recovery tool accepts NDJSON evidence exports. It reads records from the shipper envelope format.

```bash
cd /Users/rohit/attack-box
go run /Users/rohit/attack-box/cmd/attackbox-evidence \
  -input /Users/rohit/attack-box/capture-export.ndjson \
  -request-id REPLACE_REQUEST_ID \
  -kind request_body \
  -output /Users/rohit/attack-box/request-capture.bin
```

Valid kinds: `request_body`, `response_body`, `request_metadata`, `response_metadata`, `request_trailers`. The tool requires schema version 1, base64 encoding and application scope on each selected row. It checks chunk hashes, segment hashes, offsets, counts, the whole-capture hash, and a complete manifest. It rejects gaps, conflicting copies and incomplete captures before creating output. It creates a new file with mode `0600`; it will not overwrite a file or print captured bytes to the terminal. Limits: 64 MiB input, 16 MiB decoded data, 1 MiB per exported record, and 32,768 parts.

The live dashboard runs locally and reads evidence via SSH or from the archive. See [monitoring guide](monitoring-setup.md) for setup and query examples.
