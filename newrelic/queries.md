# AttackBox NRQL Queries

Operator reference for common New Relic queries. All queries respect chunk-safe deduplication via `(record_id, body_sha256, chunk_index)`.

**Note:** Queries marked "(Pending Validation)" use field names that require deployment validation against actual emitted events.

## Verification Queries

### Verify All Six Streams Active

```nrql
FROM Log, Log_AttackEvidence, Log_Security, Log_Operations
SELECT count(*WHERE stream IN ('edge', 'transcript', 'probe', 'runtime', 'egress', 'heartbeat')
FACET stream
SINCE 10 minutes ago
```

Expected: Six rows with nonzero counts. Missing streams indicate a producer failure.

### Verify Heartbeat Sources

```nrql
FROM Log, Log_AttackEvidence, Log_Security, Log_Operations
SELECT count(*) AS 'Events', latest(timestamp) AS 'Last Event'
WHERE stream = 'heartbeat'
FACET source
SINCE 10 minutes ago
```

Expected: `shipper` and `bait` update within 90 seconds. `shipper_accounting` also appears when accounting reports arrive. It does not replace the regular shipper heartbeat.

### Verify Metrics Flowing

```nrql
FROM Metric
SELECT count(*)
WHERE metricName LIKE 'attackbox.%'
FACET metricName
SINCE 10 minutes ago
```

Expected metrics:
- Bait: `attackbox.requests`, `attackbox.sessions`, `attackbox.probes`, `attackbox.request_bytes`, `attackbox.response_bytes`, `attackbox.probe_followups`, `attackbox.session_duration_seconds`, `attackbox.stream_disconnect_seconds`, `attackbox.retry_delay_seconds`, `attackbox.concurrent_status_requests`
- Shipper: `attackbox.telemetry.ingest_errors_total`, `attackbox.telemetry.ingest_retries_total`, `attackbox.heartbeat`
- Host: `attackbox.egress_blocked` (if egress adapter configured)

### Check Bait Liveness

```nrql
FROM Log, Log_AttackEvidence, Log_Security, Log_Operations
SELECT latest(bait_connected) AS 'Connected',
       latest(last_bait_record_age_ms) / 1000 AS 'Age (sec)',
       latest(spool_clients) AS 'Clients'
WHERE stream = 'heartbeat' AND source = 'shipper'
SINCE 5 minutes ago
```

Expected: `bait_connected = 1`, age < 60 seconds, clients ≥ 1.

### Check Queue Health

```nrql
FROM Log, Log_AttackEvidence, Log_Security, Log_Operations
SELECT latest(queue_bytes) / 1048576 AS 'Queue (MB)',
       latest(queue_backlog_bytes) / 1048576 AS 'Backlog (MB)',
       latest(ship_dropped_total) AS 'Dropped'
WHERE stream = 'heartbeat' AND source = 'shipper'
SINCE 5 minutes ago
```

Expected: Backlog < 128 MB, dropped count stable.

## Chunk-Safe Deduplication

**Critical:** Log events may be chunked and replayed. Always deduplicate by the tuple `(record_id, body_sha256, chunk_index)`.

### Probe Decisions (Deduped)

```nrql
FROM Log, Log_AttackEvidence, Log_Security, Log_Operations
SELECT latest(timestamp) AS 'Time',
       latest(session_id) AS 'Session',
       latest(src_ip) AS 'Source IP',
       latest(probe_id) AS 'Probe'
WHERE stream = 'probe'
  AND action = 'decision'
  AND record_id IS NOT NULL
FACET record_id, body_sha256, chunk_index
SINCE 1 hour ago
LIMIT 100
```

Each row is one unique probe decision event chunk.

### Falco Events (Deduped, Pending Validation)

```nrql
FROM Log, Log_AttackEvidence, Log_Security, Log_Operations
SELECT latest(timestamp) AS 'Time',
       latest(action) AS 'Action',
       latest(resource) AS 'Resource'
WHERE stream = 'runtime'
  AND action = 'falco'
  AND record_id IS NOT NULL
FACET record_id, body_sha256, chunk_index
SINCE 1 hour ago
LIMIT 100
```

**Pending:** `event.priority`, `event.rule` fields require adapter validation.

### Egress Blocks (Deduped, Pending Validation)

```nrql
FROM Log, Log_AttackEvidence, Log_Security, Log_Operations
SELECT latest(timestamp) AS 'Time',
       latest(event.dst_ip) AS 'Destination',
       latest(event.dst_port) AS 'Port',
       latest(event.proto) AS 'Protocol'
WHERE stream = 'egress'
  AND action = 'egress_blocked'
  AND record_id IS NOT NULL
FACET record_id, body_sha256, chunk_index
SINCE 1 hour ago
LIMIT 100
```

**Pending:** Adapter wraps firewall data under `event.*` attributes per design.

### Reconstruct Chunked Event Body

```nrql
FROM Log, Log_AttackEvidence, Log_Security, Log_Operations
SELECT body_chunk, body_sha256, chunk_index, chunk_count
WHERE record_id = '<record-id-here>'
  AND body_sha256 = '<sha256-here>'
ORDER BY chunk_index ASC
```

Manually concatenate `body_chunk` fields in chunk order to recover the full body.

## Attack Pattern Queries

### Active Sessions (Last Hour)

```nrql
FROM Metric
SELECT sum(attackbox.sessions) AS 'Sessions'
WHERE metricName = 'attackbox.sessions'
SINCE 1 hour ago
```

**Note:** `session_id` removed per SafeLabels; session count is aggregated.

### Top Attack Tasks

```nrql
FROM Metric
SELECT sum(attackbox.probes) AS 'Probes'
WHERE metricName = 'attackbox.probes'
FACET task
SINCE 1 hour ago
LIMIT 20
```

### Probe Distribution by ID

```nrql
FROM Metric
SELECT sum(attackbox.probes) AS 'Count'
WHERE metricName = 'attackbox.probes'
FACET probe_id
SINCE 1 hour ago
LIMIT 20
```

### Request Rate by Persona

```nrql
FROM Metric
SELECT rate(sum(attackbox.requests), 1 minute) AS 'Requests/min'
WHERE metricName = 'attackbox.requests'
FACET persona
TIMESERIES AUTO
```

### Session Duration Distribution

```nrql
FROM Metric
SELECT histogram(attackbox.session_duration_seconds, 10, 20)
WHERE metricName = 'attackbox.session_duration_seconds'
SINCE 1 hour ago
```

### Stream Disconnect Timing

```nrql
FROM Metric
SELECT percentile(attackbox.stream_disconnect_seconds, 50, 95, 99)
WHERE metricName = 'attackbox.stream_disconnect_seconds'
FACET persona, endpoint
SINCE 1 hour ago
```

### Retry Behavior

```nrql
FROM Metric
SELECT histogram(attackbox.retry_delay_seconds, 5, 20) AS 'Delay Distribution'
WHERE metricName = 'attackbox.retry_delay_seconds'
  AND attackbox.retry_delay_seconds > 0
SINCE 1 hour ago
```

## Session Investigation

### Session Timeline (Deduped Events)

```nrql
FROM Log, Log_AttackEvidence, Log_Security, Log_Operations
SELECT timestamp, stream, action, task, probe_id, status
WHERE session_id = '<session-id-here>'
  AND record_id IS NOT NULL
ORDER BY timestamp ASC
LIMIT 1000
```

### Session Requests

```nrql
FROM Log, Log_AttackEvidence, Log_Security, Log_Operations
SELECT timestamp, method, endpoint, status, task
WHERE session_id = '<session-id-here>'
  AND stream = 'edge'
  AND direction = 'request'
  AND record_id IS NOT NULL
ORDER BY timestamp ASC
```

### Session Probe Decisions

```nrql
FROM Log, Log_AttackEvidence, Log_Security, Log_Operations
SELECT timestamp, action, probe_id, task
WHERE session_id = '<session-id-here>'
  AND stream = 'probe'
  AND action = 'decision'
  AND record_id IS NOT NULL
ORDER BY timestamp ASC
```

## Threat Intelligence

### Source IP Activity

```nrql
FROM Log, Log_AttackEvidence, Log_Security, Log_Operations
SELECT count(*) AS 'Requests',
       latest(user_agent) AS 'User-Agent'
WHERE stream = 'edge' AND direction = 'request'
FACET src_ip
SINCE 1 hour ago
LIMIT 50
```

**Note:** High-cardinality source/session investigation belongs in Log, not Metric.

### User-Agent Distribution

```nrql
FROM Log, Log_AttackEvidence, Log_Security, Log_Operations
SELECT count(*) AS 'Requests'
WHERE stream = 'edge' AND direction = 'request'
FACET user_agent
SINCE 1 hour ago
LIMIT 50
```

## Health and Diagnostics

### NrIntegrationError Events

```nrql
FROM NrIntegrationError
SELECT timestamp, message, newRelicFeature, instrumentation.name
SINCE 1 hour ago
LIMIT 100
```

Expected: Zero events. Any errors indicate ingest API failures, quota exhaustion, or malformed payloads.

### Shipper Metrics

```nrql
FROM Log, Log_AttackEvidence, Log_Security, Log_Operations
SELECT latest(queue_bytes) AS 'Queue Bytes',
       latest(queue_backlog_bytes) AS 'Backlog',
       latest(spool_clients) AS 'Clients',
       latest(ship_dropped_total) AS 'Dropped',
       latest(bait_connected) AS 'Bait'
WHERE stream = 'heartbeat' AND source = 'shipper'
TIMESERIES 1 minute
SINCE 1 hour ago
```

### Stopped Events

```nrql
FROM Log, Log_AttackEvidence, Log_Security, Log_Operations
SELECT timestamp, nr_sent, nr_dropped, nr_lost, local_sent, local_dropped
WHERE stream = 'runtime' AND action = 'stopped'
ORDER BY timestamp DESC
LIMIT 10
```

Inspect after a service restart to verify graceful shutdown and telemetry accounting.

## Data Retention

- **Metrics:** 30 days (raw dimensional data), 13 months (aggregated)
- **Logs:** Plan-dependent (typically 8–30 days for Standard, up to 90+ days for Pro+)
- **NrIntegrationError:** 8 days

For long-term retention, configure the optional archive S3 bucket per `implementation_plan.md`.

## Pending Validation

The following field names require deployment validation:

**Runtime stream (Falco):**
- `event.priority` (Critical, Emergency, etc.)
- `event.rule` (Falco rule name)
- Other Falco JSON fields under `event.*`

**Egress stream (firewall):**
- `event.dst_ip`, `event.dst_port`, `event.proto`
- Other firewall log fields under `event.*`

**Probe stream (observations):**
- Observation array structure and probe_id filtering
- Canary-reuse detection requires observations array queries
- A `canary-reuse` observation holds, for each canary, a comma list of states: `present_in_history`, `newly_echoed`, `destination_placed`, `credential_presented`, `presented_undelivered`. It also holds `credential_source` and `independently_observed` (always `unavailable`). `present_in_history` is not exfiltration. Each state is reported once for each canary in a session.
- Replies that the responder does not score are observations with `probe_id` `attribution`, a `status`, and a `reason`.
- `attackbox.probe_followups` counts attributed replies only.

After deployment, verify these queries against actual emitted events and update as needed.

## Live capture format

Current exports store body text in `body_chunk`; `message` is an inert action label. For raw capture, reconstruct and verify all chunks, decode each base64 segment, and validate the completion manifest. Use the Go recovery tool and setup procedure in `/Users/rohit/attack-box/docs/live-evidence.md`. A redacted context log is not the raw evidence.

## Host Infrastructure acceptance

Native Infrastructure owns host resource metrics. On 2026-11-23, agent 2.1.1 on `srv-000000` reported dimensional `host.*` metrics. Use `average` for these series; `latest` and `SystemSample` did not return values in this account. Verify the reporting host entity separately.

```sql
FROM Metric SELECT average(host.cpuPercent), average(host.memoryUsedPercent), average(host.diskFreeBytes)
WHERE host.hostname = 'srv-000000' SINCE 5 minutes ago
```

The current reporting host GUID is `ODc2NDQ1MHxJTkZSQXxOQXw3NzIwMjUwODE5MTg3MDg1NTI0`. Query the entity with NerdGraph or open it in New Relic; do not infer entity health from metric counts.

```sql
FROM Log, Log_AttackEvidence, Log_Security, Log_Operations SELECT count(*) WHERE hostname = 'srv-000000'
FACET logtype SINCE 5 minutes ago
```

The following readiness queries apply only after the optional Go collector and OTel profile are deployed:

```sql
FROM Metric SELECT latest(attackbox_component_observed), latest(attackbox_component_running), latest(attackbox_component_ready), latest(attackbox_component_coverage_verified)
WHERE sensor_id = 'srv-000000' FACET component SINCE 5 minutes ago LIMIT MAX
```

```sql
FROM Metric SELECT latest(attackbox_inventory_snapshot_valid), latest(attackbox_inventory_snapshot_age_seconds)
WHERE sensor_id = 'srv-000000' SINCE 5 minutes ago
```

Confirm fresh samples, source age below 90 seconds and all 12 expected inventory rows. The coverage gauge remains `-1`; local readiness does not certify remote forensic delivery. Host installation alone does not provide application spans. After trace rollout, query `Span` for `attackbox-bait` and `attackbox-shipper`; match their trusted `host.id` to the native agent display name. See the [New Relic resource contract](https://docs.newrelic.com/docs/opentelemetry/best-practices/opentelemetry-best-practices-resources/).

Local health command: `curl -fsS http://127.0.0.1:18003/v1/status`. New Relic queries require a user key; an ingest key cannot query account data.
