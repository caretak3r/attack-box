# AttackBox NRQL Queries

Operator reference for common New Relic queries. All queries respect chunk-safe deduplication via `(record_id, body_sha256, chunk_index)`.

## Verification Queries

### Verify All Six Streams Active

```nrql
FROM Log 
SELECT count(*) 
WHERE stream IN ('edge', 'transcript', 'probe', 'runtime', 'egress', 'heartbeat') 
FACET stream 
SINCE 10 minutes ago
```

Expected: Six rows with nonzero counts. Missing streams indicate a producer failure.

### Verify Heartbeat Sources

```nrql
FROM Log 
SELECT count(*) AS 'Events', latest(timestamp) AS 'Last Event'
WHERE stream = 'heartbeat' 
FACET source 
SINCE 10 minutes ago
```

Expected: Two sources (`shipper`, `bait`), both updated within the last 90 seconds.

### Verify Metrics Flowing

```nrql
FROM Metric 
SELECT count(*) 
WHERE metricName LIKE 'attackbox.%' 
FACET metricName 
SINCE 10 minutes ago
```

Expected: At least `attackbox.requests`, `attackbox.sessions`, `attackbox.probes` present.

### Check Bait Liveness

```nrql
FROM Log 
SELECT latest(bait_connected) AS 'Connected', 
       latest(last_bait_record_age_ms) / 1000 AS 'Age (sec)',
       latest(spool_clients) AS 'Clients'
WHERE stream = 'heartbeat' AND source = 'shipper'
SINCE 5 minutes ago
```

Expected: `bait_connected = 1`, age < 60 seconds, clients ≥ 1.

### Check Queue Health

```nrql
FROM Log 
SELECT latest(queue_bytes) / 1048576 AS 'Queue (MB)',
       latest(queue_backlog_bytes) / 1048576 AS 'Backlog (MB)',
       latest(ship_dropped_total) AS 'Dropped'
WHERE stream = 'heartbeat' AND source = 'shipper'
SINCE 5 minutes ago
```

Expected: Backlog < 128 MB, dropped count stable.

## Chunk-Safe Deduplication

**Critical:** Log events may be chunked and replayed. Always deduplicate by the tuple `(record_id, body_sha256, chunk_index)`.

### Canary Activity (Deduped)

```nrql
FROM Log 
SELECT latest(timestamp) AS 'Time',
       latest(session_id) AS 'Session',
       latest(src_ip) AS 'Source IP'
WHERE stream = 'probe' 
  AND action = 'canary-reuse' 
  AND record_id IS NOT NULL
FACET record_id, body_sha256, chunk_index
SINCE 1 hour ago
LIMIT 100
```

Each row is one unique canary event. `record_id` alone is insufficient—body changes and chunks must be distinct.

### Falco Critical Events (Deduped)

```nrql
FROM Log 
SELECT latest(timestamp) AS 'Time',
       latest(action) AS 'Action',
       latest(resource) AS 'Resource',
       latest(priority) AS 'Priority'
WHERE stream = 'runtime' 
  AND action = 'falco' 
  AND priority IN ('Critical', 'Emergency')
  AND record_id IS NOT NULL
FACET record_id, body_sha256, chunk_index
SINCE 1 hour ago
LIMIT 100
```

### Egress Blocks (Deduped)

```nrql
FROM Log 
SELECT latest(timestamp) AS 'Time',
       latest(dst_ip) AS 'Destination',
       latest(dst_port) AS 'Port',
       latest(proto) AS 'Protocol'
WHERE stream = 'egress' 
  AND action = 'egress_blocked'
  AND record_id IS NOT NULL
FACET record_id, body_sha256, chunk_index
SINCE 1 hour ago
LIMIT 100
```

### Reconstruct Chunked Event Body

```nrql
FROM Log 
SELECT message, body_sha256, chunk_index, chunk_count
WHERE record_id = '<record-id-here>' 
  AND body_sha256 = '<sha256-here>'
ORDER BY chunk_index ASC
```

Manually concatenate `message` fields in chunk order to recover the full body.

## Attack Pattern Queries

### Active Sessions (Last Hour)

```nrql
FROM Metric 
SELECT uniqueCount(session_id) AS 'Unique Sessions'
WHERE metricName = 'attackbox.requests'
SINCE 1 hour ago
```

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
TIMESERIES AUTO
FACET persona
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
SINCE 1 hour ago
FACET persona, endpoint
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
FROM Log 
SELECT timestamp, stream, action, task, probe_id, status
WHERE session_id = '<session-id-here>'
  AND record_id IS NOT NULL
ORDER BY timestamp ASC
LIMIT 1000
```

### Session Requests

```nrql
FROM Log 
SELECT timestamp, method, endpoint, status, task
WHERE session_id = '<session-id-here>'
  AND stream = 'edge'
  AND direction = 'request'
  AND record_id IS NOT NULL
ORDER BY timestamp ASC
```

### Session Declarations

```nrql
FROM Log 
SELECT timestamp, action, client_model, operator_alias, harness_name
WHERE session_id = '<session-id-here>'
  AND stream = 'probe'
  AND action IN ('register-model', 'register-harness', 'operator-alias')
  AND record_id IS NOT NULL
ORDER BY timestamp ASC
```

### Session Probes Issued

```nrql
FROM Log 
SELECT timestamp, probe_id, task, action
WHERE session_id = '<session-id-here>'
  AND stream = 'probe'
  AND record_id IS NOT NULL
ORDER BY timestamp ASC
```

## Threat Intelligence

### Source IP Activity

```nrql
FROM Log 
SELECT count(*) AS 'Requests', 
       uniqueCount(session_id) AS 'Sessions',
       latest(user_agent) AS 'User-Agent'
WHERE stream = 'edge' AND direction = 'request'
FACET src_ip
SINCE 1 hour ago
LIMIT 50
```

### User-Agent Distribution

```nrql
FROM Log 
SELECT count(*) AS 'Requests'
WHERE stream = 'edge' AND direction = 'request'
FACET user_agent
SINCE 1 hour ago
LIMIT 50
```

### Model Declarations

```nrql
FROM Log 
SELECT timestamp, session_id, src_ip, client_model
WHERE stream = 'probe' 
  AND action = 'register-model'
  AND client_model IS NOT NULL
  AND record_id IS NOT NULL
SINCE 1 day ago
LIMIT 200
```

### Harness Declarations

```nrql
FROM Log 
SELECT timestamp, session_id, harness_name, harness_version, runtime
WHERE stream = 'probe' 
  AND action = 'register-harness'
  AND harness_name IS NOT NULL
  AND record_id IS NOT NULL
SINCE 1 day ago
LIMIT 200
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
FROM Log 
SELECT latest(queue_bytes) AS 'Queue Bytes',
       latest(queue_backlog_bytes) AS 'Backlog',
       latest(spool_clients) AS 'Clients',
       latest(ship_dropped_total) AS 'Dropped',
       latest(bait_connected) AS 'Bait'
WHERE stream = 'heartbeat' AND source = 'shipper'
TIMESERIES 1 minute
SINCE 1 hour ago
```

### Ingest Errors

```nrql
FROM Log 
SELECT timestamp, action, error_message, retry_count
WHERE stream = 'runtime' AND action = 'newrelic_error'
ORDER BY timestamp DESC
LIMIT 100
```

### Stopped Events

```nrql
FROM Log 
SELECT timestamp, nr_sent, nr_dropped, nr_lost, local_sent, local_dropped
WHERE stream = 'runtime' AND action = 'stopped'
ORDER BY timestamp DESC
LIMIT 10
```

Inspect after a service restart to verify graceful shutdown and telemetry accounting.

## False-Positive Filtering

Some events are expected behavior and do not indicate compromise:

### Legitimate Tool Declarations

Client libraries often declare tools even when not invoking them. High `tool-invocation` task counts are expected.

```nrql
FROM Metric 
SELECT sum(attackbox.probes) 
WHERE metricName = 'attackbox.probes' 
  AND task = 'tool-invocation'
SINCE 1 hour ago
```

### Bait Heartbeat Trust Limits

**Warning threshold:** `last_bait_record_age_ms > 60000` (60 seconds)  
**Critical threshold:** `last_bait_record_age_ms > 90000` (90 seconds)

The bait emits a `bait_heartbeat` event every 30 seconds. Age between 30–60s is normal during low traffic. Age > 90s indicates a hung bait process.

### Shipper Heartbeat Trust Limits

**Warning threshold:** No shipper heartbeat for 60 seconds  
**Critical threshold:** No shipper heartbeat for 120 seconds

A missing shipper heartbeat means:
- Host down
- Egress blocked (cannot reach New Relic)
- Shipper process crashed

The alert must trigger power-off per the threat model.

### Queue Backlog Expected Range

- **Normal:** 0–64 MB
- **Warning:** 64–128 MB (temporary ingest degradation)
- **Critical:** > 224 MB (approaching 256 MB limit; oldest records being dropped)

Persistent backlog indicates New Relic ingest issues or insufficient throughput. Short spikes during traffic bursts are expected.

## Data Retention

- **Metrics:** 30 days (raw dimensional data), 13 months (aggregated)
- **Logs:** Plan-dependent (typically 8–30 days for Standard, up to 90+ days for Pro+)
- **NrIntegrationError:** 8 days

For long-term retention, configure the optional archive S3 bucket per `implementation_plan.md`.
