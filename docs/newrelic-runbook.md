# New Relic Operator Runbook — AttackBox

Operational guide for New Relic monitoring, alert response, and troubleshooting.

## Table of Contents

1. [Key Provisioning](#key-provisioning)
2. [Verification After Deployment](#verification-after-deployment)
3. [Alert Response](#alert-response)
4. [Chunk-Safe Deduplication](#chunk-safe-deduplication)
5. [False Positives and Trust Limits](#false-positives-and-trust-limits)
6. [Investigation Workflows](#investigation-workflows)
7. [Troubleshooting](#troubleshooting)
8. [Data Retention and Archival](#data-retention-and-archival)

---

## Key Provisioning

### Create Dedicated Ingest-Only Key

**Critical:** Use a dedicated `Ingest - License` key for the decoy, **never** the account's original license key.

1. Navigate to: **Account settings → API keys → Keys → Create a key**
2. Key type: **Ingest - License**
3. Name: `attackbox-decoy-ingest` (or similar identifiable name)
4. Account: Select the dedicated AttackBox account/subaccount
5. Notes: `Dedicated ingest key for decoy VPS. Revoke on compromise.`
6. Click **Create key**

**Key format:** 40 alphanumeric characters, either lowercase hex or ending in `NRAL`.

**Example:** `REDACTED` or `abc123...NRAL`

### Key Scope and Limitations

The `Ingest - License` key permits:
- ✅ Submitting logs to the Log API
- ✅ Submitting metrics to the Metric API
- ✅ Submitting traces and other telemetry

The key **does not** permit:
- ❌ Querying data via NRQL
- ❌ Reading logs, metrics, or events
- ❌ Using the NerdGraph API
- ❌ Accessing the New Relic UI
- ❌ Creating or modifying dashboards, alerts, or configuration

**Threat model:** A stolen ingest key can submit arbitrary telemetry, consume quota, and poison data. It cannot query existing data or access the UI. Use a dedicated account to contain the blast radius.

### Key Validation

The shipper validates the key at startup:

```bash
# Valid formats
ATTACKBOX_NR_LICENSE_KEY=REDACTED  # 40-char hex
ATTACKBOX_NR_LICENSE_KEY=REDACTED                      # ends in NRAL

# Rejected formats (startup fails)
ATTACKBOX_NR_LICENSE_KEY=NRAK-...   # User key
ATTACKBOX_NR_LICENSE_KEY=NRAA-...   # Admin key
ATTACKBOX_NR_LICENSE_KEY=NRII-...   # Insert key (deprecated)
ATTACKBOX_NR_LICENSE_KEY=NRIQ-...   # Query key (deprecated)
ATTACKBOX_NR_LICENSE_KEY=NRJS-...   # Browser key
ATTACKBOX_NR_LICENSE_KEY=NRBR-...   # Browser key
```

Validation code: `internal/telemetry/newrelic.go:34-57`

### Key Storage

**On the host:**
```bash
# File: /etc/attackbox/shipper.env
# Owner: root:root
# Mode: 0600
ATTACKBOX_NR_LICENSE_KEY=<40-char-key>
```

**In systemd:**
```ini
[Service]
EnvironmentFile=/etc/attackbox/shipper.env
```

**Never:**
- Store the key in a world-readable file
- Include it in Docker images, git repositories, or configuration management
- Share it with the bait container (spool mode keeps the key host-side only)

### Key Rotation

1. Create a new `Ingest - License` key (follow [Create Dedicated Ingest-Only Key](#create-dedicated-ingest-only-key))
2. Update `/etc/attackbox/shipper.env` with the new key
3. Restart the shipper: `systemctl restart attackbox-shipper`
4. Verify heartbeat in New Relic (see [Verification After Deployment](#verification-after-deployment))
5. Deactivate the old key: **API keys → Keys → (old key) → Deactivate**

### Key Revocation

**On compromise or ingest abuse:**

1. **Deactivate immediately:** New Relic UI → **API keys → Keys → (key) → Deactivate**
2. Power off the decoy: Provider console or mobile app
3. Check New Relic for malicious telemetry (spikes, poisoned data)
4. Rotate to a new key before rebuilding

---

## Verification After Deployment

Run these queries within **10 minutes** of deploying the decoy to confirm all telemetry is flowing.

### 1. All Six Streams Active

```nrql
FROM Log
SELECT count(*) AS 'Events'
WHERE stream IN ('edge', 'transcript', 'probe', 'runtime', 'egress', 'heartbeat')
FACET stream
SINCE 10 minutes ago
```

**Expected:** Six rows with nonzero counts:
- `edge`: Request/response logs
- `transcript`: Message and tool logs
- `probe`: Gate and declaration logs
- `runtime`: Falco, shipper, and bait lifecycle events
- `egress`: Blocked connection attempts
- `heartbeat`: Liveness signals

**Missing streams:**
- `edge`/`transcript`/`probe`: Bait not receiving requests or not connected to shipper socket
- `runtime`: Falco not configured or shipper stdin adapters not running
- `egress`: Firewall log integration not active
- `heartbeat`: Shipper not running or New Relic unreachable

### 2. Heartbeat Sources Present

```nrql
FROM Log
SELECT count(*) AS 'Events' AS 'Events', latest(timestamp) AS 'Last Event'
WHERE stream = 'heartbeat'
FACET source
SINCE 10 minutes ago
```

**Expected:** Two sources:
- `source = shipper`: Host heartbeat (direct POST, bypasses queue)
- `source = bait`: Bait liveness (via socket, every 30 seconds)

Both should update within the last **90 seconds**.

**Missing `shipper`:** Host down, shipper crashed, or egress blocked (critical).

**Missing `bait`:** Container down, bait crashed, or socket disconnected (critical).

### 3. Metrics Flowing

```nrql
FROM Metric
SELECT count(*) AS 'Events'
WHERE metricName LIKE 'attackbox.%'
FACET metricName
SINCE 10 minutes ago
```

**Expected metrics:**
- `attackbox.requests`: Request count by persona, endpoint, status_class
- `attackbox.sessions`: New session count by persona
- `attackbox.probes`: Probe count by persona, probe_id, task
- `attackbox.request_bytes`: Request body bytes
- `attackbox.response_bytes`: Response body bytes
- `attackbox.probe_followups`: Follow-up probe responses
- `attackbox.session_duration_seconds`: Session age
- `attackbox.stream_disconnect_seconds`: Disconnect timing
- `attackbox.retry_delay_seconds`: Retry delay observations
- `attackbox.concurrent_status_requests`: Concurrency gate hits

**Low traffic?** Trigger a test request:
```bash
curl -X POST https://<decoy-ip>/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen3:8b","messages":[{"role":"user","content":"test"}]}'
```

### 4. Bait Liveness

```nrql
FROM Log
SELECT latest(bait_connected) AS 'Connected',
       latest(last_bait_record_age_ms) / 1000 AS 'Age (sec)',
       latest(spool_clients) AS 'Clients'
WHERE stream = 'heartbeat' AND source = 'shipper'
SINCE 5 minutes ago
```

**Expected:**
- `bait_connected = 1`
- `last_bait_record_age_ms < 60000` (< 60 seconds)
- `spool_clients >= 1`

**`bait_connected = 0`:** Socket disconnected; container down or bait exited.

**High age:** Bait connected but not sending records; process hung.

### 5. Queue Health

```nrql
FROM Log
SELECT latest(queue_bytes) / 1048576 AS 'Queue (MB)',
       latest(queue_backlog_bytes) / 1048576 AS 'Backlog (MB)',
       latest(ship_dropped_total) AS 'Dropped'
WHERE stream = 'heartbeat' AND source = 'shipper'
SINCE 5 minutes ago
```

**Expected:**
- Backlog: **0–64 MB** (normal), **64–128 MB** (warning), **> 224 MB** (critical)
- Dropped: stable (increments only on queue exhaustion)

**Backlog growing:** Ingest throttled or New Relic API slow; records queued to disk.

### 6. No Integration Errors

```nrql
FROM NrIntegrationError
SELECT count(*) AS 'Events'
SINCE 10 minutes ago
```

**Expected:** Zero events.

**Nonzero:** Ingest API failures, quota exhaustion, malformed payloads, or authentication errors. Check details:

```nrql
FROM NrIntegrationError
SELECT timestamp, message, newRelicFeature
SINCE 1 hour ago
LIMIT 100
```

---

## Alert Response

### Critical Alerts

#### Shipper Heartbeat Lost

**Alert:** No shipper heartbeat for 120 seconds.

**Cause:** Host down, egress blocked, or shipper crashed.

**Action:**
1. **Power off immediately** (threat model assumes host compromise).
2. Provider console: Stop the VPS.
3. Take a snapshot for forensic analysis (do not download).
4. Check New Relic for activity before the outage (canaries, Falco events).
5. Rebuild the decoy with new keys.

**Do not:**
- SSH to the host (SSH is disabled).
- Restart the service (the heartbeat loss may indicate compromise).

#### Bait Connection Lost

**Alert:** `bait_connected = 0` for 120 seconds.

**Cause:** Container stopped, bait crashed, or socket inaccessible.

**Action:**
1. Check logs for `runtime`/`stopped` events:
   ```nrql
   FROM Log
   SELECT timestamp, action, reason, nr_sent, nr_dropped
   WHERE stream = 'runtime' AND action = 'stopped'
   ORDER BY timestamp DESC
   LIMIT 10
   ```
2. If the decoy is otherwise healthy (shipper heartbeat present), restart the container:
   - Via cloud-init/systemd: `systemctl restart attackbox`
3. If the shipper is also missing, follow [Shipper Heartbeat Lost](#shipper-heartbeat-lost).

#### Bait Record Age Excessive

**Alert:** `last_bait_record_age_ms > 90000` (90 seconds) while `bait_connected = 1`.

**Cause:** Bait process hung (deadlock, infinite loop, or blocked on I/O).

**Action:**
1. Restart the bait container: `systemctl restart attackbox`
2. Inspect the last records:
   ```nrql
   FROM Log
   SELECT timestamp, stream, action, session_id
   WHERE source = 'bait'
   ORDER BY timestamp DESC
   LIMIT 20
   ```
3. If the issue recurs, the hung state may indicate a code bug or an attack; rebuild after inspection.

#### Falco Critical Event

**Alert:** Falco detected a `Critical` or `Emergency` event.

**Cause:** Sandbox escape, privilege escalation, or unexpected kernel/syscall activity.

**Action:**
1. **Power off immediately.**
2. Examine the Falco event (deduped):
   ```nrql
   FROM Log
   SELECT latest(timestamp) AS 'Time',
          latest(resource) AS 'Resource',
          latest(priority) AS 'Priority',
          latest(rule) AS 'Rule'
   WHERE stream = 'runtime'
     AND action = 'falco'
     AND priority IN ('Critical', 'Emergency')
   FACET record_id, body_sha256, chunk_index
   SINCE 1 hour ago
   ```
3. Take a snapshot; do not download.
4. Review the session timeline leading up to the event (see [Session Investigation](#session-investigation)).
5. Rebuild the decoy.

**Common false positives:** None expected for `Critical`/`Emergency` rules. Investigate every alert.

#### Blocked Egress Spike

**Alert:** High rate of blocked egress attempts (> 50 in 3 minutes).

**Cause:** Sandbox breakout attempt, compromised bait scanning, or malicious payload execution.

**Action:**
1. Check blocked destinations:
   ```nrql
   FROM Log
   SELECT latest(timestamp) AS 'Time',
          latest(dst_ip) AS 'Destination',
          latest(dst_port) AS 'Port'
   WHERE stream = 'egress' AND action = 'egress_blocked'
   FACET record_id, body_sha256, chunk_index
   SINCE 1 hour ago
   LIMIT 100
   ```
2. Identify the session(s):
   ```nrql
   FROM Log
   SELECT session_id, count(*) AS 'Blocks'
   WHERE stream = 'egress' AND action = 'egress_blocked'
   SINCE 1 hour ago
   FACET session_id
   ```
3. If the spike is targeted (C2 beaconing, specific IPs), **power off**.
4. If the spike is scanning (many random IPs), investigate the session and monitor.

**Low-level scan (10–50 blocks):** Expected behavior; monitor for escalation.

#### Ingest Error Spike

**Alert:** High rate of `newrelic_error` events (> 100 in 3 minutes).

**Cause:** Quota exhaustion, authentication failure, or API outage.

**Action:**
1. Check error messages:
   ```nrql
   FROM Log
   SELECT timestamp, error_message, retry_count
   WHERE stream = 'runtime' AND action = 'newrelic_error'
   ORDER BY timestamp DESC
   LIMIT 100
   ```
2. **Quota exhausted:** Deactivate the ingest key and power off (potential telemetry flood attack).
3. **Authentication failure:** Verify the key is valid; rotate if needed.
4. **API outage:** Check New Relic status page; wait for recovery.

#### NrIntegrationError Events

**Alert:** `NrIntegrationError` events present.

**Cause:** Malformed payloads, oversized attributes, or New Relic platform issues.

**Action:**
1. Inspect errors:
   ```nrql
   FROM NrIntegrationError
   SELECT timestamp, message, newRelicFeature, instrumentation.name
   SINCE 1 hour ago
   LIMIT 100
   ```
2. **Attribute too large:** Records may exceed 4,094 characters; chunking should prevent this. Bug in chunking logic.
3. **Request too large:** Batch exceeds 1 MB; adjust shipper batch size or investigate payload inflation.
4. **Platform error:** Transient; monitor for recurrence.

#### Queue Backlog Critical

**Alert:** Shipper queue backlog > 224 MB (87.5% of 256 MB capacity).

**Cause:** Prolonged New Relic API throttling or outage; ingest slower than production.

**Action:**
1. Check New Relic API status.
2. If the API is healthy, the decoy may be under heavy attack; consider rate-limiting or pausing traffic.
3. **Backlog near 256 MB:** Oldest records being dropped; shipper will emit `ship_queue_dropped_total` and log `queue_overflow`.
4. If the backlog persists for > 30 minutes, telemetry will be lost; prioritize restoring ingest.

#### Canary Token Reused

**Alert:** Client returned a session-unique canary credential.

**Cause:** Credential leakage behavior; client disclosed a fake secret.

**Action:**
1. Examine the session:
   ```nrql
   FROM Log
   SELECT timestamp, session_id, src_ip, action
   WHERE stream = 'probe' AND action = 'decision'
   FACET record_id, body_sha256, chunk_index
   SINCE 1 hour ago
   ```
2. Review the session timeline (see [Session Investigation](#session-investigation)).
3. Expected behavior for some clients (credential managers, autocomplete); verify intent via other probes.
4. If combined with shell execution or URL exfiltration, the client is actively attempting credential theft.

### Informational Alerts

#### New Session Started

**Action:** Open the live log view in New Relic; monitor the session's probe responses.

#### Prompt Injection Detected

**Action:** Review the session's task labels and probe responses. Expected behavior; informational only.

#### Credential Access Attempts

**Action:** Check for follow-up canary reuse. High activity may indicate a targeted attack.

#### Shell Execution Attempts

**Action:** Verify the responder issued the `shell-execution` probe and logged the intended command.

#### Request Rate Unusual

**Action:** Identify the source(s):
```nrql
FROM Metric
SELECT sum(attackbox.requests)
WHERE metricName = 'attackbox.requests'
FACET src_ip
SINCE 1 hour ago
```

High rate may be:
- Legitimate testing
- Scanner probing
- Flood attack (monitor for ingest quota consumption)

---

## Chunk-Safe Deduplication

**Critical:** Log events may be chunked (bodies > 3,500 characters) and replayed (after checkpoint recovery). Always deduplicate by the tuple `(record_id, body_sha256, chunk_index)`.

### Why Deduplication Matters

1. **Chunking:** Bodies exceeding 3,500 runes are split into multiple events, each with the same `record_id` but distinct `chunk_index` values (0, 1, 2, ...).
2. **Replay:** After a shipper crash, records are replayed from the last checkpoint. Duplicate events carry the same `record_id`, `body_sha256`, and `chunk_index`.

### Wrong: Deduplicating by `record_id` Alone

```nrql
-- WRONG: Loses all but one chunk
FROM Log
SELECT count(*) AS 'Events'
WHERE stream = 'probe' AND action = 'decision'
```

This discards chunks 1, 2, 3, ... and breaks body reassembly.

### Correct: Deduplicating by `(record_id, body_sha256, chunk_index)`

```nrql
-- CORRECT: Preserves every distinct chunk
FROM Log
SELECT latest(timestamp) AS 'Time',
       latest(session_id) AS 'Session'
WHERE stream = 'probe'
  AND action = 'decision'
  AND record_id IS NOT NULL
FACET record_id, body_sha256, chunk_index
SINCE 1 hour ago
```

Each row is one unique chunk. If the event is unchunked, `chunk_index = 0` and `chunk_count = 1`.

**Note:** Canary observations have `probe_id = 'canary-reuse'` within the `observations` array attribute. Array filtering syntax (`observations.probe_id`) requires account-side validation.



### Reconstructing Chunked Bodies

To recover the full body of a chunked event:

```nrql
FROM Log
SELECT message, body_sha256, chunk_index, chunk_count
WHERE record_id = '<record-id-here>'
  AND body_sha256 = '<sha256-here>'
ORDER BY chunk_index ASC
```

Manually concatenate the `message` fields in chunk order (0, 1, 2, ...).

### Deduplication in Dashboards and Alerts

**Dashboards:** Use `FACET record_id, body_sha256, chunk_index` for event tables.

**Example alert:**
```nrql
-- Count unique record_ids (may overcount by chunk_count - 1 per event)
FROM Log
SELECT count(*) AS 'Events'
WHERE stream = 'probe' AND action = 'decision'
```

For critical alerts (Falco, canary), overcounting is acceptable; the alert fires on any event.

---

## False Positives and Trust Limits

### Bait Heartbeat Trust Limits

**Signal:** `last_bait_record_age_ms` from `stream = heartbeat`, `source = shipper`.

**Thresholds:**
- **Normal:** 0–60,000 ms (0–60 seconds)
- **Warning:** 60,000–90,000 ms (60–90 seconds)
- **Critical:** > 90,000 ms (> 90 seconds)

**Why these limits:**
- The bait emits a `bait_heartbeat` event every **30 seconds** (see `research/host-shipper-design.md:113`).
- During low traffic, the age oscillates between 30–60 seconds (normal).
- Age > 60 seconds indicates the bait is idle or delayed; acceptable for up to 90 seconds.
- Age > 90 seconds indicates the bait process is hung (deadlock, infinite loop, or blocked I/O).

**False positives:**
- During a traffic burst, the bait may delay heartbeat emission; age can reach 70–80 seconds.
- If the alert fires during a known high-traffic period, verify the bait is responding to requests before restarting.

**Check bait responsiveness:**
```nrql
FROM Metric
SELECT rate(sum(attackbox.requests), 1 minute) AS 'Requests/min'
WHERE metricName = 'attackbox.requests'
TIMESERIES 1 minute
SINCE 10 minutes ago
```

If requests are flowing and age < 90s, the bait is healthy.

### Shipper Heartbeat Trust Limits

**Signal:** Presence of `stream = heartbeat`, `source = shipper` events.

**Thresholds:**
- **Warning:** No events for 60 seconds
- **Critical:** No events for 120 seconds

**Why these limits:**
- The shipper emits a heartbeat every **30 seconds** (direct POST, bypasses the queue).
- Missing heartbeats indicate:
  - Host down
  - Egress blocked (cannot reach New Relic HTTPS endpoint)
  - Shipper process crashed

**False positives:** None expected. The shipper heartbeat is independent of traffic and queue state. A missing heartbeat is a genuine failure.

**Action on alert:** Follow [Shipper Heartbeat Lost](#shipper-heartbeat-lost) (power off).

### Legitimate Tool Declarations

**Observation:** High `tool-invocation` task counts.

**Cause:** Client libraries often declare tools in every request, even when not invoking them.

**Expected:** OpenAI SDK, LangChain, and other frameworks send tool schemas by default. High counts are normal.

**Not a false positive if:**
- Combined with `shell-execution`, `credential-access`, or `url-exfiltration` tasks.
- The client uses the responder's fake tool output in follow-up requests.

**Check follow-ups:**
```nrql
FROM Metric
SELECT sum(attackbox.probe_followups)
WHERE metricName = 'attackbox.probe_followups'
FACET probe_id
SINCE 1 hour ago
```

High `probe_followups` indicates the client is acting on the responder's probes.

### Queue Backlog Expected Range

**Normal:** 0–64 MB
**Warning:** 64–128 MB (temporary ingest degradation)
**Critical:** > 224 MB (approaching 256 MB limit; oldest records being dropped)

**Cause of backlog:**
- New Relic API throttling
- API outage or high latency
- Traffic burst exceeding ingest throughput

**Expected during:**
- Heavy attack traffic (many simultaneous sessions)
- Prolonged API throttling (429 responses)

**Not expected during:**
- Idle or low traffic (backlog should drain within minutes)

**Action on persistent backlog (> 30 minutes):**
1. Check New Relic API status.
2. If the API is healthy, the shipper may be under heavy load; consider rate-limiting at the edge proxy.
3. If the backlog reaches 256 MB, the shipper will start dropping the oldest segments; telemetry loss is imminent.

### Canary Reuse False Positives

**Observation:** Canary tokens returned by the client.

**Legitimate causes:**
- Credential managers or browser autocomplete suggesting fake tokens.
- SDK retry logic echoing the previous response.

**False positive if:**
- The client returns the canary once and does not use it in follow-up requests.
- No other high-risk tasks (`shell-execution`, `url-exfiltration`) in the session.

**Genuine attack if:**
- The client uses the canary in a subsequent request (e.g., `Authorization: Bearer sk-local-<hex>`).
- Combined with exfiltration attempts or shell commands.

**Check session timeline:**
```nrql
FROM Log
SELECT timestamp, stream, action, task, probe_id
WHERE session_id = '<session-id-from-alert>'
ORDER BY timestamp ASC
LIMIT 100
```

---

## Investigation Workflows

### Session Investigation

**Goal:** Understand the full timeline of a suspicious session.

**Step 1: Session Timeline**
```nrql
FROM Log
SELECT timestamp, stream, action, task, probe_id, status
WHERE session_id = '<session-id-here>'
  AND record_id IS NOT NULL
ORDER BY timestamp ASC
LIMIT 1000
```

**Step 2: Requests**
```nrql
FROM Log
SELECT timestamp, method, endpoint, status, task
WHERE session_id = '<session-id-here>'
  AND stream = 'edge'
  AND direction = 'request'
  AND record_id IS NOT NULL
ORDER BY timestamp ASC
```

**Step 3: Declarations**
```nrql
FROM Log
SELECT timestamp, action, client_model, operator_alias, harness_name
WHERE session_id = '<session-id-here>'
  AND stream = 'probe'
  AND action IN ('register-model', 'register-harness', 'operator-alias')
  AND record_id IS NOT NULL
ORDER BY timestamp ASC
```

**Step 4: Probes Issued**
```nrql
FROM Log
SELECT timestamp, probe_id, task, action
WHERE session_id = '<session-id-here>'
  AND stream = 'probe'
  AND record_id IS NOT NULL
ORDER BY timestamp ASC
```

**Step 5: Canary and Egress**
```nrql
FROM Log
SELECT timestamp, action, resource
WHERE session_id = '<session-id-here>'
  AND stream IN ('probe', 'egress')
  AND action IN ('decision', 'egress_blocked')
  AND record_id IS NOT NULL
ORDER BY timestamp ASC
```

### Source IP Investigation

**Goal:** Identify patterns across sessions from the same source.

**Step 1: Activity Summary**
```nrql
FROM Log
SELECT count(*) AS 'Events' AS 'Requests',
       count(DISTINCT session_id) AS 'Sessions' -- Note: High-cardinality, use Log only,
       latest(user_agent) AS 'User-Agent'
WHERE stream = 'edge' AND direction = 'request' AND src_ip = '<ip-here>'
SINCE 1 day ago
```

**Step 2: Attack Tasks**
```nrql
FROM Metric
SELECT sum(attackbox.probes)
WHERE metricName = 'attackbox.probes' AND src_ip = '<ip-here>'
FACET task
SINCE 1 day ago
```

**Step 3: Sessions**
```nrql
FROM Log
SELECT session_id, min(timestamp) AS 'Started', count(*) AS 'Events'
WHERE src_ip = '<ip-here>'
  AND record_id IS NOT NULL
FACET session_id
SINCE 1 day ago
```

### Model Declaration Analysis

**Goal:** Identify which models/harnesses are probing the decoy.

**Declared Models:**
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

**Declared Harnesses:**
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

**Most Common Models:**
```nrql
FROM Log
SELECT count(*) AS 'Events' AS 'Sessions'
WHERE stream = 'probe' AND action = 'register-model'
FACET client_model
SINCE 1 day ago
LIMIT 50
```

---

## Troubleshooting

### No Logs Appearing

**Symptoms:** Zero events in New Relic; all queries return empty.

**Checks:**
1. Verify the ingest key is correct: `echo $ATTACKBOX_NR_LICENSE_KEY` on the host.
2. Check shipper logs: `journalctl -u attackbox-shipper -n 100`
3. Verify egress: `curl -I https://log-api.newrelic.com` from the host (should return 404 or 405, not a timeout).
4. Check for firewall blocks: `journalctl -k | grep nft` for dropped packets.
5. Verify the bait is running: `systemctl status attackbox`

**Common causes:**
- Wrong key (User key instead of Ingest key; rejected at startup).
- Egress firewall blocking HTTPS to New Relic endpoints.
- Shipper not running or crashed on startup.

### Missing Streams

**Symptoms:** Some streams present, others absent.

**Checks:**
1. **Missing `edge`/`transcript`/`probe`:** Bait not receiving traffic or not connected to shipper socket.
   - Test request: `curl https://<decoy-ip>/v1/models`
   - Check bait logs: `docker logs <container-id>`
   - Verify socket: `ls -la /run/attackbox/spool.sock` (should be mode 0220, group `abx-bait`)
2. **Missing `runtime`:** Falco not running or stdin adapter not configured.
   - Check Falco: `systemctl status falco`
   - Verify Falco output: `program_output.program` in `/etc/falco/falco.yaml`
3. **Missing `egress`:** Firewall log integration not active.
   - Check nftables rules: `nft list ruleset | grep log`
   - Verify egress adapter: `systemctl status attackbox-shipper-egress` (or equivalent)
4. **Missing `heartbeat`:** Shipper not running.
   - Check shipper: `systemctl status attackbox-shipper`

### Metrics Not Appearing

**Symptoms:** Logs present, metrics absent or stale.

**Checks:**
1. Verify metric flush: Metrics are batched and flushed every **5 seconds** or **200 events**.
2. Check for metric drops:
   ```nrql
   FROM Log
   SELECT latest(nr_dropped), latest(nr_errors)
   WHERE stream = 'runtime' AND action IN ('stop', 'stopped')
   ORDER BY timestamp DESC
   LIMIT 10
   ```
3. Verify the metric names:
   ```nrql
   FROM Metric
   SELECT count(*) AS 'Events'
   WHERE metricName LIKE 'attackbox.%'
   FACET metricName
   SINCE 1 hour ago
   ```
4. If metrics are entirely absent, check shipper logs for `newrelic_error` events:
   ```bash
   journalctl -u attackbox-shipper | grep newrelic_error
   ```

**Common causes:**
- Metric API throttling (check New Relic quota).
- Malformed metric names (rejected by New Relic).
- Shipper queue full (metrics are deprioritized vs. logs).

### High Dropped Counts

**Symptoms:** `ship_dropped_total` or `nr_dropped` increasing.

**Checks:**
1. Check queue backlog:
   ```nrql
   FROM Log
   SELECT latest(queue_backlog_bytes) / 1048576 AS 'Backlog (MB)'
   WHERE stream = 'heartbeat' AND source = 'shipper'
   ```
2. Check for ingest errors:
   ```nrql
   FROM Log
   SELECT timestamp, error_message, retry_count
   WHERE stream = 'runtime' AND action = 'newrelic_error'
   ORDER BY timestamp DESC
   LIMIT 100
   ```
3. Verify New Relic API status.

**Common causes:**
- Prolonged API outage or throttling.
- Traffic burst exceeding ingest throughput.
- Shipper queue exhausted (256 MB limit).

### Duplicate Events

**Symptoms:** Same `record_id` appearing multiple times with identical `body_sha256` and `chunk_index`.

**Cause:** Shipper crashed and replayed records from the last checkpoint.

**Expected:** Duplicates are deduplicable via `(record_id, body_sha256, chunk_index)`. Alerts and dashboards should use this tuple (see [Chunk-Safe Deduplication](#chunk-safe-deduplication)).

**Not expected:** Duplicates with different `body_sha256` (indicates a bug in chunking or ID generation).

### Shipper Restarting Frequently

**Symptoms:** `runtime`/`started` events every few minutes.

**Checks:**
1. Check exit status: `journalctl -u attackbox-shipper | grep 'Main process exited'`
2. Check for panics or crashes: `journalctl -u attackbox-shipper -n 500`
3. Verify disk space: `df -h /var/lib/attackbox-shipper`
4. Check for OOM kills: `journalctl -k | grep -i 'out of memory'`

**Common causes:**
- Disk full (queue directory at `/var/lib/attackbox-shipper/queue`).
- Memory limit exceeded (`MemoryMax=256M` in systemd unit).
- Corrupt queue state (delete `/var/lib/attackbox-shipper/queue/state.json` and restart; oldest segment replays).

---

## Data Retention and Archival

### New Relic Retention

**Metrics:** 30 days (raw dimensional data), 13 months (aggregated).

**Logs:** Plan-dependent:
- **Free/Standard:** 8 days
- **Pro:** 30 days
- **Enterprise:** Configurable (up to 90+ days)

**NrIntegrationError:** 8 days.

### Optional Archive

For long-term retention (> 90 days), configure an S3-compatible object-locked bucket per `implementation_plan.md:16`.

**Key requirements:**
- Write-only key scope (no read or delete).
- Object lock enabled (WORM: Write-Once-Read-Many).
- Separate from New Relic ingest (independent failure domain).

**Shipper configuration:**
```bash
ATTACKBOX_ARCHIVE_URL=https://<bucket>.s3.amazonaws.com/attackbox-logs
ATTACKBOX_ARCHIVE_KEY=<write-only-key>
```

**Verification:**
```bash
# Check archive writes (shipper logs)
journalctl -u attackbox-shipper | grep archive_write
```

### Querying Archived Data

New Relic cannot query archived data. For forensic analysis of old sessions:

1. Download the archive object (requires separate read credentials).
2. Parse JSON lines locally.
3. Filter by `session_id`, `src_ip`, or `timestamp`.

**Do not:**
- Feed archived logs to an LLM with tools.
- Paste commands or URLs from archived logs into a terminal or browser.

---

## Appendix: Metric Reference

| Emitted Name | Type | Labels | Producer |
|---|---|---|---|
| `attackbox.requests` | count | persona, endpoint, status_class | server, every request |
| `attackbox.sessions` | count | persona | server, new session |
| `attackbox.probes` | count | persona, probe_id, task | server, probe decision |
| `attackbox.request_bytes` | count | persona, endpoint | server, request body |
| `attackbox.response_bytes` | count | persona, endpoint | server, response body |
| `attackbox.probe_followups` | count | persona, probe_id | server, follow-up response |
| `attackbox.session_duration_seconds` | gauge | persona | server, session age |
| `attackbox.stream_disconnect_seconds` | gauge | persona, endpoint | server, disconnect timing |
| `attackbox.retry_delay_seconds` | gauge | persona | server, retry delay |
| `attackbox.concurrent_status_requests` | gauge | persona | server, concurrency gate |
| `attackbox.egress_blocked` | count | — | host (firewall log shipper) |
| `attackbox.heartbeat` | gauge | — | shipper, every 30s |

---

## Appendix: Stream Reference

| Stream | Contents | Producer |
|---|---|---|
| `edge` | Request/response logs (method, path, headers, bodies) | Bait |
| `transcript` | Messages, tools, tool results, fake output | Bait |
| `probe` | Gates, declarations, nonces, follow-ups | Bait |
| `runtime` | Falco events, shipper lifecycle, bait lifecycle | Falco, shipper, bait |
| `egress` | Blocked connection attempts | Host firewall |
| `heartbeat` | Liveness signals (`source = shipper` or `source = bait`) | Shipper, bait |

---

## Support

For questions or issues:
- Check `implementation_plan.md` for design details.
- Check `research/host-shipper-design.md` for shipper architecture.
- Check `research/host-shipper-threat-review.md` for security corrections.
- Check `newrelic/queries.md` for additional NRQL examples.
