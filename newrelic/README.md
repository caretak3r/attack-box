# AttackBox New Relic Configuration

An account ID of `0` is unset. Enter your account ID before you import a template.

Offline dashboard and alert definitions for New Relic monitoring.

## Contents

- **`dashboards/`**: Dashboard JSON definitions (import via New Relic UI or Terraform)
- **`alerts/`**: Alert condition YAML definitions (apply via Terraform or manually)
- **`queries.md`**: NRQL query reference for verification and investigation
- **`../docs/newrelic-runbook.md`**: Complete operator runbook

## Quick Start

### 1. Provision Ingest Key

Follow `docs/newrelic-runbook.md` → "Key Provisioning" to create a dedicated `Ingest - License` key.

**Key type:** `Ingest - License` (40 alphanumeric characters)
**Scope:** Logs and metrics only; no query or UI access
**Storage:** `/etc/attackbox/shipper.env` on host (root:root, mode 0600)

### 2. Import Dashboard

The dashboard uses offline account placeholders (`"accountIds": [0]`). Replace every widget account ID before import. New Relic's dashboard-account choice does not replace each query's account ID. Run the local checks first:

```bash
python3 /Users/rohit/attack-box/newrelic/validate_dashboard.py --self-test
python3 /Users/rohit/attack-box/newrelic/validate_dashboard.py
jq --argjson account_id 1234567 \
  '(.pages[].widgets[].rawConfiguration.nrqlQueries[]?.accountIds) = [$account_id]' \
  /Users/rohit/attack-box/newrelic/dashboards/attackbox-overview.json
```

Replace `1234567` with the intended query account. The command prints the import JSON; it does not change the checked-in template or call New Relic.

**Via New Relic UI:**
1. Navigate to **Dashboards → Import dashboard**
2. Paste the `jq` output into the **Dashboard JSON** box
3. Select the intended dashboard account and permissions, then save.

Inspect every page after import. **Live Watch** and **Telemetry Health** use fixed 5/15-minute windows with a 30-second refresh setting. This setting is not a delivery-latency guarantee. **Evidence & Forensics** follows the dashboard time picker and defaults to 15 minutes. Use a `deployment_id` or `sensor_id` filter when the account holds more than one decoy. The account-wide `NrIntegrationError` table does not carry these decoy fields; inspect it without those filters if it is empty.

**Via Terraform:**
```hcl
resource "newrelic_one_dashboard_json" "attackbox_overview" {
  # Use the account-substituted JSON, not the offline placeholder template.
  json = file("/absolute/path/to/account-substituted-dashboard.json")
}
```

### 3. Configure Alerts

**Via New Relic UI:**
1. Create a new alert policy: **Alerts → Alert policies → Create a policy**
2. Name: `AttackBox Critical Alerts`
3. For each alert in `alerts/critical-alerts.yaml`:
   - Click **Create a condition → NRQL**
   - Copy the alert name, description, and NRQL query
   - Set thresholds per the YAML definition
   - Save the condition
4. Add notification channels (phone, email, Slack, PagerDuty)
5. Repeat for `alerts/informational-alerts.yaml` with a separate policy

**Mapping used when the conditions were created in the UI** (the YAML uses Terraform and NerdGraph names):

- `INFO` priority: New Relic has only `CRITICAL` and `WARNING`. Use `WARNING`.
- `evaluation_offset: 3`: use the streaming method **Event flow**. Set **Delay** to 3 windows (3 minutes for a 60-second window, 15 minutes for a 300-second window).
- `threshold_occurrences: AT_LEAST_ONCE`: choose **at least once in**.
- `expiration`: choose **Add lost signal threshold**. `expiration_duration` is the time. `open_violation_on_expiration` is the box "Open new lost signal alert event". `close_violations_on_expiration` is the box "Close all current open alert events".
- Policy setting **Issue creation preference**: choose **One issue per condition**. The default (**One issue per policy**) lets one open issue hide the alerts of the other conditions.
- Before you save a condition, open **View as code** → **Create with NerdGraph**. It shows the exact values that New Relic will store.
- A policy without a workflow sends no notification. Create the workflow and its destination yourself.

**Via Terraform:**
```hcl
resource "newrelic_alert_policy" "attackbox_critical" {
  name = "AttackBox Critical Alerts"
}

resource "newrelic_nrql_alert_condition" "shipper_heartbeat_lost" {
  policy_id = newrelic_alert_policy.attackbox_critical.id
  name      = "AttackBox - Shipper Heartbeat Lost"
  type      = "static"

  nrql {
    query = "FROM Log SELECT count(*) WHERE stream = 'heartbeat' AND source = 'shipper'"
  }

  critical {
    operator              = "below"
    threshold             = 1
    threshold_duration    = 120
    threshold_occurrences = "at_least_once"
  }

  violation_time_limit_seconds = 3600

  aggregation_window = 60
  expiration_duration = 180
  open_violation_on_expiration = true
}

# ... (additional conditions per alerts/critical-alerts.yaml)
```

### 4. Verify Deployment

After deploying the decoy, run verification queries from `queries.md`:

```nrql
-- All six streams active
FROM Log
SELECT count(*)
WHERE stream IN ('edge', 'transcript', 'probe', 'runtime', 'egress', 'heartbeat')
FACET stream
SINCE 10 minutes ago
```

Expected: Six streams with nonzero counts.

See `docs/newrelic-runbook.md` → "Verification After Deployment" for the complete checklist.

## Files

### `/Users/rohit/attack-box/newrelic/dashboards/attackbox-overview.json`

Three-page dashboard:
1. **Live Watch**: Five-minute completed request/session/source indicators and heartbeat age; a recent-arrivals feed from `action = 'request_received'` that appears before a long response completes; 15-minute status/persona traffic, export lag, backlog, loss, source/session tables and probe follow-ups. Arrival capture completion refers to the request body, not completion of the response.
2. **Evidence & Forensics**: Separate redacted request/response context and raw base64 capture tables; manifests, segment offsets/hashes, serialized observations, host-owned Falco/egress records and evidence provenance.
3. **Telemetry Health**: Bait connection reports, backlog, producer silence, export-attempt lag, spool counters, truncation flags and account-wide integration errors.

Request totals use `uniqueCount(record_id, precision: 10000)` with `chunk_index = 0`, `direction = 'request'`, and `action != 'capture'`. This avoids counting response records, raw capture segments, chunks or replays as extra requests. These totals count retained evidence; they cannot measure traffic that was never collected. Unique counts above the configured precision can be approximate. Session indicators mean sessions observed in the window, not open network connections. A follow-up means the bait reported attribution, not successful host execution.

Forensic chunk tables retain `(record_id, body_sha256, chunk_index)` facets. They are bounded previews, not a complete archive or reconstruction tool. Raw bytes remain base64 in `body_chunk`; redacted contextual records use a separate table. A producer's `evidence_complete` flag does not prove all segments reached New Relic. Verify manifests, offsets and hashes during export/reconstruction.

`event` and `observations` are serialized JSON strings. The dashboard displays those strings; it does not invent dotted subfields. Queue-loss charts use scalar `ship_queue_dropped_total` and `ship_dropped_bait_total` / `ship_dropped_runtime_total` / `ship_dropped_egress_total`, not the legacy JSON map `ship_dropped_total`. Booleans use `= true` / `= false`. `export_lag_ms` measures event time to export attempt, not remote acceptance or indexing. Empty charts and a live heartbeat do not prove delivery. Older deployed binaries without these scalars, `body_chunk`, capture fields or export-attempt fields show missing data until upgraded.

Local validation checks the 12-column layout, overlap, account placeholders, window settings, request-count guards and raw/context separation. It does not compile NRQL or prove live vendor acceptance. After import, use a known request, a replay, a multi-chunk response and an export outage to verify the totals and joins. Do not interpret a zero result before that canary check.

Schema and query references: [dashboard import](https://docs.newrelic.com/docs/query-your-data/explore-query-data/dashboards/dashboards-charts-import-export-data/), [widget configuration and Markdown](https://docs.newrelic.com/docs/apis/nerdgraph/examples/create-widgets-dashboards-api/), [NRQL functions and unique-count precision](https://docs.newrelic.com/docs/nrql/nrql-syntax-clauses-functions/).

### `alerts/critical-alerts.yaml`

Ten critical alerts requiring immediate action:
- Shipper heartbeat lost (power off)
- Bait connection lost (container down)
- Bait record age excessive (hung process)
- Falco critical event (sandbox escape)
- Blocked egress spike (breakout attempts)
- Ingest error spike (quota exhaustion)
- NrIntegrationError events (platform errors)
- Queue backlog critical (ingest degraded)
- Canary-reuse observation (read the state list; `present_in_history` is not credential leakage)

### `alerts/informational-alerts.yaml`

Seven informational alerts for activity monitoring:
- New session started
- Prompt injection detected
- Credential access attempts
- Shell execution attempts
- URL exfiltration attempts
- Request rate unusual
- Traffic stopped

### `queries.md`

NRQL query reference organized by use case:
- Verification queries (streams, heartbeat, metrics, liveness)
- Chunk-safe deduplication examples
- Attack pattern queries (sessions, tasks, probes, retries)
- Session investigation (timeline, requests, declarations, probes)
- Threat intelligence (source IPs, user agents, model declarations)
- Health and diagnostics (NrIntegrationError, shipper metrics, ingest errors)
- False-positive filtering guidance

## Key Concepts

### Chunk-Safe Deduplication

**Critical:** Log events may be chunked (bodies > 3,500 characters) and replayed (after checkpoint recovery). Always deduplicate by the tuple `(record_id, body_sha256, chunk_index)`.

**Wrong:**
```nrql
-- Loses all but one chunk
SELECT count(*) WHERE stream = 'probe' AND action = 'decision'
```

**Correct:**
```nrql
-- Preserves every distinct chunk
SELECT latest(timestamp)
WHERE stream = 'probe' AND action = 'decision'
FACET record_id, body_sha256, chunk_index
```

**Note:** Canary observations require `observations.probe_id` filtering (pending array-query validation). A `canary-reuse` observation holds, for each canary, a comma list of states: `present_in_history`, `newly_echoed`, `destination_placed`, `credential_presented`, `presented_undelivered`. It also holds `credential_source` and `independently_observed` (always `unavailable`). `present_in_history` is not exfiltration. Each state is reported once for each canary in a session. Unscored replies are observations with `probe_id` `attribution`, a `status`, and a `reason`. `attackbox.probe_followups` counts attributed replies only.

See `docs/newrelic-runbook.md` → "Chunk-Safe Deduplication" for details.

See `docs/newrelic-runbook.md` → "Chunk-Safe Deduplication" for details.

### Stream Reference

| Stream | Contents | Producer |
|---|---|---|
| `edge` | Request/response logs | Bait |
| `transcript` | Messages, tools, outputs | Bait |
| `probe` | Gates, declarations | Bait |
| `runtime` | Falco, shipper, bait lifecycle | Falco, shipper, bait |
| `egress` | Blocked connections | Host firewall |
| `heartbeat` | Liveness signals | Shipper, bait |

### Metric Reference

**Total: 13 emitted metrics** (10 bait + 3 shipper)

| Metric | Type | Labels |
|---|---|---|
| `attackbox.requests` | count | persona, endpoint, status_class |
| `attackbox.sessions` | count | persona |
| `attackbox.probes` | count | persona, probe_id, task |
| `attackbox.request_bytes` | count | persona, endpoint |
| `attackbox.response_bytes` | count | persona, endpoint |
| `attackbox.probe_followups` | count | persona, probe_id |
| `attackbox.session_duration_seconds` | gauge | persona |
| `attackbox.stream_disconnect_seconds` | gauge | persona, endpoint |
| `attackbox.retry_delay_seconds` | gauge | persona |
| `attackbox.concurrent_status_requests` | gauge | persona |
| `attackbox.egress_blocked` | count | — |
| `attackbox.heartbeat` | gauge | — |
| `attackbox.telemetry.ingest_errors_total` | gauge | — |
| `attackbox.telemetry.ingest_retries_total` | gauge | — |

## Alert Response

See `docs/newrelic-runbook.md` → "Alert Response" for detailed runbooks.

**Critical alerts requiring power-off:**
- Shipper heartbeat lost
- Falco critical event
- Blocked egress spike (if targeted)
- Ingest error spike (if quota exhausted)

**Critical alerts requiring restart:**
- Bait connection lost
- Bait record age excessive

**Informational alerts:**
- Monitor and investigate; no immediate action required

## Validation

Before deployment, validate syntax locally:

```bash
# JSON syntax
jq empty dashboards/*.json

# YAML syntax
yamllint alerts/*.yaml
# or
python3 -c "import yaml; yaml.safe_load(open('alerts/critical-alerts.yaml'))"
python3 -c "import yaml; yaml.safe_load(open('alerts/informational-alerts.yaml'))"
```

Cross-check metric and stream names against source:
- Metrics: `implementation_plan.md:309-326`
- Streams: `implementation_plan.md:296-303`
- Design: `research/host-shipper-design.md`
- Corrections: `research/host-shipper-threat-review.md`

## Support

- **Full runbook:** `docs/newrelic-runbook.md`
- **Design details:** `implementation_plan.md` (§280-339)
- **Shipper architecture:** `research/host-shipper-design.md`
- **Security corrections:** `research/host-shipper-threat-review.md`

## No Live Account Calls

All definitions are offline and read-only. No `newrelic` CLI or Terraform `apply` commands are executed. Import and apply these definitions manually or via your deployment pipeline.

