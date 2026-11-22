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

**Via New Relic UI:**
1. Navigate to **Dashboards → Import dashboard**
2. Upload `dashboards/attackbox-overview.json`
3. Select the AttackBox account
4. Click **Import dashboard**

**Via Terraform:**
```hcl
resource "newrelic_one_dashboard_json" "attackbox_overview" {
  json = file("${path.module}/newrelic/dashboards/attackbox-overview.json")
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

### `dashboards/attackbox-overview.json`

Three-page dashboard:
1. **Overview**: Active sessions, request rate, heartbeat status, stream health, canary activity, probe distribution
2. **Security Events**: Falco critical events, blocked egress, runtime events
3. **Telemetry Health**: Bait connection status, queue backlog, ingest errors, NrIntegrationError events, dropped records

All queries respect chunk-safe deduplication via `(record_id, body_sha256, chunk_index)`.

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
- Canary token reused (credential leakage)

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
SELECT uniqueCount(record_id) WHERE stream = 'probe' AND action = 'canary-reuse'
```

**Correct:**
```nrql
-- Preserves every distinct chunk
SELECT latest(timestamp)
WHERE stream = 'probe' AND action = 'canary-reuse'
FACET record_id, body_sha256, chunk_index
```

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
