# AttackBox New Relic Configuration — NewRelic45 Report

**Branch:** `sonnet45/newrelic`  
**Commit:** `ab35d33`  
**Status:** ✅ Complete

---

## Deliverables

### 1. Dashboard Definition

**File:** `newrelic/dashboards/attackbox-overview.json`

Three-page dashboard covering:

#### Overview Page
- Active sessions (last hour)
- Request rate by persona (timeseries)
- Heartbeat status with thresholds (60s warning, 120s critical)
- Stream health table (all six streams)
- Top attack tasks (bar chart)
- Canary activity (deduped by record_id, body_sha256, chunk_index)
- Probe distribution (pie chart)
- Traffic by persona (area chart)

#### Security Events Page
- Falco critical events (deduped, table)
- Blocked egress attempts (deduped, table with destination IPs/ports)
- Egress block rate (timeseries)
- Runtime events by action (bar chart)

#### Telemetry Health Page
- Bait connection status (bait_connected, last_bait_record_age_ms with thresholds)
- Queue backlog (MB, timeseries)
- Ingest errors (billboard with thresholds)
- NrIntegrationError events (table)
- Dropped records (timeseries)
- Spool clients (timeseries)

**All queries respect chunk-safe deduplication:** Every event query uses `FACET record_id, body_sha256, chunk_index` to preserve distinct chunks and handle replay correctly.

### 2. Alert Definitions

**Files:**
- `newrelic/alerts/critical-alerts.yaml`: 10 critical alerts
- `newrelic/alerts/informational-alerts.yaml`: 7 informational alerts

#### Critical Alerts (Require Immediate Action)

1. **Shipper Heartbeat Lost**: No shipper heartbeat for 120s → host down or egress blocked → **power off**
2. **Bait Connection Lost**: `bait_connected = 0` for 120s → container down → restart or power off
3. **Bait Record Age Excessive**: `last_bait_record_age_ms > 90000` while connected → hung process → restart
4. **Falco Critical Event**: Priority `Critical` or `Emergency` → sandbox escape → **power off**
5. **Blocked Egress Spike**: > 50 blocks in 3 minutes → breakout attempts → power off if targeted
6. **Ingest Error Spike**: > 100 errors in 3 minutes → quota exhaustion → deactivate key and power off
7. **NrIntegrationError Events**: Platform integration errors → investigate payload issues
8. **Queue Backlog Critical**: > 224 MB (87.5% of 256 MB) → ingest degraded → prioritize restore
9. **Canary Token Reused**: Client returned fake credential → credential leakage behavior → investigate
10. **Queue Backlog Warning**: > 128 MB → temporary degradation → monitor

#### Informational Alerts

1. **New Session Started**: Trigger live log view
2. **Prompt Injection Detected**: Task `prompt-extraction`, `instruction-override`, or `indirect-injection`
3. **Credential Access Attempts**: Task `credential-access`, high activity
4. **Shell Execution Attempts**: Task `shell-execution` or `persistence`
5. **URL Exfiltration Attempts**: Task `url-exfiltration`
6. **Request Rate Unusual**: > 100 requests/min sustained
7. **Traffic Stopped**: No requests for 30 minutes

### 3. NRQL Query Reference

**File:** `newrelic/queries.md`

Organized sections:
- **Verification Queries**: All six streams, heartbeat sources, metrics flowing, bait liveness, queue health
- **Chunk-Safe Deduplication**: Examples and anti-patterns, reconstruction guide
- **Attack Pattern Queries**: Active sessions, top tasks, probe distribution, request rate, session duration, retries
- **Session Investigation**: Timeline, requests, declarations, probes issued
- **Threat Intelligence**: Source IP activity, user agents, model declarations, harness declarations
- **Health and Diagnostics**: NrIntegrationError, shipper metrics, ingest errors, stopped events
- **False-Positive Filtering**: Legitimate tool declarations, heartbeat trust limits, queue backlog ranges

### 4. Operator Runbook

**File:** `docs/newrelic-runbook.md`

Comprehensive operational guide (31,285 bytes):

#### Key Provisioning
- Create dedicated `Ingest - License` key (40-char, ingest-only scope)
- Key validation rules (reject User/Admin/Query/Browser keys)
- Storage requirements (/etc/attackbox/shipper.env, root:root, 0600)
- Rotation and revocation procedures

#### Verification After Deployment
- Six-step verification checklist
- Expected values and failure modes for each check
- Test request examples

#### Alert Response
- Detailed runbooks for each critical alert
- Power-off conditions (shipper lost, Falco critical, targeted egress)
- Restart conditions (bait lost, bait hung)
- Investigation queries for each alert type

#### Chunk-Safe Deduplication
- Full explanation of why `(record_id, body_sha256, chunk_index)` is required
- Wrong vs. correct query examples
- Body reconstruction procedure for chunked events
- Dashboard and alert deduplication guidance

#### False Positives and Trust Limits
- Bait heartbeat: 0–60s normal, 60–90s warning, >90s critical
- Shipper heartbeat: 60s warning, 120s critical (no false positives expected)
- Legitimate tool declarations (SDK behavior)
- Queue backlog ranges: 0–64 MB normal, 64–128 MB warning, >224 MB critical
- Canary reuse false positives (autocomplete, retry logic)

#### Investigation Workflows
- Session investigation (5-step procedure)
- Source IP investigation (3-step procedure)
- Model declaration analysis

#### Troubleshooting
- No logs appearing (key, egress, firewall)
- Missing streams (bait, Falco, egress)
- Metrics not appearing (flush timing, throttling)
- High dropped counts (queue exhaustion)
- Duplicate events (replay expected)
- Shipper restarting (disk full, OOM)

#### Data Retention and Archival
- New Relic retention: 30 days (metrics), 8–90 days (logs), 8 days (NrIntegrationError)
- Optional archive S3 configuration
- Forensic analysis procedures

#### Appendices
- Metric reference table (12 metrics)
- Stream reference table (6 streams)

### 5. Directory Structure

```
newrelic/
├── README.md                           # Quick start and overview
├── dashboards/
│   └── attackbox-overview.json         # Importable dashboard JSON
├── alerts/
│   ├── critical-alerts.yaml            # 10 critical alert definitions
│   └── informational-alerts.yaml       # 7 informational alert definitions
└── queries.md                          # NRQL query reference

docs/
└── newrelic-runbook.md                 # Complete operator runbook
```

---

## Validation

### Syntax Validation

✅ **JSON:** Validated with `jq empty`
```
✓ JSON syntax valid
```

✅ **YAML:** Validated with Ruby YAML parser
```
✓ YAML syntax valid
```

### Cross-Reference Validation

Verified all metric names, stream names, and special attributes against source documents:

#### Metrics (12/12)
✅ All 12 metrics referenced correctly:
- `attackbox.requests` (16 refs)
- `attackbox.sessions` (5 refs)
- `attackbox.probes` (18 refs)
- `attackbox.request_bytes` (3 refs)
- `attackbox.response_bytes` (3 refs)
- `attackbox.probe_followups` (5 refs)
- `attackbox.session_duration_seconds` (5 refs)
- `attackbox.stream_disconnect_seconds` (5 refs)
- `attackbox.retry_delay_seconds` (6 refs)
- `attackbox.concurrent_status_requests` (3 refs)
- `attackbox.egress_blocked` (2 refs)
- `attackbox.heartbeat` (2 refs)

#### Streams (6/6)
✅ All 6 streams referenced correctly:
- `edge` (5 refs)
- `transcript` (7 refs, in SQL IN clauses)
- `probe` (18 refs)
- `runtime` (13 refs)
- `egress` (6 refs)
- `heartbeat` (18 refs)

#### Special Attributes (6/6)
✅ All special attributes for chunk-safe dedup and shipper monitoring:
- `record_id` (52 refs)
- `body_sha256` (27 refs)
- `chunk_index` (28 refs)
- `source` (37 refs)
- `bait_connected` (11 refs)
- `last_bait_record_age_ms` (9 refs)

**Sources verified:**
- `implementation_plan.md:309-326` (metrics)
- `implementation_plan.md:296-303` (streams)
- `research/host-shipper-design.md` (shipper attributes)
- `research/host-shipper-threat-review.md:8` (chunk-safe dedup requirements)

---

## Key Design Decisions

### 1. Chunk-Safe Deduplication

**Requirement:** Records may be chunked (bodies > 3,500 chars) and replayed (after checkpoint recovery).

**Solution:** Every event query uses `FACET record_id, body_sha256, chunk_index` to:
- Preserve all chunks (avoid discarding chunks 1, 2, 3, ...)
- Identify replay duplicates (same record_id, body_sha256, chunk_index)

**Applied to:**
- Canary activity queries
- Falco critical event queries
- Egress block queries
- All dashboard event tables
- Investigation workflow queries

**Reference:** `research/host-shipper-threat-review.md:38-41` (finding 8)

### 2. Per-Role Isolation

**Requirement:** Authenticated producer roles prevent a bait from impersonating runtime/egress events.

**Solution:**
- `source` attribute distinguishes `bait`, `shipper`, `runtime`, `egress`
- Heartbeat queries filter by `source = 'shipper'` (host liveness) vs. `source = 'bait'` (bait liveness)
- Falco queries require `stream = 'runtime'` (not spoofable by bait)
- Egress queries require `stream = 'egress'` (firewall log, not bait)

**Reference:** `research/host-shipper-threat-review.md:19-21` (finding 4)

### 3. Bounded Record Expansion

**Requirement:** Shipper must validate decoded record size and chunk expansion before disk admission.

**Solution:**
- Dashboard queries show queue backlog and dropped counts
- Alerts fire when backlog exceeds thresholds (128 MB warning, 224 MB critical)
- NrIntegrationError table catches oversized payloads rejected by New Relic

**Reference:** `research/host-shipper-threat-review.md:28-32` (finding 6)

### 4. False-Positive Guidance

**Requirement:** Operators must understand normal vs. abnormal behavior to avoid alert fatigue.

**Solution:**
- Runbook documents expected ranges:
  - Bait heartbeat age: 0–60s normal, 60–90s warning, >90s critical
  - Queue backlog: 0–64 MB normal, 64–128 MB warning, >224 MB critical
  - Tool invocations: high counts expected from SDKs
- Alert thresholds calibrated to avoid false positives:
  - Shipper heartbeat: 120s (4× heartbeat interval)
  - Bait record age: 90s (3× heartbeat interval)
  - Egress spike: 50 blocks (not 10) for critical

**Reference:** `implementation_plan.md:329-339` (alerts), `research/host-shipper-design.md:113` (heartbeat intervals)

### 5. Dedicated Ingest-Only Key

**Requirement:** Stolen key must not permit querying data or accessing the UI.

**Solution:**
- Runbook mandates `Ingest - License` key type (40 alphanumeric)
- Validation rejects User (`NRAK-`), Admin (`NRAA-`), Query (`NRIQ-`), Browser (`NRJS-`, `NRBR-`) keys
- Key stored host-side only (`/etc/attackbox/shipper.env`, root:root, 0600)
- Bait never sees the key (spool mode)

**Reference:** `implementation_plan.md:280-291` (New Relic telemetry), `research/host-shipper-design.md:54` (key isolation)

---

## Coverage Summary

### Alerts Covering All Required Scenarios

✅ **Canary detection:** `Canary Token Reused` alert (WARNING on any occurrence)  
✅ **Blocked egress:** `Blocked Egress Spike` alert (WARNING at 10, CRITICAL at 50)  
✅ **Falco critical:** `Falco Critical Event` alert (CRITICAL on any `Critical`/`Emergency` priority)  
✅ **Shipper heartbeat loss:** `Shipper Heartbeat Lost` alert (CRITICAL after 120s)  
✅ **Bait heartbeat loss:** `Bait Connection Lost` + `Bait Record Age Excessive` alerts (CRITICAL after 120s / 90s)  
✅ **Ingest spike:** `Ingest Error Spike` alert (WARNING at 20, CRITICAL at 100)  
✅ **New session/injection:** `New Session Started` + `Prompt Injection Detected` alerts (INFO)  
✅ **NrIntegrationError:** `NrIntegrationError Events` alert (WARNING at 10)

### Documentation Covering All Required Topics

✅ **Dedicated ingest-only key provisioning:** `docs/newrelic-runbook.md` § "Key Provisioning"  
✅ **Verification queries:** `newrelic/queries.md` § "Verification Queries" + runbook § "Verification After Deployment"  
✅ **Chunk-safe dedup preserving (record_id, body_sha256, chunk_index):** Runbook § "Chunk-Safe Deduplication" + queries.md examples  
✅ **False-positive/heartbeat trust limits:** Runbook § "False Positives and Trust Limits"

---

## No Live Account Calls

✅ No `newrelic` CLI commands executed  
✅ No Terraform `apply` or `plan` commands executed  
✅ No HTTP requests to New Relic APIs  
✅ No account provisioning or key creation performed

All definitions are offline and ready for manual import or Terraform deployment.

---

## Blockers

None. All deliverables complete and validated.

---

## Next Steps (For Operator)

1. **Import dashboard:** New Relic UI → Dashboards → Import → `newrelic/dashboards/attackbox-overview.json`
2. **Configure alerts:** Create alert policies and apply conditions from `newrelic/alerts/*.yaml`
3. **Provision key:** Follow `docs/newrelic-runbook.md` → "Key Provisioning"
4. **Deploy decoy:** Set `ATTACKBOX_NR_LICENSE_KEY` in `/etc/attackbox/shipper.env`
5. **Verify:** Run queries from `newrelic/queries.md` → "Verification Queries"
6. **Monitor:** Watch dashboard; respond to alerts per runbook

---

## Files Changed

```
docs/newrelic-runbook.md                     +1,044 lines
newrelic/README.md                           +258 lines
newrelic/alerts/critical-alerts.yaml         +175 lines
newrelic/alerts/informational-alerts.yaml    +145 lines
newrelic/dashboards/attackbox-overview.json  +264 lines
newrelic/queries.md                          +476 lines
```

**Total:** 2,362 lines added across 6 new files.

---

## Verification Commands

```bash
# Syntax validation
jq empty newrelic/dashboards/*.json
ruby -e "require 'yaml'; YAML.load_file('newrelic/alerts/critical-alerts.yaml'); YAML.load_file('newrelic/alerts/informational-alerts.yaml')"

# Cross-reference validation
bash /tmp/verify-newrelic.sh

# Git status
git log -1 --oneline
git diff --stat origin/main
```

**Commit:** `ab35d33 feat(newrelic): add operator-ready dashboards, alerts, and runbook`  
**Branch:** `sonnet45/newrelic`  
**Status:** Clean, ready for review and merge.
