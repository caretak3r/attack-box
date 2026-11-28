# Evidence monitoring and collection

Status: OTel Collector and evidence collection deployed on `srv-000000`. Evidence files written to `/var/lib/attackbox-evidence`. Operator-side collection via SSH and local archive. Source root: `/Users/rohit/attack-box`.

## Evidence file locations

All evidence paths are on the VPS filesystem:

| Path | Content | Retention | Format |
|---|---|---|
| `/var/lib/attackbox-public-capture/requests/capture-YYYYMMDD.jsonl` | Public HTTP requests | 7 UTC days | JSONL |
| `/var/lib/attackbox-evidence/public-otel/traces.jsonl` | Public spans | 64 MiB, 30 days, 60 backups | OTLP/JSON |
| `/var/lib/attackbox-evidence/otel/traces.jsonl` | Private spans | 64 MiB, 30 days, 60 backups | OTLP/JSON |
| `/var/lib/attackbox-evidence/otel/metrics.jsonl` | Private metrics | 64 MiB, 30 days, 60 backups | OTLP/JSON |
| `/var/lib/attackbox-evidence/shipper/events-YYYYMMDD.jsonl` | Shipper events (bait, runtime, egress) | 30 days, 8 GiB | JSONL envelope |
| `/var/log/attackbox-audit/*.jsonl` | Audit filter output | 4 files × 64 MiB | JSONL |
| `/var/log/falco-events.jsonl` | Falco output | Falco retention | JSONL |

The shipper event envelope format: `{"ts","role","seq","record"}` per line, fsynced before queue checkpoint.

## Operator-side collection

### Evidence pull script

`scripts/evidence-pull.sh` uses rsync over SSH alias `attackbox` into the local archive directory (default `~/.local/share/attackbox-evidence`). The archive mirrors host paths and never deletes.

```bash
# Pull evidence from VPS to local archive
./scripts/evidence-pull.sh
```

A launchd example in `deploy/launchd/` runs every 15 minutes on the operator Mac.

### Live dashboard console

`cmd/attackbox-live` reads evidence over one SSH session or from the local archive directory:

```bash
# Live over SSH
attackbox-live

# From local archive
attackbox-live -dir ~/.local/share/attackbox-evidence
```

Panels show:
- AI agent activity (tool chains, LiteLLM keys, env-file canary reuse, MCP)
- Exploit chains (Open WebUI, auth tokens)
- Host security (Falco, egress blocks: reply noise vs container-initiated)
- Test environment markers

Own addresses are auto-detected. Data origin: `test` = loopback, the host's own address, or operator addresses. Deploy tests send `User-Agent: attackbox-deploy-test/<12-hex commit> (attackbox-synthetic-<run>-<scenario>)`.

The dashboard runs locally. It never writes to the VPS. See `docs/live-dashboard.md` for panel descriptions.

## Query examples

### Using jq

```bash
# Extract one request's capture records
jq -c 'select(.record.stream == "edge" and .record.action == "capture" and .record.request_id == "abc123")' \
  /var/lib/attackbox-evidence/shipper/events-20261128.jsonl

# Count probes by type
jq -c 'select(.record.stream == "probe")' events-20261128.jsonl | \
  jq -s 'group_by(.record.probe_id) | map({probe: .[0].record.probe_id, count: length})'

# Find canary reuse events
jq -c 'select(.record.canary_credential_presented == true)' events-*.jsonl
```

### Using DuckDB

```bash
# Install DuckDB (if not present)
brew install duckdb  # macOS
# or download from duckdb.org

# Query shipper events
duckdb -c "
SELECT record->>'stream' as stream,
       record->>'action' as action,
       count(*) as count
FROM read_json_auto('events-*.jsonl')
GROUP BY stream, action
ORDER BY count DESC
"

# Request/response timeline
duckdb -c "
SELECT ts,
       record->>'request_id' as request_id,
       record->>'stream' as stream,
       record->>'action' as action
FROM read_json_auto('events-20261128.jsonl')
WHERE record->>'stream' IN ('edge', 'transcript', 'probe')
ORDER BY ts
"
```

## Health checks by file freshness

Monitor evidence collection by checking file modification times and sizes:

```bash
# Check shipper heartbeat (should update every 30s)
stat -f "%Sm %z" /var/lib/attackbox-evidence/shipper/events-$(date +%Y%m%d).jsonl

# Falco activity
stat -f "%Sm" /var/log/falco-events.jsonl

# Audit filter output
ls -lht /var/log/attackbox-audit/

# OTel traces
stat -f "%Sm %z" /var/lib/attackbox-evidence/otel/traces.jsonl
```

Stale files indicate:
- Shipper stopped or disconnected (no updates to events file)
- Bait not sending data (file updates but no new records)
- Falco/audit stopped (source files not growing)
- OTel collector stopped (traces.jsonl not updating)

Expected freshness:
- Shipper events: ≤90s
- Falco events: varies with syscall activity
- Audit filter: varies with audit events
- OTel traces: ≤90s during active traffic

## Evidence origin classification

Records include `sensor_id` and `deployment_id` for routing. The live dashboard classifies data origin:

- `test`: loopback (127.0.0.1), host's own external address, or operator addresses
- `internet`: everything else

Deploy test traffic includes `User-Agent: attackbox-deploy-test/<commit> (attackbox-synthetic-<run>-<scenario>)`. The UA alone never classifies a record.

The private bait stack gets no internet traffic, so its data is test-only. The public gateway serves internet requests.

## Verification gates

Before claiming collection works:
1. Known canary appears in shipper events file
2. Canary trace ID appears in traces.jsonl
3. Falco test fixture in falco-events.jsonl
4. Audit test fixture in audit filter output
5. File sizes grow during test traffic
6. SSH pull completes without errors
7. Live dashboard shows test request

Stop each component and verify its evidence stream stops updating. Restart and verify recovery.

## Deployment tests

### Private deploy bootstrap

`scripts/vultr-launch.sh bootstrap` runs `cmd/attackbox-scenarios` through SSH forward (Mac 127.0.0.1:18443 → host 127.0.0.1:8443) as a gate. Verifies evidence files on host before proceeding.

### Public release verification

`scripts/public-release/` requires release-check receipt, runs staged simulation tests, opens public ports, and verifies from the Mac. All verification reads host evidence files.

Evidence from the Mac proves the full path works: request → bait → shipper → file → SSH pull → archive → dashboard.

## Troubleshooting

### No evidence files

1. Check shipper service: `systemctl status attackbox-shipper`
2. Check bait container: `docker ps`, `docker logs attackbox-bait`
3. Check socket permissions: `ls -l /run/attackbox/*.sock`
4. Check disk space: `df -h /var/lib/attackbox-evidence`

### Files not updating

1. Check queue: `journalctl -u attackbox-shipper -n 50`
2. Check for I/O errors: `dmesg | grep -i error`
3. Check quarantine: `ls -lh /var/lib/attackbox-shipper/queue/quarantine`
4. Verify shipper not hung: look for recent heartbeat in events file

### SSH pull fails

1. Test SSH alias: `ssh attackbox hostname`
2. Check evidence directory permissions on host
3. Verify rsync on both sides: `which rsync`
4. Check local archive directory exists and is writable

### Dashboard shows no data

1. Verify running against correct archive directory
2. Check file dates match expected campaign window
3. Look for JSON parsing errors in dashboard output
4. Verify evidence files are valid JSONL: `jq empty < events-*.jsonl`

## Recovery and replay

Evidence files are append-only. The shipper queue checkpoint advances only after file write succeeds. A crash or restart replays unacknowledged records.

Duplicate records have stable IDs. Deduplicate by:
- Shipper events: `record_id` (format: `<role>-<boot>-<sequence>`)
- OTel traces: `trace.id` and `span.id`
- Audit chunks: `audit_batch_id` and `chunk_index`

After recovery, verify no gaps in sequence numbers or timestamps.

## Offline analysis

The local archive is the durable evidence store. Query it with jq, DuckDB, or custom scripts. The shipper event envelope unwraps as:

```bash
jq '.record' events-20261128.jsonl
```

For multi-day analysis:

```bash
# Merge days into one stream
cat events-202611{25..28}.jsonl > week.jsonl

# Query with DuckDB
duckdb week.jsonl "SELECT ..."
```

The live dashboard does not write to the archive. It is read-only.

## Components and trust

| Component | Input and output | Limits and failure behavior |
|---|---|---|
| Go bait and shipper | Official OTel SDK; OTLP gRPC over separate Unix sockets | 1,024 queued spans, 128 per batch, one-second flush, two-second export timeout, three-second shutdown. Overflow and failed export counters. Spans are not durable. |
| Host OTel Collector 0.165.0 | Role-specific trace sockets; readiness and Collector Prometheus scrapes; file exporter for OTLP/JSON | 192 MiB memory limiter, 320 MiB service limit, 16 MiB export queue. Queue is memory-only. |
| Go readiness collector | Root-owned inventory snapshot; fixed loopback probes; `/metrics` on `127.0.0.1:9465` | 64 MiB service limit; 15-second refresh; 90-second stale limit. Dynamic user. No Docker socket. |
| Snapshot helper | Fixed `systemctl show` and `docker inspect` commands; `/run/attackbox-monitoring/inventory.json` | Persistent root worker; one batched systemctl read and two container inspections; two seconds per command; 64 KiB maximum snapshot; refresh every 60 seconds. No environment, mounts or secret fields. |

The Collector runs as `abx-otel`. Its only output is local JSONL files. Bait uses `/run/attackbox-otel/bait/otlp.sock`. The host shipper uses `/run/attackbox-otel/shipper/otlp.sock`, restricted to `abx-ship`.

The Collector configuration is `/etc/attackbox-otel/config.yaml`, in a root-owned `0755` directory.

## Validation

Host verification: `systemctl is-active` for each service, `http://127.0.0.1:9465/metrics` for readiness, evidence file freshness.

Operator verification: SSH pull succeeds, live dashboard shows test data, jq queries return expected records, file sizes grow during test traffic.

Test failures with public ingress closed: stop each producer, fill bounded queues, restart collector. Each test must show the correct failure mode in evidence files and dashboard.

## Filesystem limits

Evidence directories have local retention limits (days, size, file count). The operator archive grows unbounded. Monitor both:

Host:
```bash
du -sh /var/lib/attackbox-evidence /var/log/attackbox-audit
df -h /var/lib /var/log
```

Operator:
```bash
du -sh ~/.local/share/attackbox-evidence
df -h ~
```

Rotation discards old host files. The archive keeps everything. Prune the archive manually if needed.
