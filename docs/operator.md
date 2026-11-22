# Attack Box setup and operations

Source baseline: `584a658`. Documentation review: 2026-11-22. No live VPS, gVisor, or New Relic verification was performed for this documentation update.

Architecture: `/Users/rohit/attack-box/docs/architecture.md`. Proposed improvements and deployment gates: `/Users/rohit/attack-box/IMPROVE.md`.

## Supported direction and current exposure

Build runtime services in Go, using the version declared by `/Users/rohit/attack-box/go.mod` (currently Go 1.25). The repository supplies the bait and shipper binaries. The shipper binary also supplies stdin adapter modes. The proposed analysis job and typed response planner are not implemented services.

The supplied Compose setup publishes proxy ports only on host loopback: `127.0.0.1:8443` for TLS and `127.0.0.1:8080` for a redirect. It enables the OpenAI persona only. Public 443, vLLM 8000, and Ollama 11434 require the coordinated I01 change in `/Users/rohit/attack-box/IMPROVE.md`. Opening the provider firewall alone does not enable them.

Use a disposable Ubuntu 24.04 VPS in a separate provider project. Keep public ingress closed during setup and private validation. Keep a tested provider-console recovery path. Do not place personal keys, production data, or production account credentials on the VPS.

Captured payloads are hostile data. Inspect approved redacted exports in a separate analysis environment, outside the decoy and the operator's Mac. Do not open extracted links, execute captured commands, render payloads as active HTML, or feed them to an agent with tools.

## Local build and verification

Run from the existing checkout. These commands do not deploy:

```bash
cd /Users/rohit/attack-box
go test ./...
CGO_ENABLED=0 go build -o /dev/null /Users/rohit/attack-box/cmd/attackbox
CGO_ENABLED=0 go build -o /dev/null /Users/rohit/attack-box/cmd/attackbox-shipper
bash /Users/rohit/attack-box/scripts/test-deploy-ubuntu.sh
```

The deployment tests are static checks. They do not prove runtime containment. The official-client harness is `/Users/rohit/attack-box/scripts/client_matrix.py`; retain its documented dependencies and interpreter rather than replacing the runtime.

For a local, loopback-only bait with remote telemetry disabled:

```bash
cd /Users/rohit/attack-box
ATTACKBOX_NR_DISABLED=true go run /Users/rohit/attack-box/cmd/attackbox -check-config
ATTACKBOX_NR_DISABLED=true go run /Users/rohit/attack-box/cmd/attackbox
```

These examples assume no conflicting `ATTACKBOX_NR_LICENSE_KEY` or `ATTACKBOX_SPOOL_SOCKET` is inherited. Local output can contain hostile text; use synthetic requests during development.

## Bait command and configuration

Source: `/Users/rohit/attack-box/cmd/attackbox/main.go` and `/Users/rohit/attack-box/cmd/attackbox/config.go`.

| Flag | Behavior |
|---|---|
| `-version` | Print build version and exit |
| `-check-config` | Validate configuration and exit; does not establish network reachability |
| `-healthcheck URL` | Check an HTTP loopback URL; rejects non-loopback hosts, credentials, and redirects |

Exactly one telemetry mode must be selected: host spool socket, direct New Relic key, or `ATTACKBOX_NR_DISABLED=true`. Use host spool mode on the VPS. Direct-key mode puts the ingest key in the bait and is outside the deployed separation.

Unset or blank settings use defaults. All bait integer limits are positive. All bait durations must be greater than zero and at most one hour. Boolean values accept `true/false`, `yes/no`, or `1/0`, without case sensitivity.

| Environment variable | Binary default | Validation or meaning |
|---|---|---|
| `ATTACKBOX_OPENAI_ADDR` | `127.0.0.1:8080` | IP, localhost, or wildcard plus port 0–65535; `off` disables |
| `ATTACKBOX_VLLM_ADDR` | `off` | Same address rules; use a distinct non-conflicting listener |
| `ATTACKBOX_OLLAMA_ADDR` | `off` | Same address rules; at least one persona must remain enabled |
| `ATTACKBOX_INSTANCE` | `attackbox` | 1–64 characters from `[A-Za-z0-9._-]` |
| `ATTACKBOX_MODELS` | Server defaults: `qwen3:8b,gpt-oss:20b,llama3.1:8b` | Comma-separated names, each at most 128 bytes; no spaces/control characters within a name |
| `ATTACKBOX_TRUSTED_PROXIES` | Empty | Comma-separated IPs or CIDRs; forwarding headers are trusted only from those peers |
| `ATTACKBOX_SECRET_FILE` | Empty: random process key | Regular file, 32–4096 bytes, no group/other permission bits; stable file needed for stable derived keys |
| `ATTACKBOX_NR_DISABLED` | `false` | Explicit local-only telemetry mode |
| `ATTACKBOX_NR_LICENSE_KEY` | Empty | Required only for direct remote mode; conflicts with spool/local mode |
| `ATTACKBOX_NR_LOG_URL` | Client default: US Log API | Direct-mode URL override; does not alter firewall policy |
| `ATTACKBOX_NR_METRIC_URL` | Client default: US Metric API | Direct-mode URL override; does not alter firewall policy |
| `ATTACKBOX_SPOOL_SOCKET` | Empty | Enables host spool mode; absolute Unix path, at most 107 bytes, no NUL |
| `ATTACKBOX_SPOOL_QUEUE` | `10000` | 1–100000 queued records; separate fixed byte ceiling also applies |
| `ATTACKBOX_SPOOL_TIMEOUT` | `5s` | Per-record socket write timeout |
| `ATTACKBOX_MAX_SESSIONS` | `10000` | 1–100000 retained sessions |
| `ATTACKBOX_MAX_BODY_BYTES` | `1048576` | 1–16777216 request bytes |
| `ATTACKBOX_MAX_LOG_BODY` | `131072` | 1–1048576 captured body bytes; accepted larger bodies are truncated in logs |
| `ATTACKBOX_MAX_PER_SOURCE` | `8` | 1–1000 in-flight requests per source; cannot exceed MAX_IN_FLIGHT |
| `ATTACKBOX_MAX_IN_FLIGHT` | `256` | 1–10000 per-listener concurrency; a process-wide cross-persona budget is proposed |
| `ATTACKBOX_HOLD_SILENT` | `150s` | Selected silent-probe delay; cannot exceed MAX_STREAM |
| `ATTACKBOX_IDLE_INTERVAL` | `45s` | Selected idle-stream interval |
| `ATTACKBOX_MAX_STREAM` | `180s` | Bounds selected holds; HTTP write timeout adds 30 seconds |
| `ATTACKBOX_TIMING` | `true` | Simulated response pacing; not actual model token timing |
| `ATTACKBOX_READ_HEADER_TIMEOUT` | `10s` | HTTP header timeout |
| `ATTACKBOX_READ_TIMEOUT` | `30s` | HTTP read timeout |
| `ATTACKBOX_IDLE_TIMEOUT` | `60s` | HTTP keep-alive idle timeout |
| `ATTACKBOX_SHUTDOWN_TIMEOUT` | `15s` | Bait shutdown deadline |

Follow-up and canary attribution (I03) adds no flag and no environment variable. Its bounds are fixed in the source.

Compose overrides include OpenAI `0.0.0.0:8080`, instance `attackbox-bait`, 5,000 sessions, a commercial-model catalog, trusted proxy subnet `172.30.0.0/24`, and secret path `/run/secrets/attackbox_secret`. vLLM and Ollama remain off. The proposed public profile must narrow trusted forwarding identity to the actual proxy peer and assign a coherent catalog to each persona.

## Shipper command and configuration

Source: `/Users/rohit/attack-box/cmd/attackbox-shipper/main.go` and `/Users/rohit/attack-box/cmd/attackbox-shipper/config.go`.

The binary supports `-version` and `-stdin-stream runtime|egress`. It does not have a configuration-check or dry-run flag. Without stdin mode it runs socket ingest, disk queue, and remote delivery. Stdin mode reads JSON lines and writes to `ATTACKBOX_SPOOL_SOCKET`; the supplied adapter units set this to the appropriate role socket. Adapter mode does not load the host ingest key.

| Environment variable | Default | Validation or meaning |
|---|---|---|
| `ATTACKBOX_NR_LICENSE_KEY` | None | Required for the shipper; local key-shape validation also applies |
| `ATTACKBOX_NR_LOG_URL` | `https://log-api.newrelic.com/log/v1` | HTTPS ingest endpoint; no automatic regional selection |
| `ATTACKBOX_NR_METRIC_URL` | `https://metric-api.newrelic.com/metric/v1` | HTTPS ingest endpoint; no automatic regional selection |
| `ATTACKBOX_SPOOL_SOCKET` | `/run/attackbox/spool.sock` | Bait UID 65532; 4 connections, 1 MiB/s, 4 MiB burst |
| `ATTACKBOX_RUNTIME_SOCKET` | Disabled | Root producer; 2 connections, 256 KiB/s, 4 MiB burst |
| `ATTACKBOX_EGRESS_SOCKET` | Disabled | Root producer; 2 connections, 128 KiB/s, 4 MiB burst |
| `ATTACKBOX_SHIP_QUEUE_DIR` | `/var/lib/attackbox-shipper/queue` | Owner-only directory; queue implementation validates ownership and file access |
| `ATTACKBOX_SHIP_QUEUE_BYTES` | `268435456` | Decimal bytes, accepted range 41943125–8589934592 |
| `ATTACKBOX_SHIP_SEGMENT_BYTES` | `16777216` | Decimal bytes, accepted range 1048576–268435456 |
| `ATTACKBOX_SHIP_SHUTDOWN_TIMEOUT` | `15s` | Duration from zero through one minute; align systemd stop timeout if changed |
| `HOSTNAME` | OS hostname, then `attackbox` | Host label in shipper telemetry |

Socket paths must be absolute, at most 107 bytes, and contain no NUL. Use distinct paths. Current byte-setting parsing silently falls back to defaults for non-integer input; it rejects parsed out-of-range integers. Check the effective configuration carefully. Strict deployment-manifest validation is proposed in `/Users/rohit/attack-box/IMPROVE.md`.

The script resolves and permits the US New Relic hosts above. For another region, endpoint configuration, firewall resolution, and deployment verification must change together. Do not assume a key selects the region.

## VPS preparation and install

Use an operator-approved source revision. Stage the full checkout at `/opt/attackbox-src` on the VPS. The script installs runtime artifacts at `/opt/attackbox`; keep these paths distinct because the installer copies files from its source directory.

Create a dedicated decoy New Relic account or subaccount and an ingest license key. Do not give the host a query/admin key. Configure retention, ingest limits, and cost alerts outside the decoy. Do not enable automatic AI processing of hostile payloads.

Create `/etc/attackbox/shipper.env` with owner `root:root` and mode `0600`. Enter the real ingest key through a protected editor or secret-delivery channel. Do not put it in shell history, repository files, or command output. The required settings are:

```dotenv
ATTACKBOX_NR_LICENSE_KEY=<replace with the dedicated ingest license key>
ATTACKBOX_SPOOL_SOCKET=/run/attackbox/spool.sock
ATTACKBOX_RUNTIME_SOCKET=/run/attackbox/runtime.sock
ATTACKBOX_EGRESS_SOCKET=/run/attackbox/egress.sock
```

The placeholder is not a valid key. The installer requires this file before service startup and appends missing role-socket settings in apply mode.

Run these commands on the VPS only after deployment authorization:

```bash
sudo bash /opt/attackbox-src/scripts/deploy-ubuntu.sh --dry-run
sudo bash /opt/attackbox-src/scripts/deploy-ubuntu.sh --apply
sudo bash /opt/attackbox-src/scripts/deploy-ubuntu.sh --verify
```

With no mode flag the script performs preflight. `--dry-run` reports proposed setup actions; it is not a runtime rehearsal. `--apply` installs dependencies, users, firewall policy, gVisor, service units, container artifacts, and binaries. It builds before applying the final restrictive egress policy. `--refresh-sets` refreshes allowed endpoint addresses; stale entries remain until ruleset reload or reboot. The script installs its refresh entry point at `/usr/local/sbin/attackbox-deploy`.

The installer creates the redaction secret and a self-signed TLS certificate if missing. It preserves existing files. Container secret files under `/opt/attackbox/secrets` must be owned by UID/GID 65532 with mode 0400. Local Compose file-secret ownership settings do not replace host file ownership. The self-signed certificate is suitable for private validation; a public TLS profile needs an explicit certificate provisioning and renewal procedure that preserves the egress boundary.

The runtime files are `/opt/attackbox/compose.yaml` and `/opt/attackbox/compose.gvisor.yaml`. The host binary is `/usr/local/bin/attackbox-shipper`. Bait runs in its container. Both containers use runsc; verify its configured host-UDS support and the bait socket from the real deployed runtime.

| VPS path | Expected owner / mode | Purpose |
|---|---|---|
| `/etc/attackbox/shipper.env` | `root:root`, 0600 | Key source; systemd passes values to shipper process environment |
| `/run/attackbox` | `abx-ship:abx-bait`, 0710 | Socket directory; container has a read-only mount |
| `/run/attackbox/spool.sock` | `abx-ship:abx-bait`, 0220 | Bait socket, with peer-UID validation |
| `/var/lib/attackbox-shipper` | Owner `abx-ship`, 0700 | Persistent state directory; never mount into bait |
| `/var/lib/attackbox-shipper/queue` | Owner `abx-ship`, 0700 | Queue segments, checkpoint, and quarantined data |

A read-only socket mount does not prohibit connection or writes through the socket. Peer credentials and shipper validation enforce producer access.

## Private checks and public-exposure gate

The current `--verify` function tests metadata denial, internal Docker name resolution, external DNS denial, internet denial, and unauthenticated New Relic HTTP access from the shipper UID. Its negative tests can treat a container launch failure as a successful block. Its HTTP checks accept any HTTP status when curl succeeds, including 401, 403, and 500. A curl failure still fails the pipeline because the script enables pipefail. It does not verify actual authenticated ingest, role-socket isolation, proxy containment, time synchronization, or public reachability. Treat it as supplementary output, not a release gate.

Before public exposure, record successful controls and denied operations separately:

1. Confirm the test process actually starts under the same runtime and network as each deployed container. Confirm permitted internal access works before interpreting denied access.
2. Send synthetic requests through the TLS proxy. Confirm persona, model catalog, status, JSON/SSE framing, and response limits. Record the tested revision and configuration.
3. Confirm the real bait can write to its socket. Confirm a bait UID cannot submit to host runtime/egress roles. Confirm malformed records fail without stopping collection.
4. Verify authenticated log and metric ingest using a trusted synthetic test marker. Find that marker in remote queries. Verify all configured producers separately.
5. Deny outbound internet, external DNS, cloud metadata, and unintended private-network access from bait and proxy. Check IPv4 and IPv6. Verify provider firewall and host policy independently.
6. Test restart with a known queued record, a remote outage, a full queue, and a client disconnect. Confirm honest loss reporting and bounded resource use. Check physical disk usage as well as logical backlog.
7. Test provider-console recovery. Record the accepted load, hardware, latency, resource peaks, and remaining gaps.
8. After I01 is implemented, verify each intended public port from a separate authorized test host. Keep management access restricted. Open public ingress only as the final approved deployment action.

Optional SSH disablement requires both `--disable-ssh` and `--console-confirmed` with `--apply`. Do it only after console recovery is tested. These instructions do not authorize that operation.

## Operations and health

On the VPS:

```bash
sudo systemctl status attackbox-shipper attackbox
sudo journalctl -u attackbox-shipper -n 50
sudo docker compose -f /opt/attackbox/compose.yaml -f /opt/attackbox/compose.gvisor.yaml ps
sudo docker compose -f /opt/attackbox/compose.yaml -f /opt/attackbox/compose.gvisor.yaml logs --tail 50 bait proxy
sudo stat /run/attackbox/spool.sock /run/attackbox/runtime.sock /run/attackbox/egress.sock
sudo du -sh /var/lib/attackbox-shipper/queue
sudo df -h /var/lib/attackbox-shipper/queue
```

The `attackbox` unit wraps detached Compose. Its journal does not replace container logs. Inspect `attackbox-falco-adapter.service`, `attackbox-egress-adapter.service`, and `falco-modern-bpf.service` when their streams stop. An oversized stdin line terminates the adapter scanner; service restart does not recover skipped source records. Native Falco on the host cannot prove the absence of activity inside gVisor.

In New Relic, filter heartbeat records by `stream='heartbeat'`, `source='shipper'`, and the configured hostname. Do not require the bait's instance label on shipper heartbeats. The shipper sends a heartbeat every 30 seconds outside its durable disk queue.

Interpret `bait_connected` as socket connection presence. Interpret `last_bait_record_age_ms=-1` as no valid bait record yet. Both queue-byte fields report unacknowledged queue bytes. Queue drops omit other possible loss stages. Missing heartbeat, stale bait activity, growing physical disk use, queue corruption, replay gaps, and endpoint failures need investigation. None alone proves compromise.

## Stop, restart, recovery, and rebuild

For a planned stop, close public ingress first, then stop bait, adapters, and shipper. The bait handles SIGTERM within its configured deadline. The shipper checkpoints confirmed remote delivery and preserves unacknowledged records for restart. It does not empty the disk queue on shutdown. Keep systemd stop limits consistent with application deadlines.

Restart the shipper before bait so the spool socket is available. The bait startup requires its initial socket connection. Do not remove queue files to fix a startup error. Recovery may truncate a torn newest tail, quarantine corrupt segments, and replay uncertain logs. Metrics in uncertain replay ranges are suppressed with a gap signal. Account for duplicates by record ID and chunk index.

For a failed release, keep ingress closed. Preserve queue data and configuration in an isolated approved location. Restore the last reviewed compatible binary/configuration or rebuild a clean host. Do not assume an older binary can read a changed queue format. A schema or queue-format change needs a tested migration or explicit rebuild path before release.

For suspected host compromise, use the provider control plane to isolate or power off the VPS. Revoke the exposed ingest key. Preserve provider snapshots only when needed for analysis, outside the operator's Mac. Treat local telemetry after suspected root access as untrusted. Rebuild from reviewed source and rotate secrets; investigate the entry path before restoring exposure. Rebuilding alone does not establish that the underlying weakness is fixed.

## Response and evidence limits

Current responses are deterministic templates and active probes. They are not an actual model or tool executor. Fixed keyword labels are hypotheses. A fake success response does not verify an exploit against a real product. A canary echoed in history does not prove exfiltration. Client-supplied assistant/tool history is untrusted.

Redaction is heuristic. Unnamed secrets, encoded secrets, unusual Unicode names, and retained schema prose can survive. Log truncation removes evidence. The proposed corpus must scrub again after each decoding/extraction boundary, retain uncertainty, and enforce bounded retention across derived exports.

### Reading probe records

Attributes on a probe record:
- `delivery`: the state that the server observed when it wrote the response (`selected`, `partially_sent`, `fully_sent`, `unknown`). It is not proof that the client read the bytes.
- `issuance`: the ID of the issuance record for the response that this request received.
- `followup`: present only when the server scored this request as the attributed reply to an earlier probe. It names that probe.
- `issuance_evicted`, `issuance_lost`: cumulative counts for the session. The first counts records that the registry dropped. The second counts the dropped records that were still open.
- `terminal_frame="failed"`: the server sent all content, but the closing stream frame failed. `delivery` is not affected.
- `canaries_issued`: the canary names that this response carried.

An `attribution` observation has `probe_id` `attribution`. It means the server did not score a request. `status` is `ambiguous`, `no_new_material`, or `lost`. `reason` gives the cause. The reason literals are in the `/Users/rohit/attack-box/docs/architecture.md` section "Probe issuance and reply attribution". A `lost` status means the registry evicted an open record.

A `canary-reuse` observation has one comma list of states for each canary: `present_in_history`, `newly_echoed`, `destination_placed`, `credential_presented`, `presented_undelivered`. The server reports each state once for each canary in a session. `credential_source` names the credential surface. `independently_observed` is always `unavailable`.

Do not draw these conclusions:
- `fully_sent` does not mean that the client read the response. `unknown` means unconfirmed.
- A scored reply does not prove the identity, model, or intent of the client.
- `observed_action="none"` means that the bait executed and fetched nothing. It does not show that the action did not happen.
- `credential_presented` is not misuse. `present_in_history` is not exfiltration.
- `no_new_material` and `ambiguous` are not non-compliance. `lost` is not client behavior.
- A missing `followup` can mean an ineligible request, an expired record, or a resend.
- `attackbox.retry_delay_seconds` starts at the end of the 429 body, not at the request arrival. It is not client think time.

`attackbox.probe_followups` counts attributed replies only. Ambiguous, `no_new_material`, and replayed requests are not counted. The count can be lower than before this change. I03 adds no setting.

## Required documentation for each new Go service

A service change must update `/Users/rohit/attack-box/docs/architecture.md` and this guide in the same change. Record binary/build commands, protocol/schema version, inputs and outputs, all flags and environment defaults, validation rules, UID, secrets, network access, resource limits, storage and retention, health, shutdown, replay/loss behavior, installation, recovery, rollback, and tests.

Mark future settings and binaries as proposed until implemented. The Go analysis job, typed response plans, public discovery profile, protected loss accounting, and adversarial acceptance suite in `/Users/rohit/attack-box/IMPROVE.md` remain future work. Do not substitute a successful build or static script test for the deployment checks above.
