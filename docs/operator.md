# Attack Box setup and operations

Source baseline: `584a658`. Documentation review: 2026-11-22. No live VPS or gVisor verification was performed for this documentation update.

Architecture: `/Users/rohit/attack-box/docs/architecture.md`. Proposed improvements and deployment gates: `/Users/rohit/attack-box/IMPROVE.md`.

Service ecosystem and monitoring: `/Users/rohit/attack-box/docs/service-ecosystem.md`. That document includes a later host snapshot and a proposed instrumentation setup; it does not certify complete monitoring.

## Supported direction and current exposure

### Count replies to the public chat challenge

With local request capture enabled, the public gateway can add an optional ACK invitation to an OpenAI, Ollama, or Anthropic chat reply. It keeps the normal answer and omits the invitation if the complete text does not fit the token limit. The invitation asks only for a random token in the next user message to the same endpoint.

The local JSONL field `chat_ack` has two values:

- `offered`: the gateway prepared a complete invitation. This does not prove delivery.
- `matched`: the next eligible request returned the exact `ACK <token>` as its final user message. Assistant and tool history do not count.

On the host, count today's observations without printing request data:

```bash
jq -n 'reduce inputs as $r ({offered:0, matched:0}; if $r.chat_ack == "offered" or $r.chat_ack == "matched" then .[$r.chat_ack] += 1 else . end)' \
  "/var/lib/attackbox-public-capture/requests/capture-$(date -u +%Y%m%d).jsonl"
```

The gateway checks the TCP peer IPv4 address, port, Host, and path. A token expires after 15 minutes or one use. A subsequent eligible chat, a restart, or contention for a tracking slot can invalidate it sooner. The table has 1,024 slots. Clients behind one NAT can replace each other's tokens. A match shows token return, not who sent it or whether a model ran. The gateway does not add ACK data to remote telemetry.

### Optional diagnostics in response policy 2

This source change requires a separately approved deployment. It adds at most one optional invitation per in-memory session, after the first responder request. Responses can proceed when the client ignores or declines the invitation. The service asks only for information already available and approved for sharing. It does not ask the client to inspect files or run commands.

A client can submit this optional object in an inference request that supports metadata:

```json
{
  "metadata": {
    "diagnostics": {
      "client_name": "agentkit",
      "client_version": "1.2.3",
      "deployment_region": "eu-west-1",
      "health_status": "healthy",
      "operator_alias": "team-blue"
    }
  }
}
```

To decline, use `{"metadata":{"diagnostics":{"status":"declined"}}}`. Fields are optional. Accepted values are bounded tokens, not free text. Do not submit names, email addresses, precise locations, hostnames, IP addresses, credentials or internal paths.

Inspect the `probe` stream and its `declarations` array. Diagnostic fields start with `claimed_`; `valid=true` means syntax acceptance only. Do not treat a claimed region as geolocation, a claimed health status as host monitoring, or a declaration as proof that an invitation caused the reply. Request and response capture and trace joins use the existing paths. Raw evidence can retain submitted invalid fields; this parser does not scrub the raw archive. See `/Users/rohit/attack-box/docs/architecture.md` for limits and session reset behavior.

### Runtime direction

Build runtime services with the Go version in `/Users/rohit/attack-box/go.mod` or later. The repository supplies the bait and shipper binaries. The shipper binary also supplies stdin adapter modes. The proposed analysis job and typed response planner are not implemented services.

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

Exactly one telemetry mode must be selected: host spool socket or local-only. Use host spool mode on the VPS.

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

The binary supports `-version` and `-stdin-stream runtime|egress`. It does not have a configuration-check or dry-run flag. Without stdin mode it runs socket ingest, disk queue, and evidence writing. Stdin mode reads JSON lines and writes to `ATTACKBOX_SPOOL_SOCKET`; the supplied adapter units set this to the appropriate role socket. Adapter mode does not load keys.

| Environment variable | Default | Validation or meaning |
|---|---|---|
| `ATTACKBOX_SENSOR_ID` | Lowercase hostname, or `attackbox` if invalid | Stable sensor label on shipper logs and metrics |
| `ATTACKBOX_DEPLOYMENT_ID` | `unset` | Deployment label on shipper logs and metrics. On a monitored host it is the campaign ID, not a commit |
| `ATTACKBOX_SPOOL_SOCKET` | `/run/attackbox/spool.sock` | Bait UID 65532; 4 connections, 1 MiB/s, 4 MiB burst |
| `ATTACKBOX_RUNTIME_SOCKET` | Disabled | Root producer; 2 connections, 256 KiB/s, 4 MiB burst |
| `ATTACKBOX_EGRESS_SOCKET` | Disabled | Root producer; 2 connections, 128 KiB/s, 4 MiB burst |
| `ATTACKBOX_SHIP_QUEUE_DIR` | `/var/lib/attackbox-shipper/queue` | Owner-only directory; queue implementation validates ownership and file access |
| `ATTACKBOX_SHIP_QUEUE_BYTES` | `268435456` | Decimal bytes, accepted range 41943125–8589934592 |
| `ATTACKBOX_SHIP_SEGMENT_BYTES` | `16777216` | Decimal bytes, accepted range 1048576–268435456 |
| `ATTACKBOX_SHIP_SHUTDOWN_TIMEOUT` | `15s` | Duration from zero through one minute; align systemd stop timeout if changed |
| `HOSTNAME` | OS hostname, then `attackbox` | Host label in shipper telemetry |

Both ID values must match `^[a-z0-9][a-z0-9._-]{0,62}$`. Use a new deployment ID when you rebuild the sensor.

Socket paths must be absolute, at most 107 bytes, and contain no NUL. Use distinct paths. Current byte-setting parsing silently falls back to defaults for non-integer input; it rejects parsed out-of-range integers. Check the effective configuration carefully. Strict deployment-manifest validation is proposed in `/Users/rohit/attack-box/IMPROVE.md`.

## VPS preparation and install

Use an operator-approved source revision. Stage the full checkout at `/opt/attackbox-src` on the VPS. The script installs runtime artifacts at `/opt/attackbox`; keep these paths distinct because the installer copies files from its source directory.

The host stores evidence on disk. The operator retrieves it over SSH. No third-party ingest key is required on the host.

The installer requires `/etc/attackbox/shipper.env` with owner `root:root` and mode `0600`. The required settings are:

```dotenv
ATTACKBOX_SPOOL_SOCKET=/run/attackbox/spool.sock
ATTACKBOX_RUNTIME_SOCKET=/run/attackbox/runtime.sock
ATTACKBOX_EGRESS_SOCKET=/run/attackbox/egress.sock
```

The installer appends missing role-socket settings in apply mode.

Run these commands on the VPS only after deployment authorization:

```bash
sudo bash /opt/attackbox-src/scripts/deploy-ubuntu.sh --dry-run
sudo bash /opt/attackbox-src/scripts/deploy-ubuntu.sh --apply
sudo bash /opt/attackbox-src/scripts/deploy-ubuntu.sh --verify
```

With no mode flag the script performs preflight. `--dry-run` reports proposed setup actions; it is not a runtime rehearsal. `--apply` installs dependencies, users, firewall policy, gVisor, service units, container artifacts, and binaries. It builds before applying the final restrictive egress policy. A reload of `nftables.service` keeps the set elements (verified on nftables 1.0.9). Do not restart `nftables.service`: a restart flushes the full ruleset, which includes the Docker rules. The script installs its refresh entry point at `/usr/local/sbin/attackbox-deploy`.

`--apply` also disables cloud-init for later boots with `/etc/cloud/cloud-init.disabled`. The egress policy blocks the provider metadata address. Without that address, cloud-init treats a reboot as a new instance: it makes new SSH host keys and puts the SSH defaults of the image back, which permit password login.

The installer creates a redaction secret and a self-signed TLS certificate for private checks. It preserves a complete existing key and certificate pair. The host files under `/opt/attackbox/secrets` need owner `65532:65532` and mode `0400`. Compose file-secret settings do not replace host permissions.

The runtime files are `/opt/attackbox/compose.yaml` and `/opt/attackbox/compose.gvisor.yaml`. The host binary is `/usr/local/bin/attackbox-shipper`. Bait runs in its container. Both containers use runsc; verify its configured host-UDS support and the bait socket from the real deployed runtime.

| VPS path | Expected owner / mode | Purpose |
|---|---|---|
| `/etc/attackbox/shipper.env` | `root:root`, 0600 | Key source; systemd passes values to shipper process environment |
| `/run/attackbox` | `abx-ship:abx-bait`, 0710 | Socket directory; container has a read-only mount |
| `/run/attackbox/spool.sock` | `abx-ship:abx-bait`, 0220 | Bait socket, with peer-UID validation |
| `/var/lib/attackbox-shipper` | Owner `abx-ship`, 0700 | Persistent state directory; never mount into bait |
| `/var/lib/attackbox-shipper/queue` | Owner `abx-ship`, 0700 | Queue segments, checkpoint, and quarantined data |

A read-only socket mount does not prohibit connection or writes through the socket. Peer credentials and shipper validation enforce producer access.

### Use a trusted certificate with DuckDNS

Use the operator Mac for [DNS-01 validation](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge). The DuckDNS token and the ACME account key stay off the decoy. The TLS private key stays on the VPS. No public listener or firewall change is necessary.

1. Register a dedicated hostname at [DuckDNS](https://www.duckdns.org/about.jsp). Set its A record to the VPS IPv4 address. DuckDNS shares [one TXT record](https://www.duckdns.org/spec.jsp) across the hostname and its descendants. Do not use that record for another service.
2. On the Mac, install lego 5 with `brew install lego`. Save the DuckDNS account token at the hidden prompt:

   ```sh
   security add-generic-password -a "$(id -un)" -s attackbox-duckdns -w
   ```

3. Read the [Let's Encrypt Subscriber Agreement](https://letsencrypt.org/repository/). If you accept it, run the command below from the checkout. Replace `your-label` with your registered label. The certificate makes this name public in Certificate Transparency logs.

   ```sh
   LEGO_ACCEPT_TOS=true bash scripts/duckdns-tls.sh your-label.duckdns.org
   ```

4. Schedule `bash scripts/duckdns-tls.sh your-label.duckdns.org` daily on the Mac with `launchd`. Use absolute paths in the job. Include Homebrew in `PATH`. If you copy the helpers outside the checkout, set `VULTR_STATE_DIR` to the launcher's state directory. Keep `duckdns-tls.sh`, `install-proxy-chain.sh`, and `vultr-launch.sh` together.

The helper installs only the public chain. It restarts only nginx when the served chain needs to change. It checks the hostname, system trust, and leaf fingerprint on `127.0.0.1:8443`. If the new chain fails that check, it restores the previous certificate. An unchanged chain needs no restart.

Renewal needs the operator's login session, an accessible Keychain, and pinned SSH access. After VPS lockdown, use an approved management path for certificate delivery. Do not reopen SSH for renewal.

## Private checks and public-exposure gate
The current `--verify` function tests metadata denial, internal Docker name resolution, external DNS denial, and internet denial from the shipper UID. Its negative tests can treat a container launch failure as a successful block. It does not verify role-socket isolation, proxy containment, time synchronization, or public reachability. Treat it as supplementary output, not a release gate.
Before public exposure, record successful controls and denied operations separately:

1. Confirm the test process actually starts under the same runtime and network as each deployed container. Confirm permitted internal access works before interpreting denied access.
2. Send synthetic requests through the TLS proxy. Confirm persona, model catalog, status, JSON/SSE framing, and response limits. Record the tested revision and configuration.
3. Confirm the real bait can write to its socket. Confirm a bait UID cannot submit to host runtime/egress roles. Confirm malformed records fail without stopping collection.
4. Verify evidence collection using a trusted synthetic test marker. Find that marker in the host evidence files. Verify all configured producers separately.
5. Deny outbound internet, external DNS, cloud metadata, and unintended private-network access from bait and proxy. Check IPv4 and IPv6. Verify provider firewall and host policy independently.
6. Test restart with a known queued record, a full queue, and a client disconnect. Confirm honest loss reporting and bounded resource use. Check physical disk usage as well as logical backlog.
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

Check the evidence files on the host for recent activity. Use the console (`cmd/attackbox-live`) or pull evidence to the Mac with `scripts/evidence-pull.sh`. Missing heartbeat, stale bait activity, growing physical disk use, queue corruption, replay gaps, and endpoint failures need investigation. None alone proves compromise.

The shipper attempts the report at startup and every 30 seconds. It sends no more than 40 rows per write. The shipper reports each final verdict for up to 20 report intervals. A new verdict starts a new interval count.

Use `shipper_boot`, `role`, and `boot` to identify a boot report. `loss_scope=committed` excludes remote delivery. If `loss=unknown`, read `loss_reason` before interpreting the counters. Then check queue backlog separately.
## Stop, restart, recovery, and rebuild

For a planned stop, close public ingress first, then stop bait, adapters, and shipper. The bait handles SIGTERM within its configured deadline. The shipper checkpoints confirmed remote delivery and preserves unacknowledged records for restart. It does not empty the disk queue on shutdown. Keep systemd stop limits consistent with application deadlines.

For a schema upgrade, stop the bait and adapters before you replace the shipper. Restart all producers and the shipper from the same release. A shipper that requires `v=1` rejects old producers, but existing durable queue entries remain readable.

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

## Live evidence and delivery

The implemented application capture, batch export, evidence recovery CLI, shutdown ordering, dashboard setup and validation gates are documented in `/Users/rohit/attack-box/docs/live-evidence.md`. The process defaults to `ATTACKBOX_FULL_EVIDENCE=true`; Compose sets it explicitly. Raw capture preserves submitted bytes and credentials; readable summaries remain redacted. This does not extend capture to proxy-rejected traffic or remove bounded-queue loss. The host collector is still proposed.

## Optional service ecosystem monitoring

The approved Go tracing and host readiness profile is documented in `/Users/rohit/attack-box/docs/monitoring-setup.md`. It uses private Unix trace sockets and loopback metrics endpoints. It does not expose public OTLP ports. It is not part of the default deployment. Follow that runbook for installation, identity, restart, remote verification and rollback. The forensic host reader remains separate work.

## Durable host readers and rejected records

This source change requires a paired shipper and host-reader release. It is not installed on the VPS until the exact-commit deployment gate passes.

Bootstrap exports `/usr/local/bin/attackbox-shipper` and `/usr/local/bin/attackbox-hostreader`. It enables `ATTACKBOX_HOST_RECEIPTS=true` in `/etc/attackbox/shipper.env`; an explicit conflicting value fails validation. The runtime and egress units use private state directories `/var/lib/attackbox-falco-reader` and `/var/lib/attackbox-egress-reader`, mode 0700. Each reader has a 128 MiB memory cap. Keep source logs and journal retention long enough to cover the maximum outage.

For migration, stop both adapters, install the paired binaries and units, validate the environment, restart the shipper, then start the adapters. Confirm both role heartbeats and a synthetic source record in the evidence files. First start replays retained source data; budget for that backlog. Do not run an old stdin adapter on a receipt-enabled socket.

For rollback, stop the readers, restore the previous shipper and unit files, restore the previous environment, then restart in the same order. Preserve cursor directories and queue data. A legacy adapter cannot resume the new source cursor and can miss data during rollback.

If a reader reports a source gap, stop source rotation and preserve the files. Restore the saved inode or journal interval from an archive before retry. Do not delete cursor state to make the service green. File rotation is limited to rename-and-reopen with the old writer closed and no intermediate rotations while the reader is behind. Copy-truncate and compressed rotated files are unsupported.

If `quarantine_records` is nonzero, inspect `/var/lib/attackbox-shipper/queue/quarantine` as inert evidence. Each mode-0600 JSON file holds the source role, queue sequence, bounded rejection reason, SHA-256 and exact queue bytes encoded as base64. Copy and verify an archive before any operator removal. There is no automatic deletion or replay command. A full quarantine stops export; it must not silently discard evidence. A positive receipt from the source socket means local durability only.

Validation commands for this change:

```bash
cd /Users/rohit/attack-box
go test -race ./internal/hostevidence ./internal/shipper ./internal/telemetry ./cmd/attackbox-shipper ./internal/server
go vet ./...
shellcheck -S error /Users/rohit/attack-box/scripts/deploy-ubuntu.sh /Users/rohit/attack-box/scripts/test-deploy-ubuntu.sh
bash /Users/rohit/attack-box/scripts/test-deploy-ubuntu.sh
```

Receipt-enabled host readers retain stable record IDs across replay. Their aggregate admission statistics participate in I02 reports. They do not use legacy producer-boot sequence accounting; source cursor and receipt evidence are separate. `loss_scope=committed` cannot prove remote acceptance or completeness before source retention.

## Evidence ingestion budget

Use `/Users/rohit/attack-box/docs/log-budget.md` for the audit forwarder and bounded local buffers. Monitoring bootstrap accepts `--log-budget-binaries` with a directory of verified Linux host binaries. The policy preserves attack request and response capture. Validate remote receipt and consumption after application.
