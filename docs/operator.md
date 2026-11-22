# Attack Box Operator Guide

**Version:** 1.0
**Status:** Deployment design only — not validated on live Ubuntu, New Relic or gVisor

## Purpose

Attack Box is a honeypot that records prompt attacks. It runs on a disposable VPS that you assume is compromised. The design limits what an attacker can steal or reach.

## Safety

**Rule 1:** Captured text is hostile. Do not give logs to an LLM with tools. Do not paste commands or URLs from logs into a terminal or browser.

**Rule 2:** New Relic AI analysis is not enabled. The logs contain attacker payloads. Do not enable NerdGraph, User keys or AI features on the decoy account.

**Rule 3:** A compromised host exposes the ingest key. Revoke the key and power off the VPS through your provider console when you see ingest abuse or anomalous traffic.

## Prerequisites

You must have:
- A cloud provider account with a separate project for the decoy
- A dedicated New Relic account or subaccount
- A domain with private registration (optional, for realistic hostnames)
- No personal keys, dotfiles or project names on the VPS

## New Relic Setup

### Create an Ingest-License Key

1. Log in to your dedicated New Relic account.
2. Go to **API Keys**.
3. Create a new **Ingest - License** key. Name it `attackbox-decoy`.
4. Copy the key. You will use this key once during deployment.
5. Do not use your account's original license key. User-created keys can be deactivated. Original keys cannot.

**What the key permits:**
- Submit logs to `https://log-api.newrelic.com/log/v1`
- Submit metrics to `https://metric-api.newrelic.com/metric/v1`

**What the key does not permit:**
- Query data
- Configure the account
- Access the NerdGraph API

**Stolen-key response:**
1. Deactivate the key in the New Relic console.
2. Power off the VPS through the provider console.
3. Rebuild with a new key.

### Verify Account Isolation

Your decoy account must not hold production data. A stolen ingest key can submit arbitrary telemetry and consume quota. This telemetry can pollute your dashboards or cost money.

If you do not have a separate account, use a free New Relic account for the decoy only.

## Configuration

### Bait Configuration (Container)

The bait runs in a gVisor sandbox with no New Relic key and no internet route. Configure it with environment variables. Set these in your container orchestration or `.env` file (not committed to git).

#### Required

| Variable | Example | Meaning |
|----------|---------|---------|
| `ATTACKBOX_SECRET_FILE` | `/run/secrets/attackbox` | Path to a file with ≥32 random bytes. This derives session, embedding and redaction keys. |
| `ATTACKBOX_SPOOL_SOCKET` | `/run/attackbox/spool.sock` | Unix socket path. The host shipper listens here. |

The bait holds no `ATTACKBOX_NR_LICENSE_KEY` in spool mode. The host shipper holds the key.

#### Listeners

Enable one or more persona listeners. Each persona is one bind address.

| Variable | Example | Meaning |
|----------|---------|---------|
| `ATTACKBOX_OPENAI_ADDR` | `0.0.0.0:8080` | OpenAI-compatible `/v1/chat/completions` and `/v1/embeddings` |
| `ATTACKBOX_VLLM_ADDR` | `0.0.0.0:8000` | vLLM-compatible `/v1/chat/completions` and `/health` |
| `ATTACKBOX_OLLAMA_ADDR` | `0.0.0.0:11434` | Ollama-native `/api/chat` and `/api/embed` |

The bait listens inside the container. A reverse proxy terminates TLS and forwards to these internal addresses. Public port 443 belongs to the proxy, not the bait.

If you do not set any listener, the bait exits with an error.

#### Optional Settings

| Variable | Default | Meaning |
|----------|---------|---------|
| `ATTACKBOX_INSTANCE` | `attackbox` | Instance label for New Relic. Use 1-64 characters from `[A-Za-z0-9._-]`. |
| `ATTACKBOX_MODELS` | `qwen3:8b,gpt-oss:20b,llama3.1:8b` | Comma-separated fake model names. If empty, the bait uses these three defaults. |
| `ATTACKBOX_TRUSTED_PROXIES` | _(empty)_ | Comma-separated CIDRs. The bait trusts `X-Forwarded-For` from these IPs only. |
| `ATTACKBOX_MAX_SESSIONS` | `10000` | Concurrent session limit (1 to 100000). |
| `ATTACKBOX_MAX_BODY_BYTES` | `1048576` | Request body size limit in bytes (1 to 16777216). |
| `ATTACKBOX_MAX_LOG_BODY` | `131072` | Logged body size in bytes (1 to 1048576). Bodies larger than this are truncated in logs but fully processed. |
| `ATTACKBOX_MAX_PER_SOURCE` | `8` | Concurrent requests per source IP (1 to 1000). |
| `ATTACKBOX_MAX_IN_FLIGHT` | `256` | Total concurrent requests (1 to 10000). `MAX_PER_SOURCE` must not exceed this. |
| `ATTACKBOX_HOLD_SILENT` | `150s` | Time the bait holds a suspicious session before responding (0 to 1h). Must not exceed `MAX_STREAM`. |
| `ATTACKBOX_IDLE_INTERVAL` | `45s` | SSE idle message interval (0 to 1h). |
| `ATTACKBOX_MAX_STREAM` | `180s` | Maximum stream duration (0 to 1h). |
| `ATTACKBOX_TIMING` | `true` | Realistic token-by-token pacing. Set `false` to send each frame immediately. |
| `ATTACKBOX_READ_HEADER_TIMEOUT` | `10s` | HTTP header read timeout (0 to 1h). |
| `ATTACKBOX_READ_TIMEOUT` | `30s` | HTTP body read timeout (0 to 1h). |
| `ATTACKBOX_IDLE_TIMEOUT` | `60s` | HTTP idle timeout (0 to 1h). |
| `ATTACKBOX_SHUTDOWN_TIMEOUT` | `15s` | Drain limit on SIGTERM (0 to 1h). |
| `ATTACKBOX_SPOOL_QUEUE` | `10000` | Spool queue size (1 to 100000). |
| `ATTACKBOX_SPOOL_TIMEOUT` | `5s` | Write timeout per spool record (0 to 1h). |

### Shipper Configuration (Host)

The shipper runs on the host as user `abx-ship`. It reads telemetry from the bait's socket and ships it to New Relic. Configure it with environment variables in `/etc/attackbox/shipper.env`.

#### Ownership and Permissions

| Path | Owner:Group | Mode | Meaning |
|------|-------------|------|---------|
| `/etc/attackbox/shipper.env` | `root:root` | `0600` | Shipper configuration file. Only root and systemd can read it. |
| `/run/attackbox/` | `abx-ship:abx-bait` | `0710` | Socket directory. The bait group can traverse but not list. |
| `/run/attackbox/spool.sock` | `abx-ship:abx-bait` | `0220` | Unix socket. Mode `0220` authorizes connection. The shipper application protocol disables writes and sends no responses, making it one-way. |
| `/var/lib/attackbox-shipper/` | `abx-ship:abx-ship` | `0700` | Queue directory. Never mount this into the container. |

Create the host group `abx-bait` with GID `65532`. The container uses UID/GID `65532`. This GID match authorizes the bait to write to the socket.

#### Required Variables

Place these in `/etc/attackbox/shipper.env`:

| Variable | Example | Meaning |
|----------|---------|---------|
| `ATTACKBOX_NR_LICENSE_KEY` | `eu01xxNRAL-...` | Your Ingest-License key from New Relic. |
| `ATTACKBOX_SPOOL_SOCKET` | `/run/attackbox/spool.sock` | Bait ingest socket. Required for six-stream deployment. |
| `ATTACKBOX_RUNTIME_SOCKET` | `/run/attackbox/runtime.sock` | Falco runtime event socket. Required for six-stream deployment. |
| `ATTACKBOX_EGRESS_SOCKET` | `/run/attackbox/egress.sock` | Egress firewall event socket. Required for six-stream deployment. |
#### Optional Variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `ATTACKBOX_NR_LOG_URL` | _(region-specific)_ | New Relic Log API URL. Omit to use the default for your region. |
| `ATTACKBOX_NR_METRIC_URL` | _(region-specific)_ | New Relic Metric API URL. Omit to use the default for your region. |
| `ATTACKBOX_SHIP_QUEUE_DIR` | `/var/lib/attackbox-shipper/queue` | Disk queue directory. |
| `ATTACKBOX_SHIP_QUEUE_BYTES` | `268435456` | Queue size limit in bytes (default 256 MiB, max 8 GiB). |
| `ATTACKBOX_SHIP_SEGMENT_BYTES` | `16777216` | Segment roll size in bytes (default 16 MiB). |
| `ATTACKBOX_SHIP_SHUTDOWN_TIMEOUT` | `15s` | Flush timeout on SIGTERM. |
| `HOSTNAME` | _(host)_ | Instance identifier in telemetry. Set by the host environment; do not override unless testing. |

### Container Mount

Mount the socket directory read-only into the container:

```bash
--mount type=bind,source=/run/attackbox,target=/run/attackbox,readonly
```

A read-only mount still permits `connect()` to a socket inside it.

## Deployment

**Warning:** These steps are not validated on live Ubuntu, New Relic or gVisor. Deployment-only validation is required.

### Automated Deployment

Use the reviewed deployment script:

```bash
# Dry-run (shows changes, makes no modifications)
sudo ./scripts/deploy-ubuntu.sh --dry-run

# Apply (after reviewing dry-run output)
sudo ./scripts/deploy-ubuntu.sh --apply
```

The script installs Docker, gVisor, creates users/groups, configures the firewall, and deploys systemd units from `deploy/` artifacts.

### SSH Disablement (Optional Final Step)

After all deployment checks pass and you verify provider console access, you may optionally disable SSH:

```bash
sudo ./scripts/deploy-ubuntu.sh --apply --disable-ssh --console-confirmed
```

This is a final hardening step. Test provider console recovery first.

### Deployment Verification

The deployment script includes healthcheck helpers for inside-gVisor validation. The Chainguard static bait image has no shell, curl, getent, or test utilities. Use the script's test mode:

```bash
# Verify deployment (runs checks from inside gVisor)
sudo ./scripts/deploy-ubuntu.sh --verify
```

The verification checks:
- Internet access is blocked (connection timeout)
- Cloud metadata `169.254.169.254` is unreachable
- DNS resolution works
- Socket is accessible
- New Relic ingest URLs are reachable from the shipper

**On the host:**

```bash
# Verify shipper is running
systemctl status attackbox-shipper

# Verify socket permissions
ls -l /run/attackbox/spool.sock
# Expected: srw--w---- abx-ship abx-bait

# Check shipper logs
journalctl -u attackbox-shipper -n 50

# Check bait logs
journalctl -u attackbox -n 50
```

**In New Relic:**

1. Wait 2 minutes for the first heartbeat.
2. Go to **Logs** and query:
   ```
   stream='heartbeat' AND instance='attackbox-01'
   ```
3. Verify you see heartbeat events with `source='shipper'` and `bait_connected=true`.

## Operations

### Local-Only Mode (Bait Direct)

To test the bait without a shipper or New Relic, set `ATTACKBOX_NR_DISABLED=true` on the bait. The bait writes logs to stdout only. This is for local development, not deployment preflight.

The shipper does not support a dry-run queue mode. Deployment preflight uses the reviewed script's `--dry-run` flag, which shows changes without applying them.

### Monitor Deployment

Query New Relic every minute for liveness:

```nrql
SELECT latest(bait_connected), latest(last_bait_record_age_ms)
FROM Log
WHERE stream='heartbeat' AND source='shipper'
SINCE 2 minutes ago
```

**Alert conditions:**
- No `source='shipper'` heartbeat for 2 minutes → shipper or egress is down → power off the VPS
- `bait_connected=false` or `last_bait_record_age_ms > 90000` for 2 minutes → bait process is down or hung → rebuild on a fresh instance

A shipper-owned heartbeat with `bait_connected=true` and recent `last_bait_record_age_ms` proves:
- The shipper process is running
- The shipper can reach New Relic
- A verified bait-role socket is connected and recently sent a record

It does not prove the host is uncompromised. Under host-root compromise, telemetry integrity is lost.

### View Logs

Go to **Logs** in New Relic. Use these queries:

**Edge logs (HTTP requests):**
```nrql
FROM Log SELECT * WHERE stream='edge' SINCE 1 hour ago
```

**Transcript logs (chat messages and responses):**
```nrql
FROM Log SELECT * WHERE stream='transcript' SINCE 1 hour ago
```

**Probe logs (counter-probe triggers):**
```nrql
FROM Log SELECT * WHERE stream='probe' SINCE 1 hour ago
```

**Egress logs (blocked connections):**
```nrql
FROM Log SELECT * WHERE stream='egress' SINCE 1 hour ago
```

**Runtime logs (Falco events):**
```nrql
FROM Log SELECT * WHERE stream='runtime' SINCE 1 hour ago
```

### View Metrics

Go to **Metrics & events** in New Relic. Use these queries:

**Request rate:**
```nrql
SELECT rate(sum(attackbox.requests), 1 minute) FROM Metric SINCE 1 hour ago TIMESERIES
```

**Session count:**
```nrql
SELECT sum(attackbox.sessions) FROM Metric SINCE 1 hour ago FACET persona
```

**Probe triggers:**
```nrql
SELECT sum(attackbox.probes) FROM Metric SINCE 1 hour ago FACET probe_id
```

### Rebuild

After compromise or anomalous behavior, rebuild on a fresh provider instance.

**Before rebuild:**
1. Deactivate the ingest key in New Relic.
2. Power off the compromised VPS through the provider console.
3. Snapshot the VPS disk for forensic analysis (optional).
4. Download `/var/lib/attackbox-shipper/queue/` for offline investigation (optional).

**Queue preservation decision:**
- **Preserve:** Keep the queue directory to analyze the attack timeline and unshipped events.
- **Discard:** Delete the queue directory if you verified all events reached New Relic and you do not need forensic replay.

Destroying the queue before investigation loses forensic evidence. Make this an explicit decision.

**Fresh instance:**
1. Create a new VPS with a new Ingest-License key.
2. Deploy with `sudo ./scripts/deploy-ubuntu.sh --apply`.
3. Verify all deployment checks pass.
4. Update DNS if the IP changed.

Do not reuse the compromised instance. Cloud-init rebuilds from scratch ensure no persistent attacker code.

### Power Off

An ingest spike or anomalous traffic means compromise. Power off through the provider console:

1. Deactivate the ingest key in New Relic.
2. Power off the VPS through the provider console (not SSH).
3. Investigate logs offline.
4. Rebuild with a new key if you want to continue.

## Redaction Limits

The bait redacts common secret patterns before it logs. Redaction is not perfect. Supported patterns:

- `Authorization: Bearer <token>`
- `Authorization: Basic <base64>`
- `api_key=<value>` and `access_token=<value>` in URLs and form data
- `password`, `api_key`, `access_token`, `secret` JSON keys
- Private keys (`REDACTED`)

**What is not redacted:**
- Novel encoding schemes
- Secrets in binary data
- Secrets in nested JSON (beyond 10 levels deep)
- Secrets in arrays with >100 elements

Do not rely on redaction for sensitive data. Use a dedicated New Relic account with no production data.

## Fake Model Behavior

The bait returns deterministic fake responses. It does not call a real model by default. Each session follows a probe sequence:

1. **Registration gates:** The bait asks the client to declare metadata (user, model, project).
2. **Counter-probes:** The bait injects probe payloads into tool definitions or assistant messages.
3. **Payout limit:** After 3 normal responses, the bait terminates the session.

**Probes include:**
- Canary tokens in fake file paths and URLs
- Nonce values in tool definitions
- Invisible Unicode characters in messages

The responder is a state machine. It does not use a model. This eliminates model theft risk and inference cost.

## Reverse-Engineering Reality

**You cannot hide that this is a honeypot from a determined reverse engineer.**

An attacker with Go reverse-engineering tools can decompile the bait binary and discover:
- The responder state machine
- Probe templates
- Redaction patterns
- Fake model logic

The design assumes the attacker has the source code. The value is in the **behavioral evidence**, not in deception. You learn:
- What the client tries to do
- What tools the client uses
- What credentials the client tests

Do not add "ignore previous instructions" text to defeat analysis. Use protocol gates (metadata, audit logs, resource limits) instead.

## Host-Root Residual Risk

**If an attacker gets root on the host, the design cannot protect telemetry.**

Host root can:
- Read `/etc/attackbox/shipper.env` and steal the ingest key
- Write to `/var/lib/attackbox-shipper/queue` and corrupt logs
- Send forged telemetry through the shipper socket
- Bypass the host firewall

**Mitigations:**
- Dedicated New Relic account isolates ingest abuse
- Absence alerts detect missing heartbeats
- Provider firewall limits outbound traffic (outside host control)

**Response:**
1. Deactivate the ingest key.
2. Power off through the provider console.
3. Do not use a heartbeat from the compromised host as evidence of safety.

## Shipper-Compromise Residual Risk

**If an attacker gets UID `abx-ship`, they can steal the ingest key and forge telemetry.**

This is a loss of:
- Telemetry confidentiality
- Telemetry integrity
- Telemetry availability
- The ingest key

**Response:**
1. Deactivate the ingest key.
2. Rebuild the VPS.

## No Live Verification

**This documentation describes a deployment design. It is not validated on live systems.**

You must validate:
- Ubuntu firewall rules (nftables) block egress correctly
- gVisor runtime isolation works
- Read-only socket mounts permit `connect()`
- New Relic ingest URLs are reachable from the shipper
- Falco least-privileged mode (Modern eBPF) detects escapes
- Provider console access survives SSH disablement

Test from inside the gVisor container. Host-only checks are not sufficient.
