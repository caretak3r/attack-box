# AttackBox Docker Deployment

Hardened container deployment for the AttackBox bait inference API with Chainguard images and comprehensive security controls.

## Image Verification

### Chainguard Go Builder
```bash
docker pull cgr.dev/chainguard/go:latest-dev
docker inspect cgr.dev/chainguard/go:latest-dev | jq -r '.[0].RepoDigests[0]'
```
**Expected**: `cgr.dev/chainguard/go@sha256:f90bc942e1f05e2d6b3b37af550fe50bbac9134a267b529573eddb50996656ab`

### Chainguard Static Runtime
```bash
docker pull cgr.dev/chainguard/static:latest
docker inspect cgr.dev/chainguard/static:latest | jq -r '.[0].RepoDigests[0]'
```
**Expected**: `cgr.dev/chainguard/static@sha256:8658e9eaeb2294fa0e49b0667f7d66b4e21fa7690b8d2a4c30cd1d013ceb9eb7`

Both digests are pinned in `Dockerfile` and verified on 2026-11-22.

## Secrets Setup

Before deployment, generate required secrets:

```bash
# 1. Redaction secret (32+ bytes of randomness)
head -c 64 /dev/urandom | base64 -w 0 > secrets/redaction.key
chmod 600 secrets/redaction.key

# 2. Self-signed TLS certificate (development only)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout secrets/server.key \
  -out secrets/server.crt \
  -subj "/CN=attackbox.local"
chmod 600 secrets/server.key
chmod 644 secrets/server.crt
```

**Production**: Replace self-signed certificate with a proper CA-signed certificate.

## Host Prerequisites

1. **Spool socket**: The host shipper must create `/run/attackbox/spool.sock` before container startup:
   ```bash
   sudo mkdir -p /run/attackbox
   sudo chown abx-ship:abx-bait /run/attackbox
   sudo chmod 0770 /run/attackbox
   # Host shipper creates the socket at startup
   ```

2. **User/Group**: The bait runs as UID/GID 65532. Create matching host group if mounting writable volumes:
   ```bash
   sudo groupadd -g 65532 abx-bait
   ```

3. **gVisor (optional)**: For `runtime: runsc` to work, install gVisor:
   ```bash
   # See https://gvisor.dev/docs/user_guide/install/
   # On Ubuntu/Debian:
   sudo apt-get update && sudo apt-get install -y runsc
   ```
   **Note**: The current host only has `runc`, so the runsc directive is ignored.

## Build & Deploy

```bash
# Build the bait image
docker compose build bait

# Start services (bait + proxy)
docker compose up -d

# Check health
docker compose ps
docker compose logs -f bait
docker compose logs -f proxy

# View bait healthcheck
docker inspect attackbox-bait | jq '.[0].State.Health'
```

## Service Architecture

```
Internet
   ↓
   ↓ HTTPS (443)
   ↓
┌──────────────────────────────┐
│ Proxy (nginx:1.27-alpine)    │
│ - TLS termination            │
│ - Loopback: 127.0.0.1:8443   │
│ - Internal + External nets   │
└──────────────────────────────┘
   ↓ HTTP (internal)
   ↓
┌──────────────────────────────┐
│ Bait (attackbox)             │
│ - OpenAI API on :8080        │
│ - Internal network only      │
│ - No egress, no New Relic key│
│ - Writes to spool socket     │
└──────────────────────────────┘
   ↓ Unix socket
   ↓
┌──────────────────────────────┐
│ Host Shipper                 │
│ /run/attackbox/spool.sock    │
│ Owns New Relic key           │
└──────────────────────────────┘
```

## Security Hardening

### Container Hardening
- **Non-root**: UID/GID 65532 (Chainguard nonroot)
- **Read-only rootfs**: Only `/tmp` and `/run/attackbox` writable (bounded tmpfs)
- **No capabilities**: `cap_drop: ALL`
- **No new privileges**: `security_opt: no-new-privileges:true`
- **No shell**: Chainguard static base has no shell, package manager, or userland
- **Static binary**: `CGO_ENABLED=0`, fully static, no C dependencies
- **Stripped**: `-ldflags='-s -w'` removes debug info and symbol table

### Resource Limits
- **CPU**: 2.0 cores limit, 0.5 cores reservation
- **Memory**: 512M limit, 128M reservation
- **PIDs**: 100 process limit
- **Disk**: Bounded tmpfs (16M `/tmp`, 4M `/run/attackbox`)

### Network Isolation
- **Bait**: Internal network only, no external egress
- **Proxy**: Both internal and external networks
- **Published ports**: Default to loopback only (`127.0.0.1`)

### Deployment Controls
- **No Watchtower**: No automatic image updates
- **Verified digests**: All base images pinned by SHA256
- **No Docker socket**: No container access to Docker API
- **No privileged**: No privileged containers or host namespaces
- **Bounded logging**: 10M × 3 files per service

## Configuration

### Bait Environment Variables

Configured via `compose.yaml` environment section or `.env` file:

- `ATTACKBOX_OPENAI_ADDR`: OpenAI-compatible API listener (default: `0.0.0.0:8080`)
- `ATTACKBOX_VLLM_ADDR`: vLLM API listener (default: `off`)
- `ATTACKBOX_OLLAMA_ADDR`: Ollama API listener (default: `off`)
- `ATTACKBOX_MODELS`: Comma-separated model names
- `ATTACKBOX_INSTANCE`: Instance identifier
- `ATTACKBOX_SECRET_FILE`: Path to redaction secret
- `ATTACKBOX_SPOOL_SOCKET`: Path to host shipper socket (required)
- `ATTACKBOX_SPOOL_QUEUE`: Spool queue depth (default: 10000)
- `ATTACKBOX_SPOOL_TIMEOUT`: Spool write timeout (default: 5s)

**Critical**: Bait must use `ATTACKBOX_SPOOL_SOCKET` and must NOT have `ATTACKBOX_NR_LICENSE_KEY`.

### Proxy Configuration

TLS and reverse proxy settings in `docker/nginx/nginx.conf`:
- TLS 1.2 and 1.3 only
- Modern cipher suites
- Proxy buffering disabled for SSE/NDJSON streaming
- 300s read/send timeouts for long responses
- 1MB request body limit
- Security headers (HSTS, X-Content-Type-Options, X-Frame-Options)

## Validation

```bash
# 1. Validate compose configuration
docker compose config

# 2. Build validation
docker compose build --no-cache

# 3. Healthcheck validation
docker compose up -d bait
sleep 15
docker compose exec bait /attackbox -version
docker compose exec bait /attackbox -check-config

# 4. API validation (through proxy)
curl -k https://127.0.0.1:8443/v1/models

# 5. Security validation
docker compose exec bait sh  # Should fail (no shell)
docker compose exec bait cat /etc/passwd  # Should fail (no cat)
docker inspect attackbox-bait | jq '.[0].HostConfig.CapDrop'  # Should show ["ALL"]
docker inspect attackbox-bait | jq '.[0].HostConfig.ReadonlyRootfs'  # Should be true
```

## Blockers

### Runtime: runsc
**Status**: Configured but non-functional on this host.

The `compose.yaml` includes `runtime: runsc` for gVisor sandboxing, but only `runc` is available:
```bash
$ docker info | grep Runtimes
 Runtimes: runc io.containerd.runc.v2
```

**Resolution**: Install gVisor on deployment hosts, or remove the `runtime: runsc` line for runc-only environments.

**Security impact**: Without gVisor, the container relies on standard namespace isolation. All other hardening (read-only rootfs, no capabilities, non-root user, seccomp, AppArmor) remains active.

### Spool Socket
**Status**: Host shipper must create `/run/attackbox/spool.sock`.

The bait expects the socket to exist before container start. If the shipper is not running or the socket is missing, the bait will fail health checks and refuse to start.

**Resolution**: Ensure the host shipper (attackbox-shipper) is running and has created the socket with correct ownership (`abx-ship:abx-bait`, mode `0220`).

## Production Checklist

- [ ] Replace self-signed TLS certificate with CA-signed certificate
- [ ] Update `compose.yaml` published ports for internet-facing deployment
- [ ] Configure trusted proxies: `ATTACKBOX_TRUSTED_PROXIES`
- [ ] Install and configure gVisor (`runsc`) runtime
- [ ] Set up host firewall rules (nftables) to block container egress
- [ ] Configure external logging (ELK, Splunk, etc.) for forensic retention
- [ ] Set up monitoring/alerting for host shipper and bait health
- [ ] Rotate redaction secret and TLS certificates before production
- [ ] Review and tune resource limits for production load
- [ ] Harden host OS per `research/ubuntu-hardening.md`

## References

- Main design: `research/host-shipper-design.md`
- Threat model corrections: `research/host-shipper-threat-review.md`
- Implementation plan: `implementation_plan.md`
- Chainguard Images: https://github.com/chainguard-images/images
