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

# 2. Self-signed TLS certificate (development only)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout secrets/server.key \
  -out secrets/server.crt \
  -subj "/CN=attackbox.local"
```

Then fix ownership and modes (see below):

```bash
sudo chown 65532:65532 secrets/redaction.key secrets/server.key secrets/server.crt
sudo chmod 0400 secrets/redaction.key secrets/server.key secrets/server.crt
```

**Host secret files must be `chown 65532:65532` and `chmod 0400`.** Compose file-based secrets are bind mounts, so the container sees the host file's owner and mode as they are. The `uid`, `gid` and `mode` keys in `compose.yaml` document the intent, but `docker compose` outside Swarm mode ignores them and prints a warning.

- Bait (uid 65532): `readSecret` in `cmd/attackbox/config.go` refuses any file with a group or other mode bit set, and refuses a file it cannot read. A file owned by another user makes bait exit at startup.
- Proxy (uid 65532): nginx must read `server.key`. A key owned by another user with mode 0400 fails with a permission error.

**Production**: Replace self-signed certificate with a proper CA-signed certificate.

## Host Prerequisites

1. **Spool socket**: The host shipper creates `/run/attackbox/spool.sock` at startup. Start it before the containers:
   ```bash
   sudo mkdir -p /run/attackbox
   sudo chown abx-ship:abx-bait /run/attackbox
   sudo chmod 2750 /run/attackbox
   ```

   The shipper sets the ingest socket to mode `0220` (write for owner and group only, `cmd/attackbox-shipper/config.go`). Bait connects as uid 65532, which is neither the owner nor "other", so it needs the socket group to be gid 65532:

   - The socket takes the group of the shipper process, or the group of the directory if the directory is setgid. The `2750` mode above (setgid, group `abx-bait` = gid 65532) gives the socket gid 65532. Alternatively run the shipper with primary group `abx-bait`.
   - The shipper (`listen` in `internal/shipper/ingest.go`) refuses a socket directory that is a symlink, has any group or other write bit (so not `0770`), or is not owned by root or the shipper's own euid. Use `0750` or `2750`, not `0770`.
   - Bait needs execute (search) permission on the directory: group `abx-bait` with `r-x` is enough.

2. **User/Group**: The bait runs as UID/GID 65532. Create matching host group if mounting writable volumes:
   ```bash
   sudo groupadd -g 65532 abx-bait
   ```

3. **gVisor (optional)**: `compose.yaml` uses the default runtime. To run bait under gVisor, install it and layer the override:
   ```bash
   # See https://gvisor.dev/docs/user_guide/install/
   # On Ubuntu/Debian:
   sudo apt-get update && sudo apt-get install -y runsc
   sudo runsc install   # registers the runsc runtime with Docker
   docker compose -f compose.yaml -f compose.gvisor.yaml up -d
   ```
   **Note**: bait reaches the shipper through a unix socket on a host bind mount. gVisor blocks host unix sockets by default, so register runsc with `--host-uds=open` (runtimeArgs in `/etc/docker/daemon.json`). Without it the spool connection fails.

## Build & Deploy

With gVisor, `/Users/rohit/attack-box/compose.gvisor.yaml` fixes bait at `172.30.0.2` and adds the matching `bait` entry to the proxy's `/etc/hosts`. Docker's embedded DNS is not available inside the runsc sandbox. Keep both addresses equal if you change the internal subnet. Do not enable host networking to repair DNS. See the [gVisor DNS guidance](https://gvisor.dev/docs/user_guide/faq/#dns-doesnt-work-on-a-docker-user-defined-bridge-network-including-docker-compose).

After startup, run `curl --noproxy '*' -kfsS --max-time 10 https://127.0.0.1:8443/v1/models` on the VPS. It must return a model list. The `-k` option permits the bootstrap self-signed certificate for this loopback check.

```bash
# Build the bait image
docker compose build bait

# Build the host shipper binary (runs on the host, not in a container)
docker build --target shipper-export --output type=local,dest=./dist .
sudo install -m 0755 dist/attackbox-shipper /usr/local/bin/attackbox-shipper
# `--target shipper` builds an image with the same binary instead

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
│ - No egress                  │
│ - Writes to spool socket     │
└──────────────────────────────┘
   ↓ Unix socket
   ↓
┌──────────────────────────────┐
│ Host Shipper                 │
│ /run/attackbox/spool.sock    │
│ Writes evidence to disk      │
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

**Critical**: Bait must use `ATTACKBOX_SPOOL_SOCKET`.

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

gVisor sandboxing lives in `compose.gvisor.yaml`, a separate override, because `runtime: runsc` makes `docker compose up` fail on hosts without it:
```bash
$ docker info | grep Runtimes
 Runtimes: runc io.containerd.runc.v2
```

**Resolution**: Install gVisor on deployment hosts and run `docker compose -f compose.yaml -f compose.gvisor.yaml up -d`. Runc-only hosts use `compose.yaml` alone.

**Security impact**: Without gVisor, the container relies on standard namespace isolation. All other hardening (read-only rootfs, no capabilities, non-root user, seccomp, AppArmor) remains active.

### Spool Socket
**Status**: Host shipper must create `/run/attackbox/spool.sock`.

The bait expects the socket to exist before container start. If the shipper is not running or the socket is missing, the bait will fail health checks and refuse to start.

**Resolution**: Ensure the host shipper (attackbox-shipper) is running and has created the socket with correct ownership (`abx-ship:abx-bait`, mode `0220`). See Host Prerequisites for the directory mode and group rules.

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
