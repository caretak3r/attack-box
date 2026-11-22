# Ubuntu 24.04 Hardening Research for Disposable Honeypot

Research for a disposable honeypot running Go apps with OpenAI/vLLM/Ollama impersonation and outbound-only New Relic telemetry.

---

## 1. T-Pot Honeypot Platform

**Primary Source:** https://github.com/telekom-security/tpotce

### Key Takeaways
- Production-tested multi-honeypot Docker platform used by Deutsche Telekom Security
- Runs 20+ honeypots simultaneously with Elastic Stack for visualization
- Built for Ubuntu/Debian with systemd, fully Dockerized
- Outbound-only telemetry by default (Sicherheitstacho submission optional)

### Files Worth Borrowing

**Docker Compose Base Pattern**
- `compose/tpot_services.yml` - Docker service definitions with security best practices
  - All containers use `read_only: true` filesystems where possible
  - `tmpfs` mounts for writable areas with explicit uid/gid isolation (2000:2000)
  - Separate network namespaces per honeypot (`adbhoney_local`, `cowrie_local`, etc.)
  - `depends_on: tpotinit` with health check gating
  - Resource limits via `cpu_count`/`cpus` commented for easy enabling

**Environment Configuration**
- `env.example` - Shows clean separation of concerns:
  - User credentials as base64 htpasswd
  - Persistence toggle (`TPOT_PERSISTENCE=on|off` - recommended off for weak CPUs)
  - Log rotation cycles (`TPOT_PERSISTENCE_CYCLES=30`)
  - Hive vs Sensor deployment types
  - LLM configuration for AI-powered honeypots (Beelzebub, Galah)

**Security Patterns Observed**
- No direct Docker socket mounts in honeypot containers
- `tpotinit` container gets host network + NET_ADMIN cap + socket access (privileged init only)
- Honeypots use bridged networks, not host mode
- Pull policy defaults to `always` for security updates

### Pitfalls Identified
- Base config exposes 20+ ports directly on host (acceptable for honeypot, not for attack-box)
- Some honeypots use commented `cpu_count: 1` limits - enable these for resource control
- LLM honeypots (Beelzebub, Galah) require external Ollama - cost risk if using OpenAI API
- Default telemetry submission to Sicherheitstacho - disable via removing `ewsposter` section in compose

---

## 2. Docker gVisor/runsc Runtime Security

**Primary Sources:**
- https://gvisor.dev/docs/user_guide/install
- https://gvisor.dev/docs/user_guide/quick_start/docker
- https://gvisor.dev/docs/architecture_guide/intro

### Key Takeaways
- Application kernel in userspace - intercepts syscalls before reaching Linux kernel
- Reduces kernel attack surface by 80%+ (most syscalls never reach host)
- OCI-compliant runtime drop-in replacement for runc
- Uses Systrap platform (signals + shared memory) on Arm by default

### Installation (Ubuntu 24.04)
```bash
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null
sudo apt-get update
sudo apt-get install -y runsc
```

### Docker Integration
Add to `/etc/docker/daemon.json`:
```json
{
  "runtimes": {
    "runsc": {
      "path": "/usr/bin/runsc",
      "runtimeArgs": [
        "--net-raw"
      ]
    }
  }
}
```
Then restart: `sudo systemctl restart docker`

Run container with gVisor: `docker run --runtime=runsc <image>`

### Security Pitfalls
- **Network raw sockets**: Requires `--net-raw` flag for Docker v27+, plus `--allow-packet-socket-write` for v28+
- **Performance overhead**: 10-50% slowdown depending on syscall intensity
- **Compatibility**: Not all syscalls implemented - test your Go app thoroughly
- **Host filesystem access**: Still inherits host's filesystem permissions if volumes mounted
- **Not a silver bullet**: Protects kernel, not Docker daemon or container escape via misconfig

---

## 3. nftables Egress Filtering (Default-Drop)

**Primary Sources:**
- https://github.com/disco-funk/paranoia-firewall (excellent reference implementation)
- https://dixon.cx/blog/default-deny-firewall-nftables-linux.html
- https://documentation.ubuntu.com/security/security-features/network/firewall/nftables

### Key Takeaways
- Default-drop on INPUT, FORWARD, and OUTPUT chains
- Pin DNS to specific IPs to prevent DHCP hijacking
- Block plain DNS (port 53), force DNS-over-TLS only
- Pin NTP to prevent clock skew attacks on TLS/DNSSEC

### Reference Configuration
From paranoia-firewall `firewall-v2/config/nftables.conf`:

**Core structure for egress control:**
```nftables
table inet filter {
    chain output {
        type filter hook output priority 0; policy drop;
        
        # Loopback always allowed
        oif "lo" accept
        
        # Established/related connections
        ct state established,related accept
        
        # HTTPS/HTTP outbound (any destination)
        tcp dport { 80, 443 } accept
        
        # DNS-over-TLS ONLY to pinned resolvers
        ip daddr { 9.9.9.9, 149.112.112.112 } tcp dport 853 accept
        
        # NTP ONLY to pinned servers
        ip daddr { 162.159.200.123, 162.159.200.1 } udp dport 123 accept
        
        # DHCP client
        udp sport 68 udp dport 67 accept
        
        # ICMPv4 errors (rate-limited)
        ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } limit rate 5/second accept
        
        # IPv6 NDP + errors
        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept
        icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } limit rate 5/second accept
        
        # Everything else DROPPED by policy
    }
}
```

### Adapting for Attack-Box (DNS/NTP/New Relic Only)

**Minimal egress for honeypot:**
```nftables
table inet filter {
    set allowed_ips {
        type ipv4_addr
        elements = {
            # New Relic ingestion endpoints (replace with actual IPs)
            162.247.240.0/22,  # US data center range
            185.221.84.0/22,   # EU data center range
            # DNS resolvers
            1.1.1.1, 1.0.0.1,  # Cloudflare
            # NTP
            162.159.200.123, 162.159.200.1  # Cloudflare
        }
    }
    
    chain output {
        type filter hook output priority 0; policy drop;
        oif "lo" accept
        ct state established,related accept
        
        # New Relic HTTPS only
        ip daddr @allowed_ips tcp dport 443 accept
        
        # DNS to Cloudflare only
        ip daddr { 1.1.1.1, 1.0.0.1 } udp dport 53 accept
        
        # NTP to Cloudflare only
        ip daddr { 162.159.200.123, 162.159.200.1 } udp dport 123 accept
        
        # DHCP client
        udp sport 68 udp dport 67 accept
        
        # Minimal ICMP
        ip protocol icmp icmp type { destination-unreachable, time-exceeded } limit rate 5/second accept
        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, destination-unreachable, packet-too-big } accept
    }
}
```

**Get New Relic IP ranges:**
```bash
dig +short collector.newrelic.com
dig +short insights-collector.newrelic.com
```

### Critical Pitfalls

**Docker networking breaks default-drop egress:**
- Docker inserts its own FORWARD rules that bypass nftables filter table
- Must use `priority -150` or mangle table to intercept before Docker
- Or use `iptables -I DOCKER-USER -j DROP` for Docker-specific chain

**Metadata service access (169.254.169.254):**
- Cloud metadata endpoints accessible by default from containers
- Block at host level BEFORE Docker starts:
```nftables
# In filter output chain, before accept rules
ip daddr 169.254.169.254 drop  # AWS/Azure metadata
ip daddr 100.100.100.200 drop  # Alibaba Cloud
```

**DNS resolution bootstrapping:**
- If blocking port 53 entirely, systemd-resolved needs DoT configured first
- Chicken-egg: Can't install packages without DNS, can't configure DoT without packages
- Solution: Allow port 53 during setup, then lock down and reload rules

---

## 4. auditd - Linux Audit System

**Primary Sources:**
- https://bulwark.nrl.ai/articles/auditd-rules-cheat-sheet
- https://cubepath.com/docs/server-security/auditing-with-auditd-on-linux
- https://www.elastic.co/security-labs/blog/linux-detection-engineering-with-auditd

### Key Takeaways
- Kernel-level syscall monitoring for detection, not prevention
- Rules loaded at boot from `/etc/audit/rules.d/*.rules`
- First-match-win ordering - general rules last
- `-e 2` locks configuration (requires reboot to change)

### Essential Rules for Honeypot

**File to create: `/etc/audit/rules.d/90-honeypot.rules`**
```bash
# Delete all existing rules
-D

# Buffer size (8192 is default, increase if events dropped)
-b 8192

# Failure mode: 1=print, 2=panic (halt system)
-f 1

## Watch critical files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k privilege_escalation
-w /usr/bin/docker -p x -k docker_execution

## Syscalls indicating compromise
# Execve - track all command execution
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec

# Network socket creation (attacker C2)
-a always,exit -F arch=b64 -S socket -S connect -k network_connect

# File deletion (covering tracks)
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete

# Privilege escalation attempts
-a always,exit -F arch=b64 -S setuid -S setgid -F a0!=0 -k privilege_change

# Docker socket access (container escape)
-w /var/run/docker.sock -p rwa -k docker_socket

## Lock configuration (requires reboot to modify)
# -e 2  # Uncomment after testing
```

**Configuration: `/etc/audit/auditd.conf`**
```ini
# Log format: ENRICHED resolves UIDs/GIDs/syscalls to names at write time
log_format = ENRICHED

# Log file management
max_log_file = 100  # MB per file
max_log_file_action = rotate
num_logs = 10  # Keep 10 rotated logs

# Disk space actions
space_left = 500  # MB
space_left_action = SYSLOG
admin_space_left = 100
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND

# Remote logging (optional - for SIEM integration)
# name_format = HOSTNAME
# name = honeypot-01
```

### Critical Pitfalls

**Performance impact:**
- Watching execve on all processes creates significant overhead
- Use `-F key=...` filters to limit scope
- Monitor `auditctl -s` for lost events counter

**Log volume explosion:**
- Execve rules on busy system generate 100K+ events/hour
- Set aggressive log rotation or forward to remote SIEM
- Consider excluding Docker shim processes: `-F exe!=/usr/bin/containerd-shim`

**Silent failure mode:**
- If `-f 2` (panic) is set and audit daemon dies, kernel panics and reboots
- Use `-f 1` (print) for honeypot - detection failure shouldn't kill system

**Race condition on boot:**
- Rules loaded after some processes already started
- Early boot activity not audited
- Mitigation: Use `audit=1` kernel parameter to enable at boot

---

## 5. Falco Runtime Security

**Primary Sources:**
- https://falco.org/docs/
- https://falco.org/docs/setup/container/
- https://github.com/falcosecurity/rules

### Key Takeaways
- Cloud-native runtime security (eBPF or kernel module)
- Pre-built rules for container/K8s threat detection
- Lower overhead than auditd for container-focused monitoring
- Real-time alerting vs. auditd's log-based detection

### Docker Deployment

**Run Falco in privileged container:**
```bash
docker run --rm -i -t \
  --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /dev:/host/dev \
  -v /proc:/host/proc:ro \
  -v /boot:/host/boot:ro \
  -v /lib/modules:/host/lib/modules:ro \
  -v /usr:/host/usr:ro \
  -v /etc:/host/etc:ro \
  falcosecurity/falco:latest
```

### Key Rules for Honeypot Detection

**Default rules cover:**
- Shell spawned in container (`Terminal shell in container`)
- Sensitive file access (`Read sensitive file untrusted`)
- Privileged container launched (`Launch Privileged Container`)
- Docker socket accessed from container (`Container Run as Root User`)
- Network tool execution in container (`Netcat Remote Code Execution in Container`)

**Custom rule for attack-box (`/etc/falco/rules.d/custom.yaml`):**
```yaml
- rule: Unexpected outbound connection from honeypot
  desc: Detect outbound connections to non-allowlisted destinations
  condition: >
    evt.type=connect and 
    container and 
    fd.sip not in (new_relic_ips, dns_ips, ntp_ips) and
    not proc.name in (curl, wget, go)
  output: >
    Suspicious outbound connection from honeypot
    (container=%container.name pid=%proc.pid command=%proc.cmdline 
    connection=%fd.name user=%user.name)
  priority: WARNING

- list: new_relic_ips
  items: ["162.247.240.0/22", "185.221.84.0/22"]

- list: dns_ips
  items: ["1.1.1.1", "1.0.0.1"]

- list: ntp_ips
  items: ["162.159.200.123", "162.159.200.1"]
```

### Critical Pitfalls

**Performance overhead:**
- eBPF mode: 1-5% CPU overhead (preferred)
- Kernel module: Requires kernel headers, breaks on kernel update
- Use eBPF unless on old kernel (<4.14)

**Alert fatigue:**
- Default rules very noisy for legitimate admin activity
- Tag containers with `falco.ignore=true` label for known-good
- Tune rule priorities and use tags to filter: `--tags container,network`

**Privileged requirement:**
- Needs access to /var/run/docker.sock and host /proc
- Same risk as Docker socket exposure (see section 7)
- Run Falco in separate namespace/cgroup to limit blast radius

**Version compatibility:**
- Rules format changes between major versions
- Pin Falco version in production: `falcosecurity/falco:0.37.0`
- Test rule updates in staging before production deploy

---

## 6. Unattended Upgrades

**Primary Sources:**
- https://documentation.ubuntu.com/security/security-updates
- https://milanjovanovic.tech/blog/unattended-upgrades-ubuntu
- https://rdp.sh/blog/automatic-security-updates-on-ubuntu-with-unattended-upgrades

### Key Takeaways
- Installed by default on Ubuntu 24.04
- Applies security updates only by default (not all updates)
- Does NOT auto-reboot by default (kernel patches require reboot)
- needrestart integration prompts interactively (breaks automation)

### Configuration Files

**Enable automatic updates: `/etc/apt/apt.conf.d/20auto-upgrades`**
```
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
```

**Configure upgrade behavior: `/etc/apt/apt.conf.d/50unattended-upgrades`**
```
// Security updates only (default)
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    // Uncomment for all updates (not recommended for production)
    // "${distro_id}:${distro_codename}-updates";
};

// Auto-reboot configuration
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";  // 3 AM local time

// Auto-reboot even if users logged in (honeypot acceptable)
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";

// Email notifications (requires postfix/sendmail configured)
// Unattended-Upgrade::Mail "admin@example.com";
// Unattended-Upgrade::MailReport "on-change";

// Remove unused dependencies
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";

// Block on package install (honeypot: false for async)
Unattended-Upgrade::InstallOnShutdown "false";
```

**Disable needrestart interactive prompts: `/etc/needrestart/needrestart.conf`**
```perl
# Restart services automatically without prompting
$nrconf{restart} = 'a';  # 'a' = automatic, 'l' = list only
```

**Or systemd override:**
```bash
# Disable needrestart entirely for unattended-upgrades
mkdir -p /etc/systemd/system/apt-daily-upgrade.service.d
cat > /etc/systemd/system/apt-daily-upgrade.service.d/override.conf << 'EOF'
[Service]
Environment="NEEDRESTART_MODE=a"
Environment="DEBIAN_FRONTEND=noninteractive"
EOF
systemctl daemon-reload
```

### Critical Pitfalls

**Reboot timing on honeypot:**
- Default NO auto-reboot leaves kernel/systemd vulnerabilities unpatched
- Setting auto-reboot disrupts honeypot availability
- Mitigation: Schedule reboot window during low-attack hours (3-5 AM UTC typically quietest)

**Docker containers not restarted:**
- Unattended-upgrades updates host Docker package
- Does NOT restart containers - old container images keep running
- Mitigation: Separate `watchtower` container for image updates, or cron job:
```bash
# /etc/cron.daily/docker-update
#!/bin/bash
docker compose -f /opt/attackbox/docker-compose.yml pull
docker compose -f /opt/attackbox/docker-compose.yml up -d --remove-orphans
```

**Package pinning broken by security updates:**
- If you pin specific package versions, security updates still override
- Check `/var/log/unattended-upgrades/` for surprises

**Upgrade failures not obvious:**
- Failed upgrades logged to `/var/log/unattended-upgrades/unattended-upgrades.log`
- No default alerting - set up log monitoring or email

**Cloud-init conflict:**
- cloud-init may re-enable password SSH auth after unattended-upgrade
- See SSH disablement section for mitigation

---

## 7. Chainguard Runtime Images

**Primary Sources:**
- https://www.chainguard.dev/docs/chainguard/containers/overview
- https://edu.chainguard.dev/chainguard/chainguard-images/getting-started-distroless

### Key Takeaways
- Distroless: No shell, no package manager, no unnecessary binaries
- Based on Wolfi (Chainguard's own "undistro" for supply chain security)
- Two variants: Standard (distroless) and Dev (includes shell for debugging)
- Zero to near-zero CVEs (aggressive patching cadence)

### Using Chainguard Images

**Go application example:**
```dockerfile
# Multi-stage build
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app/attackbox

# Runtime with Chainguard distroless
FROM cgr.dev/chainguard/static:latest
COPY --from=builder /app/attackbox /attackbox
ENTRYPOINT ["/attackbox"]
```

**Available base images:**
- `cgr.dev/chainguard/static:latest` - Static binaries only (Go, Rust)
- `cgr.dev/chainguard/glibc-dynamic:latest` - Dynamic linking support
- `cgr.dev/chainguard/go:latest` - Go runtime included
- `cgr.dev/chainguard/python:latest` - Python runtime
- `cgr.dev/chainguard/node:latest` - Node.js runtime

**Add -dev suffix for shell access during development:**
- `cgr.dev/chainguard/static:latest-dev` includes `/bin/sh`

### Critical Pitfalls

**No shell = debugging hell:**
- Cannot `docker exec -it <container> sh` into production containers
- Mitigation: Use -dev variant in staging, ship with standard (no shell) to prod
- Or use `kubectl debug` / `docker debug` (requires Docker 23.0+)

**Missing system utilities:**
- No `curl`, `wget`, `netstat`, `ps` - nothing beyond your app binary
- Health checks must use app-native methods (HTTP endpoint, not shell script)
- Example Docker healthcheck:
```dockerfile
# This FAILS in distroless (no /bin/sh):
HEALTHCHECK CMD curl -f http://localhost:8080/health || exit 1

# This WORKS (native HTTP):
HEALTHCHECK CMD ["/attackbox", "--health-check"]
```

**User ID required:**
- Chainguard images run as non-root by default (UID 65532)
- Volume mounts must have correct ownership on host: `chown 65532:65532 /data`
- Or override in compose:
```yaml
services:
  app:
    image: cgr.dev/chainguard/static:latest
    user: "1000:1000"  # Match host user
```

**CA certificates bundled but not updateable:**
- Chainguard includes CA certs, but no `update-ca-certificates` command
- For custom internal CAs, must rebuild image with certs baked in

**Image pull auth:**
- Free tier has rate limits (500 pulls/day per IP)
- Paid tier required for production at scale
- Alternative: Use official `distroless` images from Google (gcr.io/distroless/static-debian12)

---

## 8. Cloud Metadata Service Access (Critical Pitfall)

**Primary Sources:**
- https://ops.tips/blog/blocking-docker-containers-from-ec2-metadata
- https://docs.aws.eu/AWSEC2/latest/UserGuide/instance-metadata-limiting-access.html
- https://docs.emqx.com/en/enterprise/latest/deploy/cluster/security.html

### The Threat
- Cloud metadata endpoints expose instance credentials, user-data, and secrets
- Accessible from containers by default (169.254.169.254, etc.)
- Attacker gaining RCE in container can steal cloud IAM credentials

### Metadata Endpoints by Provider
- **AWS**: 169.254.169.254, fd00:ec2::254 (IPv6)
- **Azure**: 169.254.169.254
- **GCP**: metadata.google.internal (169.254.169.254)
- **Alibaba Cloud**: 100.100.100.200
- **Oracle Cloud**: 169.254.169.254
- **DigitalOcean**: 169.254.169.254

### Blocking Methods

**Method 1: iptables (before Docker starts)**
```bash
# Add to /etc/rc.local or systemd service that runs before Docker
iptables -I OUTPUT -d 169.254.169.254 -j DROP
iptables -I OUTPUT -d 100.100.100.200 -j DROP  # Alibaba
ip6tables -I OUTPUT -d fd00:ec2::254 -j DROP   # AWS IPv6
```

**Method 2: nftables (integrated with firewall)**
```nftables
table inet filter {
    chain output {
        type filter hook output priority 0; policy drop;
        
        # Block metadata BEFORE any accept rules
        ip daddr { 169.254.169.254, 100.100.100.200 } drop
        ip6 daddr fd00:ec2::254 drop
        
        # ... rest of output rules
    }
}
```

**Method 3: Docker network isolation (defense in depth)**
```bash
# Create Docker network with no default gateway
docker network create --internal honeypot-net

# Containers on this network cannot reach external IPs (including metadata)
docker run --network=honeypot-net <image>
```

**Method 4: IMDSv2 (AWS-specific, defense in depth)**
- Instance Metadata Service Version 2 requires token-based authentication
- Blocks SSRF-based metadata access from containers
- Configure at instance launch:
```bash
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-tokens required \
  --http-endpoint enabled
```

### Critical Pitfalls

**Docker bridge bypasses host iptables:**
- Docker inserts FORWARD rules that can bypass OUTPUT chain
- Metadata blocking must be in OUTPUT or use `iptables -I DOCKER-USER`
- With nftables, use `priority -150` to intercept before Docker

**169.254.0.0/16 is link-local:**
- Blocking entire 169.254.0.0/16 breaks IPv4 link-local (APIPA)
- Only block specific /32 addresses (169.254.169.254, 100.100.100.200)

**DNS-based metadata access:**
- GCP uses `metadata.google.internal` hostname
- Attacker can resolve before connection (cached IP bypass)
- Block both hostname resolution AND IP in firewall

**Container escape still wins:**
- If attacker escapes container to host, host credentials may be accessible
- This is defense-in-depth, not silver bullet

---

## 9. Docker Socket Exposure (Critical Pitfall)

**Primary Sources:**
- https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet
- https://www.netdata.cloud/guides/docker/docker-socket-security
- https://blog.quarkslab.com/why-is-exposing-the-docker-socket-a-really-bad-idea.html

### The Threat
- Mounting `/var/run/docker.sock` into container = root on host
- Attacker can spawn privileged container with host filesystem mounted
- Read-only socket mount does NOT mitigate (can still create containers)

### Why It's Root Access
```bash
# From inside container with socket access:
docker run -v /:/hostfs --privileged alpine chroot /hostfs /bin/bash
# Now have unrestricted root shell on host
```

### Safe Alternatives

**Option 1: Don't mount the socket (preferred)**
- For monitoring: Use Docker stats API via TCP with TLS auth
- For builds: Use BuildKit with rootless Docker or Kaniko
- For orchestration: Use Kubernetes API instead of raw Docker

**Option 2: Docker socket proxy (defense in depth)**
```yaml
# tecnativa/docker-socket-proxy - filters allowed API endpoints
services:
  docker-proxy:
    image: tecnativa/docker-socket-proxy:latest
    environment:
      CONTAINERS: 1  # Allow listing containers
      SERVICES: 0    # Block service creation
      VOLUMES: 0     # Block volume mounts
      IMAGES: 0      # Block image operations
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - proxy-net
  
  app:
    image: myapp
    environment:
      DOCKER_HOST: tcp://docker-proxy:2375
    networks:
      - proxy-net

networks:
  proxy-net:
    internal: true  # No external access
```

**Option 3: Separate orchestration node**
- Run Docker daemon on separate host
- Honeypot containers connect via TCP with mTLS
- Blast radius limited to orchestration host, not honeypot data

### Critical Pitfalls

**Watchtower/auto-updaters need socket:**
- Many auto-update tools require socket access to restart containers
- Risk: One compromised container pwns entire host
- Mitigation: Run Watchtower on separate host, only manage specific containers

**Monitoring tools (Prometheus exporters, etc.):**
- Many exporters want socket to scrape container metrics
- Use cAdvisor (runs privileged but isolated) or Docker TCP API with auth

**Docker-in-Docker (DinD):**
- Using `docker:dind` as build environment seems safer
- Actually shares kernel with host (not isolated VM)
- Still vulnerable to kernel exploits

**Read-only mount does NOT help:**
- `docker.sock:ro` can still create containers, just can't delete socket file itself
- Read-only is false sense of security

---

## 10. Safe SSH Disablement

**Primary Sources:**
- https://www.nerdstuckathome.com/posts/cloud-init-ssh-passwords/
- https://bugs.launchpad.net/ubuntu/+source/cloud-init/+bug/2088207
- https://docs.cloud-init.io/en/latest/explanation/hardening.html

### Key Takeaways
- Disabling SSH on honeypot removes management channel (acceptable for disposable)
- Cloud-init can re-enable SSH unexpectedly on reboot
- Need alternative access method (console, cloud provider serial console)

### Approaches

**Option 1: Disable sshd service**
```bash
sudo systemctl stop ssh
sudo systemctl disable ssh
sudo systemctl mask ssh  # Prevents any restart
```

**Option 2: Firewall block (keep service running for emergency)**
```nftables
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Allow localhost
        iif "lo" accept
        
        # Allow established connections
        ct state established,related accept
        
        # SSH blocked (no rule = dropped by policy)
        # tcp dport 22 accept  # Commented out
        
        # Only allow from specific cloud console IP if needed
        # ip saddr <cloud-console-ip> tcp dport 22 accept
    }
}
```

**Option 3: Null route sshd port (kernel-level)**
```bash
# Add to /etc/rc.local
iptables -A INPUT -p tcp --dport 22 -j REJECT --reject-with tcp-reset
```

### Cloud-init Conflicts

**Problem: cloud-init overwrites /etc/ssh/sshd_config**
- On some clouds, cloud-init runs on every boot
- May re-enable password authentication even if you disabled it
- Config in `/etc/cloud/cloud.cfg.d/` overrides sshd_config

**Solution: Disable cloud-init SSH module**
Create `/etc/cloud/cloud.cfg.d/99-disable-ssh.cfg`:
```yaml
# Disable cloud-init SSH management
ssh_pwauth: false
no_ssh_fingerprints: true
ssh:
  emit_keys_to_console: false

# Prevent cloud-init from modifying sshd_config
disable_root: true
ssh_deletekeys: false
ssh_genkeytypes: []

# Lock down SSH if it must run
ssh_authorized_keys: []
password: RANDOM
chpasswd: { expire: false }
```

Then disable cloud-init entirely after first boot:
```bash
sudo touch /etc/cloud/cloud-init.disabled
```

### Alternative Access Methods

**Cloud serial console:**
- AWS: EC2 Serial Console (requires IMDSv2 and explicit enable)
- GCP: Serial console access via gcloud CLI
- Azure: Boot diagnostics serial console
- DigitalOcean: Droplet console in web UI

**Emergency access account:**
```bash
# Create console-only user (no SSH)
sudo useradd -m -s /bin/bash rescue
sudo passwd rescue
echo "rescue ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/rescue

# Disable SSH for this user specifically
echo "DenyUsers rescue" | sudo tee -a /etc/ssh/sshd_config
```

### Critical Pitfalls

**Locking yourself out:**
- Always test console access BEFORE disabling SSH
- Keep SSH enabled on first boot, test alternatives, then disable

**Cloud-init revert on upgrade:**
- Ubuntu package upgrades may reset cloud-init config
- Pin cloud-init version or recheck config after upgrades

**Firewall rules cleared on reboot:**
- nftables rules require `nftables.service` enabled
- Verify rules persist: `sudo systemctl enable nftables`

**systemd-networkd DHCP hook:**
- Some clouds use DHCP hooks that modify /etc/ssh/sshd_config
- Check `/etc/dhcp/dhclient-enter-hooks.d/` and `/etc/networkd-dispatcher/`

---

## Summary Recommendations

### Minimal Secure Base (Disposable Honeypot)

1. **Host OS**: Ubuntu 24.04 LTS, minimal install
2. **Firewall**: nftables default-drop egress, allow only:
   - DNS to Cloudflare (1.1.1.1, 1.0.0.1)
   - NTP to Cloudflare (162.159.200.123, 162.159.200.1)
   - HTTPS to New Relic IP ranges
   - Block 169.254.169.254 (metadata)
3. **Container Runtime**: Docker with gVisor (runsc) for all honeypot containers
4. **Images**: Chainguard distroless for Go apps
5. **Monitoring**: 
   - Falco for real-time container threats
   - auditd for host-level syscall audit
   - Logs shipped to New Relic only
6. **Updates**: Unattended-upgrades with auto-reboot at 3 AM UTC
7. **Access**: SSH disabled, cloud serial console only
8. **Docker Security**:
   - Never mount /var/run/docker.sock into containers
   - Use `--read-only` and `tmpfs` for all containers
   - Bridge networks, never host mode except init container
   - Pin image versions, enable pull policy "always" for security updates

### Files to Create

1. `/etc/nftables.conf` - Based on paranoia-firewall with New Relic IPs
2. `/etc/audit/rules.d/90-honeypot.rules` - From auditd section above
3. `/etc/apt/apt.conf.d/50unattended-upgrades` - Auto-reboot enabled
4. `/etc/cloud/cloud.cfg.d/99-disable-ssh.cfg` - Prevent cloud-init SSH reconfig
5. `/etc/docker/daemon.json` - Enable runsc runtime
6. `docker-compose.yml` - Based on T-Pot patterns (read_only, tmpfs, isolated networks)
7. `/etc/falco/rules.d/custom.yaml` - Unexpected outbound connection detection

### Order of Operations

1. Install Ubuntu 24.04 minimal
2. Configure nftables BEFORE connecting to internet (block metadata)
3. Connect to internet (only DNS/NTP/HTTPS allowed)
4. Install Docker, gVisor, Falco, auditd
5. Configure unattended-upgrades
6. Deploy containers with gVisor runtime
7. Test all egress rules (DNS works, metadata blocked, New Relic reachable)
8. Disable cloud-init SSH module
9. Disable/firewall SSH
10. Test serial console access
11. Enable auditd -e 2 lock (last step, requires reboot to change)

---

**Research completed**: 2026-11-21
**Primary focus**: Outbound-only security for disposable honeypot infrastructure
**Next steps**: Implement configs in attack-box repository, test egress rules, validate New Relic connectivity
