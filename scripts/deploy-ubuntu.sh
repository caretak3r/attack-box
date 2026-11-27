#!/usr/bin/env bash
# Ubuntu 24.04 idempotent deployment for attack-box
# Non-destructive preflight by default; --apply for mutations; --verify for real validation
# Both --disable-ssh --console-confirmed required for SSH/cloud-init changes

set -euo pipefail

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly DEPLOY_DIR="${SCRIPT_DIR}/../deploy"
readonly BAIT_UID=65532
readonly BAIT_GID=65532
readonly BAIT_USER="abx-bait"
readonly SHIP_USER="abx-ship"
readonly SHIP_GROUP="abx-ship"
readonly SPOOL_SOCKET="/run/attackbox/spool.sock"
readonly SECRETS_DIR="/opt/attackbox/secrets"
readonly REFRESH_BIN="/usr/local/sbin/attackbox-deploy"
readonly QUEUE_DIR="/var/lib/attackbox-shipper/queue"
readonly NR_LOG_HOST="log-api.newrelic.com"
readonly NR_METRIC_HOST="metric-api.newrelic.com"

# Flags
MODE="preflight"
DISABLE_SSH=false
CONSOLE_CONFIRMED=false
NATIVE_KEY_STDIN=false

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Ubuntu 24.04 deployment for attack-box honeypot.
Default: non-destructive preflight (no mutations).

Options:
    --apply                  Apply changes (mutations)
    --dry-run                Explicit preflight (same as default, no mutations)
    --verify                 Real validation: proxy/bait metadata, DNS/NTP, NR endpoints
                             (requires Linux with Docker + gVisor; reports prerequisites)
    --refresh-install-sets   Populate expiring official New Relic installation destinations
    --native-key-stdin       Read the provisioning User API key from stdin (apply only)
    --refresh-sets           Re-resolve NR/Ubuntu endpoints into the nftables sets
                             (run by attackbox-nft-refresh.timer; needs the table loaded)
    --disable-ssh            Mark SSH for disablement (needs --console-confirmed)
    --console-confirmed      Confirm console access verified (needs --disable-ssh)
    -h, --help               Show this help

SSH disablement requires BOTH --disable-ssh AND --console-confirmed.
Verification mode requires Linux, Docker, and gVisor runtime.
For a manual source transfer, run go mod vendor before you upload the source.
EOF
    exit "${1:-0}"
}

log() {
    echo -e "${BLUE}●${NC} $*"
}

warn() {
    echo -e "${YELLOW}○${NC} $*"
}

err() {
    echo -e "${RED}✗${NC} $*" >&2
}

ok() {
    echo -e "${GREEN}✓${NC} $*"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --apply) MODE="apply"; shift ;;
        --dry-run) MODE="preflight"; shift ;;
        --verify) MODE="verify"; shift ;;
        --native-key-stdin) NATIVE_KEY_STDIN=true; shift ;;
        --refresh-install-sets) MODE="refresh-install"; shift ;;
        --refresh-sets) MODE="refresh"; shift ;;
        --disable-ssh) DISABLE_SSH=true; shift ;;
        --console-confirmed) CONSOLE_CONFIRMED=true; shift ;;
        -h|--help) usage 0 ;;
        *) err "Unknown option: $1"; usage 1 ;;
    esac
done

# Validation
if [[ "$DISABLE_SSH" == true && "$CONSOLE_CONFIRMED" != true ]]; then
    err "SSH disablement requires BOTH --disable-ssh AND --console-confirmed"
    exit 1
fi
if [[ "$DISABLE_SSH" != true && "$CONSOLE_CONFIRMED" == true ]]; then
    err "--console-confirmed requires --disable-ssh"
    exit 1
fi

# Check OS
check_os() {
    log "Checking OS version..."
    if [[ ! -f /etc/os-release ]]; then
        err "/etc/os-release not found"
        return 1
    fi

    source /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
        err "Not Ubuntu (found: $ID)"
        return 1
    fi

    if [[ "$VERSION_ID" != "24.04" ]]; then
        warn "Expected Ubuntu 24.04, found $VERSION_ID"
    fi

    ok "Ubuntu $VERSION_ID detected"
}

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "Must run as root"
        exit 1
    fi
}

# Check Linux for verify mode
check_linux() {
    if [[ "$MODE" == "verify" ]]; then
        if [[ "$(uname -s)" != "Linux" ]]; then
            err "Verification mode requires Linux"
            err "Prerequisites: Ubuntu 24.04, Docker, gVisor runtime"
            exit 1
        fi
    fi
}

# Safety check directory
check_directory_safety() {
    local dir="$1"
    local expected_owner="$2"
    local expected_group="$3"
    local expected_mode="$4"

    if [[ ! -d "$dir" ]]; then
        return 1
    fi

    # Check not a symlink
    if [[ -L "$dir" ]]; then
        err "$dir is a symlink (security risk)"
        return 1
    fi

    # Check owner/group
    local actual_owner
    local actual_group
    actual_owner=$(stat -c '%U' "$dir" 2>/dev/null || stat -f '%Su' "$dir" 2>/dev/null)
    actual_group=$(stat -c '%G' "$dir" 2>/dev/null || stat -f '%Sg' "$dir" 2>/dev/null)

    if [[ "$actual_owner" != "$expected_owner" ]] || [[ "$actual_group" != "$expected_group" ]]; then
        warn "$dir has wrong ownership: $actual_owner:$actual_group (expected $expected_owner:$expected_group)"
        if [[ "$MODE" == "apply" ]]; then
            chown "$expected_owner:$expected_group" "$dir"
            ok "Corrected $dir ownership"
        fi
    fi

    # Check mode
    local actual_mode
    actual_mode=$(stat -c '%a' "$dir" 2>/dev/null || stat -f '%A' "$dir" 2>/dev/null | tail -c 4)

    if [[ "$actual_mode" != "$expected_mode" ]]; then
        warn "$dir has wrong mode: $actual_mode (expected $expected_mode)"
        if [[ "$MODE" == "apply" ]]; then
            chmod "$expected_mode" "$dir"
            ok "Corrected $dir mode"
        fi
    fi

    return 0
}

# User/group setup
setup_users() {
    log "Checking users and groups..."

    # abx-bait group and user
    if ! getent group "$BAIT_USER" >/dev/null; then
        if [[ "$MODE" == "apply" ]]; then
            groupadd --gid "$BAIT_GID" "$BAIT_USER"
            ok "Created group $BAIT_USER (GID $BAIT_GID)"
        else
            warn "Would create group $BAIT_USER (GID $BAIT_GID)"
        fi
    else
        ok "Group $BAIT_USER exists"
    fi

    if ! id "$BAIT_USER" >/dev/null 2>&1; then
        if [[ "$MODE" == "apply" ]]; then
            useradd --uid "$BAIT_UID" --gid "$BAIT_GID" --no-create-home --shell /usr/sbin/nologin --system "$BAIT_USER"
            ok "Created user $BAIT_USER (UID $BAIT_UID)"
        else
            warn "Would create user $BAIT_USER (UID $BAIT_UID)"
        fi
    else
        ok "User $BAIT_USER exists"
    fi

    # abx-ship user and group
    if ! getent group "$SHIP_GROUP" >/dev/null; then
        if [[ "$MODE" == "apply" ]]; then
            groupadd --system "$SHIP_GROUP"
            ok "Created group $SHIP_GROUP"
        else
            warn "Would create group $SHIP_GROUP"
        fi
    else
        ok "Group $SHIP_GROUP exists"
    fi

    if ! id "$SHIP_USER" >/dev/null 2>&1; then
        if [[ "$MODE" == "apply" ]]; then
            useradd --system --gid "$SHIP_GROUP" --groups "$BAIT_USER" --no-create-home --shell /usr/sbin/nologin "$SHIP_USER"
            ok "Created user $SHIP_USER (supplementary group: $BAIT_USER)"
        else
            warn "Would create user $SHIP_USER"
        fi
    else
        # Check supplementary groups
        if ! id -nG "$SHIP_USER" | grep -qw "$BAIT_USER"; then
            if [[ "$MODE" == "apply" ]]; then
                usermod -a -G "$BAIT_USER" "$SHIP_USER"
                ok "Added $SHIP_USER to group $BAIT_USER"
            else
                warn "Would add $SHIP_USER to group $BAIT_USER"
            fi
        fi
        ok "User $SHIP_USER exists"
    fi
}

# Directories
setup_directories() {
    log "Checking directories..."

    # /run/attackbox: abx-ship:abx-bait mode 2710 (setgid: sockets inherit abx-bait)
    # /var/lib/attackbox-shipper/queue: abx-ship:abx-ship mode 0700
    local dirs=(
        "/run/attackbox:2710:$SHIP_USER:$BAIT_USER"
        "$QUEUE_DIR:0700:$SHIP_USER:$SHIP_GROUP"
    )

    for entry in "${dirs[@]}"; do
        IFS=':' read -r dir mode owner group <<< "$entry"

        if ! check_directory_safety "$dir" "$owner" "$group" "$mode"; then
            if [[ "$MODE" == "apply" ]]; then
                mkdir -p "$dir"
                chmod "$mode" "$dir"
                chown "$owner:$group" "$dir"
                ok "Created $dir ($mode $owner:$group)"
            else
                warn "Would create $dir ($mode $owner:$group)"
            fi
        else
            ok "Directory $dir correct"
        fi
    done
}

# Install packages (bootstrap only, no daemon startup)
install_packages() {
    log "Checking required packages..."

    local packages=(
        apt-transport-https
        ca-certificates
        curl
        gnupg
        auditd
        unattended-upgrades
        nftables
        dnsutils
        jq
        openssl
        lsb-release
    )

    local missing=()
    for pkg in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            missing+=("$pkg")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        if [[ "$MODE" == "apply" ]]; then
            apt-get update -qq
            apt-get install -y "${missing[@]}"
            ok "Installed: ${missing[*]}"
        else
            warn "Would install: ${missing[*]}"
        fi
    else
        ok "All required packages installed"
    fi
}

# Docker setup (install but don't start)
setup_docker() {
    log "Checking Docker installation..."

    if ! command -v docker >/dev/null; then
        if [[ "$MODE" == "apply" ]]; then
            install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
            chmod a+r /etc/apt/keyrings/docker.gpg

            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list

            apt-get update -qq
            apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

            # Stop Docker immediately after install
            systemctl stop docker
            systemctl stop containerd

            ok "Installed Docker (stopped)"
        else
            warn "Would install Docker"
        fi
    else
        ok "Docker installed: $(docker --version)"

        # Ensure Docker is stopped before firewall enforcement
        if systemctl is-active --quiet docker; then
            if [[ "$MODE" == "apply" ]]; then
                systemctl stop docker
                ok "Stopped Docker for firewall enforcement"
            else
                warn "Would stop Docker for firewall enforcement"
            fi
        fi
    fi

    # Preserve existing daemon.json, only add runsc if needed. The bait reaches
    # the shipper through a host unix socket, which gVisor blocks unless runsc
    # runs with --host-uds=open, so an existing runsc entry is patched too.
    local daemon_json="/etc/docker/daemon.json"
    if [[ -f "$daemon_json" ]]; then
        if ! jq -e '(.runtimes.runsc.runtimeArgs // []) | any(. == "--host-uds=open")' "$daemon_json" >/dev/null 2>&1; then
            if [[ "$MODE" == "apply" ]]; then
                # Merge runsc (path + --host-uds=open) into existing config
                local tmp
                tmp=$(mktemp)
                jq '.runtimes.runsc = ((.runtimes.runsc // {"path": "/usr/bin/runsc"})
                    | .runtimeArgs = (((.runtimeArgs // []) | map(select(startswith("--host-uds=") | not))) + ["--host-uds=open"]))' \
                    "$daemon_json" > "$tmp"
                cat "$tmp" > "$daemon_json"
                rm -f "$tmp"
                ok "Set runsc runtime with --host-uds=open in existing daemon.json"
            else
                warn "Would set runsc runtime with --host-uds=open in existing daemon.json"
            fi
        else
            ok "Docker daemon.json already has runsc with --host-uds=open"
        fi
    else
        if [[ "$MODE" == "apply" ]]; then
            cat > "$daemon_json" <<'EOF'
{
  "runtimes": {
    "runsc": {
      "path": "/usr/bin/runsc",
      "runtimeArgs": ["--host-uds=open"]
    }
  },
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF
            ok "Created daemon.json with runsc (--host-uds=open)"
        else
            warn "Would create daemon.json with runsc"
        fi
    fi
}

# Start Docker after bootstrap firewall
start_docker() {
    log "Starting Docker..."

    if [[ "$MODE" != "apply" ]]; then
        warn "Would start Docker"
        return 0
    fi

    systemctl start docker
    ok "Started Docker (under bootstrap firewall)"
}

# gVisor setup
setup_gvisor() {
    log "Checking gVisor (runsc)..."

    if ! command -v runsc >/dev/null; then
        if [[ "$MODE" == "apply" ]]; then
            curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg

            echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" > /etc/apt/sources.list.d/gvisor.list

            apt-get update -qq
            apt-get install -y runsc
            ok "Installed runsc"
        else
            warn "Would install runsc (gVisor)"
        fi
    else
        ok "runsc installed: $(runsc --version 2>&1 | head -1)"
    fi
}

# Falco setup (install, configure output, but don't enable yet)
setup_falco() {
    log "Checking Falco..."

    if ! command -v falco >/dev/null; then
        if [[ "$MODE" == "apply" ]]; then
            if ! dpkg -l | grep -q "linux-headers-$(uname -r)"; then
                apt-get install -y "linux-headers-$(uname -r)"
            fi

            curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
            echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" > /etc/apt/sources.list.d/falcosecurity.list

            apt-get update -qq
            apt-get install -y falco

            systemctl disable falco
            ok "Installed Falco (not yet enabled)"
        else
            warn "Would install Falco"
        fi
    else
        ok "Falco installed"
    fi

    # JSON output via a config.d drop-in: the packaged falco.yaml (rules_files,
    # engine, outputs) stays intact and the drop-in survives package upgrades.
    if command -v falco >/dev/null; then
        local dropin_dir="/etc/falco/config.d"
        local dropin="${dropin_dir}/attackbox.yaml"
        local want
        want=$(cat <<'EOF'
json_output: true
json_include_output_property: true
webserver:
  listen_address: 127.0.0.1
file_output:
  enabled: true
  keep_alive: false
  filename: /var/log/falco-events.jsonl
EOF
)
        if [[ ! -f "$dropin" ]] || [[ "$(cat "$dropin")" != "$want" ]]; then
            if [[ "$MODE" == "apply" ]]; then
                mkdir -p "$dropin_dir"
                printf '%s\n' "$want" > "$dropin"
                ok "Installed Falco JSON output drop-in"
            else
                warn "Would install Falco JSON output drop-in"
            fi
        else
            ok "Falco JSON output drop-in already installed"
        fi
        if [[ -f /etc/falco/falco.yaml ]] && ! grep -q 'config\.d' /etc/falco/falco.yaml; then
            warn "falco.yaml has no config_files entry for $dropin_dir (needs Falco >= 0.38); drop-in is inactive"
        fi
    fi
}

# Resolve New Relic endpoints via DNS
resolve_nr_endpoints() {
    # stdout is captured by the caller as the tmpdir path: log to stderr
    log "Resolving New Relic endpoints..." >&2

    local log_ips_v4=()
    local log_ips_v6=()
    local metric_ips_v4=()
    local metric_ips_v6=()

    # Resolve log API - separate A and AAAA
    while IFS= read -r ip; do
        [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && log_ips_v4+=("$ip")
    done < <(dig +short "$NR_LOG_HOST" A | grep -v '\.$')

    while IFS= read -r ip; do
        [[ "$ip" =~ : ]] && log_ips_v6+=("$ip")
    done < <(dig +short "$NR_LOG_HOST" AAAA | grep -v '\.$')

    # Resolve metric API - separate A and AAAA
    while IFS= read -r ip; do
        [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && metric_ips_v4+=("$ip")
    done < <(dig +short "$NR_METRIC_HOST" A | grep -v '\.$')

    while IFS= read -r ip; do
        [[ "$ip" =~ : ]] && metric_ips_v6+=("$ip")
    done < <(dig +short "$NR_METRIC_HOST" AAAA | grep -v '\.$')

    # Require BOTH hosts to resolve
    if [[ ${#log_ips_v4[@]} -eq 0 ]]; then
        err "Failed to resolve $NR_LOG_HOST A records"
        return 1
    fi
    if [[ ${#metric_ips_v4[@]} -eq 0 ]]; then
        err "Failed to resolve $NR_METRIC_HOST A records"
        return 1
    fi

    # Use mktemp for temp files
    # Return tmpdir path for setup_firewall
    local tmpdir
    tmpdir=$(mktemp -d)
    echo "${log_ips_v4[@]}" > "$tmpdir/nr-log-ipv4.txt"
    echo "${log_ips_v6[@]}" > "$tmpdir/nr-log-ipv6.txt"
    echo "${metric_ips_v4[@]}" > "$tmpdir/nr-metric-ipv4.txt"
    echo "${metric_ips_v6[@]}" > "$tmpdir/nr-metric-ipv6.txt"
    echo "$tmpdir"  # Return tmpdir path
}

# Host DNS/NTP must match what the nftables output policy allows (Cloudflare
# only). Install before any firewall loads, or host lookups time out.
use_host_dns_stub() {
    local resolver="$1" stub="$2" backup="${1}.pre-attackbox"
    [[ "$(readlink "$resolver" || true)" != "$stub" ]] || return 0
    if [[ "$MODE" != "apply" ]]; then
        warn "Would route the host resolver through systemd-resolved"
        return 0
    fi

    if [[ ! -s "$stub" || -d "$resolver" ]]; then
        err "Cannot switch the host resolver to $stub"
        return 1
    fi
    if ! dig @127.0.0.53 +short +time=3 +tries=1 registry-1.docker.io A | grep -E '^[0-9.]+$' >/dev/null; then
        err "The systemd-resolved stub cannot resolve Docker Hub"
        return 1
    fi
    if [[ ( -e "$resolver" || -L "$resolver" ) && ! -e "$backup" && ! -L "$backup" ]]; then
        cp -pP -- "$resolver" "$backup"
    fi
    ln -sfn -- "$stub" "$resolver"
    ok "Host DNS uses the systemd-resolved stub"
}

setup_host_dns_ntp() {
    log "Checking host DNS/NTP configuration..."

    local entries=(
        "resolved-attackbox.conf:/etc/systemd/resolved.conf.d/attackbox.conf:systemd-resolved"
        "timesyncd-attackbox.conf:/etc/systemd/timesyncd.conf.d/attackbox.conf:systemd-timesyncd"
    )

    local entry name target svc src
    for entry in "${entries[@]}"; do
        IFS=':' read -r name target svc <<< "$entry"
        src="${DEPLOY_DIR}/systemd/${name}"

        if [[ ! -f "$src" ]]; then
            err "Config not found: $src"
            return 1
        fi

        if [[ ! -f "$target" ]] || ! cmp -s "$src" "$target"; then
            if [[ "$MODE" == "apply" ]]; then
                mkdir -p "$(dirname "$target")"
                cp "$src" "$target"
                systemctl restart "$svc"
                ok "Installed $target"
            else
                warn "Would install $target"
            fi
        else
            ok "$target already installed"
        fi
    done

    use_host_dns_stub /etc/resolv.conf /run/systemd/resolve/stub-resolv.conf
}

# nftables firewall (enforced before Docker starts)
# Bootstrap firewall (metadata blocking + root registry access)
bootstrap_firewall() {
    log "Loading bootstrap firewall (metadata blocking)..."

    if [[ "$MODE" != "apply" ]]; then
        warn "Would load bootstrap firewall"
        return 0
    fi

    # A second base chain cannot override an existing policy's drop. Keep the
    # running host's containment and telemetry rules during upgrades. Permit
    # root registry access for at most 20 minutes; clear it on normal/error exit.
    if nft list table inet attackbox >/dev/null 2>&1; then
        trap 'nft flush set inet attackbox bootstrap_root_uids 2>/dev/null || true' EXIT
        nft -f - <<'UPGRADE'
add set inet attackbox bootstrap_root_uids { type uid; flags timeout; timeout 20m; }
flush set inet attackbox bootstrap_root_uids
add element inet attackbox bootstrap_root_uids { 0 timeout 20m }
insert rule inet attackbox output_policy meta skuid @bootstrap_root_uids tcp dport { 80, 443 } accept
UPGRADE
        ok "Existing containment retained; root registry access expires in 20 minutes"
        return 0
    fi

    # Create minimal bootstrap table on a new host only.
    nft -f - <<'EOF'
add table inet attackbox_bootstrap
flush table inet attackbox_bootstrap

table inet attackbox_bootstrap {
    chain forward_early {
        type filter hook forward priority -150; policy accept;

        # Block metadata from containers
        ip daddr { 169.254.169.254, 100.100.100.200 } counter log prefix "METADATA-BLOCK: " drop
        ip6 daddr fe80:ec2::254/128 counter log prefix "METADATA-BLOCK: " drop

        # Allow established/related
        ct state established,related accept

        # Drop NEW container-originated forwarding
        iifname "docker0" ct state new counter log prefix "CONTAINER-EGRESS-BLOCK: " drop
        iifname "br-*" ct state new counter log prefix "CONTAINER-EGRESS-BLOCK: " drop
    }

    chain output_policy {
        type filter hook output priority 0; policy drop;

        # Loopback
        oif lo accept

        # Established/related
        ct state established,related accept

        # Block metadata
        ip daddr { 169.254.169.254, 100.100.100.200 } counter log prefix "METADATA-BLOCK-OUT: " reject
        ip6 daddr fe80:ec2::254/128 counter log prefix "METADATA-BLOCK-OUT: " reject

        # DNS (Cloudflare)
        ip daddr { 1.1.1.1, 1.0.0.1 } udp dport 53 accept
        ip6 daddr { 2606:4700:4700::1111, 2606:4700:4700::1001 } udp dport 53 accept
        ip daddr { 1.1.1.1, 1.0.0.1 } tcp dport 53 accept
        ip6 daddr { 2606:4700:4700::1111, 2606:4700:4700::1001 } tcp dport 53 accept

        # NTP (Cloudflare)
        ip daddr { 162.159.200.123, 162.159.200.1 } udp dport 123 accept

        # DHCP client
        udp sport 68 udp dport 67 accept

        # Bootstrap: root-only registry access (Docker Hub, Chainguard)
        skuid 0 tcp dport { 80, 443 } accept

        # ICMP errors
        ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } limit rate 5/second accept
        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, destination-unreachable, packet-too-big, time-exceeded } accept

        # Log and drop everything else
        counter log prefix "OUTPUT-DROP: " drop
    }
}
EOF

    systemctl enable nftables
    ok "Loaded bootstrap firewall (metadata blocking + root registry)"
}

# Add resolved New Relic IPs (files written by resolve_nr_endpoints) and the
# shipper UID to the attackbox sets.
populate_nr_sets() {
    local tmpdir="$1"
    local entry set_name file ip
    local ips=()

    for entry in nr_log_ipv4:nr-log-ipv4 nr_log_ipv6:nr-log-ipv6 \
                 nr_metric_ipv4:nr-metric-ipv4 nr_metric_ipv6:nr-metric-ipv6; do
        set_name="${entry%%:*}"
        file="$tmpdir/${entry##*:}.txt"
        [[ -f "$file" ]] || continue
        ips=()
        read -ra ips < "$file" || true
        for ip in "${ips[@]}"; do
            nft add element inet attackbox "$set_name" { "$ip" }
        done
    done

    # Populate shipper UID
    local ship_uid
    ship_uid=$(id -u "$SHIP_USER")
    nft add element inet attackbox shipper_uids { "$ship_uid" }

    populate_otlp_sets
    populate_native_sets runtime
}

# Fixed DNS names only; never accept an endpoint or address from a request.
# Resolve every required host before mutation. An empty/invalid answer fails closed.
populate_native_sets() {
    local phase="$1" prefix host family address
    local hosts=() v4=() v6=()
    if [[ "$phase" == runtime ]]; then
        prefix=nr_infra
        hosts=(infra-api.newrelic.com identity-api.newrelic.com infrastructure-command-api.newrelic.com metric-api.newrelic.com log-api.newrelic.com)
    elif [[ "$phase" == install ]]; then
        prefix=nr_install
        hosts=(download.newrelic.com api.newrelic.com insights-collector.newrelic.com urly.service.newrelic.com d20hasrqv82i0q.cloudfront.net github.com api.github.com raw.githubusercontent.com objects.githubusercontent.com release-assets.githubusercontent.com download.docker.com download.falco.org storage.googleapis.com archive.ubuntu.com security.ubuntu.com)
    else
        return 1
    fi
    for host in "${hosts[@]}"; do
        local resolved=0
        while IFS= read -r address; do
            [[ "$address" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
            v4+=("$address"); resolved=1
        done < <(dig +short +time=3 +tries=1 "$host" A)
        while IFS= read -r address; do
            [[ "$address" =~ ^[a-fA-F0-9:]+$ && "$address" == *:* ]] || continue
            v6+=("$address"); resolved=1
        done < <(dig +short +time=3 +tries=1 "$host" AAAA)
        [[ $resolved == 1 ]] || { err "Cannot resolve native New Relic endpoint $host"; return 1; }
    done
    [[ ${#v4[@]} -le 128 && ${#v6[@]} -le 128 ]] || return 1
    for family in ipv4 ipv6; do
        local entries=()
        if [[ $family == ipv4 ]]; then entries=("${v4[@]}"); else entries=("${v6[@]}"); fi
        for address in "${entries[@]}"; do
            nft add element inet attackbox "${prefix}_${family}" "{" "$address" "}"
        done
    done
}

# Optional profile: leave the collector sets empty until its user exists.
# No new egress permission is granted to root, bait, or the evidence shipper.
populate_otlp_sets() {
    local collector_uid ip
    local v4=() v6=()
    collector_uid=$(id -u abx-otel 2>/dev/null) || return 0
    [[ "$collector_uid" =~ ^[0-9]+$ && "$collector_uid" != 0 ]] || return 1
    while IFS= read -r ip; do
        [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && v4+=("$ip")
    done < <(dig +short otlp.nr-data.net A | grep -v '\.$')
    while IFS= read -r ip; do
        [[ "$ip" =~ : ]] && v6+=("$ip")
    done < <(dig +short otlp.nr-data.net AAAA | grep -v '\.$')
    if [[ ${#v4[@]} -eq 0 || ${#v4[@]} -gt 32 || ${#v6[@]} -gt 32 ]]; then
        err "OTLP DNS returned no IPv4 addresses or too many addresses"
        return 1
    fi
    for ip in "${v4[@]}"; do
        nft add element inet attackbox nr_otlp_ipv4 "{" "$ip" "}"
    done
    for ip in "${v6[@]}"; do
        nft add element inet attackbox nr_otlp_ipv6 "{" "$ip" "}"
    done
    nft add element inet attackbox collector_uids "{" "$collector_uid" "}"
}

setup_firewall() {
    log "Checking nftables firewall..."

    local nft_rules="${DEPLOY_DIR}/nftables/attackbox.nft"

    if [[ ! -f "$nft_rules" ]]; then
        err "nftables rules not found: $nft_rules"
        return 1
    fi

    if [[ "$MODE" == "apply" ]]; then
        # Resolve NR endpoints first and capture tmpdir
        local tmpdir
        tmpdir=$(resolve_nr_endpoints)

        # Save current ruleset for ERR trap. "nft list ruleset" output only
        # adds, so the restore must flush first or it collides with live rules.
        local backup
        backup=$(mktemp)
        { echo "flush ruleset"; nft list ruleset; } > "$backup"

        # ERR trap for rollback
        trap 'nft -f "'"$backup"'" 2>/dev/null; rm -f "'"$backup"'" "'"$tmpdir"'"/*.txt; rmdir "'"$tmpdir"'" 2>/dev/null; err "Firewall setup failed, rolled back"' ERR

        # Load attackbox table (idempotent)
        if ! nft -c -f "$nft_rules"; then
            err "nftables rules validation failed"
            return 1
        fi


        # Delete bootstrap table if present
        nft delete table inet attackbox_bootstrap 2>/dev/null || true
        nft -f "$nft_rules"

        # Populate Ubuntu mirrors after table load
        resolve_ubuntu_mirrors


        # Populate NR endpoint sets and shipper UID
        populate_nr_sets "$tmpdir"

        # Persist across reboot: nftables.service loads /etc/nftables.conf. The
        # sets come back empty, attackbox-nft-refresh.timer repopulates them.
        if [[ -f /etc/nftables.conf ]] && ! cmp -s "$nft_rules" /etc/nftables.conf \
            && [[ ! -f /etc/nftables.conf.pre-attackbox ]]; then
            cp -p /etc/nftables.conf /etc/nftables.conf.pre-attackbox
        fi
        install -m 0644 -o root -g root "$nft_rules" /etc/nftables.conf
        install -m 0750 -o root -g root "${SCRIPT_DIR}/deploy-ubuntu.sh" "$REFRESH_BIN"

        # Clear trap and cleanup on success
        trap - ERR
        rm -f "$backup" "$tmpdir"/*.txt
        rmdir "$tmpdir"

        systemctl enable nftables

        ok "Installed nftables rules with rollback safety"
        ok "Persisted rules to /etc/nftables.conf (sets refreshed by attackbox-nft-refresh.timer)"
        warn "Firewall enforced before Docker starts"
    else
        warn "Would install nftables rules and populate endpoints"
    fi
}

# sysctl hardening
setup_sysctl() {
    log "Checking sysctl hardening..."

    local sysctl_conf="${DEPLOY_DIR}/sysctl/attackbox.conf"
    local target="/etc/sysctl.d/90-attackbox.conf"

    if [[ ! -f "$sysctl_conf" ]]; then
        err "sysctl config not found: $sysctl_conf"
        return 1
    fi

    if [[ ! -f "$target" ]] || ! cmp -s "$sysctl_conf" "$target"; then
        if [[ "$MODE" == "apply" ]]; then
            cp "$sysctl_conf" "$target"
            sysctl -p "$target"
            ok "Applied sysctl hardening (ip_forward=1 for Docker)"
        else
            warn "Would install sysctl hardening"
        fi
    else
        ok "sysctl hardening already applied"
    fi
}

# auditd rules
setup_auditd() {
    log "Checking auditd rules..."

    # Legacy unlink/rename syscalls do not exist on arm64 and make augenrules
    # reject the file, so they ship in a separate file for x86_64 only.
    local entries=("attackbox.rules:90-attackbox.rules")
    if [[ "$(uname -m)" == "x86_64" ]]; then
        entries+=("attackbox-x86_64.rules:91-attackbox-x86_64.rules")
    fi

    local entry src target changed=false
    for entry in "${entries[@]}"; do
        src="${DEPLOY_DIR}/auditd/${entry%%:*}"
        target="/etc/audit/rules.d/${entry##*:}"

        if [[ ! -f "$src" ]]; then
            err "auditd rules not found: $src"
            return 1
        fi

        if [[ ! -f "$target" ]] || ! cmp -s "$src" "$target"; then
            if [[ "$MODE" == "apply" ]]; then
                cp "$src" "$target"
                changed=true
            else
                warn "Would install $target"
            fi
        else
            ok "auditd rules $target already applied"
        fi
    done

    if [[ "$changed" == true ]]; then
        augenrules --load
        systemctl restart auditd
        ok "Applied auditd rules"
    fi
}

# Unattended upgrades (enable security updates, no auto-reboot)
setup_unattended_upgrades() {
    log "Checking unattended-upgrades..."

    local config="/etc/apt/apt.conf.d/50unattended-upgrades"
    local auto_config="/etc/apt/apt.conf.d/20auto-upgrades"
    local sources="/etc/apt/sources.list.d/ubuntu.sources"
    local vultr_mirror='^URIs: https?://ubuntu\.mirror\.constant\.com/?[[:space:]]*$'
    if [[ -f "$sources" ]] && grep -Eq "$vultr_mirror" "$sources"; then
        if [[ "$MODE" == "apply" ]]; then
            local updated
            updated=$(mktemp "${sources}.XXXXXX")
            sed -E "s|$vultr_mirror|URIs: https://archive.ubuntu.com/ubuntu/|" "$sources" > "$updated"
            chmod --reference="$sources" "$updated"
            mv -fT -- "$updated" "$sources"
            ok "Set the Ubuntu archive to an allowed mirror"
        else
            warn "Would replace the Vultr Ubuntu mirror with archive.ubuntu.com"
        fi
    fi

    if [[ -f "$config" ]]; then
        if grep -q 'Automatic-Reboot "false"' "$config"; then
            ok "unattended-upgrades configured (no auto-reboot)"
        else
            if [[ "$MODE" == "apply" ]]; then
                if ! grep -q "Automatic-Reboot" "$config"; then
                    echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> "$config"
                else
                    sed -i 's/Automatic-Reboot "true"/Automatic-Reboot "false"/' "$config"
                fi
                ok "Disabled automatic reboots in unattended-upgrades"
            else
                warn "Would disable automatic reboots"
            fi
        fi
    fi

    # Enable automatic security updates
    if [[ ! -f "$auto_config" ]] || ! grep -q 'APT::Periodic::Unattended-Upgrade "1"' "$auto_config"; then
        if [[ "$MODE" == "apply" ]]; then
            cat > "$auto_config" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
            ok "Enabled automatic security updates"
        else
            warn "Would enable automatic security updates"
        fi
    else
        ok "Automatic security updates enabled"
    fi
}

apply_initial_security_updates() {
    local stamp="$1" reboot
    [[ ! -f "$stamp" ]] || return 0
    if [[ "$MODE" != "apply" ]]; then
        warn "Would refresh Ubuntu indexes and run unattended security updates"
        return 0
    fi

    reboot=$(apt-config shell reboot Unattended-Upgrade::Automatic-Reboot/b) || return
    if [[ "$reboot" == "reboot='true'" ]]; then
        err "Disable automatic reboot before applying initial security updates"
        return 1
    fi

    log "Applying initial Ubuntu security updates..."
    apt-get update -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/ubuntu.sources \
        -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=false -o APT::Update::Error-Mode=any \
        -o Acquire::Retries=0 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 || return
    unattended-upgrade --verbose || return
    mkdir -p -- "$(dirname "$stamp")" && touch -- "$stamp" || return
    ok "Initial Ubuntu security update run complete"
}

# Systemd units
setup_systemd_units() {
    log "Checking systemd units..."

    local units=(
        "attackbox-shipper.service"
        "attackbox-falco-adapter.service"
        "attackbox-egress-adapter.service"
        "attackbox.service"
        "attackbox-nft-refresh.service"
        "attackbox-nft-refresh.timer"
    )

    for unit in "${units[@]}"; do
        local unit_file="${DEPLOY_DIR}/systemd/${unit}"
        local target="/etc/systemd/system/${unit}"

        if [[ ! -f "$unit_file" ]]; then
            err "Unit file not found: $unit_file"
            continue
        fi

        if [[ ! -f "$target" ]] || ! cmp -s "$unit_file" "$target"; then
            if [[ "$MODE" == "apply" ]]; then
                cp "$unit_file" "$target"
                ok "Installed $unit"
            else
                warn "Would install $unit"
            fi
        else
            ok "Unit $unit already installed"
        fi
    done

    # Journald config
    local journald_conf="${DEPLOY_DIR}/systemd/journald-attackbox.conf"
    local journald_target="/etc/systemd/journald.conf.d/attackbox.conf"

    if [[ -f "$journald_conf" ]]; then
        mkdir -p "$(dirname "$journald_target")"
        if [[ ! -f "$journald_target" ]] || ! cmp -s "$journald_conf" "$journald_target"; then
            if [[ "$MODE" == "apply" ]]; then
                cp "$journald_conf" "$journald_target"
                systemctl restart systemd-journald
                ok "Installed journald config"
            else
                warn "Would install journald config"
            fi
        else
            ok "Journald config already installed"
        fi
    fi

    if [[ "$MODE" == "apply" ]]; then
        systemctl daemon-reload
    fi
}

# Check binaries exist
check_binaries() {
    log "Checking binaries..."

    # Readers and shipper run on host; bait runs in container
    local binaries=(
        "/usr/local/bin/attackbox-shipper"
        "/usr/local/bin/attackbox-hostreader"
    )

    local missing=()
    for bin in "${binaries[@]}"; do
        if [[ ! -x "$bin" ]]; then
            missing+=("$bin")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        err "Missing binaries: ${missing[*]}"
        err "Place binaries in /usr/local/bin/ before starting services"
        return 1
    fi

    ok "All binaries present"
}

# Check shipper.env exists
check_shipper_env() {
    log "Checking shipper.env..."

    local env_file="/etc/attackbox/shipper.env"

    if [[ ! -f "$env_file" ]]; then
        err "Missing $env_file"
        err "Create with root:root 0600 containing ATTACKBOX_NR_* variables"
        return 1
    fi

    # Check ownership and mode
    local owner
    local mode
    owner=$(stat -c '%U:%G' "$env_file" 2>/dev/null || stat -f '%Su:%Sg' "$env_file")
    mode=$(stat -c '%a' "$env_file" 2>/dev/null || stat -f '%A' "$env_file" | tail -c 4)

    if [[ "$owner" != "root:root" ]]; then
        err "$env_file has wrong ownership: $owner (must be root:root)"
        return 1
    fi

    if [[ "$mode" != "600" ]]; then
        err "$env_file has wrong mode: $mode (must be 0600)"
        return 1
    fi

    # Required socket settings for six-stream deployment
    local required_settings=(
        "ATTACKBOX_SPOOL_SOCKET=/run/attackbox/spool.sock"
        "ATTACKBOX_RUNTIME_SOCKET=/run/attackbox/runtime.sock"
        "ATTACKBOX_EGRESS_SOCKET=/run/attackbox/egress.sock"
        "ATTACKBOX_HOST_RECEIPTS=true"
    )

    local missing=()
    for setting in "${required_settings[@]}"; do
        local key="${setting%%=*}"
        if ! grep -q "^${key}=" "$env_file"; then
            missing+=("$setting")
        elif [[ "$key" == "ATTACKBOX_HOST_RECEIPTS" ]] && ! grep -qxF "$setting" "$env_file"; then
            err "$env_file must set ATTACKBOX_HOST_RECEIPTS=true for durable host readers"
            return 1
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        if [[ "$MODE" == "apply" ]]; then
            # Append missing settings idempotently
            for setting in "${missing[@]}"; do
                echo "$setting" >> "$env_file"
            done
            ok "Appended missing socket settings to $env_file"
        else
            warn "Missing socket settings in $env_file:"
            for setting in "${missing[@]}"; do
                warn "  $setting"
            done
            return 1
        fi
    fi

    ok "Shipper env file correct"
}

# Start services
start_services() {
    log "Starting services..."

    if [[ "$MODE" != "apply" ]]; then
        warn "Would start services"
        return 0
    fi

    # Check prerequisites
    check_binaries || return 1
    check_shipper_env || return 1

    # Start Docker (firewall already enforced)
    systemctl start docker
    ok "Started Docker"

    # Start shipper
    # Upgrade the receipt protocol as a pair; do not leave old tail processes
    # running against a newly installed receipt-enabled shipper.
    systemctl stop attackbox-falco-adapter attackbox-egress-adapter
    systemctl enable attackbox-shipper
    systemctl restart attackbox-shipper
    ok "Started attackbox-shipper"

    # Start Falco with Modern eBPF
    systemctl enable falco-modern-bpf
    systemctl restart falco-modern-bpf
    ok "Started falco-modern-bpf"

    # Start adapters
    systemctl enable attackbox-falco-adapter
    systemctl restart attackbox-falco-adapter
    ok "Started attackbox-falco-adapter"

    systemctl enable attackbox-egress-adapter
    systemctl restart attackbox-egress-adapter
    ok "Started attackbox-egress-adapter"

    # Keep nftables NR/Ubuntu sets fresh (they are empty after a reboot)
    systemctl enable --now attackbox-nft-refresh.timer
    ok "Enabled attackbox-nft-refresh.timer"
}

# SSH disablement
disable_ssh() {
    if [[ "$DISABLE_SSH" != true || "$CONSOLE_CONFIRMED" != true ]]; then
        return 0
    fi

    log "Disabling SSH and cloud-init..."

    if [[ "$MODE" == "apply" ]]; then
        systemctl stop ssh
        systemctl disable ssh
        systemctl mask ssh

        touch /etc/cloud/cloud-init.disabled

        ok "SSH and cloud-init disabled"
        warn "Ensure provider console access is working!"
    else
        warn "Would disable SSH and cloud-init"
    fi
}


# Resolve Ubuntu mirrors
resolve_ubuntu_mirrors() {
    log "Resolving Ubuntu mirror endpoints..."

    local ubuntu_ips_v4=()
    local ubuntu_ips_v6=()

    for host in archive.ubuntu.com security.ubuntu.com; do
        while IFS= read -r ip; do
            [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ubuntu_ips_v4+=("$ip")
        done < <(dig +short "$host" A | grep -v '\.$')

        while IFS= read -r ip; do
            [[ "$ip" =~ : ]] && ubuntu_ips_v6+=("$ip")
        done < <(dig +short "$host" AAAA | grep -v '\.$')
    done

    if [[ ${#ubuntu_ips_v4[@]} -gt 0 ]]; then
        ok "Resolved ${#ubuntu_ips_v4[@]} Ubuntu mirror IPv4 addresses"
        for ip in "${ubuntu_ips_v4[@]}"; do
            nft add element inet attackbox ubuntu_ipv4 { "$ip" }
        done
    fi

    if [[ ${#ubuntu_ips_v6[@]} -gt 0 ]]; then
        ok "Resolved ${#ubuntu_ips_v6[@]} Ubuntu mirror IPv6 addresses"
        for ip in "${ubuntu_ips_v6[@]}"; do
            nft add element inet attackbox ubuntu_ipv6 { "$ip" }
        done
    fi
}

# Re-resolve endpoints into the live sets (timer entry point). Sets are
# additive: stale IPs stay until the next boot or reload of /etc/nftables.conf.
refresh_endpoint_sets() {
    log "Refreshing nftables endpoint sets..."

    if ! nft list table inet attackbox >/dev/null 2>&1; then
        err "nftables table inet attackbox not loaded"
        return 1
    fi

    local tmpdir
    tmpdir=$(resolve_nr_endpoints)
    populate_nr_sets "$tmpdir"
    rm -f "$tmpdir"/*.txt
    rmdir "$tmpdir"

    resolve_ubuntu_mirrors
    ok "Endpoint sets refreshed"
}

# Build and pre-pull bait before firewall
prepare_bait() {
    log "Preparing bait containers..."

    if [[ "$MODE" != "apply" ]]; then
        warn "Would build bait, install shipper, create secrets, and pre-pull images"
        return 0
    fi

    # Install Compose project to /opt/attackbox
    local repo_root="${SCRIPT_DIR}/.."
    mkdir -p /opt/attackbox
    cp "$repo_root/compose.yaml" /opt/attackbox/
    cp "$repo_root/compose.gvisor.yaml" /opt/attackbox/
    cp "$repo_root/Dockerfile" /opt/attackbox/
    cp -r "$repo_root/docker" /opt/attackbox/

    # Create secrets directory with safe permissions
    mkdir -p "$SECRETS_DIR"
    chmod 700 "$SECRETS_DIR"

    # Create secrets if they don't exist (don't overwrite existing)
    if [[ ! -f "$SECRETS_DIR/redaction.key" ]]; then
        (umask 077; head -c 32 /dev/urandom | base64 > "$SECRETS_DIR/redaction.key")
        ok "Generated redaction.key"
    fi

    if [[ ! -f "$SECRETS_DIR/server.crt" ]] || [[ ! -f "$SECRETS_DIR/server.key" ]]; then
        (umask 077; openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$SECRETS_DIR/server.key" \
            -out "$SECRETS_DIR/server.crt" \
            -days 365 -subj "/CN=attackbox-proxy" 2>/dev/null)
        ok "Generated TLS certificate"
    fi

    # Compose file secrets are bind mounts: the container sees the host owner
    # and mode and ignores the uid/mode keys in compose.yaml. Bait and proxy
    # both run as 65532 and bait refuses any group/other mode bit. Also fixes
    # files left root:root by an earlier run.
    local secret
    for secret in redaction.key server.key server.crt; do
        chown "${BAIT_UID}:${BAIT_GID}" "$SECRETS_DIR/$secret"
        chmod 0400 "$SECRETS_DIR/$secret"
    done
    ok "Secrets owned by ${BAIT_UID}:${BAIT_GID} mode 0400"

    # Build bait image (dev tag for compose.yaml)
    if [[ -f "$repo_root/Dockerfile" ]]; then
        docker build --network=none --build-arg OFFLINE_GO_BUILD=1 -t attackbox-bait:dev "$repo_root"
        ok "Built bait image"
    else
        err "Dockerfile not found in repository root"
        return 1
    fi

    # Extract and install shipper binary from shipper-export target
    log "Installing shipper binary..."
    local shipper_build
    shipper_build=$(mktemp -d)
    docker build --network=none --build-arg OFFLINE_GO_BUILD=1 --target shipper-export --output type=local,dest="$shipper_build" "$repo_root"
    # Atomic replacement also works while the old executable is running.
    local binary staged_binary
    for binary in attackbox-shipper attackbox-hostreader; do
        staged_binary=$(mktemp "/usr/local/bin/.${binary}.XXXXXX")
        install -m 0755 -o root -g root "$shipper_build/$binary" "$staged_binary"
        mv -f -- "$staged_binary" "/usr/local/bin/$binary"
    done
    rm -rf "$shipper_build"
    ok "Installed attackbox-shipper binary"

    # Pre-pull Chainguard nginx proxy with verified multi-arch digest
    docker pull cgr.dev/chainguard/nginx@sha256:c1642395cc75f39c931d66d939f7e78cbdf671d6cfd821616632b0639c3c6d63
    ok "Pre-pulled Chainguard nginx proxy"

    # Pre-pull busybox verification image
    docker pull busybox@sha256:650fd573e056b679a5110a70aabeb01e26b76e545ec4b9c70a9523f2dfaf18c6
    ok "Pre-pulled busybox verification image"
}

# Start bait service
start_bait() {
    log "Starting bait service..."

    if [[ "$MODE" != "apply" ]]; then
        warn "Would start bait service"
        return 0
    fi

    systemctl enable attackbox
    systemctl restart attackbox
    ok "Bait service started (Compose --wait ensures readiness)"
}

# setup_docker stops Docker, which stops attackbox-public.service
# (PartOf=docker.service), and no unit starts it again. An enabled unit is one
# the operator wants running; a host without the public gateway has no such unit.
restore_public_gateway() {
    systemctl is-enabled --quiet attackbox-public.service 2>/dev/null || return 0
    log "Restoring the public gateway..."
    # A fresh Collector start puts its UID back in the reloaded nft set.
    if systemctl stop attackbox-public-otel.service && systemctl start attackbox-public.service; then
        ok "Public gateway restarted"
    else
        err "Public gateway did not come back"
        return 1
    fi
}

# Enhanced verification
run_verification_enhanced() {
    log "Running enhanced validation checks..."

    if [[ "$(uname -s)" != "Linux" ]]; then
        err "Verification requires Linux"
        return 1
    fi

    if ! command -v docker >/dev/null; then
        err "Verification requires Docker"
        return 1
    fi

    bash "${SCRIPT_DIR}/bootstrap-infrastructure.sh" --verify

    # Use verified multi-arch busybox digest for tests
    # Verification: docker pull busybox:1.36.1
    # Command: docker inspect busybox:1.36.1 | jq -r '.[0].RepoDigests[] | select(contains("docker.io"))'
    # Digest: busybox@sha256:650fd573e056b679a5110a70aabeb01e26b76e545ec4b9c70a9523f2dfaf18c6
    # Multi-arch: linux/amd64, linux/arm64 verified 2024-03-xx
    local test_img="busybox@sha256:650fd573e056b679a5110a70aabeb01e26b76e545ec4b9c70a9523f2dfaf18c6"

    # Derive actual Compose network name (attackbox_internal)
    local network
    network=$(docker network ls --format '{{.Name}}' | grep -E '^(attackbox_internal|opt-attackbox_internal)$' | head -1)
    if [[ -z "$network" ]]; then
        err "Compose internal network not found"
        return 1
    fi

    # Test metadata blocking
    log "Testing metadata blocking from container..."
    # Any failure counts as blocked: busybox wget wording varies by failure mode
    if ! docker run --rm --runtime=runsc --network "$network" "$test_img" timeout 2 wget -O- http://169.254.169.254/ >/dev/null 2>&1; then
        ok "Metadata blocked from container"
    else
        err "Metadata NOT blocked - required check failed"
        return 1
    fi

    # runsc cannot use Docker's embedded DNS. The gVisor overlay pins bait
    # and supplies its hosts entry to nginx. Verify the actual forwarding
    # path, including TLS; -k permits the bootstrap self-signed certificate.
    log "Testing HTTPS proxy to bait..."
    if curl --noproxy '*' -kfsS --max-time 10 https://127.0.0.1:8443/v1/models |
        jq -e '.object == "list" and (.data | type == "array")' >/dev/null; then
        ok "HTTPS proxy forwards to bait"
    else
        err "HTTPS proxy cannot reach bait - required check failed"
        return 1
    fi

    # Verify external DNS is blocked
    log "Verifying external DNS blocked from bait network..."
    if ! docker run --rm --runtime=runsc --network "$network" "$test_img" timeout 2 nslookup google.com 1.1.1.1 >/dev/null 2>&1; then
        ok "External DNS blocked from bait network"
    else
        err "External DNS NOT blocked - required check failed"
        return 1
    fi

    # Test Internet blocked
    log "Testing Internet blocking from container..."
    if ! docker run --rm --runtime=runsc --network "$network" "$test_img" timeout 2 wget -O- https://example.com >/dev/null 2>&1; then
        ok "Internet blocked from container"
    else
        err "Internet NOT blocked - required check failed"
        return 1
    fi

    # Test exact NR HTTPS endpoints as shipper UID with curl
    log "Testing New Relic HTTPS endpoints as shipper UID..."
    local nr_ok=0

    # Test log-api.newrelic.com/log/v1
    local log_url="https://${NR_LOG_HOST}/log/v1"
    if sudo -u "$SHIP_USER" timeout 5 curl -s -o /dev/null -w "%{http_code}" "$log_url" 2>/dev/null | grep -qE '^[0-9]{3}$'; then
        ok "NR log endpoint reachable"
        nr_ok=$((nr_ok + 1))
    fi

    # Test metric-api.newrelic.com/metric/v1
    local metric_url="https://${NR_METRIC_HOST}/metric/v1"
    if sudo -u "$SHIP_USER" timeout 5 curl -s -o /dev/null -w "%{http_code}" "$metric_url" 2>/dev/null | grep -qE '^[0-9]{3}$'; then
        ok "NR metric endpoint reachable"
        nr_ok=$((nr_ok + 1))
    fi

    if [[ $nr_ok -eq 2 ]]; then
        ok "Both NR endpoints reachable"
    else
        err "Not all NR endpoints reachable - required check failed"
        return 1
    fi

    ok "All verification checks passed"
}
# Main execution
main() {
    log "Attack-box Ubuntu deployment"
    log "Mode: $MODE"

    check_root

    if [[ "$MODE" == "refresh" ]]; then
        refresh_endpoint_sets
        exit $?
    fi

    if [[ "$MODE" == "refresh-install" ]]; then
        populate_native_sets install
        exit $?
    fi

    check_linux
    check_os

    if [[ "$MODE" == "verify" ]]; then
        run_verification_enhanced
        exit $?
    fi

    local native_api_key="${NEW_RELIC_API_KEY:-}"
    unset NEW_RELIC_API_KEY
    if [[ "$NATIVE_KEY_STDIN" == true ]]; then
        [[ "$MODE" == apply ]] || { err "--native-key-stdin requires --apply"; exit 1; }
        IFS= read -r native_api_key || { err "Missing native provisioning API key on stdin"; exit 1; }
    fi
    if [[ "$MODE" == apply ]] && ! systemctl is-active --quiet newrelic-infra.service; then
        [[ "$native_api_key" =~ ^NRAK-[A-Za-z0-9_-]{20,200}$ ]] || { err "Native Infrastructure bootstrap requires a User API key; use --native-key-stdin"; exit 1; }
    fi

    setup_users
    setup_directories
    install_packages
    setup_docker
    setup_gvisor
    setup_falco
    setup_host_dns_ntp
    bootstrap_firewall
    start_docker
    prepare_bait
    if [[ "$MODE" != apply ]]; then bash "${SCRIPT_DIR}/bootstrap-infrastructure.sh" --dry-run; fi
    setup_firewall
    setup_sysctl
    setup_auditd
    setup_unattended_upgrades
    apply_initial_security_updates /var/lib/attackbox/initial-security-upgrade
    setup_systemd_units

    if [[ "$MODE" == "apply" ]]; then
        start_services
        start_bait
        # Report a failure after the private checks; do not stop them.
        local public_gateway=ok
        restore_public_gateway || public_gateway=failed
        printf '%s\n' "$native_api_key" | bash "${SCRIPT_DIR}/bootstrap-infrastructure.sh" --apply
        unset native_api_key
        run_verification_enhanced
        [[ "$public_gateway" == ok ]] || { err "Private stack verified, but the public gateway is down: systemctl start attackbox-public.service"; exit 1; }
        disable_ssh

        echo ""
        ok "Deployment complete"
        warn "Services started:"
        warn "  - Native New Relic Infrastructure"
        warn "  - Docker (with gVisor runtime)"
        warn "  - attackbox-shipper (with socket)"
        warn "  - attackbox-bait (with proxy)"
        warn "  - falco-modern-bpf"
        warn "  - attackbox-falco-adapter"
        warn "  - attackbox-egress-adapter"
        warn ""
        warn "Run with --verify to test metadata blocking, DNS, and NR endpoints"
    else
        echo ""
        ok "Preflight check complete (no changes made)"
        warn "Run with --apply to apply changes"
        warn "Run with --verify to test real validation (requires Linux + Docker + gVisor)"
    fi
}

main "$@"
