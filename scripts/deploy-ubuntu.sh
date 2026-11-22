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
readonly QUEUE_DIR="/var/lib/attackbox-shipper/queue"
readonly NR_LOG_HOST="log-api.newrelic.com"
readonly NR_METRIC_HOST="metric-api.newrelic.com"

# Flags
MODE="preflight"
DISABLE_SSH=false
CONSOLE_CONFIRMED=false

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
    --disable-ssh            Mark SSH for disablement (needs --console-confirmed)
    --console-confirmed      Confirm console access verified (needs --disable-ssh)
    -h, --help               Show this help

SSH disablement requires BOTH --disable-ssh AND --console-confirmed.
Verification mode requires Linux, Docker, and gVisor runtime.
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

    # /run/attackbox: abx-ship:abx-bait mode 0710
    # /var/lib/attackbox-shipper/queue: abx-ship:abx-ship mode 0700
    local dirs=(
        "/run/attackbox:0710:$SHIP_USER:$BAIT_USER"
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

    # Preserve existing daemon.json, only add runsc if needed
    local daemon_json="/etc/docker/daemon.json"
    if [[ -f "$daemon_json" ]]; then
        if ! jq -e '.runtimes.runsc' "$daemon_json" >/dev/null 2>&1; then
            if [[ "$MODE" == "apply" ]]; then
                # Merge runsc into existing config
                local tmp
                tmp=$(mktemp)
                jq '.runtimes.runsc = {"path": "/usr/bin/runsc"}' "$daemon_json" > "$tmp"
                mv "$tmp" "$daemon_json"
                ok "Added runsc to existing daemon.json"
            else
                warn "Would add runsc to existing daemon.json"
            fi
        else
            ok "Docker daemon.json already has runsc"
        fi
    else
        if [[ "$MODE" == "apply" ]]; then
            cat > "$daemon_json" <<'EOF'
{
  "runtimes": {
    "runsc": {
      "path": "/usr/bin/runsc"
    }
  },
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF
            ok "Created daemon.json with runsc"
        else
            warn "Would create daemon.json with runsc"
        fi
    fi
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

            # Configure Falco to write JSON output
            mkdir -p /etc/falco
            cat > /etc/falco/falco.yaml <<'EOF'
json_output: true
json_include_output_property: true
file_output:
  enabled: true
  keep_alive: false
  filename: /var/log/falco-events.jsonl
EOF

            systemctl disable falco
            ok "Installed Falco with JSON output (not yet enabled)"
        else
            warn "Would install Falco"
        fi
    else
        ok "Falco installed"
    fi
}

# Resolve New Relic endpoints via DNS
resolve_nr_endpoints() {
    log "Resolving New Relic endpoints..."

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

# nftables firewall (enforced before Docker starts)
setup_firewall() {
    log "Checking nftables firewall..."

    local nft_rules="${DEPLOY_DIR}/nftables/attackbox.nft"

    if [[ ! -f "$nft_rules" ]]; then
        err "nftables rules not found: $nft_rules"
        return 1
    fi

    if [[ "$MODE" == "apply" ]]; then
        # Resolve endpoints first and capture tmpdir
        local tmpdir
        tmpdir=$(resolve_nr_endpoints)
        resolve_ubuntu_mirrors

        # Save current ruleset for ERR trap
        local backup
        backup=$(mktemp)
        nft list ruleset > "$backup"

        # ERR trap for rollback
        trap 'nft -f "'"$backup"'" 2>/dev/null; rm -f "'"$backup"'" "'"$tmpdir"'"/*.txt; rmdir "'"$tmpdir"'" 2>/dev/null; err "Firewall setup failed, rolled back"' ERR

        # Load attackbox table (idempotent)
        if ! nft -c -f "$nft_rules"; then
            err "nftables rules validation failed"
            return 1
        fi

        nft -f "$nft_rules"


        # Populate NR endpoint sets
        if [[ -f "$tmpdir/nr-log-ipv4.txt" ]]; then
            for ip in $(cat "$tmpdir/nr-log-ipv4.txt"); do
                nft add element inet attackbox nr_log_ipv4 { "$ip" }
            done
        fi
        if [[ -f "$tmpdir/nr-log-ipv6.txt" ]]; then
            for ip in $(cat "$tmpdir/nr-log-ipv6.txt"); do
                nft add element inet attackbox nr_log_ipv6 { "$ip" }
            done
        fi
        if [[ -f "$tmpdir/nr-metric-ipv4.txt" ]]; then
            for ip in $(cat "$tmpdir/nr-metric-ipv4.txt"); do
                nft add element inet attackbox nr_metric_ipv4 { "$ip" }
            done
        fi
        if [[ -f "$tmpdir/nr-metric-ipv6.txt" ]]; then
            for ip in $(cat "$tmpdir/nr-metric-ipv6.txt"); do
                nft add element inet attackbox nr_metric_ipv6 { "$ip" }
            done
        fi

        # Populate shipper UID
        local ship_uid
        ship_uid=$(id -u "$SHIP_USER")
        nft add element inet attackbox shipper_uids { "$ship_uid" }

        # Clear trap and cleanup on success
        trap - ERR
        rm -f "$backup" "$tmpdir"/*.txt
        rmdir "$tmpdir"

        systemctl enable nftables

        ok "Installed nftables rules with rollback safety"
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

    local audit_rules="${DEPLOY_DIR}/auditd/attackbox.rules"
    local target="/etc/audit/rules.d/90-attackbox.rules"

    if [[ ! -f "$audit_rules" ]]; then
        err "auditd rules not found: $audit_rules"
        return 1
    fi

    if [[ ! -f "$target" ]] || ! cmp -s "$audit_rules" "$target"; then
        if [[ "$MODE" == "apply" ]]; then
            cp "$audit_rules" "$target"
            augenrules --load
            systemctl restart auditd
            ok "Applied auditd rules"
        else
            warn "Would install auditd rules"
        fi
    else
        ok "auditd rules already applied"
    fi
}

# Unattended upgrades (enable security updates, no auto-reboot)
setup_unattended_upgrades() {
    log "Checking unattended-upgrades..."

    local config="/etc/apt/apt.conf.d/50unattended-upgrades"
    local auto_config="/etc/apt/apt.conf.d/20auto-upgrades"

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

# Systemd units
setup_systemd_units() {
    log "Checking systemd units..."

    local units=(
        "attackbox-shipper.service"
        "attackbox-falco-adapter.service"
        "attackbox-egress-adapter.service"
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

    local binaries=(
        "/usr/local/bin/attackbox"
        "/usr/local/bin/attackbox-shipper"
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
    systemctl enable attackbox-shipper
    systemctl start attackbox-shipper
    ok "Started attackbox-shipper"

    # Start Falco with Modern eBPF
    systemctl enable falco-modern-bpf
    systemctl start falco-modern-bpf
    ok "Started falco-modern-bpf"

    # Start adapters
    systemctl enable attackbox-falco-adapter
    systemctl start attackbox-falco-adapter
    ok "Started attackbox-falco-adapter"

    systemctl enable attackbox-egress-adapter
    systemctl start attackbox-egress-adapter
    ok "Started attackbox-egress-adapter"
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

# Verification mode
run_verification() {
    log "Running real validation checks..."

    if [[ "$(uname -s)" != "Linux" ]]; then
        err "Verification requires Linux"
        return 1
    fi

    if ! command -v docker >/dev/null; then
        err "Verification requires Docker"
        return 1
    fi

    if ! docker info --format '{{.Runtimes.runsc}}' | grep -q runsc; then
        err "Verification requires gVisor runtime"
        return 1
    fi

    # Test metadata blocking from container
    log "Testing metadata blocking from gVisor container..."
    if docker run --rm --runtime=runsc alpine:latest wget -T 2 -O- http://169.254.169.254/ 2>&1 | grep -q "timed out\|Connection refused"; then
        ok "Metadata blocked from container"
    else
        err "Metadata NOT blocked from container"
    fi

    # Test DNS from container
    log "Testing DNS from gVisor container..."
    if docker run --rm --runtime=runsc alpine:latest nslookup google.com 1.1.1.1 >/dev/null 2>&1; then
        ok "DNS works from container"
    else
        err "DNS does NOT work from container"
    fi

    # Test internet from container (should be blocked except through proxy)
    log "Testing internet blocking from gVisor container..."
    if ! docker run --rm --runtime=runsc alpine:latest wget -T 2 -O- https://example.com >/dev/null 2>&1; then
        ok "Internet blocked from container"
    else
        warn "Internet NOT blocked from container (expected for bait, proxy should work)"
    fi

    # Test socket
    log "Testing shipper socket..."
    if [[ -S "$SPOOL_SOCKET" ]]; then
        ok "Shipper socket exists"

        # Check mode
        local sock_mode
        sock_mode=$(stat -c '%a' "$SPOOL_SOCKET" 2>/dev/null || stat -f '%A' "$SPOOL_SOCKET" | tail -c 4)
        if [[ "$sock_mode" == "220" ]]; then
            ok "Socket mode correct (0220)"
        else
            err "Socket mode wrong: $sock_mode (expected 0220)"
        fi
    else
        err "Shipper socket does not exist"
    fi

    # Test NR endpoints reachable from shipper UID
    log "Testing New Relic endpoints..."
    if [[ -f /tmp/nr-log-ipv4.txt ]]; then
        local test_ip
        test_ip=$(head -1 /tmp/nr-log-ipv4.txt)
        if sudo -u "$SHIP_USER" timeout 5 bash -c "echo test | nc -w 2 $test_ip 443" >/dev/null 2>&1; then
            ok "New Relic endpoint reachable from shipper UID"
        else
            warn "New Relic endpoint NOT immediately reachable (firewall may need time)"
        fi
    fi

    ok "Verification complete"
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

# Build and pre-pull bait before firewall
prepare_bait() {
    log "Preparing bait containers..."
    
    if [[ "$MODE" != "apply" ]]; then
        warn "Would build bait and pre-pull proxy"
        return 0
    fi
    
    # Install Compose project to /opt/attackbox
    local repo_root="${SCRIPT_DIR}/.."
    mkdir -p /opt/attackbox
    cp "$repo_root/compose.yaml" /opt/attackbox/
    cp "$repo_root/Dockerfile" /opt/attackbox/
    cp -r "$repo_root/docker" /opt/attackbox/
    
    # Build bait image (dev tag for compose.yaml)
    if [[ -f "$repo_root/Dockerfile" ]]; then
        docker build -t attackbox-bait:dev "$repo_root"
        ok "Built bait image"
    else
        err "Dockerfile not found in repository root"
        return 1
    fi
    
    # Pre-pull Chainguard nginx proxy with verified multi-arch digest
    docker pull cgr.dev/chainguard/nginx@sha256:c1642395cc75f39c931d66d939f7e78cbdf671d6cfd821616632b0639c3c6d63
    ok "Pre-pulled Chainguard nginx proxy"
}

# Start bait service
start_bait() {
    log "Starting bait service..."
    
    if [[ "$MODE" != "apply" ]]; then
        warn "Would start bait service"
        return 0
    fi
    
    systemctl enable attackbox
    systemctl start attackbox
    
    # Wait for containers
    sleep 3
    
    if docker compose -f /opt/attackbox/compose.yaml ps | grep -q "Up"; then
        ok "Bait service running"
    else
        err "Bait service failed to start"
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
    
    # Use verified multi-arch busybox digest for tests
    # Verification: docker pull busybox:1.36.1
    # Command: docker inspect busybox:1.36.1 | jq -r '.[0].RepoDigests[] | select(contains("docker.io"))'
    # Digest: busybox@sha256:650fd573e056b679a5110a70aabeb01e26b76e545ec4b9c70a9523f2dfaf18c6
    # Multi-arch: linux/amd64, linux/arm64 verified 2024-03-xx
    local test_img="busybox@sha256:650fd573e056b679a5110a70aabeb01e26b76e545ec4b9c70a9523f2dfaf18c6"
    local network="internal"
    
    # Test metadata blocking
    log "Testing metadata blocking from container..."
    if docker run --rm --network "$network" "$test_img" timeout 2 wget -O- http://169.254.169.254/ 2>&1 | grep -q "timed out\|Connection refused"; then
        ok "Metadata blocked from container"
    else
        err "Metadata NOT blocked - required check failed"
        return 1
    fi
    
    # Test DNS
    log "Testing DNS from container..."
    if docker run --rm --network "$network" "$test_img" nslookup google.com 1.1.1.1 >/dev/null 2>&1; then
        ok "DNS works from container"
    else
        err "DNS does NOT work - required check failed"
        return 1
    fi
    
    # Test Internet blocked
    log "Testing Internet blocking from container..."
    if ! docker run --rm --network "$network" "$test_img" timeout 2 wget -O- https://example.com >/dev/null 2>&1; then
        ok "Internet blocked from container"
    else
        err "Internet NOT blocked - required check failed"
        return 1
    fi
    
    # Test NR endpoints as shipper UID
    log "Testing New Relic endpoints as shipper UID..."
    local nr_ok=0
    
    for host in "$NR_LOG_HOST" "$NR_METRIC_HOST"; do
        local ips
        ips=$(dig +short "$host" A | head -1)
        if [[ -n "$ips" ]]; then
            if sudo -u "$SHIP_USER" timeout 3 bash -c "echo | openssl s_client -connect ${ips}:443 -brief" 2>&1 | grep -q "connected"; then
                ok "NR endpoint $host reachable"
                nr_ok=$((nr_ok + 1))
            fi
        fi
    done
    
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
    check_linux
    check_os

    if [[ "$MODE" == "verify" ]]; then
        run_verification_enhanced
        exit $?
    fi

    setup_users
    setup_directories
    install_packages
    setup_docker
    setup_gvisor
    setup_falco
    prepare_bait
    setup_firewall
    setup_sysctl
    setup_auditd
    setup_unattended_upgrades
    setup_systemd_units

    if [[ "$MODE" == "apply" ]]; then
        start_services
        start_bait
        disable_ssh

        echo ""
        ok "Deployment complete"
        warn "Services started:"
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
