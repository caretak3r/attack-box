#!/usr/bin/env bash
# Ubuntu 24.04 idempotent deployment for attack-box
# Non-destructive preflight by default; --apply for mutations
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

# Flags
APPLY_MODE=false
DISABLE_SSH=false
CONSOLE_CONFIRMED=false

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Ubuntu 24.04 deployment for attack-box honeypot.
Default: non-destructive preflight (no mutations).

Options:
    --apply                  Apply changes (required for mutations)
    --disable-ssh            Mark SSH for disablement (needs --console-confirmed)
    --console-confirmed      Confirm console access verified (needs --disable-ssh)
    -h, --help              Show this help

SSH disablement requires BOTH --disable-ssh AND --console-confirmed.
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
        --apply) APPLY_MODE=true; shift ;;
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

# User/group setup
setup_users() {
    log "Checking users and groups..."
    
    # abx-bait group and user
    if ! getent group "$BAIT_USER" >/dev/null; then
        if [[ "$APPLY_MODE" == true ]]; then
            groupadd --gid "$BAIT_GID" "$BAIT_USER"
            ok "Created group $BAIT_USER (GID $BAIT_GID)"
        else
            warn "Would create group $BAIT_USER (GID $BAIT_GID)"
        fi
    else
        ok "Group $BAIT_USER exists"
    fi
    
    if ! id "$BAIT_USER" >/dev/null 2>&1; then
        if [[ "$APPLY_MODE" == true ]]; then
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
        if [[ "$APPLY_MODE" == true ]]; then
            groupadd --system "$SHIP_GROUP"
            ok "Created group $SHIP_GROUP"
        else
            warn "Would create group $SHIP_GROUP"
        fi
    else
        ok "Group $SHIP_GROUP exists"
    fi
    
    if ! id "$SHIP_USER" >/dev/null 2>&1; then
        if [[ "$APPLY_MODE" == true ]]; then
            useradd --system --gid "$SHIP_GROUP" --no-create-home --shell /usr/sbin/nologin "$SHIP_USER"
            # Add abx-bait to abx-ship group for socket access
            usermod -a -G "$SHIP_GROUP" "$BAIT_USER"
            ok "Created user $SHIP_USER"
        else
            warn "Would create user $SHIP_USER"
        fi
    else
        ok "User $SHIP_USER exists"
    fi
}

# Directories
setup_directories() {
    log "Checking directories..."
    
    local dirs=(
        "/run/attackbox:0770:root:$SHIP_GROUP"
        "$QUEUE_DIR:0700:$SHIP_USER:$SHIP_GROUP"
        "/var/log/attackbox-shipper:0750:root:adm"
    )
    
    for entry in "${dirs[@]}"; do
        IFS=':' read -r dir mode owner group <<< "$entry"
        
        if [[ ! -d "$dir" ]]; then
            if [[ "$APPLY_MODE" == true ]]; then
                mkdir -p "$dir"
                chmod "$mode" "$dir"
                chown "$owner:$group" "$dir"
                ok "Created $dir ($mode $owner:$group)"
            else
                warn "Would create $dir ($mode $owner:$group)"
            fi
        else
            ok "Directory $dir exists"
        fi
    done
}

# Install packages
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
        if [[ "$APPLY_MODE" == true ]]; then
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

# Docker setup
setup_docker() {
    log "Checking Docker installation..."
    
    if ! command -v docker >/dev/null; then
        if [[ "$APPLY_MODE" == true ]]; then
            # Add Docker GPG key
            install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
            chmod a+r /etc/apt/keyrings/docker.gpg
            
            # Add Docker repository
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
            
            apt-get update -qq
            apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            ok "Installed Docker"
        else
            warn "Would install Docker"
        fi
    else
        ok "Docker installed: $(docker --version)"
    fi
}

# gVisor setup
setup_gvisor() {
    log "Checking gVisor (runsc)..."
    
    if ! command -v runsc >/dev/null; then
        if [[ "$APPLY_MODE" == true ]]; then
            # Add gVisor GPG key
            curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
            
            # Add gVisor repository
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
    
    # Docker daemon.json configuration
    local daemon_json="/etc/docker/daemon.json"
    local needs_config=false
    
    if [[ -f "$daemon_json" ]]; then
        if ! grep -q '"runsc"' "$daemon_json"; then
            needs_config=true
        fi
    else
        needs_config=true
    fi
    
    if [[ "$needs_config" == true ]]; then
        if [[ "$APPLY_MODE" == true ]]; then
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
            systemctl restart docker
            ok "Configured Docker daemon for gVisor"
        else
            warn "Would configure Docker daemon for gVisor"
        fi
    else
        ok "Docker daemon already configured for gVisor"
    fi
}

# Falco setup
setup_falco() {
    log "Checking Falco..."
    
    if ! command -v falco >/dev/null; then
        if [[ "$APPLY_MODE" == true ]]; then
            # Check for kernel headers
            if ! dpkg -l | grep -q "linux-headers-$(uname -r)"; then
                apt-get install -y "linux-headers-$(uname -r)"
            fi
            
            # Add Falco GPG key and repository
            curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
            echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" > /etc/apt/sources.list.d/falcosecurity.list
            
            apt-get update -qq
            apt-get install -y falco
            
            # Prefer Modern eBPF if supported
            if falco --modern-bpf --dry-run 2>&1 | grep -q "Modern BPF"; then
                warn "Falco Modern eBPF available but needs configuration"
            fi
            
            systemctl disable falco
            ok "Installed Falco (not yet enabled)"
        else
            warn "Would install Falco"
        fi
    else
        ok "Falco installed"
    fi
}

# nftables firewall
setup_firewall() {
    log "Checking nftables firewall..."
    
    local nft_conf="/etc/nftables.conf"
    local nft_rules="${DEPLOY_DIR}/nftables/attackbox.nft"
    
    if [[ ! -f "$nft_rules" ]]; then
        err "nftables rules not found: $nft_rules"
        return 1
    fi
    
    if [[ "$APPLY_MODE" == true ]]; then
        # Backup existing config
        if [[ -f "$nft_conf" ]]; then
            cp "$nft_conf" "${nft_conf}.backup.$(date +%s)"
        fi
        
        # Install our rules with rollback safety
        cp "$nft_rules" "$nft_conf"
        
        # Test load
        if ! nft -c -f "$nft_conf"; then
            err "nftables rules validation failed"
            # Restore backup if validation fails
            local backup
            backup=$(find "$(dirname "$nft_conf")" -name "$(basename "$nft_conf").backup.*" -type f 2>/dev/null | sort -r | head -1)
            if [[ -n "$backup" ]]; then
                cp "$backup" "$nft_conf"
            fi
            return 1
        fi
        
        # Apply with rollback timer
        log "Applying firewall rules with 30s rollback timer..."
        nft -f "$nft_conf"
        
        # Schedule rollback
        (
            sleep 30
            if [[ -f /tmp/attackbox-firewall-confirmed ]]; then
                rm /tmp/attackbox-firewall-confirmed
            else
                nft flush ruleset
                warn "Firewall rules rolled back (no confirmation)"
            fi
        ) &
        
        warn "Firewall loaded. Confirm connectivity within 30s or rules will rollback."
        warn "To confirm: touch /tmp/attackbox-firewall-confirmed"
        
        systemctl enable nftables
        ok "Installed nftables rules (pending confirmation)"
    else
        warn "Would install nftables rules from $nft_rules"
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
        if [[ "$APPLY_MODE" == true ]]; then
            cp "$sysctl_conf" "$target"
            sysctl -p "$target"
            ok "Applied sysctl hardening"
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
        if [[ "$APPLY_MODE" == true ]]; then
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

# Unattended upgrades
setup_unattended_upgrades() {
    log "Checking unattended-upgrades..."
    
    local config="/etc/apt/apt.conf.d/50unattended-upgrades"
    
    if [[ -f "$config" ]]; then
        if grep -q 'Automatic-Reboot "false"' "$config"; then
            ok "unattended-upgrades configured (no auto-reboot)"
        else
            if [[ "$APPLY_MODE" == true ]]; then
                # Ensure no automatic reboots
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
    else
        warn "unattended-upgrades config not found"
    fi
}

# Systemd units
setup_systemd_units() {
    log "Checking systemd units..."
    
    local units=(
        "attackbox-shipper.service"
    )
    
    for unit in "${units[@]}"; do
        local unit_file="${DEPLOY_DIR}/systemd/${unit}"
        local target="/etc/systemd/system/${unit}"
        
        if [[ ! -f "$unit_file" ]]; then
            err "Unit file not found: $unit_file"
            continue
        fi
        
        if [[ ! -f "$target" ]] || ! cmp -s "$unit_file" "$target"; then
            if [[ "$APPLY_MODE" == true ]]; then
                cp "$unit_file" "$target"
                systemctl daemon-reload
                ok "Installed $unit"
            else
                warn "Would install $unit"
            fi
        else
            ok "Unit $unit already installed"
        fi
    done
}

# SSH disablement
disable_ssh() {
    if [[ "$DISABLE_SSH" != true || "$CONSOLE_CONFIRMED" != true ]]; then
        return 0
    fi
    
    log "Disabling SSH and cloud-init..."
    
    if [[ "$APPLY_MODE" == true ]]; then
        systemctl stop ssh
        systemctl disable ssh
        systemctl mask ssh
        
        # Disable cloud-init
        touch /etc/cloud/cloud-init.disabled
        
        ok "SSH and cloud-init disabled"
        warn "Ensure provider console access is working!"
    else
        warn "Would disable SSH and cloud-init"
    fi
}

# Log rotation
setup_log_rotation() {
    log "Checking log rotation..."
    
    local logrotate_conf="/etc/logrotate.d/attackbox-shipper"
    
    if [[ ! -f "$logrotate_conf" ]]; then
        if [[ "$APPLY_MODE" == true ]]; then
            cat > "$logrotate_conf" <<'EOF'
/var/log/attackbox-shipper/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
EOF
            ok "Configured log rotation"
        else
            warn "Would configure log rotation"
        fi
    else
        ok "Log rotation already configured"
    fi
}

# Main execution
main() {
    log "Attack-box Ubuntu deployment"
    log "Mode: $([ "$APPLY_MODE" == true ] && echo "APPLY" || echo "DRY-RUN")"
    
    check_root
    check_os
    
    setup_users
    setup_directories
    install_packages
    setup_docker
    setup_gvisor
    setup_falco
    setup_firewall
    setup_sysctl
    setup_auditd
    setup_unattended_upgrades
    setup_systemd_units
    setup_log_rotation
    disable_ssh
    
    echo ""
    if [[ "$APPLY_MODE" == true ]]; then
        ok "Deployment complete"
        warn "Remember to:"
        warn "  1. Confirm firewall: touch /tmp/attackbox-firewall-confirmed"
        warn "  2. Create /etc/attackbox/shipper.env (root:root 0600)"
        warn "  3. Place binaries in /usr/local/bin/"
        warn "  4. Start services: systemctl start attackbox-shipper"
    else
        ok "Preflight check complete (no changes made)"
        warn "Run with --apply to apply changes"
    fi
}

main "$@"
