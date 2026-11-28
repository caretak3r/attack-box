#!/usr/bin/env bash
set -euo pipefail
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly DEPLOY_SCRIPT="${SCRIPT_DIR}/deploy-ubuntu.sh"
TESTS_RUN=0; TESTS_PASSED=0; TESTS_FAILED=0
readonly RED='\033[0;31m'; readonly GREEN='\033[0;32m'; readonly BLUE='\033[0;34m'; readonly NC='\033[0m'
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); echo ""; echo -e "${BLUE}●${NC} Running: $1"; if $2; then TESTS_PASSED=$((TESTS_PASSED + 1)); echo -e "${GREEN}✓${NC} PASS: $1"; return 0; else TESTS_FAILED=$((TESTS_FAILED + 1)); echo -e "${RED}✗${NC} FAIL: $1"; return 1; fi; }
test_help_accessible() { bash "$DEPLOY_SCRIPT" --help 2>&1 | grep -q "Usage:"; }
test_unknown_option_rejection() { ! bash "$DEPLOY_SCRIPT" --unknown-flag >/dev/null 2>&1; }
test_ssh_requires_both_flags() { ! bash "$DEPLOY_SCRIPT" --disable-ssh >/dev/null 2>&1 && ! bash "$DEPLOY_SCRIPT" --console-confirmed >/dev/null 2>&1; }
test_dryrun_explicit_alias() { bash "$DEPLOY_SCRIPT" --help 2>&1 | grep -q "dry-run"; }
test_verify_mode_exists() { bash "$DEPLOY_SCRIPT" --help 2>&1 | grep -q "verify"; }
test_no_flush_ruleset() { local nft="${SCRIPT_DIR}/../deploy/nftables/attackbox.nft"; ! grep -q "flush ruleset" "$nft" && grep -q "flush table" "$nft"; }
test_host_dns_stub_switch() (
    local tmp MODE=preflight answer=''
    tmp=$(mktemp -d) || return
    trap 'rm -f "$tmp/stub" "$tmp/resolv" "$tmp/resolv.pre-attackbox" "$tmp/helper.sh"; rmdir "$tmp"' EXIT
    log() { :; }; warn() { :; }; ok() { :; }; err() { :; }
    dig() { printf '%s\n' "$answer"; }
    printf 'nameserver 108.61.10.10\n' > "$tmp/resolv"
    printf 'nameserver 127.0.0.53\n' > "$tmp/stub"
    awk '/^use_host_dns_stub\(\) \{/ {copy=1} copy {print} copy && /^}$/ {exit}' "$DEPLOY_SCRIPT" > "$tmp/helper.sh"
    source "$tmp/helper.sh"

    use_host_dns_stub "$tmp/resolv" "$tmp/stub" && [[ ! -L "$tmp/resolv" && ! -e "$tmp/resolv.pre-attackbox" ]] || return 1
    MODE=apply
    ! use_host_dns_stub "$tmp/resolv" "$tmp/stub" && [[ ! -L "$tmp/resolv" && ! -e "$tmp/resolv.pre-attackbox" ]] || return 1
    answer=192.0.2.10
    use_host_dns_stub "$tmp/resolv" "$tmp/stub" && [[ "$(readlink "$tmp/resolv")" == "$tmp/stub" ]] || return 1
    answer=''
    use_host_dns_stub "$tmp/resolv" "$tmp/stub" && grep -Fxq 'nameserver 108.61.10.10' "$tmp/resolv.pre-attackbox"
)
test_shipper_uid_population() { grep -q "shipper_uids" "$DEPLOY_SCRIPT" && grep -q "nft add element.*shipper_uids" "$DEPLOY_SCRIPT"; }
test_firewall_before_docker() { local fw=$(sed -n '/^main()/,/^}/p' "$DEPLOY_SCRIPT" | grep -n "setup_firewall" | cut -d: -f1); local st=$(sed -n '/^main()/,/^}/p' "$DEPLOY_SCRIPT" | grep -n "start_services" | cut -d: -f1); [[ -n "$fw" && -n "$st" && "$fw" -lt "$st" ]]; }
test_socket_permissions() { grep -q "/run/attackbox:2710" "$DEPLOY_SCRIPT" && grep -q "SHIP_USER.*BAIT_USER" "$DEPLOY_SCRIPT"; }
test_adapter_pipelines() {
    local fa="${SCRIPT_DIR}/../deploy/systemd/attackbox-falco-adapter.service"
    local ea="${SCRIPT_DIR}/../deploy/systemd/attackbox-egress-adapter.service"
    grep -q '^ExecStart=/usr/local/bin/attackbox-hostreader -source falco ' "$fa" &&
    grep -q '^ExecStart=/usr/local/bin/attackbox-hostreader -source journal ' "$ea" &&
    grep -q '^StateDirectory=attackbox-falco-reader$' "$fa" &&
    grep -q '^StateDirectory=attackbox-egress-reader$' "$ea" &&
    grep -q 'ATTACKBOX_HOST_RECEIPTS=true' "$DEPLOY_SCRIPT" &&
    grep -q 'for binary in attackbox-shipper attackbox-hostreader' "$DEPLOY_SCRIPT" &&
    grep -q 'systemctl restart attackbox-shipper' "$DEPLOY_SCRIPT" &&
    grep -q 'systemctl restart attackbox-falco-adapter' "$DEPLOY_SCRIPT"
}
test_bait_unit_exists() { [[ -f "${SCRIPT_DIR}/../deploy/systemd/attackbox.service" ]] && [[ -f "${SCRIPT_DIR}/../compose.yaml" ]]; }
test_forward_direction() {
    python3 - "${SCRIPT_DIR}/../deploy/nftables/attackbox.nft" <<'PYTEST'
import pathlib, sys
s = pathlib.Path(sys.argv[1]).read_text()
f = s.split('chain forward_early {', 1)[1].split('chain input_early {', 1)[0]
allow = 'ip saddr 172.30.0.3 ip daddr 172.30.0.2 tcp dport 8080 accept'
assert allow in f
for bridge in ('docker0', 'br-*'):
    deny = f'iifname "{bridge}" counter log prefix "CONTAINER-EGRESS-BLOCK: " drop'
    inbound = f'oifname "{bridge}" tcp dport {{ 8080, 8443 }} accept'
    assert f.index(allow) < f.index(deny) < f.index(inbound)
    assert deny in s.split('chain input_early {', 1)[1].split('chain output_policy {', 1)[0]
PYTEST
}
test_rollback_trap() { grep -q "trap.*ERR" "$DEPLOY_SCRIPT" && grep -q "trap - ERR" "$DEPLOY_SCRIPT"; }
test_no_attackbox_bait_latest() { ! grep -q "attackbox-bait:latest" "$DEPLOY_SCRIPT"; }
test_ssh_after_start_bait() { local ssh_line=$(grep -n "disable_ssh" "$DEPLOY_SCRIPT" | grep -v "^[0-9]*:disable_ssh()" | head -1 | cut -d: -f1); local bait_line=$(grep -n "start_bait" "$DEPLOY_SCRIPT" | grep -v "^[0-9]*:start_bait()" | head -1 | cut -d: -f1); [[ -n "$ssh_line" && -n "$bait_line" && "$bait_line" -lt "$ssh_line" ]]; }
test_no_nginxinc_image() { ! grep -q "nginxinc/" "$DEPLOY_SCRIPT"; }
test_verified_digest_in_verification() { grep -q "run_verification_enhanced" "$DEPLOY_SCRIPT" && grep -q "busybox@sha256:" "$DEPLOY_SCRIPT"; }
test_no_attackbox_listeners() { ! grep -q "ATTACKBOX_LISTENERS" "$DEPLOY_SCRIPT"; }
test_service_uses_root_compose() { grep -q "/opt/attackbox/compose.yaml" "${SCRIPT_DIR}/../deploy/systemd/attackbox.service"; }
test_uses_chainguard_nginx() { grep -q "cgr.dev/chainguard/nginx@sha256:" "$DEPLOY_SCRIPT"; }
test_mktemp_usage() { grep -q "mktemp" "$DEPLOY_SCRIPT"; }
test_separate_a_aaaa() { grep -q 'dig +short.*A | grep' "$DEPLOY_SCRIPT" && grep -q 'dig +short.*AAAA | grep' "$DEPLOY_SCRIPT"; }
test_prepare_bait() { grep -q "prepare_bait" "$DEPLOY_SCRIPT"; }
test_start_bait() { grep -q "start_bait" "$DEPLOY_SCRIPT"; }
test_ubuntu_mirrors() { grep -q "resolve_ubuntu_mirrors\|ubuntu_ipv4" "$DEPLOY_SCRIPT"; }
test_initial_security_updates_retry() (
    local tmp
    tmp=$(mktemp -d) || return
    trap 'rm -f "$tmp/stamp" "$tmp/update.sh"; rmdir "$tmp"' EXIT
    local MODE=preflight calls='' reboot_setting='' refresh_result=0 result=1
    log() { :; }; warn() { :; }; ok() { :; }; err() { :; }
    apt-config() { printf '%s' "$reboot_setting"; }
    apt-get() { calls+=a; return "$refresh_result"; }
    unattended-upgrade() { calls+=u; return "$result"; }
    awk '/^apply_initial_security_updates\(\) \{/ {copy=1} copy {print} copy && /^}$/ {exit}' "$DEPLOY_SCRIPT" > "$tmp/update.sh"
    source "$tmp/update.sh"

    apply_initial_security_updates "$tmp/stamp" && [[ -z "$calls" && ! -e "$tmp/stamp" ]] || return 1
    MODE=apply
    reboot_setting="reboot='true'"
    ! apply_initial_security_updates "$tmp/stamp" && [[ -z "$calls" && ! -e "$tmp/stamp" ]] || return 1
    reboot_setting=''
    refresh_result=1
    ! apply_initial_security_updates "$tmp/stamp" && [[ "$calls" == a && ! -e "$tmp/stamp" ]] || return 1
    refresh_result=0
    calls=''
    ! apply_initial_security_updates "$tmp/stamp" && [[ "$calls" == au && ! -e "$tmp/stamp" ]] || return 1
    result=0
    apply_initial_security_updates "$tmp/stamp" && [[ "$calls" == auau && -f "$tmp/stamp" ]] || return 1
    apply_initial_security_updates "$tmp/stamp" && [[ "$calls" == auau ]]
)
test_metadata_forward_blocking() { local nft="${SCRIPT_DIR}/../deploy/nftables/attackbox.nft"; grep -q "169.254.169.254" "$nft" && grep -q "forward_early" "$nft" && grep -q "priority -150" "$nft"; }
test_private_network_blocking() { local nft="${SCRIPT_DIR}/../deploy/nftables/attackbox.nft"; grep -q "10.0.0.0/8" "$nft" && grep -q "172.16.0.0/12" "$nft" && grep -q "192.168.0.0/16" "$nft"; }
test_no_alpine_anywhere() { ! grep -q "alpine" "$DEPLOY_SCRIPT"; }
test_gvisor_overlay_in_service() { grep -q "compose.gvisor.yaml" "${SCRIPT_DIR}/../deploy/systemd/attackbox.service"; }
test_runsc_host_uds_documented() { grep -q "host-uds=open" "${SCRIPT_DIR}/../compose.gvisor.yaml"; }
test_secret_installation() { grep -q "redaction.key\|server.crt\|server.key" "$DEPLOY_SCRIPT" && grep -q "/opt/attackbox/secrets" "$DEPLOY_SCRIPT"; }
test_shipper_export_installation() { grep -q "shipper-export" "$DEPLOY_SCRIPT" && grep -q "/usr/local/bin/attackbox-shipper" "$DEPLOY_SCRIPT"; }
test_mirror_population_after_table() { local resolve_line=$(grep -n "resolve_ubuntu_mirrors" "$DEPLOY_SCRIPT" | grep -v "^resolve_ubuntu_mirrors()" | head -1 | cut -d: -f1); local nft_line=$(grep -n "nft -f.*nft_rules" "$DEPLOY_SCRIPT" | head -1 | cut -d: -f1); [[ -n "$resolve_line" && -n "$nft_line" && "$nft_line" -lt "$resolve_line" ]]; }
test_no_ubuntu_mirrors_define() { ! grep -q "define ubuntu_mirrors" "${SCRIPT_DIR}/../deploy/nftables/attackbox.nft"; }
test_proxy_oifname_restriction() { local nft="${SCRIPT_DIR}/../deploy/nftables/attackbox.nft"; grep -q 'oifname "docker0"' "$nft" && grep -q 'oifname "br-\*"' "$nft"; }
test_verification_derives_network() { grep -q "docker network ls.*grep.*attackbox_internal" "$DEPLOY_SCRIPT"; }
test_verification_runsc() { grep -q "docker run.*--runtime=runsc.*--network" "$DEPLOY_SCRIPT"; }
test_verification_proxy_path() { grep -q 'https://127.0.0.1:8443/v1/models' "$DEPLOY_SCRIPT" && grep -q 'HTTPS proxy cannot reach bait' "$DEPLOY_SCRIPT"; }
test_verification_external_dns_blocked() { grep -q "External DNS blocked" "$DEPLOY_SCRIPT"; }
test_verification_before_ssh() { local ver_line=$(grep -n "run_verification_enhanced" "$DEPLOY_SCRIPT" | grep -v "^[0-9]*:run_verification_enhanced()" | tail -1 | cut -d: -f1); local ssh_line=$(grep -n "disable_ssh" "$DEPLOY_SCRIPT" | grep -v "^[0-9]*:disable_ssh()" | head -1 | cut -d: -f1); [[ -n "$ver_line" && -n "$ssh_line" && "$ver_line" -lt "$ssh_line" ]]; }
test_no_host_attackbox_binary() { ! grep -q '"/usr/local/bin/attackbox"' "$DEPLOY_SCRIPT"; }
test_busybox_prepull() { grep -q "docker pull busybox@sha256:" "$DEPLOY_SCRIPT"; }
test_public_gateway_restore() (
    local tmp MODE=apply enabled=0 fail=''
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    log() { :; }; ok() { :; }; err() { :; }
    systemctl() {
        if [[ "$1" == is-enabled ]]; then return "$enabled"; fi
        if [[ "$*" == "$fail" ]]; then return 1; fi
        printf '%s\n' "$*" >> "$tmp/calls"
    }
    awk '/^restore_public_gateway\(\) \{/ {copy=1} copy {print} copy && /^}$/ {exit}' "$DEPLOY_SCRIPT" > "$tmp/function"
    source "$tmp/function"

    restore_public_gateway || return 1
    [[ "$(cat "$tmp/calls")" == $'stop attackbox-public-otel.service\nstart attackbox-public.service' ]] || return 1
    fail='start attackbox-public.service'
    ! restore_public_gateway || return 1
    enabled=1; : > "$tmp/calls"
    restore_public_gateway || return 1
    [[ ! -s "$tmp/calls" ]] || return 1
)
test_release_version_label() (
    local tmp
    tmp=$(mktemp -d)
    ok() { :; }; err() { :; }
    systemctl() { printf '%s\n' "$*" >> "$tmp/calls"; }
    awk '/^set_release_version\(\) \{/ {copy=1} copy {print} copy && /^}/ {exit}' "$DEPLOY_SCRIPT" > "$tmp/function"
    source "$tmp/function"
    printf 'ATTACKBOX_HOST_ID=h1\nATTACKBOX_RELEASE_VERSION=old\nATTACKBOX_CAMPAIGN_ID=c1\n' > "$tmp/env"; chmod 600 "$tmp/env"
    set_release_version "$tmp/env" || return 1
    [[ ! -e "$tmp/calls" ]] || return 1
    ATTACKBOX_RELEASE_VERSION=abc123 set_release_version "$tmp/env" || return 1
    [[ "$(cat "$tmp/env")" == $'ATTACKBOX_HOST_ID=h1\nATTACKBOX_RELEASE_VERSION=abc123\nATTACKBOX_CAMPAIGN_ID=c1' ]] || return 1
    [[ "$(cat "$tmp/calls")" == 'try-restart attackbox-otel.service' && ! -e "$tmp/env.bak" ]] || return 1
    ATTACKBOX_RELEASE_VERSION=abc123 set_release_version "$tmp/env" || return 1
    [[ "$(wc -l < "$tmp/calls")" -eq 1 ]] || return 1
    ! ATTACKBOX_RELEASE_VERSION='a/b' set_release_version "$tmp/env" || return 1
    ATTACKBOX_RELEASE_VERSION=abc123 set_release_version "$tmp/absent" || return 1
    grep -q 'ATTACKBOX_RELEASE_VERSION=\$commit ./scripts/deploy-ubuntu.sh' "${SCRIPT_DIR}/vultr-launch.sh" || return 1
    rm -rf "$tmp"
)
test_deployment_id_label() (
    local tmp
    tmp=$(mktemp -d)
    ok() { :; }; err() { :; }
    awk '/^set_deployment_id\(\) \{/ {copy=1} copy {print} copy && /^}/ {exit}' "$DEPLOY_SCRIPT" > "$tmp/function"
    source "$tmp/function"
    printf 'ATTACKBOX_CAMPAIGN_ID=c1\nATTACKBOX_SENSOR_ID=h1\nATTACKBOX_DEPLOYMENT_ID=0123abc\n' > "$tmp/env"; chmod 600 "$tmp/env"
    set_deployment_id "$tmp/env" || return 1
    [[ "$(cat "$tmp/env")" == $'ATTACKBOX_CAMPAIGN_ID=c1\nATTACKBOX_SENSOR_ID=h1\nATTACKBOX_DEPLOYMENT_ID=c1' && ! -e "$tmp/env.bak" ]] || return 1
    [[ "$(stat -f %Lp "$tmp/env" 2>/dev/null || stat -c %a "$tmp/env")" == 600 ]] || return 1
    set_deployment_id "$tmp/env" || return 1
    printf 'ATTACKBOX_CAMPAIGN_ID=Bad/Id\nATTACKBOX_DEPLOYMENT_ID=0123abc\n' > "$tmp/bad"
    ! set_deployment_id "$tmp/bad" || return 1
    grep -qx 'ATTACKBOX_DEPLOYMENT_ID=0123abc' "$tmp/bad" || return 1
    printf 'ATTACKBOX_SENSOR_ID=h1\n' > "$tmp/none"
    set_deployment_id "$tmp/none" && set_deployment_id "$tmp/absent" || return 1
    [[ "$(grep -n '^        set_deployment_id$' "$DEPLOY_SCRIPT" | cut -d: -f1)" -lt "$(grep -n '^        start_services$' "$DEPLOY_SCRIPT" | cut -d: -f1)" ]] || return 1
    rm -rf "$tmp"
)
test_docker_before_prepare() { local dock_line=$(grep -n "start_docker" "$DEPLOY_SCRIPT" | grep -v "^[0-9]*:start_docker()" | head -1 | cut -d: -f1); local prep_line=$(grep -n "prepare_bait" "$DEPLOY_SCRIPT" | grep -v "^[0-9]*:prepare_bait()" | head -1 | cut -d: -f1); [[ -n "$dock_line" && -n "$prep_line" && "$dock_line" -lt "$prep_line" ]]; }
test_prepare_before_final_firewall() { local prep_line=$(grep -n "^[[:space:]]*prepare_bait$" "$DEPLOY_SCRIPT" | head -1 | cut -d: -f1); local fw_line=$(grep -n "^[[:space:]]*setup_firewall$" "$DEPLOY_SCRIPT" | head -1 | cut -d: -f1); [[ -n "$prep_line" && -n "$fw_line" && "$prep_line" -lt "$fw_line" ]]; }
test_attackbox_service_in_units() { grep -q '"attackbox.service"' "$DEPLOY_SCRIPT"; }
test_mktemp_shipper_build() { ! grep -q '/tmp/shipper-build' "$DEPLOY_SCRIPT"; }
test_socket_env_settings() { grep -q "ATTACKBOX_SPOOL_SOCKET" "$DEPLOY_SCRIPT" && grep -q "ATTACKBOX_RUNTIME_SOCKET" "$DEPLOY_SCRIPT" && grep -q "ATTACKBOX_EGRESS_SOCKET" "$DEPLOY_SCRIPT"; }
test_shipper_primary_group_bait() { grep -q "^Group=abx-bait$" "${SCRIPT_DIR}/../deploy/systemd/attackbox-shipper.service"; }
test_shipper_supplementary_group() { grep -q "^SupplementaryGroups=abx-ship$" "${SCRIPT_DIR}/../deploy/systemd/attackbox-shipper.service"; }
test_runtime_directory_mode_0710() { grep -q "^RuntimeDirectoryMode=0710$" "${SCRIPT_DIR}/../deploy/systemd/attackbox-shipper.service"; }
test_no_chgrp_prestart() { ! grep -q "ExecStartPre.*chgrp" "${SCRIPT_DIR}/../deploy/systemd/attackbox-shipper.service"; }
test_docs_no_max_clients() { ! grep -q "ATTACKBOX_SHIP_MAX_CLIENTS" "${SCRIPT_DIR}/../docs/operator.md"; }
test_docs_socket_paths() { grep -q "ATTACKBOX_SPOOL_SOCKET" "${SCRIPT_DIR}/../docs/operator.md" && grep -q "ATTACKBOX_RUNTIME_SOCKET" "${SCRIPT_DIR}/../docs/operator.md" && grep -q "ATTACKBOX_EGRESS_SOCKET" "${SCRIPT_DIR}/../docs/operator.md"; }
test_newrelic_migration() (
    local tmp MODE=apply
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    # Mock functions
    log() { :; }
    ok() { :; }
    warn() { :; }
    systemctl() {
        case "$*" in
            "is-active --quiet newrelic-infra.service") return 0 ;;
            "stop newrelic-infra.service") return 0 ;;
            "disable newrelic-infra.service") return 0 ;;
            *) return 1 ;;
        esac
    }
    dpkg-query() { printf 'install ok installed\n'; }
    apt-get() { return 0; }
    grep() { command grep "$@"; }
    cat() { command cat "$@"; }
    rm() { command rm "$@"; }

    # Create fixture NR files
    mkdir -p "$tmp/etc/newrelic-infra" "$tmp/etc/systemd/system/newrelic-infra.service.d" \
        "$tmp/etc/apt/sources.list.d" "$tmp/etc/apt/trusted.gpg.d" \
        "$tmp/etc/attackbox" "$tmp/etc/attackbox-public-otel" "$tmp/usr/local/bin"
    touch "$tmp/etc/newrelic-infra.yml" "$tmp/etc/newrelic-infra/agent.yml" \
        "$tmp/etc/systemd/system/newrelic-infra.service.d/override.conf" \
        "$tmp/etc/apt/sources.list.d/newrelic-infra.list" \
        "$tmp/etc/apt/trusted.gpg.d/newrelic-infra.gpg" "$tmp/usr/local/bin/newrelic" \
        "$tmp/etc/attackbox/otel-license.key" "$tmp/etc/attackbox-public-otel/license.key"

    # Create shipper.env with NR line and kept line
    cat > "$tmp/etc/attackbox/shipper.env" <<'ENV'
ATTACKBOX_CAMPAIGN_ID=test-campaign
ATTACKBOX_NR_LICENSE_KEY=0123456789abcdef0123456789abcdef01234567
ATTACKBOX_HOST_ID=test-host
ENV

    # Redirect paths in function
    local old_root="$tmp"
    awk '/^remove_newrelic_migration\(\) \{/,/^}$/' "$DEPLOY_SCRIPT" | \
        sed "s|/etc/|$tmp/etc/|g; s|/usr/|$tmp/usr/|g" > "$tmp/function"
    source "$tmp/function"

    # First run - should remove everything
    remove_newrelic_migration

    # Verify NR files removed
    [[ ! -e "$tmp/etc/newrelic-infra.yml" ]] || return 1
    [[ ! -e "$tmp/etc/newrelic-infra" ]] || return 1
    [[ ! -e "$tmp/etc/systemd/system/newrelic-infra.service.d" ]] || return 1
    [[ ! -e "$tmp/etc/apt/sources.list.d/newrelic-infra.list" ]] || return 1
    [[ ! -e "$tmp/etc/apt/trusted.gpg.d/newrelic-infra.gpg" ]] || return 1
    [[ ! -e "$tmp/etc/attackbox/otel-license.key" ]] || return 1
    [[ ! -e "$tmp/usr/local/bin/newrelic" ]] || return 1
    # The public release ledger owns its collector key; only its rollback removes it.
    [[ -e "$tmp/etc/attackbox-public-otel/license.key" ]] || return 1

    # Verify NR line removed from shipper.env but kept lines remain
    [[ -f "$tmp/etc/attackbox/shipper.env" ]] || return 1
    grep -q 'ATTACKBOX_CAMPAIGN_ID=test-campaign' "$tmp/etc/attackbox/shipper.env" || return 1
    grep -q 'ATTACKBOX_HOST_ID=test-host' "$tmp/etc/attackbox/shipper.env" || return 1
    ! grep -q 'ATTACKBOX_NR_LICENSE_KEY' "$tmp/etc/attackbox/shipper.env" || return 1

    # Second run - should be no-op and exit 0
    remove_newrelic_migration

    rm -rf "$tmp"
)

main() {
    echo "Attack-box deployment test suite - Full Semantic Controls"; echo "=========================================================="
    [[ ! -f "$DEPLOY_SCRIPT" ]] && { echo -e "${RED}✗${NC} Deploy script not found"; exit 1; }
    run_test "Help accessible" test_help_accessible
    run_test "Unknown option rejection" test_unknown_option_rejection
    run_test "SSH requires both confirmations" test_ssh_requires_both_flags
    run_test "--dry-run explicit alias" test_dryrun_explicit_alias
    run_test "--verify mode exists" test_verify_mode_exists
    run_test "No flush ruleset" test_no_flush_ruleset
    run_test "Host DNS switches only to a working stub and keeps the original" test_host_dns_stub_switch
    run_test "Shipper UID populated" test_shipper_uid_population
    run_test "Firewall before Docker" test_firewall_before_docker
    run_test "Socket permissions" test_socket_permissions
    run_test "Durable host reader deployment contract" test_adapter_pipelines
    run_test "Bait unit exists" test_bait_unit_exists
    run_test "Forward direction" test_forward_direction
    run_test "Rollback trap" test_rollback_trap
    run_test "No attackbox-bait:latest" test_no_attackbox_bait_latest
    run_test "SSH after start_bait" test_ssh_after_start_bait
    run_test "No nginxinc image" test_no_nginxinc_image
    run_test "Verified digest in verification" test_verified_digest_in_verification
    run_test "No ATTACKBOX_LISTENERS" test_no_attackbox_listeners
    run_test "Service uses root compose.yaml" test_service_uses_root_compose
    run_test "Uses Chainguard nginx" test_uses_chainguard_nginx
    run_test "mktemp usage" test_mktemp_usage
    run_test "Separate A/AAAA" test_separate_a_aaaa
    run_test "prepare_bait exists" test_prepare_bait
    run_test "start_bait exists" test_start_bait
    run_test "Ubuntu mirrors" test_ubuntu_mirrors
    run_test "First security update retries failures and skips after success" test_initial_security_updates_retry
    run_test "Metadata forward blocking" test_metadata_forward_blocking
    run_test "Private network blocking" test_private_network_blocking
    run_test "No alpine anywhere" test_no_alpine_anywhere
    run_test "gVisor overlay in service" test_gvisor_overlay_in_service
    run_test "runsc host-uds documented" test_runsc_host_uds_documented
    run_test "Secret installation" test_secret_installation
    run_test "Shipper export installation" test_shipper_export_installation
    run_test "Mirror population after table load" test_mirror_population_after_table
    run_test "No ubuntu_mirrors define" test_no_ubuntu_mirrors_define
    run_test "Proxy oifname restriction" test_proxy_oifname_restriction
    run_test "Verification derives network" test_verification_derives_network
    run_test "Verification uses runsc" test_verification_runsc
    run_test "Verification HTTPS proxy path" test_verification_proxy_path
    run_test "Verification external DNS blocked" test_verification_external_dns_blocked
    run_test "Verification before SSH" test_verification_before_ssh
    run_test "No host attackbox binary" test_no_host_attackbox_binary
    run_test "Busybox prepull" test_busybox_prepull
    run_test "Docker before prepare" test_docker_before_prepare
    run_test "Prepare before final firewall" test_prepare_before_final_firewall
    run_test "attackbox.service in units" test_attackbox_service_in_units
    run_test "mktemp shipper build" test_mktemp_shipper_build
    run_test "Socket env settings" test_socket_env_settings
    run_test "Shipper primary group bait" test_shipper_primary_group_bait
    run_test "Shipper supplementary group" test_shipper_supplementary_group
    run_test "Runtime directory mode 0710" test_runtime_directory_mode_0710
    run_test "No chgrp prestart" test_no_chgrp_prestart
    run_test "Docs no max_clients" test_docs_no_max_clients
    run_test "Docs socket paths" test_docs_socket_paths
    run_test "Public gateway restored after Docker stop" test_public_gateway_restore
    run_test "New Relic migration idempotent" test_newrelic_migration
    run_test "Release label follows the deploy" test_release_version_label
    run_test "Deployment label is the campaign ID" test_deployment_id_label
    echo ""; echo "=========================================================="; echo "Test Results"; echo "=========================================================="
    echo "Tests run:    $TESTS_RUN"; echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    if [[ $TESTS_FAILED -gt 0 ]]; then echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"; exit 1; else echo -e "Tests failed: 0"; echo ""; echo -e "${GREEN}✓${NC} All tests passed"; exit 0; fi
}
main "$@"
