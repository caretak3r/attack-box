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
test_no_broad_egress() { local nft="${SCRIPT_DIR}/../deploy/nftables/attackbox.nft"; grep -q "skuid 0.*tcp dport.*80.*443" "$nft" && grep -q "skuid @shipper_uids" "$nft"; }
test_nr_dns_resolution() { grep -q "resolve_nr_endpoints" "$DEPLOY_SCRIPT" && grep -q "NR_LOG_HOST" "$DEPLOY_SCRIPT" && grep -q "NR_METRIC_HOST" "$DEPLOY_SCRIPT"; }
test_shipper_uid_population() { grep -q "shipper_uids" "$DEPLOY_SCRIPT" && grep -q "nft add element.*shipper_uids" "$DEPLOY_SCRIPT"; }
test_firewall_before_docker() { local fw=$(sed -n '/^main()/,/^}/p' "$DEPLOY_SCRIPT" | grep -n "setup_firewall" | cut -d: -f1); local st=$(sed -n '/^main()/,/^}/p' "$DEPLOY_SCRIPT" | grep -n "start_services" | cut -d: -f1); [[ -n "$fw" && -n "$st" && "$fw" -lt "$st" ]]; }
test_socket_permissions() { grep -q "/run/attackbox:2710" "$DEPLOY_SCRIPT" && grep -q "SHIP_USER.*BAIT_USER" "$DEPLOY_SCRIPT"; }
test_adapter_pipelines() { local fa="${SCRIPT_DIR}/../deploy/systemd/attackbox-falco-adapter.service"; local ea="${SCRIPT_DIR}/../deploy/systemd/attackbox-egress-adapter.service"; grep -q "tail -n0 -F" "$fa" && grep -q "journalctl -kf" "$ea"; }
test_bait_unit_exists() { [[ -f "${SCRIPT_DIR}/../deploy/systemd/attackbox.service" ]] && [[ -f "${SCRIPT_DIR}/../compose.yaml" ]]; }
test_forward_direction() { local nft="${SCRIPT_DIR}/../deploy/nftables/attackbox.nft"; grep -q "iifname \"docker0\" ct state new.*drop" "$nft" && grep -q "iifname \"br-\*\" ct state new.*drop" "$nft"; }
test_both_nr_hosts_required() { grep -q "Failed to resolve.*NR_LOG_HOST" "$DEPLOY_SCRIPT" && grep -q "Failed to resolve.*NR_METRIC_HOST" "$DEPLOY_SCRIPT"; }
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
test_verification_internal_dns() { grep -q "nslookup attackbox-proxy" "$DEPLOY_SCRIPT"; }
test_verification_external_dns_blocked() { grep -q "External DNS blocked" "$DEPLOY_SCRIPT"; }
test_verification_curl_nr() { grep -q "sudo.*curl.*log_url\|metric_url" "$DEPLOY_SCRIPT"; }
test_verification_before_ssh() { local ver_line=$(grep -n "run_verification_enhanced" "$DEPLOY_SCRIPT" | grep -v "^[0-9]*:run_verification_enhanced()" | tail -1 | cut -d: -f1); local ssh_line=$(grep -n "disable_ssh" "$DEPLOY_SCRIPT" | grep -v "^[0-9]*:disable_ssh()" | head -1 | cut -d: -f1); [[ -n "$ver_line" && -n "$ssh_line" && "$ver_line" -lt "$ssh_line" ]]; }
test_no_host_attackbox_binary() { ! grep -q '"/usr/local/bin/attackbox"' "$DEPLOY_SCRIPT"; }
test_busybox_prepull() { grep -q "docker pull busybox@sha256:" "$DEPLOY_SCRIPT"; }
test_bootstrap_before_docker() { local boot_line=$(grep -n "bootstrap_firewall" "$DEPLOY_SCRIPT" | grep -v "^[0-9]*:bootstrap_firewall()" | head -1 | cut -d: -f1); local dock_line=$(grep -n "start_docker" "$DEPLOY_SCRIPT" | grep -v "^[0-9]*:start_docker()" | head -1 | cut -d: -f1); [[ -n "$boot_line" && -n "$dock_line" && "$boot_line" -lt "$dock_line" ]]; }
test_docker_before_prepare() { local dock_line=$(grep -n "start_docker" "$DEPLOY_SCRIPT" | grep -v "^[0-9]*:start_docker()" | head -1 | cut -d: -f1); local prep_line=$(grep -n "prepare_bait" "$DEPLOY_SCRIPT" | grep -v "^[0-9]*:prepare_bait()" | head -1 | cut -d: -f1); [[ -n "$dock_line" && -n "$prep_line" && "$dock_line" -lt "$prep_line" ]]; }
test_prepare_before_final_firewall() { local prep_line=$(grep -n "^[[:space:]]*prepare_bait$" "$DEPLOY_SCRIPT" | head -1 | cut -d: -f1); local fw_line=$(grep -n "^[[:space:]]*setup_firewall$" "$DEPLOY_SCRIPT" | head -1 | cut -d: -f1); [[ -n "$prep_line" && -n "$fw_line" && "$prep_line" -lt "$fw_line" ]]; }
test_attackbox_service_in_units() { grep -q '"attackbox.service"' "$DEPLOY_SCRIPT"; }
test_nr_exact_paths() { grep -q '/log/v1' "$DEPLOY_SCRIPT" && grep -q '/metric/v1' "$DEPLOY_SCRIPT"; }
test_mktemp_shipper_build() { ! grep -q '/tmp/shipper-build' "$DEPLOY_SCRIPT"; }
main() {
    echo "Attack-box deployment test suite - Full Semantic Controls"; echo "=========================================================="
    [[ ! -f "$DEPLOY_SCRIPT" ]] && { echo -e "${RED}✗${NC} Deploy script not found"; exit 1; }
    run_test "Help accessible" test_help_accessible
    run_test "Unknown option rejection" test_unknown_option_rejection
    run_test "SSH requires both confirmations" test_ssh_requires_both_flags
    run_test "--dry-run explicit alias" test_dryrun_explicit_alias
    run_test "--verify mode exists" test_verify_mode_exists
    run_test "No flush ruleset" test_no_flush_ruleset
    run_test "No broad egress" test_no_broad_egress
    run_test "NR DNS resolution" test_nr_dns_resolution
    run_test "Shipper UID populated" test_shipper_uid_population
    run_test "Firewall before Docker" test_firewall_before_docker
    run_test "Socket permissions" test_socket_permissions
    run_test "Adapter pipelines" test_adapter_pipelines
    run_test "Bait unit exists" test_bait_unit_exists
    run_test "Forward direction" test_forward_direction
    run_test "Both NR hosts required" test_both_nr_hosts_required
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
    run_test "Verification internal DNS" test_verification_internal_dns
    run_test "Verification external DNS blocked" test_verification_external_dns_blocked
    run_test "Verification uses curl for NR" test_verification_curl_nr
    run_test "Verification before SSH" test_verification_before_ssh
    run_test "No host attackbox binary" test_no_host_attackbox_binary
    run_test "Busybox prepull" test_busybox_prepull
    run_test "Bootstrap before Docker" test_bootstrap_before_docker
    run_test "Docker before prepare" test_docker_before_prepare
    run_test "Prepare before final firewall" test_prepare_before_final_firewall
    run_test "attackbox.service in units" test_attackbox_service_in_units
    run_test "NR exact paths" test_nr_exact_paths
    run_test "mktemp shipper build" test_mktemp_shipper_build
    echo ""; echo "=========================================================="; echo "Test Results"; echo "=========================================================="
    echo "Tests run:    $TESTS_RUN"; echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    if [[ $TESTS_FAILED -gt 0 ]]; then echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"; exit 1; else echo -e "Tests failed: 0"; echo ""; echo -e "${GREEN}✓${NC} All tests passed"; exit 0; fi
}
main "$@"
