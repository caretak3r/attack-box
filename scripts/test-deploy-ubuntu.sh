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
test_no_flush_ruleset() { local nft="${SCRIPT_DIR}/../deploy/nftables/attackbox.nft"; ! grep -q "flush ruleset" "$nft" && grep -q "table inet attackbox" "$nft"; }
test_no_broad_egress() { local nft="${SCRIPT_DIR}/../deploy/nftables/attackbox.nft"; ! grep -E "tcp dport \{.*80.*443.*\} accept" "$nft" | grep -qv "^#" && grep -q "skuid @shipper_uids" "$nft"; }
test_nr_dns_resolution() { grep -q "resolve_nr_endpoints" "$DEPLOY_SCRIPT" && grep -q "NR_LOG_HOST" "$DEPLOY_SCRIPT" && grep -q "NR_METRIC_HOST" "$DEPLOY_SCRIPT"; }
test_shipper_uid_population() { grep -q "shipper_uids" "$DEPLOY_SCRIPT" && grep -q "nft add element.*shipper_uids" "$DEPLOY_SCRIPT"; }
test_firewall_before_docker() { local fw=$(sed -n '/^main()/,/^}/p' "$DEPLOY_SCRIPT" | grep -n "setup_firewall" | cut -d: -f1); local st=$(sed -n '/^main()/,/^}/p' "$DEPLOY_SCRIPT" | grep -n "start_services" | cut -d: -f1); [[ -n "$fw" && -n "$st" && "$fw" -lt "$st" ]]; }
test_socket_permissions() { grep -q "/run/attackbox:0710" "$DEPLOY_SCRIPT" && grep -q "SHIP_USER.*BAIT_USER" "$DEPLOY_SCRIPT"; }
test_adapter_units_exist() { [[ -f "${SCRIPT_DIR}/../deploy/systemd/attackbox-falco-adapter.service" ]] && [[ -f "${SCRIPT_DIR}/../deploy/systemd/attackbox-egress-adapter.service" ]]; }
test_falco_output() { grep -q "file_output" "$DEPLOY_SCRIPT" || [[ -f "${SCRIPT_DIR}/../deploy/systemd/attackbox-falco-adapter.service" ]]; }
test_rollback_safety() { grep -q "nft list ruleset.*backup" "$DEPLOY_SCRIPT" && ! grep -q "nft flush ruleset" "$DEPLOY_SCRIPT"; }
test_sysctl_ip_forward() { grep -q "net.ipv4.ip_forward = 1" "${SCRIPT_DIR}/../deploy/sysctl/attackbox.conf"; }
test_no_dangerous_sysctl() { local sc="${SCRIPT_DIR}/../deploy/sysctl/attackbox.conf"; ! grep -q "overcommit_memory = 1" "$sc" && ! grep -q "rmem_max = 134217728" "$sc" && ! grep -q "tcp_timestamps = 0" "$sc"; }
test_daemon_json_preservation() { grep -q "jq.*daemon.json" "$DEPLOY_SCRIPT" || grep -q "if.*daemon.json.*then" "$DEPLOY_SCRIPT"; }
test_security_updates() { grep -q "APT::Periodic::Unattended-Upgrade" "$DEPLOY_SCRIPT" || grep -q "20auto-upgrades" "$DEPLOY_SCRIPT"; }
test_journald_config() { [[ -f "${SCRIPT_DIR}/../deploy/systemd/journald-attackbox.conf" ]]; }
test_binaries_checked() { grep -q "check_binaries" "$DEPLOY_SCRIPT"; }
test_shipper_env_required() { grep -q "check_shipper_env" "$DEPLOY_SCRIPT" && grep -q "0600" "$DEPLOY_SCRIPT"; }
test_directory_safety() { grep -q "check_directory_safety" "$DEPLOY_SCRIPT"; }
test_no_trailing_whitespace() { ! grep " $" "$DEPLOY_SCRIPT" >/dev/null 2>&1 && ! grep " $" "${SCRIPT_DIR}/../deploy/nftables/attackbox.nft" >/dev/null 2>&1 && ! grep " $" "${SCRIPT_DIR}/../deploy/sysctl/attackbox.conf" >/dev/null 2>&1; }
test_metadata_forward_blocking() { local nft="${SCRIPT_DIR}/../deploy/nftables/attackbox.nft"; grep -q "169.254.169.254" "$nft" && grep -q "forward" "$nft" && grep -q "priority -150" "$nft"; }
test_private_network_blocking() { local nft="${SCRIPT_DIR}/../deploy/nftables/attackbox.nft"; grep -q "10.0.0.0/8" "$nft" && grep -q "172.16.0.0/12" "$nft" && grep -q "192.168.0.0/16" "$nft"; }
main() {
    echo "Attack-box deployment test suite - Semantic Controls"; echo "===================================================="
    [[ ! -f "$DEPLOY_SCRIPT" ]] && { echo -e "${RED}✗${NC} Deploy script not found: $DEPLOY_SCRIPT"; exit 1; }
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
    run_test "Adapter units exist" test_adapter_units_exist
    run_test "Falco output" test_falco_output
    run_test "Rollback safety" test_rollback_safety
    run_test "sysctl ip_forward" test_sysctl_ip_forward
    run_test "No dangerous sysctl" test_no_dangerous_sysctl
    run_test "daemon.json preserved" test_daemon_json_preservation
    run_test "Security updates" test_security_updates
    run_test "Journald config" test_journald_config
    run_test "Binaries checked" test_binaries_checked
    run_test "shipper.env required" test_shipper_env_required
    run_test "Directory safety" test_directory_safety
    run_test "No trailing whitespace" test_no_trailing_whitespace
    run_test "Metadata forward blocking" test_metadata_forward_blocking
    run_test "Private network blocking" test_private_network_blocking
    echo ""; echo "===================================================="; echo "Test Results"; echo "===================================================="
    echo "Tests run:    $TESTS_RUN"; echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    if [[ $TESTS_FAILED -gt 0 ]]; then echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"; exit 1; else echo -e "Tests failed: 0"; echo ""; echo -e "${GREEN}✓${NC} All tests passed"; exit 0; fi
}
main "$@"
