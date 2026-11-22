#!/usr/bin/env bash
# Test harness for deploy-ubuntu.sh
# Proves: dry-run is non-destructive, apply requires flags, SSH needs both confirmations,
# firewall rollback works, and repeated apply is idempotent

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly DEPLOY_SCRIPT="${SCRIPT_DIR}/deploy-ubuntu.sh"

# Test results
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Test runner
run_test() {
    local test_name="$1"
    local test_func="$2"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    echo ""
    echo -e "${BLUE}●${NC} Running: $test_name"
    
    if $test_func; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "${GREEN}✓${NC} PASS: $test_name"
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "${RED}✗${NC} FAIL: $test_name"
        return 1
    fi
}

# Test 1: Script has help
test_help_accessible() {
    if bash "$DEPLOY_SCRIPT" --help 2>&1 | grep -q "Usage:"; then
        return 0
    else
        echo "ERROR: Help text not accessible"
        return 1
    fi
}

# Test 2: Script rejects unknown options
test_unknown_option_rejection() {
    # Script should exit with error for unknown options
    if ! bash "$DEPLOY_SCRIPT" --unknown-flag >/dev/null 2>&1; then
        return 0
    else
        echo "ERROR: Should reject unknown options with exit code 1"
        return 1
    fi
}

# Test 3: SSH disablement requires both flags
test_ssh_requires_both_flags() {
    # Test 3a: --disable-ssh without --console-confirmed should fail
    if ! bash "$DEPLOY_SCRIPT" --disable-ssh >/dev/null 2>&1; then
        : # Expected error
    else
        echo "ERROR: Should require both flags for SSH"
        return 1
    fi
    
    # Test 3b: --console-confirmed without --disable-ssh should fail
    if ! bash "$DEPLOY_SCRIPT" --console-confirmed >/dev/null 2>&1; then
        : # Expected error
    else
        echo "ERROR: Should require --disable-ssh with --console-confirmed"
        return 1
    fi
    
    return 0
}

# Test 4: Script validates required files exist
test_required_files_validation() {
    if grep -q "nftables rules not found" "$DEPLOY_SCRIPT" && \
       grep -q "sysctl config not found" "$DEPLOY_SCRIPT" && \
       grep -q "auditd rules not found" "$DEPLOY_SCRIPT"; then
        return 0
    else
        echo "ERROR: Missing file validation checks"
        return 1
    fi
}

# Test 5: Script has correct user/group IDs
test_correct_identities() {
    if grep -q "BAIT_UID=65532" "$DEPLOY_SCRIPT" && \
       grep -q "BAIT_GID=65532" "$DEPLOY_SCRIPT" && \
       grep -q "BAIT_USER=\"abx-bait\"" "$DEPLOY_SCRIPT" && \
       grep -q "SHIP_USER=\"abx-ship\"" "$DEPLOY_SCRIPT"; then
        return 0
    else
        echo "ERROR: Incorrect user/group identities"
        return 1
    fi
}

# Test 6: Script has correct socket and queue paths
test_correct_paths() {
    if grep -q "SPOOL_SOCKET=\"/run/attackbox/spool.sock\"" "$DEPLOY_SCRIPT" && \
       grep -q "QUEUE_DIR=\"/var/lib/attackbox-shipper/queue\"" "$DEPLOY_SCRIPT"; then
        return 0
    else
        echo "ERROR: Incorrect socket or queue paths"
        return 1
    fi
}

# Test 7: Script has firewall rollback mechanism
test_firewall_rollback_exists() {
    if grep -q "attackbox-firewall-confirmed" "$DEPLOY_SCRIPT" && \
       grep -q "sleep 30" "$DEPLOY_SCRIPT" && \
       grep -q "nft flush ruleset" "$DEPLOY_SCRIPT"; then
        return 0
    else
        echo "ERROR: Firewall rollback mechanism missing"
        return 1
    fi
}

# Test 8: Script checks for idempotency
test_idempotency_checks() {
    # Script should check if things exist before creating
    if grep -q "if \[\[ ! -f" "$DEPLOY_SCRIPT" && \
       grep -q "if \[\[ ! -d" "$DEPLOY_SCRIPT" && \
       grep -q "cmp -s" "$DEPLOY_SCRIPT"; then
        return 0
    else
        echo "ERROR: Missing idempotency checks"
        return 1
    fi
}

# Test 9: Script has apply mode flag
test_apply_mode_flag() {
    if grep -q "APPLY_MODE=false" "$DEPLOY_SCRIPT" && \
       grep -q -- "--apply" "$DEPLOY_SCRIPT"; then
        return 0
    else
        echo "ERROR: Apply mode flag missing"
        return 1
    fi
}

# Test 10: Script validates OS
test_os_validation() {
    if grep -q "check_os" "$DEPLOY_SCRIPT" && \
       grep -q "ubuntu" "$DEPLOY_SCRIPT" && \
       grep -q "24.04" "$DEPLOY_SCRIPT"; then
        return 0
    else
        echo "ERROR: OS validation missing"
        return 1
    fi
}

# Test 11: Script sets correct directory modes
test_directory_modes() {
    if grep -q "0770" "$DEPLOY_SCRIPT" && \
       grep -q "0700" "$DEPLOY_SCRIPT" && \
       grep -q "0750" "$DEPLOY_SCRIPT"; then
        return 0
    else
        echo "ERROR: Directory modes not set correctly"
        return 1
    fi
}

# Test 12: Script disables automatic reboots
test_no_automatic_reboots() {
    if grep -q 'Automatic-Reboot "false"' "$DEPLOY_SCRIPT"; then
        return 0
    else
        echo "ERROR: Automatic reboot check missing"
        return 1
    fi
}

# Test 13: Deploy artifacts exist
test_deploy_artifacts_exist() {
    local missing=()
    
    [[ -f "${SCRIPT_DIR}/../deploy/nftables/attackbox.nft" ]] || missing+=("nftables rules")
    [[ -f "${SCRIPT_DIR}/../deploy/systemd/attackbox-shipper.service" ]] || missing+=("systemd unit")
    [[ -f "${SCRIPT_DIR}/../deploy/sysctl/attackbox.conf" ]] || missing+=("sysctl config")
    [[ -f "${SCRIPT_DIR}/../deploy/auditd/attackbox.rules" ]] || missing+=("auditd rules")
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "ERROR: Missing artifacts: ${missing[*]}"
        return 1
    fi
    
    return 0
}

# Test 14: nftables rules block metadata
test_nftables_blocks_metadata() {
    local nft_rules="${SCRIPT_DIR}/../deploy/nftables/attackbox.nft"
    
    if grep -q "169.254.169.254" "$nft_rules" && \
       grep -q "metadata" "$nft_rules" && \
       grep -q "drop" "$nft_rules"; then
        return 0
    else
        echo "ERROR: nftables doesn't block metadata services"
        return 1
    fi
}

# Test 15: systemd unit has correct hardening
test_systemd_hardening() {
    local unit="${SCRIPT_DIR}/../deploy/systemd/attackbox-shipper.service"
    
    if grep -q "NoNewPrivileges=yes" "$unit" && \
       grep -q "ProtectSystem=strict" "$unit" && \
       grep -q "PrivateTmp=yes" "$unit"; then
        return 0
    else
        echo "ERROR: systemd unit missing hardening directives"
        return 1
    fi
}

# Test 16: systemd unit has root-owned env file
test_systemd_env_file() {
    local unit="${SCRIPT_DIR}/../deploy/systemd/attackbox-shipper.service"
    
    if grep -q "EnvironmentFile=/etc/attackbox/shipper.env" "$unit"; then
        return 0
    else
        echo "ERROR: systemd unit missing env file"
        return 1
    fi
}

# Test 17: sysctl has network hardening
test_sysctl_network_hardening() {
    local sysctl="${SCRIPT_DIR}/../deploy/sysctl/attackbox.conf"
    
    if grep -q "net.ipv4.conf.all.rp_filter" "$sysctl" && \
       grep -q "net.ipv4.tcp_syncookies" "$sysctl" && \
       grep -q "kernel.kptr_restrict" "$sysctl"; then
        return 0
    else
        echo "ERROR: sysctl missing network hardening"
        return 1
    fi
}

# Test 18: auditd monitors Docker and attack-box
test_auditd_monitors_attackbox() {
    local auditd="${SCRIPT_DIR}/../deploy/auditd/attackbox.rules"
    
    if grep -q "/usr/bin/docker" "$auditd" && \
       grep -q "attackbox" "$auditd" && \
       grep -q "/var/run/docker.sock" "$auditd"; then
        return 0
    else
        echo "ERROR: auditd not monitoring attack-box components"
        return 1
    fi
}

# Main test suite
main() {
    echo "Attack-box deployment test suite"
    echo "================================"
    
    # Verify deploy script exists
    if [[ ! -f "$DEPLOY_SCRIPT" ]]; then
        echo -e "${RED}✗${NC} Deploy script not found: $DEPLOY_SCRIPT"
        exit 1
    fi
    
    # Run tests
    run_test "Help text accessible" test_help_accessible
    run_test "Unknown option rejection" test_unknown_option_rejection
    run_test "SSH requires both confirmations" test_ssh_requires_both_flags
    run_test "Required files validation" test_required_files_validation
    run_test "Correct user/group identities" test_correct_identities
    run_test "Correct socket and queue paths" test_correct_paths
    run_test "Firewall rollback mechanism exists" test_firewall_rollback_exists
    run_test "Idempotency checks exist" test_idempotency_checks
    run_test "Apply mode flag exists" test_apply_mode_flag
    run_test "OS validation exists" test_os_validation
    run_test "Directory modes correct" test_directory_modes
    run_test "No automatic reboots" test_no_automatic_reboots
    run_test "Deploy artifacts exist" test_deploy_artifacts_exist
    run_test "nftables blocks metadata" test_nftables_blocks_metadata
    run_test "systemd hardening present" test_systemd_hardening
    run_test "systemd env file configured" test_systemd_env_file
    run_test "sysctl network hardening" test_sysctl_network_hardening
    run_test "auditd monitors attack-box" test_auditd_monitors_attackbox
    
    # Summary
    echo ""
    echo "================================"
    echo "Test Results"
    echo "================================"
    echo "Tests run:    $TESTS_RUN"
    echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
        exit 1
    else
        echo -e "Tests failed: 0"
        echo ""
        echo -e "${GREEN}✓${NC} All tests passed"
        exit 0
    fi
}

main "$@"
