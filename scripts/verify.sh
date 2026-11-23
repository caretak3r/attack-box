#!/usr/bin/env bash
# Attack Box comprehensive verification gate.
# FINAL acceptance gate: all components must exist and pass.
# Use --partial for development with incomplete components.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

# Parse flags
PARTIAL=false
while [[ $# -gt 0 ]]; do
	case $1 in
		--partial)
			PARTIAL=true
			shift
			;;
		--help|-h)
			cat <<-EOF
			Usage: $0 [--partial]

			FINAL acceptance gate for Attack Box. All components must exist and pass.

			Flags:
			  --partial    Development mode: skip incomplete components instead of failing
			  --help       Show this message

			Checks:
			  - Format: gofmt, go vet
			  - Build: attackbox, attackbox-shipper (CGO_ENABLED=0, stripped)
			  - Tests: go test -race, go test with coverage
			  - Shell: shellcheck scripts/*.sh
			  - Smoke: existing three-persona live server
			  - Client matrix: OpenAI/Ollama compatibility
			  - Shipper: six-stream and full-metric integration
			  - Containers: Dockerfile build, compose config
			  - Deployment: Ubuntu, Vultr launcher and native bootstrap tests (requires Bats)
			  - Docs: operator guide, env consistency

			Exit 0 only when all checks pass. Prerequisites fail immediately.
			EOF
			exit 0
			;;
		*)
			echo "Unknown flag: $1" >&2
			echo "Use --help for usage" >&2
			exit 2
			;;
	esac
done

# Color output helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓${NC} $*"; }
fail() { echo -e "${RED}✗${NC} $*" >&2; exit 1; }
skip() { echo -e "${YELLOW}○${NC} $*"; }
info() { echo -e "${BLUE}●${NC} $*"; }

# Track overall status
declare -i TOTAL=0 PASSED=0 FAILED=0 SKIPPED=0

check() {
	local name=$1
	shift
	TOTAL+=1
	info "$name"
	if "$@"; then
		PASSED+=1
		pass "$name"
	else
		FAILED+=1
		fail "$name failed"
	fi
}

skip_check() {
	local name=$1 reason=$2
	TOTAL+=1
	SKIPPED+=1
	skip "$name: $reason"
}

require_or_skip() {
	local name=$1 condition=$2 message=$3
	if eval "$condition"; then
		return 0
	elif [[ $PARTIAL == true ]]; then
		skip_check "$name" "$message"
		return 1
	else
		fail "$name: $message (use --partial to skip)"
	fi
}

# Prerequisites
info "Attack Box verification gate"
if [[ $PARTIAL == true ]]; then
	info "Mode: PARTIAL (development)"
else
	info "Mode: FINAL (all components required)"
fi
info "Working directory: $root"
echo

# Check Go
if ! command -v go >/dev/null 2>&1; then
	fail "go not found in PATH (required)"
fi
pass "go $(go version | awk '{print $3}')"

# Check shellcheck
if ! command -v shellcheck >/dev/null 2>&1; then
	fail "shellcheck not found in PATH (required)"
fi
pass "shellcheck $(shellcheck --version | awk '/version:/ {print $2}')"

# Check Docker if container validation needed
if [[ $PARTIAL == false ]] && ! command -v docker >/dev/null 2>&1; then
	fail "docker not found in PATH (required for final gate)"
fi

echo
info "Format checks"
check "gofmt" bash -c '
	out=$(gofmt -l .)
	if [[ -n "$out" ]]; then
		echo "Files need formatting:" >&2
		echo "$out" >&2
		exit 1
	fi
'

check "go vet" go vet ./...

echo
info "Build verification"
check "attackbox build" bash -c '
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dev/null ./cmd/attackbox
'

if require_or_skip "attackbox-shipper build" "[[ -d cmd/attackbox-shipper ]]" "cmd/attackbox-shipper not implemented"; then
	check "attackbox-shipper build" bash -c '
		CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dev/null ./cmd/attackbox-shipper
	'
fi

echo
info "Test suite"
check "go test (race)" go test -race -count=1 ./...
check "go test (coverage)" go test -count=1 -coverprofile=/tmp/attackbox-coverage.out ./...

if [[ -f /tmp/attackbox-coverage.out ]]; then
	coverage=$(go tool cover -func=/tmp/attackbox-coverage.out | tail -1 | awk '{print $3}')
	info "Overall coverage: $coverage"
fi

echo
info "Shell scripts"
check "shellcheck" bash -c '
	shellcheck -S error scripts/*.sh
'

echo
info "Smoke test (three-persona live server)"
check "smoke.sh" ./scripts/smoke.sh

echo
info "Client compatibility matrix"
if require_or_skip "client matrix" "[[ -f scripts/client_matrix.py ]]" "scripts/client_matrix.py not found"; then
	check "client_matrix.py help" python3 scripts/client_matrix.py --help >/dev/null
	check "client matrix execution" python3 scripts/client_matrix.py
fi

echo
info "Shipper integration"
if require_or_skip "shipper integration" "[[ -d cmd/attackbox-shipper && -d internal/shipper ]]" "shipper not implemented"; then
	# Run shipper package tests
	check "shipper package tests" go test -race -count=1 ./internal/shipper/...

	# Require real integration test with six-stream and full-metric evidence in either package
	if grep -q "TestShipperIntegration\|TestSixStreams\|TestFullMetric" internal/shipper/*_test.go cmd/attackbox-shipper/*_test.go 2>/dev/null; then
		check "shipper six-stream integration" go test -race -count=1 -run 'Integration|SixStream|FullMetric' ./internal/shipper/... ./cmd/attackbox-shipper/...
	else
		fail "shipper integration: no TestShipperIntegration, TestSixStreams, or TestFullMetric found in internal/shipper/ or cmd/attackbox-shipper/"
	fi
fi

echo
info "Container validation"
# Support both compose.yaml and docker-compose.yml
compose_file=""
if [[ -f compose.yaml ]]; then
	compose_file="compose.yaml"
elif [[ -f docker-compose.yml ]]; then
	compose_file="docker-compose.yml"
fi

if require_or_skip "container files" "[[ -f Dockerfile && -n $compose_file ]]" "Dockerfile or compose file not present"; then
	# Clean up test image on exit
	trap 'docker rmi attackbox-verify-test attackbox-verify-shipper >/dev/null 2>&1 || true' EXIT
	check "Dockerfile build" docker build -t attackbox-verify-test .
	# Build the actual host binaries too; the default image only builds bait.
	check "Host shipper and reader build" docker build --target shipper-build -t attackbox-verify-shipper .
	check "docker compose config" docker compose -f "$compose_file" config >/dev/null
	check "gVisor compose config" docker compose -f "$compose_file" -f compose.gvisor.yaml config >/dev/null
fi

echo
info "Deployment validation"
if require_or_skip "native bootstrap tests" "command -v bats >/dev/null && [[ -f scripts/test-bootstrap-infrastructure.bats ]]" "install Bats and include the native bootstrap tests"; then
	check "native bootstrap tests" bats scripts/test-bootstrap-infrastructure.bats
	check "native agent configuration tests" python3 -B -m unittest discover -s deploy/newrelic -p 'test_*.py'
fi
if require_or_skip "deployment scripts" "[[ -f scripts/deploy-ubuntu.sh && -f scripts/test-deploy-ubuntu.sh ]]" "scripts/deploy-ubuntu.sh or test-deploy-ubuntu.sh not implemented"; then
	check "deploy-ubuntu.sh syntax" bash -n scripts/deploy-ubuntu.sh
	check "test-deploy-ubuntu.sh syntax" bash -n scripts/test-deploy-ubuntu.sh
	check "test-deploy-ubuntu.sh execution" scripts/test-deploy-ubuntu.sh
fi
if require_or_skip "vultr launch scripts" "[[ -f scripts/vultr-launch.sh && -f scripts/test-vultr-launch.sh ]]" "scripts/vultr-launch.sh or test-vultr-launch.sh not implemented"; then
	check "vultr-launch.sh syntax" bash -n scripts/vultr-launch.sh
	check "test-vultr-launch.sh execution" scripts/test-vultr-launch.sh
fi

echo
info "Documentation consistency"
check "implementation_plan.md exists" test -f implementation_plan.md
check "REMAINING_WORK.md exists" test -f REMAINING_WORK.md
check "SECURITY_FIXES.md exists" test -f SECURITY_FIXES.md

# Verify documented environment variables match config
if [[ -f cmd/attackbox/config.go ]]; then
	# Extract ATTACKBOX_* from config.go
	config_vars=$(grep -o 'ATTACKBOX_[A-Z_]*[A-Z]' cmd/attackbox/config.go | sort -u)
	config_count=$(echo "$config_vars" | wc -l | tr -d ' ')

	# Extract ATTACKBOX_* from implementation_plan.md
	if [[ -f implementation_plan.md ]]; then
		doc_vars=$(grep -o 'ATTACKBOX_[A-Z_]*' implementation_plan.md | sort -u)
		doc_count=$(echo "$doc_vars" | wc -l | tr -d ' ')

		# Check that all config vars are documented
		missing_docs=""
		while IFS= read -r var; do
			if ! echo "$doc_vars" | grep -q "^${var}$"; then
				missing_docs="${missing_docs}${var} "
			fi
		done <<< "$config_vars"

		if [[ -n $missing_docs ]]; then
			fail "Environment variables in config.go but not documented: $missing_docs"
		fi
		pass "Environment variables: $config_count in config, $doc_count documented"
	fi
fi

# Require operator documentation in FINAL mode
if [[ $PARTIAL == false ]]; then
	if require_or_skip "operator docs" "[[ -f docs/operator.md ]]" "docs/operator.md not present"; then
		check "docs/operator.md exists" test -f docs/operator.md
	fi
	if require_or_skip "architecture docs" "[[ -f docs/architecture.md ]]" "docs/architecture.md not present"; then
		check "docs/architecture.md exists" test -f docs/architecture.md
	fi
	if require_or_skip "New Relic runbook" "[[ -f docs/newrelic-runbook.md ]]" "docs/newrelic-runbook.md not present"; then
		check "docs/newrelic-runbook.md exists" test -f docs/newrelic-runbook.md
	fi
	if require_or_skip "New Relic artifacts" "[[ -d newrelic && -n \$(find newrelic -type f 2>/dev/null) ]]" "newrelic/ dashboard/alert artifacts not present"; then
		artifact_count=$(find newrelic -type f 2>/dev/null | wc -l | tr -d ' ')
		pass "New Relic artifacts: $artifact_count files in newrelic/"
	fi
fi

echo
info "=================="
info "Verification Summary"
info "=================="
echo -e "Total:   $TOTAL"
echo -e "${GREEN}Passed:  $PASSED${NC}"
if [[ $SKIPPED -gt 0 ]]; then
	echo -e "${YELLOW}Skipped: $SKIPPED${NC}"
	if [[ $PARTIAL == false ]]; then
		fail "FINAL gate cannot have skipped checks"
	fi
fi
if [[ $FAILED -gt 0 ]]; then
	echo -e "${RED}Failed:  $FAILED${NC}"
	echo
	fail "Verification gate FAILED"
fi

echo
if [[ $SKIPPED -gt 0 ]]; then
	skip "PARTIAL gate complete (run without --partial when all components ready)"
else
	pass "FINAL gate PASSED"
fi
exit 0
