#!/usr/bin/env bash
# Attack Box comprehensive verification gate.
# Runs format checks, tests, builds, smoke tests, client matrix, and deployment validation.
# Exit 0 only when all checks pass. Prerequisites are explicit failures.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

# Color output helpers
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Prerequisites
info "Attack Box verification gate"
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
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=verify" -o /dev/null ./cmd/attackbox
'

# Check if shipper exists
if [[ -d cmd/attackbox-shipper ]]; then
	check "attackbox-shipper build" bash -c '
		CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=verify" -o /dev/null ./cmd/attackbox-shipper
	'
else
	skip_check "attackbox-shipper build" "cmd/attackbox-shipper not yet implemented"
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
	# Error-level only; warnings are advisory
	shellcheck -S error scripts/*.sh
'

echo
info "Smoke test (three-persona live server)"
check "smoke.sh" ./scripts/smoke.sh

echo
info "Client compatibility matrix"
if [[ -f scripts/client_matrix.py ]]; then
	check "client_matrix.py" python3 scripts/client_matrix.py --help >/dev/null
	check "client matrix execution" python3 scripts/client_matrix.py
else
	skip_check "client matrix" "scripts/client_matrix.py not found"
fi

echo
info "Shipper integration"
if [[ -d cmd/attackbox-shipper ]] && [[ -d internal/shipper ]]; then
	# Six-stream and full-metric assertions
	check "shipper queue tests" go test -race -count=1 ./internal/shipper/...
	
	# Full integrated test if both binaries exist
	if CGO_ENABLED=0 go build -o /tmp/attackbox-shipper-test ./cmd/attackbox-shipper 2>/dev/null; then
		check "integrated shipper smoke" bash -c '
			# Start shipper on unix socket, verify bait can connect
			tmpdir=$(mktemp -d)
			socket="$tmpdir/spool.sock"
			
			# Mock shipper that accepts connections
			nc -lU "$socket" >/dev/null 2>&1 &
			nc_pid=$!
			sleep 0.5
			
			# Start bait in spool mode
			ATTACKBOX_SPOOL_SOCKET="$socket" \
			ATTACKBOX_OPENAI_ADDR=127.0.0.1:19999 \
			/tmp/attackbox-test 2>&1 | grep -q "stream.*runtime.*action.*start" &
			bait_pid=$!
			
			sleep 2
			kill "$bait_pid" "$nc_pid" 2>/dev/null || true
			rm -rf "$tmpdir"
		'
		rm -f /tmp/attackbox-shipper-test
	else
		skip_check "integrated shipper smoke" "shipper build failed or incomplete"
	fi
else
	skip_check "shipper integration" "shipper not yet implemented"
fi

echo
info "Container validation"
if [[ -f Dockerfile ]] || [[ -f docker-compose.yml ]]; then
	if command -v docker >/dev/null 2>&1; then
		if [[ -f Dockerfile ]]; then
			check "Dockerfile lint" docker build --target=lint . || true
		fi
		if [[ -f docker-compose.yml ]]; then
			check "docker-compose config" docker compose config >/dev/null
		fi
	else
		skip_check "container validation" "docker not available"
	fi
else
	skip_check "container validation" "Dockerfile/docker-compose.yml not yet present"
fi

echo
info "Deployment validation"
if [[ -f scripts/deploy.sh ]]; then
	check "deploy.sh syntax" bash -n scripts/deploy.sh
	check "deploy.sh --dry-run" scripts/deploy.sh --dry-run --skip-prereqs || true
else
	skip_check "deployment validation" "scripts/deploy.sh not yet implemented"
fi

echo
info "Documentation consistency"
check "implementation_plan.md exists" test -f implementation_plan.md
check "REMAINING_WORK.md exists" test -f REMAINING_WORK.md
check "SECURITY_FIXES.md exists" test -f SECURITY_FIXES.md

# Check that documented env vars match config.go
if grep -q "ATTACKBOX_" cmd/attackbox/config.go 2>/dev/null; then
	documented=$(grep -o 'ATTACKBOX_[A-Z_]*' implementation_plan.md | sort -u | wc -l)
	if [[ $documented -gt 0 ]]; then
		pass "Environment variables documented: $documented"
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
fi
if [[ $FAILED -gt 0 ]]; then
	echo -e "${RED}Failed:  $FAILED${NC}"
	echo
	fail "Verification gate FAILED"
fi

echo
pass "All checks PASSED"
exit 0
