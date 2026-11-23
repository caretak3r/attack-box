#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
archive=${1:?supply the pinned native Collector archive}
cd "$repo_root"
shellcheck -x scripts/install-monitoring.sh deploy/otel/prepare-sockets.sh
bash -n scripts/install-monitoring.sh deploy/otel/prepare-sockets.sh
python3 -m unittest discover -s deploy/otel -p "test_*.py"
bash scripts/install-monitoring.sh --check --archive "$archive"
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
printf invalid > "$stage/invalid.tar.gz"
expect_fail() {
  if "$@" >"$stage/result" 2>&1; then
    echo "unexpected success: $*" >&2
    exit 1
  fi
}
expect_fail bash scripts/install-monitoring.sh
expect_fail bash scripts/install-monitoring.sh --check --apply
expect_fail bash scripts/install-monitoring.sh --archive
expect_fail bash scripts/install-monitoring.sh --check --archive "$stage/invalid.tar.gz"
grep -q 'SHA256 mismatch' "$stage/result"
expect_fail bash scripts/install-monitoring.sh --check --archive "$archive" --hostcollector-binary /missing
grep -q 'supplied together' "$stage/result"
expect_fail bash scripts/install-monitoring.sh --check --archive "$archive" --hostcollector-binary "$stage/invalid.tar.gz" --hostcollector-sha256 "$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$stage/invalid.tar.gz")"
grep -q 'Linux amd64 ELF' "$stage/result"
expect_fail bash deploy/otel/prepare-sockets.sh invalid
printf '%s\n' 'PASS: installer arguments, checksum rejection, static ELF gate, shellcheck and config validation'
