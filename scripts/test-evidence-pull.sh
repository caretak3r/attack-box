#!/bin/bash
set -euo pipefail

FIXTURE="$(mktemp -d)"
ARCHIVE="$(mktemp -d)"
trap 'rm -rf "$FIXTURE" "$ARCHIVE"' EXIT

mkdir -p "$FIXTURE/var/lib/attackbox-public-capture/requests"
mkdir -p "$FIXTURE/var/lib/attackbox-evidence/shipper"
mkdir -p "$FIXTURE/var/log/attackbox-audit"
echo "test-capture" > "$FIXTURE/var/lib/attackbox-public-capture/requests/capture-20261128.jsonl"
echo "test-evidence" > "$FIXTURE/var/lib/attackbox-evidence/shipper/events-20261128.jsonl"
echo "test-audit" > "$FIXTURE/var/log/attackbox-audit/audit.log"
echo "test-falco" > "$FIXTURE/var/log/falco-events.jsonl"

# Simple fake SSH that just execs the command locally
FAKE_SSH="$(mktemp)"
cat > "$FAKE_SSH" <<'EOSSH'
#!/bin/bash
shift  # skip hostname
exec "$@"
EOSSH
chmod +x "$FAKE_SSH"

export ATTACKBOX_REMOTE_ROOT="$FIXTURE"
export ATTACKBOX_EVIDENCE_ARCHIVE="$ARCHIVE"
export ATTACKBOX_SSH="$FAKE_SSH"

output=$(bash scripts/evidence-pull.sh)

if [[ ! -f "$ARCHIVE/var/lib/attackbox-public-capture/requests/capture-20261128.jsonl" ]]; then
	echo "FAIL: capture file not mirrored" >&2
	exit 1
fi

if [[ ! -f "$ARCHIVE/var/lib/attackbox-evidence/shipper/events-20261128.jsonl" ]]; then
	echo "FAIL: evidence file not mirrored" >&2
	exit 1
fi

if [[ ! -f "$ARCHIVE/var/log/attackbox-audit/audit.log" ]]; then
	echo "FAIL: audit file not mirrored" >&2
	exit 1
fi

if [[ ! -f "$ARCHIVE/var/log/falco-events.jsonl" ]]; then
	echo "FAIL: falco file not mirrored" >&2
	exit 1
fi

dir_mode=$(stat -f "%Lp" "$ARCHIVE/var" 2>/dev/null || stat -c "%a" "$ARCHIVE/var" 2>/dev/null)
if [[ "$dir_mode" != "700" ]]; then
	echo "FAIL: directory mode is $dir_mode, expected 700" >&2
	exit 1
fi

rm "$FIXTURE/var/lib/attackbox-public-capture/requests/capture-20261128.jsonl"
bash scripts/evidence-pull.sh >/dev/null

if [[ ! -f "$ARCHIVE/var/lib/attackbox-public-capture/requests/capture-20261128.jsonl" ]]; then
	echo "FAIL: file deleted on host was deleted in archive (should be kept)" >&2
	exit 1
fi

if ! echo "$output" | grep -q "files"; then
	echo "FAIL: output missing file count" >&2
	exit 1
fi

if ! echo "$output" | grep -q "bytes"; then
	echo "FAIL: output missing byte count" >&2
	exit 1
fi

if echo "$output" | grep -iq "test-"; then
	echo "FAIL: output contains file content" >&2
	exit 1
fi

LOCK_TEST="$(mktemp -d)"
trap 'rm -rf "$FIXTURE" "$ARCHIVE" "$LOCK_TEST"' EXIT
export ATTACKBOX_EVIDENCE_ARCHIVE="$LOCK_TEST"
mkdir -p "$LOCK_TEST/.pull.lock"

if output=$(bash scripts/evidence-pull.sh 2>&1) || echo "$output" | grep -q "already running"; then
	echo "PASS: lock test"
else
	echo "FAIL: did not detect running instance" >&2
	exit 1
fi

echo "all tests passed"
