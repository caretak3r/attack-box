#!/bin/bash
set -euo pipefail

ARCHIVE_ROOT="${ATTACKBOX_EVIDENCE_ARCHIVE:-$HOME/.local/share/attackbox-evidence}"
SSH="${ATTACKBOX_SSH:-ssh}"
REMOTE_ROOT="${ATTACKBOX_REMOTE_ROOT:-}"
REMOTE_HOST="attackbox"
LOCK_DIR="$ARCHIVE_ROOT/.pull.lock"

cleanup() {
	rmdir "$LOCK_DIR" 2>/dev/null || true
}
trap cleanup EXIT

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
	echo "evidence-pull already running" >&2
	exit 1
fi

umask 077
mkdir -p "$ARCHIVE_ROOT"

files=0
bytes=0
while IFS= read -r line; do
	if [[ $line =~ ^sent\ ([0-9]+)\ bytes\ +received\ ([0-9]+)\ bytes ]]; then
		bytes=$((bytes + ${BASH_REMATCH[2]}))
	elif [[ $line != "" && $line != *"/"  && $line != "sending incremental file list" ]]; then
		files=$((files + 1))
	fi
done < <(rsync -av --relative -e "$SSH" \
	"$REMOTE_HOST:$REMOTE_ROOT/./var/lib/attackbox-public-capture/requests/" \
	"$REMOTE_HOST:$REMOTE_ROOT/./var/lib/attackbox-evidence/" \
	"$REMOTE_HOST:$REMOTE_ROOT/./var/log/attackbox-audit/" \
	"$REMOTE_HOST:$REMOTE_ROOT/./var/log/falco-events.jsonl" \
	"$ARCHIVE_ROOT/" 2>&1)

find "$ARCHIVE_ROOT" -type d -exec chmod 0700 {} +

echo "$files files, $bytes bytes"
