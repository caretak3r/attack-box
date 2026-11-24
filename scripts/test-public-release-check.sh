#!/usr/bin/env bash
set -euo pipefail
umask 077

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/attackbox-public-ci-test.XXXXXXXX")
sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
image=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
state=$tmp/state/attackbox-public-ci
receipt=$state/$sha-amd64.verified
cleanup() {
  rm -f -- "$tmp/bin/git" "$tmp/bin/docker" "$tmp/scripts/public-release-check.sh" "$receipt" "$state/target"
  rmdir -- "$state/check.lock" "$state" "$tmp/state" "$tmp/scripts" "$tmp/bin" "$tmp" 2>/dev/null || true
}
trap cleanup EXIT
mkdir -p -- "$tmp/bin" "$tmp/scripts" "$state"
cp -- "$root/scripts/public-release-check.sh" "$tmp/scripts/"
cat > "$tmp/bin/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ -z ${VULTR_API_KEY:-}${NEW_RELIC_API_KEY:-}${ATTACKBOX_NR_LICENSE_KEY:-}${NEW_RELIC_LICENSE_KEY:-} ]] || { echo 'credentials leaked to child' >&2; exit 1; }
case "$1 ${2:-}" in
  'rev-parse --verify') printf '%s\n' "$FAKE_SHA" ;;
  'rev-parse HEAD') printf '%s\n' "$FAKE_HEAD" ;;
  '-c gpg.minTrustLevel=fully') [[ ${3:-} == verify-commit && ${FAKE_SIGNED:-yes} == yes ]] || exit 1 ;;
  'rev-parse --absolute-git-dir') printf '%s\n' "$FAKE_GIT_DIR" ;;
  'status --porcelain') printf '%s' "${FAKE_DIRTY:-}" ;;
  *) printf 'unexpected git call\n' >&2; exit 1 ;;
esac
EOF
cat > "$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ -z ${VULTR_API_KEY:-}${NEW_RELIC_API_KEY:-}${ATTACKBOX_NR_LICENSE_KEY:-}${NEW_RELIC_LICENSE_KEY:-} ]] || { echo 'credentials leaked to child' >&2; exit 1; }
[[ ${1:-} == image && ${2:-} == inspect ]] || { printf 'unexpected docker call\n' >&2; exit 1; }
printf '%s\n' "$FAKE_METADATA"
EOF
chmod +x "$tmp/bin/git" "$tmp/bin/docker"
export PATH="$tmp/bin:$PATH" FAKE_SHA=$sha FAKE_HEAD=$sha FAKE_GIT_DIR=$tmp/state
export FAKE_METADATA="linux/amd64 65532:65532 [\"/attackbox-public\"] $image"
export COMMIT=$sha PLATFORM=linux/amd64 APPROVE=$sha
export VULTR_API_KEY=synthetic NEW_RELIC_API_KEY=synthetic ATTACKBOX_NR_LICENSE_KEY=synthetic NEW_RELIC_LICENSE_KEY=synthetic
script=$tmp/scripts/public-release-check.sh
checks=0
expect_failure() {
  local want=$1 output
  shift
  if output=$("$@" 2>&1); then
    printf 'unexpected success: %s\n' "$want" >&2; exit 1
  fi
  [[ $output == *"$want"* ]] || { printf 'wrong failure for %s: %s\n' "$want" "$output" >&2; exit 1; }
  checks=$((checks + 1))
}
expect_failure 'no successful public release record' bash "$script" authorize
printf '%s linux/amd64 %s\n' "$sha" "$image" > "$receipt"
[[ $(bash "$script" authorize) == "$image" ]] || { echo 'valid authorization failed' >&2; exit 1; }
checks=$((checks + 1))
expect_failure 'APPROVE must match' env APPROVE=wrong bash "$script" authorize
expect_failure 'PLATFORM=linux/amd64' env PLATFORM=linux/arm64 bash "$script" authorize
expect_failure 'full release SHA' env COMMIT=bad bash "$script" authorize
expect_failure 'release commit differs' env FAKE_HEAD=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb bash "$script" authorize
expect_failure 'signature is missing or untrusted' env FAKE_SIGNED=no bash "$script" authorize
expect_failure 'checkout has tracked changes' env FAKE_DIRTY=' M file' bash "$script" authorize
expect_failure 'image metadata changed' env FAKE_METADATA="linux/amd64 0:0 [\"/attackbox-public\"] $image" bash "$script" authorize
printf '%s linux/arm64 %s\n' "$sha" "$image" > "$receipt"
expect_failure 'release record does not match' bash "$script" authorize
printf '%s linux/amd64 %s\n' "$sha" "$image" > "$receipt"
mkdir -- "$state/check.lock"
expect_failure 'release check is in progress' bash "$script" authorize
rmdir -- "$state/check.lock"
mv -- "$receipt" "$state/target"
ln -s -- target "$receipt"
expect_failure 'no successful public release record' bash "$script" authorize
rm -- "$receipt"
mv -- "$state/target" "$receipt"
printf 'public release authorization: %s checks passed\n' "$checks"
