#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() { printf 'public-bundle: %s\n' "$*" >&2; exit 1; }
[[ $# == 3 ]] || fail 'expected bundle path, SHA-256 and release commit'
bundle=$1
expected_sha=$2
commit=$3
[[ $bundle == /* && -f $bundle && ! -L $bundle ]] || fail 'bundle must be an absolute regular file'
[[ $expected_sha =~ ^[0-9a-f]{64}$ && $commit =~ ^[0-9a-f]{40}$ ]] || fail 'invalid digest or commit'
if command -v sha256sum >/dev/null 2>&1; then
  hash=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  hash=(shasum -a 256)
else
  fail 'SHA-256 tool unavailable'
fi

runtime_files=(
  compose.public.yaml deploy/public-compose.sh deploy/public-otel/config.yaml deploy/public-otel/prepare-socket.sh
  deploy/otel/version.env deploy/systemd/attackbox-public-otel.service deploy/systemd/attackbox-public.service
  scripts/verify-public-bundle.sh
)
payload=(manifest image.tar otelcol-contrib "${runtime_files[@]}")
tmp=$(mktemp -d "${TMPDIR:-/tmp}/attackbox-public-bundle.XXXXXXXX")
cleanup() {
  local file
  for file in "${payload[@]}" SHA256SUMS; do rm -f -- "$tmp/$file"; done
  rm -f -- "$tmp/bundle.tar" "$tmp/actual" "$tmp/expected" "$tmp/actual-checksums" "$tmp/expected-checksums"
  rmdir -- "$tmp/deploy/public-otel" "$tmp/deploy/otel" "$tmp/deploy/systemd" "$tmp/deploy" "$tmp/scripts" "$tmp" 2>/dev/null || true
}
trap cleanup EXIT
head -c 1073741825 "$bundle" > "$tmp/bundle.tar"
[[ $(wc -c < "$tmp/bundle.tar") -le 1073741824 ]] || fail 'bundle exceeds 1 GiB'
bundle=$tmp/bundle.tar
[[ $("${hash[@]}" "$bundle" | cut -d' ' -f1) == "$expected_sha" ]] || fail 'bundle checksum mismatch'
[[ $(head -c 9 "$bundle" | od -An -tx1 | tr -d '[:space:]') == 6d616e696665737400 ]] || fail 'bundle must be an uncompressed tar'
printf '%s\n' "${payload[@]}" SHA256SUMS | LC_ALL=C sort > "$tmp/expected"
tar -tf "$bundle" | LC_ALL=C sort > "$tmp/actual"
cmp -s "$tmp/expected" "$tmp/actual" || fail 'unexpected or duplicate bundle members'
LC_ALL=C tar --numeric-owner -tvf "$bundle" | awk '
  {
    if (substr($1, 1, 1) != "-") exit 1
    if ($2 ~ /^[0-9]+\/[0-9]+$/) size = $3
    else if ($2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/) size = $5
    else exit 1
    if (size !~ /^[0-9]+$/ || size > 1073741824) exit 1
    total += size
    if (total > 1073741824) exit 1
  }
  END {if (NR == 0) exit 1}
' || fail 'bundle contains non-regular files or oversized contents'
(cd -- "$tmp" && tar --no-same-owner --no-same-permissions -xf "$bundle") || fail 'bundle extraction failed'
[[ $(wc -c < "$tmp/SHA256SUMS") -le 4096 && $(wc -c < "$tmp/manifest") -le 256 ]] || fail 'oversized bundle metadata'
awk 'NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/ {bad=1} END {exit bad}' "$tmp/SHA256SUMS" || fail 'invalid checksum list'
printf '%s\n' "${payload[@]}" | LC_ALL=C sort > "$tmp/expected-checksums"
awk '{print $2}' "$tmp/SHA256SUMS" | LC_ALL=C sort > "$tmp/actual-checksums"
cmp -s "$tmp/expected-checksums" "$tmp/actual-checksums" || fail 'checksum list differs from bundle members'
(cd -- "$tmp" && "${hash[@]}" -c SHA256SUMS >/dev/null 2>&1) || fail 'bundle file checksum mismatch'
[[ $(awk 'END {print NR}' "$tmp/manifest") -eq 3 ]] || fail 'invalid bundle manifest'
[[ $(awk 'NR == 1 {print}' "$tmp/manifest") == "commit=$commit" ]] || fail 'release commit mismatch'
[[ $(awk 'NR == 2 {print}' "$tmp/manifest") == 'platform=linux/amd64' ]] || fail 'release platform mismatch'
image=$(awk 'NR == 3 && index($0, "image=") == 1 {print substr($0, 7)}' "$tmp/manifest")
[[ $image =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'invalid image digest'
printf '%s\n' "$image"
