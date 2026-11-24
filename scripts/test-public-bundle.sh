#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

docker run -i --rm --pull=never --platform=linux/amd64 --network=none \
  --mount "type=bind,source=$root/scripts/public-release-check.sh,target=/candidate,readonly" \
  --mount "type=bind,source=$root/scripts/verify-public-bundle.sh,target=/verifier,readonly" \
  --entrypoint /bin/bash ubuntu:24.04 -s <<'LINUX'
set -euo pipefail
fail() { echo "public bundle: $*" >&2; exit 1; }
sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
image=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
state=/tmp/state/attackbox-public-ci
mkdir -p /tmp/bin /tmp/repo/scripts "$state" /tmp/fixture/deploy/{public-otel,otel,systemd} /tmp/fixture/scripts /tmp/collector /tmp/extract
cp /candidate /tmp/repo/scripts/public-release-check.sh
cp /verifier /tmp/fixture/scripts/verify-public-bundle.sh
for file in compose.public.yaml deploy/public-compose.sh deploy/public-otel/config.yaml deploy/public-otel/prepare-socket.sh deploy/systemd/attackbox-public-otel.service deploy/systemd/attackbox-public.service; do
  printf 'synthetic %s\n' "$file" > "/tmp/fixture/$file"
done
printf 'not packaged\n' > /tmp/fixture/private-marker
printf 'synthetic collector\n' > /tmp/collector/otelcol-contrib
tar -czf /tmp/collector.tar.gz -C /tmp/collector otelcol-contrib
collector_sha=$(sha256sum /tmp/collector.tar.gz | cut -d' ' -f1)
printf 'OTELCOL_LINUX_AMD64_SHA256=%s\n' "$collector_sha" > /tmp/fixture/deploy/otel/version.env
printf 'incorrect archive\n' > /tmp/bad.tar.gz
cat > /tmp/bin/git <<'MOCK'
#!/bin/bash
set -euo pipefail
[[ -z ${VULTR_API_KEY:-}${NEW_RELIC_API_KEY:-}${ATTACKBOX_NR_LICENSE_KEY:-}${NEW_RELIC_LICENSE_KEY:-} ]] || exit 1
case "$1 ${2:-}" in
  'rev-parse --verify'|'rev-parse HEAD') printf '%s\n' "$COMMIT" ;;
  '-c gpg.minTrustLevel=fully') [[ ${3:-} == verify-commit ]] ;;
  'status --porcelain') ;;
  'rev-parse --absolute-git-dir') echo /tmp/state ;;
  'archive --format=tar') shift 4; tar -cf - -C /tmp/fixture "$@" ;;
  *) exit 1 ;;
esac
MOCK
cat > /tmp/bin/docker <<'MOCK'
#!/bin/bash
set -euo pipefail
[[ -z ${VULTR_API_KEY:-}${NEW_RELIC_API_KEY:-}${ATTACKBOX_NR_LICENSE_KEY:-}${NEW_RELIC_LICENSE_KEY:-} ]] || exit 1
case "$1 ${2:-}" in
  'image inspect') printf 'linux/amd64 65532:65532 ["/attackbox-public"] %s\n' "$TEST_IMAGE" ;;
  'image save') [[ ${3:-} == --output && ${5:-} == "$TEST_IMAGE" ]]; printf 'synthetic image\n' > "$4" ;;
  *) exit 1 ;;
esac
MOCK
cat > /tmp/bin/shasum <<'MOCK'
#!/bin/bash
set -euo pipefail
[[ ${1:-} == -a && ${2:-} == 256 ]]
shift 2
if [[ ${SWAP_AFTER_HASH:-} == yes && ${1:-} == /tmp/state/attackbox-public-ci/package.*/collector.tar.gz ]]; then
  /usr/bin/sha256sum "$@"
  cp /tmp/bad.tar.gz "$PUBLIC_COLLECTOR_LINUX_ARCHIVE"
else
  exec /usr/bin/sha256sum "$@"
fi
MOCK
chmod +x /tmp/bin/git /tmp/bin/docker /tmp/bin/shasum
export PATH=/tmp/bin:$PATH COMMIT=$sha APPROVE=$sha PLATFORM=linux/amd64 TEST_IMAGE=$image
export VULTR_API_KEY=synthetic NEW_RELIC_API_KEY=synthetic ATTACKBOX_NR_LICENSE_KEY=synthetic NEW_RELIC_LICENSE_KEY=synthetic
printf '%s linux/amd64 %s\n' "$sha" "$image" > "$state/$sha-amd64.verified"
script=/tmp/repo/scripts/public-release-check.sh
expect_failure() {
  local want=$1 output
  shift
  if output=$("$@" 2>&1); then fail "unexpected success: $want"; fi
  [[ $output == *"$want"* ]] || fail "wrong failure for $want: $output"
}
mkdir "$state/check.lock"
expect_failure 'release check is in progress' env PUBLIC_COLLECTOR_LINUX_ARCHIVE=/tmp/collector.tar.gz bash "$script" package
rmdir "$state/check.lock"
expect_failure 'Linux Collector archive checksum mismatch' env PUBLIC_COLLECTOR_LINUX_ARCHIVE=/tmp/bad.tar.gz bash "$script" package
[[ ! -e $state/$sha-amd64.bundle.tar ]] || fail 'bad archive produced a bundle'
if compgen -G "$state/package.*" >/dev/null; then fail 'failed package left staging files'; fi
cp /tmp/collector.tar.gz /tmp/swap.tar.gz
output=$(SWAP_AFTER_HASH=yes PUBLIC_COLLECTOR_LINUX_ARCHIVE=/tmp/swap.tar.gz bash "$script" package)
[[ $output == *'Bundle:'* && $output == *'SHA-256:'* ]] || fail 'bundle receipt missing'
bundle=$state/$sha-amd64.bundle.tar
cmp /tmp/bad.tar.gz /tmp/swap.tar.gz || fail 'archive replacement was not exercised'
if compgen -G "$state/package.*" >/dev/null; then fail 'successful package left staging files'; fi
[[ $(stat -c '%h' "$bundle") == 1 && ! -e $state/check.lock ]] || fail 'bundle alias or lock remains'
tar -xf "$bundle" -C /tmp/extract
cmp /tmp/collector/otelcol-contrib /tmp/extract/otelcol-contrib || fail 'Collector changed after archive replacement'
(cd /tmp/extract && sha256sum -c SHA256SUMS >/dev/null)
members=(manifest image.tar otelcol-contrib compose.public.yaml deploy/public-compose.sh deploy/public-otel/config.yaml deploy/public-otel/prepare-socket.sh deploy/otel/version.env deploy/systemd/attackbox-public-otel.service deploy/systemd/attackbox-public.service scripts/verify-public-bundle.sh SHA256SUMS)
printf '%s\n' "${members[@]}" | sort > /tmp/expected
tar -tf "$bundle" | sort > /tmp/actual
cmp /tmp/expected /tmp/actual || fail 'bundle contains unexpected files'
[[ -x /tmp/extract/otelcol-contrib ]] || fail 'collector is not executable'
grep -Fxq "commit=$sha" /tmp/extract/manifest || fail 'manifest commit mismatch'
grep -Fxq "image=$image" /tmp/extract/manifest || fail 'manifest image mismatch'
bundle_sha=$(sha256sum "$bundle" | cut -d' ' -f1)
[[ $(bash /verifier "$bundle" "$bundle_sha" "$sha") == "$image" ]] || fail 'valid bundle did not verify'
expect_failure 'bundle checksum mismatch' bash /verifier "$bundle" "$(printf '%064d' 0)" "$sha"
expect_failure 'release commit mismatch' bash /verifier "$bundle" "$bundle_sha" bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
mkdir /tmp/portable
for cmd in bash head wc awk sort tar cmp grep mktemp rm rmdir od tr cut; do
  ln -s "$(command -v "$cmd")" "/tmp/portable/$cmd"
done
ln -s /tmp/bin/shasum /tmp/portable/shasum
[[ $(env PATH=/tmp/portable /bin/bash /verifier "$bundle" "$bundle_sha" "$sha") == "$image" ]] || fail 'shasum fallback failed'
gzip -c "$bundle" > /tmp/compressed.tar.gz
bad_sha=$(sha256sum /tmp/compressed.tar.gz | cut -d' ' -f1)
expect_failure 'bundle must be an uncompressed tar' bash /verifier /tmp/compressed.tar.gz "$bad_sha" "$sha"
cp "$bundle" /tmp/duplicate.tar
tar -rf /tmp/duplicate.tar -C /tmp/extract manifest
bad_sha=$(sha256sum /tmp/duplicate.tar | cut -d' ' -f1)
expect_failure 'unexpected or duplicate bundle members' bash /verifier /tmp/duplicate.tar "$bad_sha" "$sha"
rm /tmp/extract/compose.public.yaml
ln -s /tmp/fixture/private-marker /tmp/extract/compose.public.yaml
tar -cf /tmp/symlink.tar -C /tmp/extract "${members[@]}"
bad_sha=$(sha256sum /tmp/symlink.tar | cut -d' ' -f1)
expect_failure 'bundle contains non-regular files' bash /verifier /tmp/symlink.tar "$bad_sha" "$sha"
rm /tmp/extract/compose.public.yaml
cp /tmp/fixture/compose.public.yaml /tmp/extract/compose.public.yaml
cp /tmp/extract/SHA256SUMS /tmp/original-checksums
printf '%064d  ../../private-marker\n' 0 > /tmp/extract/SHA256SUMS
tar -cf /tmp/checksums.tar -C /tmp/extract "${members[@]}"
bad_sha=$(sha256sum /tmp/checksums.tar | cut -d' ' -f1)
expect_failure 'checksum list differs from bundle members' bash /verifier /tmp/checksums.tar "$bad_sha" "$sha"
cp /tmp/original-checksums /tmp/extract/SHA256SUMS
printf 'tampered image\n' > /tmp/extract/image.tar
tar -cf /tmp/tampered.tar -C /tmp/extract "${members[@]}"
bad_sha=$(sha256sum /tmp/tampered.tar | cut -d' ' -f1)
expect_failure 'bundle file checksum mismatch' bash /verifier /tmp/tampered.tar "$bad_sha" "$sha"
mkdir /tmp/manifest-case
tar -xf "$bundle" -C /tmp/manifest-case
printf 'commit=%s\nplatform=linux/amd64\nimage=%s=extra\n' "$sha" "$image" > /tmp/manifest-case/manifest
(cd /tmp/manifest-case && sha256sum "${members[@]:0:${#members[@]}-1}" > SHA256SUMS)
tar -cf /tmp/manifest.tar -C /tmp/manifest-case "${members[@]}"
bad_sha=$(sha256sum /tmp/manifest.tar | cut -d' ' -f1)
expect_failure 'invalid image digest' bash /verifier /tmp/manifest.tar "$bad_sha" "$sha"
mkdir /tmp/fourth-record
tar -xf "$bundle" -C /tmp/fourth-record
printf 'commit=%s\nplatform=linux/amd64\nimage=%s\ncommit=%s' "$sha" "$image" bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb > /tmp/fourth-record/manifest
(cd /tmp/fourth-record && sha256sum "${members[@]:0:${#members[@]}-1}" > SHA256SUMS)
tar -cf /tmp/fourth-record.tar -C /tmp/fourth-record "${members[@]}"
bad_sha=$(sha256sum /tmp/fourth-record.tar | cut -d' ' -f1)
expect_failure 'invalid bundle manifest' bash /verifier /tmp/fourth-record.tar "$bad_sha" "$sha"
mkdir /tmp/sparse-case
tar -xf "$bundle" -C /tmp/sparse-case
truncate -s 1073741825 /tmp/sparse-case/image.tar
tar --sparse -cf /tmp/sparse.tar -C /tmp/sparse-case "${members[@]}"
bad_sha=$(sha256sum /tmp/sparse.tar | cut -d' ' -f1)
expect_failure 'oversized contents' bash /verifier /tmp/sparse.tar "$bad_sha" "$sha"
expect_failure 'bundle already exists' env PUBLIC_COLLECTOR_LINUX_ARCHIVE=/tmp/collector.tar.gz bash "$script" package
echo 'public bundle: checksum, allowlist, lock and overwrite checks passed'
LINUX
