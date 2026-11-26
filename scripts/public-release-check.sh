#!/usr/bin/env bash
set -euo pipefail
umask 077
unset VULTR_API_KEY NEW_RELIC_API_KEY ATTACKBOX_NR_LICENSE_KEY NEW_RELIC_LICENSE_KEY

fail() { printf 'public-release: %s\n' "$*" >&2; exit 1; }
hash_file() { shasum -a 256 "$1" | cut -d' ' -f1; }
snapshot_archive() {
  head -c 536870913 "$1" > "$2"
  [[ $(wc -c < "$2") -le 536870912 ]] || fail 'Collector archive exceeds 512 MiB'
}
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$root"
mode=${1:-}
[[ $# == 1 && ( $mode == check || $mode == authorize || $mode == package ) ]] || fail 'expected check, authorize or package'
[[ ${PLATFORM:-} == linux/amd64 ]] || fail 'set PLATFORM=linux/amd64'
[[ ${COMMIT:-} =~ ^[0-9a-f]{40}$ ]] || fail 'set COMMIT to the full release SHA'
commit=$(git rev-parse --verify --end-of-options "$COMMIT^{commit}") || fail 'release commit not found'
[[ $commit == "$COMMIT" && $(git rev-parse HEAD) == "$commit" ]] || fail 'release commit differs from checkout HEAD'
git -c gpg.minTrustLevel=fully verify-commit "$commit" >/dev/null 2>&1 || fail 'release commit signature is missing or untrusted'
status=$(git status --porcelain --untracked-files=no) || fail 'cannot inspect checkout status'
[[ -z $status ]] || fail 'checkout has tracked changes'
state=$(git rev-parse --absolute-git-dir)/attackbox-public-ci
receipt=$state/$commit-amd64.verified
lock=$state/check.lock
expected='linux/amd64 65532:65532 ["/attackbox-public"] '

if [[ $mode == authorize || $mode == package ]]; then
  [[ ${APPROVE:-} == "$commit" ]] || fail 'APPROVE must match the full release SHA'
  [[ -f $receipt && ! -L $receipt ]] || fail 'no successful public release record'
  if [[ $mode == package ]]; then
    stage=
    runtime_files=(
      compose.public.yaml deploy/public-compose.sh deploy/public-otel/config.yaml deploy/public-otel/prepare-socket.sh
      deploy/otel/version.env deploy/systemd/attackbox-public-otel.service deploy/systemd/attackbox-public.service
      scripts/verify-public-bundle.sh
    )
    cleanup_package() {
      local result=$? failed=0 dir file
      trap - EXIT
      if [[ -n $stage && -d $stage && ! -L $stage ]]; then
        for dir in "$stage/source" "$stage/source/deploy" "$stage/source/deploy/public-otel" "$stage/source/deploy/otel" "$stage/source/deploy/systemd" "$stage/source/scripts"; do
          [[ ! -L $dir ]] || failed=1
        done
        if [[ $failed == 0 ]]; then
          for file in "${runtime_files[@]}" manifest image.tar otelcol-contrib SHA256SUMS; do
            rm -f -- "$stage/source/$file" || failed=1
          done
          rm -f -- "$stage/collector.tar.gz" "$stage/bundle.tar" || failed=1
          for dir in "$stage/source/deploy/public-otel" "$stage/source/deploy/otel" "$stage/source/deploy/systemd" "$stage/source/deploy" "$stage/source/scripts" "$stage/source" "$stage"; do
            [[ ! -d $dir ]] || rmdir -- "$dir" || failed=1
          done
        fi
      elif [[ -n $stage ]]; then
        failed=1
      fi
      rmdir -- "$lock" || failed=1
      if [[ $failed != 0 ]]; then
        printf 'public-release: package staging cleanup failed\n' >&2
        result=1
      fi
      exit "$result"
    }
    mkdir -- "$lock" 2>/dev/null || fail 'release check is in progress'
    trap cleanup_package EXIT
  else
    [[ ! -e $lock && ! -L $lock ]] || fail 'release check is in progress'
  fi
  record=$(<"$receipt")
  prefix="$commit linux/amd64 "
  [[ $record == "$prefix"* ]] || fail 'release record does not match commit and platform'
  image_id=${record#"$prefix"}
  [[ $image_id =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'invalid image digest in release record'
  metadata=$(docker image inspect --format '{{.Os}}/{{.Architecture}} {{.Config.User}} {{json .Config.Entrypoint}} {{.Id}}' "$image_id") || fail 'verified image is unavailable'
  [[ $metadata == "$expected$image_id" ]] || fail 'verified image metadata changed'
  if [[ $mode == authorize ]]; then
    printf '%s\n' "$image_id"
    exit 0
  fi
  [[ ${PUBLIC_COLLECTOR_LINUX_ARCHIVE:-} == /* && -f $PUBLIC_COLLECTOR_LINUX_ARCHIVE && ! -L $PUBLIC_COLLECTOR_LINUX_ARCHIVE ]] || fail 'set PUBLIC_COLLECTOR_LINUX_ARCHIVE to the absolute pinned Linux archive'
  bundle=$state/$commit-amd64.bundle.tar
  [[ ! -e $bundle && ! -L $bundle ]] || fail 'bundle already exists'
  stage=$(mktemp -d "$state/package.XXXXXXXX")
  mkdir -- "$stage/source"
  git archive --format=tar "$commit" -- "${runtime_files[@]}" | tar -xf - -C "$stage/source"
  for file in "${runtime_files[@]}"; do
    [[ -f $stage/source/$file && ! -L $stage/source/$file ]] || fail "invalid bundle file: $file"
  done
  pin=$(awk -F= '$1 == "OTELCOL_LINUX_AMD64_SHA256" {print $2}' "$stage/source/deploy/otel/version.env")
  snapshot_archive "$PUBLIC_COLLECTOR_LINUX_ARCHIVE" "$stage/collector.tar.gz"
  [[ $pin =~ ^[0-9a-f]{64}$ && $(hash_file "$stage/collector.tar.gz") == "$pin" ]] || fail 'Linux Collector archive checksum mismatch'
  tar -xOzf "$stage/collector.tar.gz" otelcol-contrib > "$stage/source/otelcol-contrib"
  chmod 0755 "$stage/source/otelcol-contrib"
  docker image save --output "$stage/source/image.tar" "$image_id"
  printf 'commit=%s\nplatform=linux/amd64\nimage=%s\n' "$commit" "$image_id" > "$stage/source/manifest"
  files=(manifest image.tar otelcol-contrib "${runtime_files[@]}")
  (cd -- "$stage/source" && shasum -a 256 "${files[@]}" > SHA256SUMS && tar -cf "$stage/bundle.tar" -- "${files[@]}" SHA256SUMS)
  bundle_sha=$(hash_file "$stage/bundle.tar")
  verified_image=$(bash "$stage/source/scripts/verify-public-bundle.sh" "$stage/bundle.tar" "$bundle_sha" "$commit") || fail 'bundle verification failed'
  [[ $verified_image == "$image_id" ]] || fail 'bundle image does not match release receipt'
  ln -- "$stage/bundle.tar" "$bundle" 2>/dev/null || fail 'cannot create bundle without overwriting'
  printf 'Bundle: %s\nSHA-256: %s\n' "$bundle" "$bundle_sha"
  exit 0
fi

mkdir -p -- "$state"
mkdir -- "$lock" 2>/dev/null || fail 'another public release check owns the lock'
trap 'rmdir -- "$lock" 2>/dev/null || true' EXIT
rm -f -- "$receipt"
run=$(mktemp -d "$state/run.XXXXXXXX")
mkdir -- "$run/source"
printf 'Checking public release %s\nWorkspace: %s\n' "$commit" "$run"
paths=(
  go.mod go.sum Dockerfile.public compose.public.yaml
  cmd/attackbox-public/main.go cmd/attackbox-public/main_test.go
  cmd/attackbox-public/check.go cmd/attackbox-public/check_test.go cmd/attackbox-public/collector_test.go
  internal/observability/tracing.go internal/observability/tracing_test.go
  internal/publicedge/gateway.go internal/publicedge/gateway_test.go internal/publicedge/capture.go internal/publicedge/capture_test.go
  internal/publicedge/answer.go internal/publicedge/answer_test.go internal/publicedge/ollama.go internal/publicedge/personas.go internal/publicedge/mcp.go
  scripts/public-firewall-ledger.sh scripts/test-public-firewall-ledger.sh
  deploy/public-compose.sh deploy/public-otel/config.yaml deploy/public-otel/prepare-socket.sh deploy/public-otel/collector_integration_test.go
  deploy/otel/version.env deploy/systemd/attackbox-public-otel.service deploy/systemd/attackbox-public.service
  scripts/public-release-check.sh scripts/verify-public-bundle.sh scripts/public-host-stage.sh
  scripts/test-public-release-check.sh scripts/test-public-compose.sh scripts/test-public-otel-socket.sh
  scripts/test-public-bundle.sh scripts/test-public-host-stage.sh
)
git archive --format=tar "$commit" -- "${paths[@]}" | tar -xf - -C "$run/source"
cd -- "$run/source"

[[ ${ATTACKBOX_TEST_COLLECTOR:-} == /* && -f $ATTACKBOX_TEST_COLLECTOR && -x $ATTACKBOX_TEST_COLLECTOR && ! -L $ATTACKBOX_TEST_COLLECTOR ]] || fail 'set ATTACKBOX_TEST_COLLECTOR to an absolute regular executable'
[[ ${PUBLIC_COLLECTOR_ARCHIVE:-} == /* && -f $PUBLIC_COLLECTOR_ARCHIVE && ! -L $PUBLIC_COLLECTOR_ARCHIVE ]] || fail 'set PUBLIC_COLLECTOR_ARCHIVE to the absolute pinned archive path'
case "$(uname -s)/$(uname -m)" in
  Darwin/arm64) pin=OTELCOL_DARWIN_ARM64_SHA256 ;;
  Linux/x86_64) pin=OTELCOL_LINUX_AMD64_SHA256 ;;
  *) fail 'collector tests require Darwin arm64 or Linux amd64' ;;
esac
expected_archive=$(awk -F= -v key="$pin" '$1 == key {print $2}' deploy/otel/version.env)
[[ $expected_archive =~ ^[0-9a-f]{64}$ ]] || fail 'collector archive pin is invalid'
snapshot_archive "$PUBLIC_COLLECTOR_ARCHIVE" "$run/collector.tar.gz"
[[ $(hash_file "$run/collector.tar.gz") == "$expected_archive" ]] || fail 'collector archive checksum mismatch'
tar -xOzf "$run/collector.tar.gz" otelcol-contrib > "$run/collector"
chmod 0755 "$run/collector"
[[ $(hash_file "$ATTACKBOX_TEST_COLLECTOR") == "$(hash_file "$run/collector")" ]] || fail 'collector executable differs from the pinned archive'
export ATTACKBOX_TEST_COLLECTOR="$run/collector"
[[ $("$ATTACKBOX_TEST_COLLECTOR" --version) == 'otelcol-contrib version 0.165.0' ]] || fail 'unexpected Collector version'

export GOWORK=off GOTOOLCHAIN=local GOPROXY=off
unformatted=$(gofmt -l cmd/attackbox-public internal/publicedge internal/observability deploy/public-otel) || fail 'gofmt could not read the public source'
[[ -z $unformatted ]] || fail 'public Go files need gofmt'
shell_files=(
  scripts/public-release-check.sh scripts/verify-public-bundle.sh scripts/public-host-stage.sh
  scripts/test-public-release-check.sh scripts/test-public-compose.sh scripts/test-public-otel-socket.sh
  scripts/public-firewall-ledger.sh scripts/test-public-firewall-ledger.sh
  scripts/test-public-bundle.sh scripts/test-public-host-stage.sh deploy/public-compose.sh deploy/public-otel/prepare-socket.sh
)
for file in "${shell_files[@]}"; do bash -n "$file"; done
shellcheck -S error "${shell_files[@]}"
bash scripts/test-public-release-check.sh
bash scripts/test-public-firewall-ledger.sh
bash scripts/test-public-compose.sh
bash scripts/test-public-otel-socket.sh
bash scripts/test-public-bundle.sh
bash scripts/test-public-host-stage.sh
env ATTACKBOX_PUBLIC_IMAGE=attackbox-public:local ATTACKBOX_PUBLIC_BIND_IP=127.0.0.2 \
  ATTACKBOX_HOST_ID=ci-host ATTACKBOX_CAMPAIGN_ID=ci-campaign \
  docker compose -f compose.public.yaml config --quiet
go test -race -count=1 ./cmd/attackbox-public ./internal/publicedge ./internal/observability ./deploy/public-otel
go vet ./cmd/attackbox-public ./internal/publicedge ./internal/observability ./deploy/public-otel
(umask 022; go mod vendor)
image="attackbox-public-release:$commit-amd64"
docker buildx build --platform linux/amd64 --network=none --file Dockerfile.public \
  --build-arg "RELEASE_VERSION=$commit" --load --tag "$image" .
metadata=$(docker image inspect --format '{{.Os}}/{{.Architecture}} {{.Config.User}} {{json .Config.Entrypoint}} {{.Id}}' "$image")
image_id=${metadata#"$expected"}
[[ $metadata == "$expected"* && $image_id =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'unexpected public image metadata'
printf '%s linux/amd64 %s\n' "$commit" "$image_id" > "$run/verified"
mv -- "$run/verified" "$receipt"
printf 'Verified public image %s\nRelease record: %s\n' "$image_id" "$receipt"
