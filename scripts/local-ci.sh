#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() { printf 'local-ci: %s\n' "$*" >&2; exit 1; }

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
mode=${1:-}
case "$mode" in
    deploy)
        if ! git cat-file -e HEAD:scripts/vultr-launch.sh 2>/dev/null || ! git diff --quiet HEAD -- scripts/vultr-launch.sh; then
            fail 'Vultr launcher is not committed and unchanged in this checkout'
        fi
        exec bash scripts/vultr-launch.sh bootstrap
        ;;
    check|release-check|authorize-deploy) ;;
    *) fail 'expected check, release-check, deploy, or authorize-deploy' ;;
esac

commit=$(git rev-parse --verify --end-of-options "${COMMIT:-HEAD}^{commit}")
state=$(git rev-parse --absolute-git-dir)/attackbox-ci
if [[ $mode != check ]]; then
    platform=${PLATFORM:-}
    case "$platform" in
        linux/amd64|linux/arm64) ;;
        *) fail 'set PLATFORM to linux/amd64 or linux/arm64' ;;
    esac
    receipt="$state/$commit-${platform#linux/}.verified"
fi

if [[ $mode == authorize-deploy ]]; then
    [[ ${APPROVE:-} == "$commit" ]] || fail "set APPROVE=$commit to approve this deployment"
    [[ $(git rev-parse HEAD) == "$commit" ]] || fail 'release commit differs from checkout HEAD'
    status=$(git status --porcelain --untracked-files=no)
    [[ -z $status ]] || fail 'checkout has tracked changes'
    [[ -f $receipt ]] || fail "no successful release-check for $commit $platform"
    verified=$(<"$receipt")
    prefix="$commit $platform "
    [[ $verified == "$prefix"* && ${verified#"$prefix"} =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'invalid release record'
    git cat-file -e "$commit:scripts/vultr-launch.sh" 2>/dev/null || fail 'Vultr launcher is not committed in this checkout'
    printf '%s\n' "$commit"
    exit 0
fi

mkdir -p -- "$state"
run=$(mktemp -d "$state/run.XXXXXXXX")
trap 'rm -rf -- "$run"' EXIT
mkdir -- "$run/source"
git archive "$commit" | tar -xf - -C "$run/source"
printf 'Checking commit %s\n' "$commit"
(
    cd -- "$run/source"
    # Permission tests need group-readable fixture modes to survive file creation.
    umask 022
	unset VULTR_API_KEY
    bash scripts/verify.sh
)
[[ $mode == release-check ]] || exit 0

(cd -- "$run/source" && GOWORK=off GOFLAGS= GOTOOLCHAIN=local go mod vendor)
image="attackbox-release-check:$commit-${platform#linux/}"
docker buildx build --platform "$platform" --network=none --build-arg OFFLINE_GO_BUILD=1 \
    --target bait --load --tag "$image" "$run/source"
metadata=$(docker image inspect --format '{{.Os}}/{{.Architecture}} {{.Config.User}} {{json .Config.Entrypoint}} {{.Id}}' "$image")
expected="$platform 65532:65532 [\"/attackbox\"] "
image_id=${metadata#"$expected"}
[[ $metadata == "$expected"* && $image_id =~ ^sha256:[0-9a-f]{64}$ ]] || fail "unexpected bait image metadata: $metadata"
printf '%s %s %s\n' "$commit" "$platform" "$image_id" > "$run/verified"
mv -f -- "$run/verified" "$receipt"
printf 'Verified %s: %s\nRelease record: %s\n' "$commit" "$metadata" "$receipt"
