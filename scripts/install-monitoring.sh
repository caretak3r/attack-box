#!/usr/bin/env bash
# Opt-in host Collector installer. Never edit keys, spool or network policy.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=deploy/otel/version.env
source "$repo_root/deploy/otel/version.env"
mode=''
archive=''
host_binary=''
host_sha=''
log_budget_binaries=''
usage() { echo 'usage: install-monitoring.sh --check|--apply [--archive PATH] [--hostcollector-binary PATH --hostcollector-sha256 SHA256] [--log-budget-binaries DIRECTORY]'; }
while (($#)); do
  case $1 in
    --check|--apply) [[ -z $mode ]] || { usage >&2; exit 2; }; mode=$1; shift ;;
    --archive) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; archive=$2; shift 2 ;;
    --hostcollector-binary) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; host_binary=$2; shift 2 ;;
    --log-budget-binaries) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; log_budget_binaries=$2; shift 2 ;;
    --hostcollector-sha256) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; host_sha=$2; shift 2 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ -n $mode ]] || { usage >&2; exit 2; }
if [[ -n $log_budget_binaries ]]; then bash "$repo_root/scripts/install-log-budget.sh" --check "$log_budget_binaries"; fi
fail() { echo "monitoring: $*" >&2; exit 1; }
for command in curl tar python3; do command -v "$command" >/dev/null || fail "missing $command"; done
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) platform=linux_amd64; expected=$OTELCOL_LINUX_AMD64_SHA256 ;;
  Darwin/arm64) platform=darwin_arm64; expected=$OTELCOL_DARWIN_ARM64_SHA256 ;;
  *) fail 'supported validation platforms: Linux amd64 and Darwin arm64' ;;
esac
[[ -z $host_binary && -z $host_sha || -n $host_binary && -n $host_sha ]] || fail 'hostcollector binary and SHA256 must be supplied together'
if [[ -n $host_binary ]]; then
  python3 - "$host_binary" "$host_sha" <<'PYHOST'
import hashlib, pathlib, re, struct, sys
p = pathlib.Path(sys.argv[1])
if p.is_symlink() or not p.is_file(): raise SystemExit('hostcollector must be a regular file')
data = p.read_bytes()
if not re.fullmatch(r'[0-9a-f]{64}', sys.argv[2]) or hashlib.sha256(data).hexdigest() != sys.argv[2]:
    raise SystemExit('hostcollector SHA256 mismatch')
if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 62:
    raise SystemExit('hostcollector must be a Linux amd64 ELF executable')
offset = struct.unpack_from('<Q', data, 32)[0]
size, count = struct.unpack_from('<HH', data, 54)
if size < 56 or count == 0 or offset + size * count > len(data): raise SystemExit('invalid ELF program headers')
for index in range(count):
    if struct.unpack_from('<I', data, offset + index * size)[0] == 3:
        raise SystemExit('hostcollector must be static (no PT_INTERP)')
PYHOST
fi
if [[ $mode == --apply ]]; then
  [[ -n $host_binary ]] || fail '--apply requires a verified hostcollector binary'
  for unit in attackbox-hostcollector.service attackbox-hostcollector-snapshot.service attackbox-hostcollector-snapshot.timer; do
    [[ -f $repo_root/deploy/systemd/$unit ]] || fail "missing staged $unit"
  done
  [[ $EUID -eq 0 && $platform == linux_amd64 ]] || fail '--apply requires Linux amd64 root'
  for command in systemctl nft getent useradd groupadd install; do command -v "$command" >/dev/null || fail "missing $command"; done
  getent group abx-bait >/dev/null || fail 'base deployment abx-bait group missing'
  getent group abx-ship >/dev/null || fail 'base deployment abx-ship group missing'
  [[ -x /usr/local/sbin/attackbox-deploy ]] || fail 'base deployment refresh helper missing'
fi
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
if [[ -z $archive ]]; then
  archive="$stage/collector.tar.gz"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --retry 2 \
    "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v${OTELCOL_VERSION}/otelcol-contrib_${OTELCOL_VERSION}_${platform}.tar.gz" -o "$archive"
fi
python3 - "$archive" "$expected" <<'PY'
import hashlib, pathlib, sys
h = hashlib.sha256()
with pathlib.Path(sys.argv[1]).open('rb') as source:
    for chunk in iter(lambda: source.read(1024 * 1024), b''):
        h.update(chunk)
if h.hexdigest() != sys.argv[2]:
    raise SystemExit('Collector archive SHA256 mismatch')
PY
# Extract only the expected executable from the verified official archive.
tar -xzf "$archive" -C "$stage" otelcol-contrib
"$stage/otelcol-contrib" --version | python3 -c 'import sys; assert sys.stdin.read().strip() == "otelcol-contrib version " + sys.argv[1]' "$OTELCOL_VERSION"
mkdir "$stage/credentials"
# --check does not read live keys, require root, write /etc, or start services.
env ATTACKBOX_HOST_ID=validation ATTACKBOX_HOST_NAME=validation \
  ATTACKBOX_CAMPAIGN_ID=validation ATTACKBOX_BAIT_INSTANCE_ID=validation-bait \
  ATTACKBOX_SHIPPER_INSTANCE_ID=validation-shipper ATTACKBOX_MONITOR_INSTANCE_ID=validation-monitor \
  ATTACKBOX_OTEL_INSTANCE_ID=validation-otel ATTACKBOX_BAIT_CONTAINER_ID=validation \
  ATTACKBOX_RELEASE_VERSION=validation CREDENTIALS_DIRECTORY="$stage/credentials" \
  "$stage/otelcol-contrib" validate --config="$repo_root/deploy/otel/config.yaml"
if [[ $mode == --check ]]; then
  echo "PASS: checksum, pinned Collector ${OTELCOL_VERSION}, and staged config; no services changed"
  exit 0
fi
# Validate trusted values without sourcing shell code. License is never printed.
getent group abx-otel >/dev/null || groupadd --system abx-otel
getent passwd abx-otel >/dev/null || useradd --system --gid abx-otel --home-dir /nonexistent --shell /usr/sbin/nologin abx-otel
# Existing root-owned helper refreshes the Ubuntu destination and UID sets.
/usr/local/sbin/attackbox-deploy --refresh-sets
install -d -m 0755 /usr/local/libexec /etc/attackbox/otel /etc/attackbox-otel /etc/systemd/system/attackbox-shipper.service.d
install -d -o root -g root -m 0755 /run/attackbox-otel
install -m 0755 "$stage/otelcol-contrib" /usr/local/bin/attackbox-otel
install -m 0644 "$repo_root/deploy/otel/config.yaml" /etc/attackbox-otel/config.yaml
install -m 0644 "$repo_root/deploy/otel/bait-otel.conf" /etc/attackbox/otel/bait-otel.conf
install -m 0644 "$repo_root/compose.monitoring.yaml" /opt/attackbox/compose.monitoring.yaml
install -m 0755 "$repo_root/deploy/otel/prepare-sockets.sh" /usr/local/libexec/attackbox-otel-sockets
install -m 0644 "$repo_root/deploy/otel/tmpfiles.conf" /etc/tmpfiles.d/attackbox-otel.conf
install -m 0644 "$repo_root/deploy/systemd/attackbox-otel.service" /etc/systemd/system/attackbox-otel.service
install -m 0644 "$repo_root/deploy/otel/shipper-otel.conf" /etc/systemd/system/attackbox-shipper.service.d/otel.conf
install -m 0600 "$stage/shipper-monitoring.env" /etc/attackbox/shipper-monitoring.env
systemd-tmpfiles --create /etc/tmpfiles.d/attackbox-otel.conf
install -m 0755 "$host_binary" /usr/local/bin/attackbox-hostcollector
for unit in attackbox-hostcollector.service attackbox-hostcollector-snapshot.service attackbox-hostcollector-snapshot.timer; do
  install -m 0644 "$repo_root/deploy/systemd/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
systemctl restart attackbox-hostcollector-snapshot.service
systemctl enable --now attackbox-hostcollector-snapshot.timer
systemctl enable attackbox-hostcollector.service
systemctl restart attackbox-hostcollector.service
systemctl is-active --quiet attackbox-hostcollector.service
systemctl enable attackbox-otel.service
systemctl restart attackbox-otel.service
systemctl is-active --quiet attackbox-otel.service
curl --fail --silent --show-error --max-time 5 http://127.0.0.1:9465/metrics >/dev/null
curl --fail --silent --show-error --max-time 5 http://127.0.0.1:13133/ >/dev/null
printf '%s\n' 'Collector process healthy. Export remains unverified.' \
  'Shipper drop-in installed; restart shipper separately. Bait overlay not applied.'

if [[ -n $log_budget_binaries ]]; then bash "$repo_root/scripts/install-log-budget.sh" --apply "$log_budget_binaries"; fi
