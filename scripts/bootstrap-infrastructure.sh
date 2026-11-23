#!/usr/bin/env bash
# Native New Relic Infrastructure bootstrap. Bash >=3.2. Apply/verify: Ubuntu amd64 root.
# The User API key is read once from stdin and exists only in provisioning process memory.
set -Eeuo pipefail
umask 077
unset NEW_RELIC_API_KEY
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=deploy/newrelic/version.env
source "$ROOT/deploy/newrelic/version.env"
usage() {
  printf '%s\n' 'usage: bootstrap-infrastructure.sh --stage DIR|--apply|--verify|--dry-run' \
    'Stage the pinned Linux CLI before transfer. Apply reads a User API key on stdin.' \
    'Set NEW_RELIC_ACCOUNT_ID before first install. US region only. Never put the key in argv.' \
    'Verify checks the native agent and its local configuration, not account ingestion.'
}
fail() { printf 'infrastructure bootstrap: %s\n' "$*" >&2; exit 1; }
mode=${1:---help}
case "$mode" in
  --help|-h) usage; exit 0 ;;
  --dry-run) [[ $# == 1 ]] || fail 'unexpected arguments'; printf '%s\n' 'Would install native New Relic Infrastructure; no writes, downloads or service changes.'; exit 0 ;;
  --stage) [[ $# == 2 ]] || fail '--stage requires a directory' ;;
  --apply|--verify) [[ $# == 1 ]] || fail 'unexpected arguments' ;;
  *) usage >&2; exit 2 ;;
esac
verify_archive() {
  python3 - "$1" "$NRCLI_LINUX_AMD64_SHA256" <<'PY'
import hashlib, pathlib, sys
p = pathlib.Path(sys.argv[1])
if p.is_symlink() or not p.is_file(): raise SystemExit('missing regular New Relic CLI archive')
h = hashlib.sha256()
with p.open('rb') as f:
    for block in iter(lambda: f.read(1024 * 1024), b''): h.update(block)
if h.hexdigest() != sys.argv[2]: raise SystemExit('New Relic CLI archive SHA256 mismatch')
PY
}
if [[ $mode == --stage ]]; then
  destination=$2
  [[ -d $destination && ! -L $destination ]] || fail 'stage directory must exist and must not be a symlink'
  archive=$destination/newrelic-cli-linux-amd64.tar.gz
  if [[ -e $archive || -L $archive ]]; then verify_archive "$archive"; exit 0; fi
  temporary=$(mktemp "$destination/.newrelic-cli.XXXXXX")
  trap 'rm -f -- "$temporary"' EXIT
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 600 --retry 2 \
    "https://download.newrelic.com/install/newrelic-cli/v${NRCLI_VERSION}/newrelic-cli_${NRCLI_VERSION}_Linux_x86_64.tar.gz" -o "$temporary"
  verify_archive "$temporary"
  mv -- "$temporary" "$archive"
  exit 0
fi
[[ $(uname -s)/$(uname -m) == Linux/x86_64 && $EUID == 0 ]] || fail 'requires Linux amd64 root'
verify_agent() {
  systemctl is-enabled --quiet newrelic-infra.service || return 1
  systemctl is-active --quiet newrelic-infra.service || return 1
  dpkg-query -W -f='${Status}\n' newrelic-infra | grep -qx 'install ok installed' || return 1
  [[ -x /usr/bin/newrelic-infra ]] || return 1
  python3 "$ROOT/deploy/newrelic/verify-config.py" || return 1
  curl --noproxy '*' --fail --silent --show-error --max-time 5 http://127.0.0.1:18003/v1/status |
    python3 -c 'import json,sys; assert json.load(sys.stdin)["checks"]["health"]["healthy"] is True' || return 1
  # Permanent endpoint sets and the installed refresh service must survive reboot.
  for family in ipv4 ipv6; do nft list set inet attackbox "nr_infra_$family" >/dev/null || return 1; done
  systemctl is-enabled --quiet attackbox-nft-refresh.timer || return 1
  systemctl is-active --quiet attackbox-nft-refresh.timer || return 1
}
if [[ $mode == --verify ]]; then
  verify_agent || fail 'native agent, config, or persistent egress refresh is not ready'
  printf '%s\n' 'PASS: native Infrastructure local readiness; confirm host ingestion with an account query.'
  exit 0
fi
# Validate base policy before reading an API key or making installation changes.
[[ -x /usr/local/sbin/attackbox-deploy ]] || fail 'base firewall refresh helper missing'
for name in nr_infra_ipv4 nr_infra_ipv6 nr_install_ipv4 nr_install_ipv6; do
  nft list set inet attackbox "$name" >/dev/null || fail "base firewall set $name missing"
done
/usr/local/sbin/attackbox-deploy --refresh-sets
if [[ -e /etc/newrelic-infra.yml || -L /etc/newrelic-infra.yml ]]; then
  python3 "$ROOT/deploy/newrelic/configure-agent.py" --secure-only
fi
if verify_agent; then
  printf '%s\n' 'Native Infrastructure is already ready; operator configuration preserved.'
  exit 0
fi
# Existing installations need explicit repair rather than a hidden reconfiguration.
if dpkg-query -W -f='${Status}\n' newrelic-infra 2>/dev/null | grep -qx 'install ok installed'; then
  fail 'existing native agent failed verification; repair it explicitly before bootstrap'
fi
account=${NEW_RELIC_ACCOUNT_ID:-0}
[[ $account =~ ^[1-9][0-9]{0,11}$ ]] || fail 'invalid NEW_RELIC_ACCOUNT_ID'
[[ ${NEW_RELIC_REGION:-US} == US ]] || fail 'only US New Relic endpoints are approved'
archive=$ROOT/bootstrap/newrelic-cli-linux-amd64.tar.gz
verify_archive "$archive"
IFS= read -r api_key || fail 'User API key required on stdin'
[[ $api_key =~ ^NRAK-[A-Za-z0-9_-]{20,200}$ ]] || fail 'invalid User API key format'
stage=$(mktemp -d)
cleanup() {
  local status=$1
  unset api_key
  # The official installer can write credentials before a later recipe fails.
  if [[ -e /etc/newrelic-infra.yml || -L /etc/newrelic-infra.yml ]]; then
    python3 "$ROOT/deploy/newrelic/configure-agent.py" --secure-only || status=1
  fi
  # Flush install-only egress even after failed/aborted installation. Sets also expire.
  nft flush set inet attackbox nr_install_ipv4 >/dev/null 2>&1 || status=1
  nft flush set inet attackbox nr_install_ipv6 >/dev/null 2>&1 || status=1
  rm -rf -- "$stage"
  return "$status"
}
trap 'status=$?; trap - EXIT; cleanup "$status"; exit "$?"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
tar -xzf "$archive" -C "$stage" newrelic
mkdir "$stage/home"
# The root refresh helper owns all allowlisted destination names, not CLI input.
/usr/local/sbin/attackbox-deploy --refresh-install-sets
printf '%s\n' 'Installing native Infrastructure with the verified official New Relic CLI.'
# Isolated HOME prevents a permanent admin-key profile. Logs are private and removed on exit.
# Do not use set -x here: keys must never reach command traces.
# shellcheck disable=SC2016 # API key is read by the child shell, not expanded into argv.
if ! printf '%s\n' "$api_key" | env -i \
    HOME="$stage/home" PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    DEBIAN_FRONTEND=noninteractive NEW_RELIC_ACCOUNT_ID="$account" NEW_RELIC_REGION=US \
    /bin/bash -c 'IFS= read -r NEW_RELIC_API_KEY; export NEW_RELIC_API_KEY; exec timeout --kill-after=30s 1200s "$1" install -y </dev/null' \
    _ "$stage/newrelic" >"$stage/install.log" 2>&1; then
  fail 'official CLI installation failed; installation output suppressed to protect credentials'
fi
unset api_key
# Official package setup may use a readable default; restrict the file containing its ingest key.
[[ -f /etc/newrelic-infra.yml && ! -L /etc/newrelic-infra.yml ]] || fail 'agent configuration missing or symlinked'
python3 "$ROOT/deploy/newrelic/configure-agent.py" --fresh
# Retain CLI-generated files for diagnosis outside the active logging directory.
install -d -m 0700 /etc/newrelic-infra/bootstrap-backup
for config in discovered.yml logging.yml; do
  if [[ -e /etc/newrelic-infra/logging.d/$config ]]; then
    [[ ! -e /etc/newrelic-infra/bootstrap-backup/$config ]] || fail "logging backup already exists: $config"
    mv -- "/etc/newrelic-infra/logging.d/$config" "/etc/newrelic-infra/bootstrap-backup/$config"
    chmod 0600 "/etc/newrelic-infra/bootstrap-backup/$config"
  fi
done
install -m 0600 "$ROOT/deploy/newrelic/host-logging.yml" /etc/newrelic-infra/logging.d/attackbox-host.yml
systemctl enable newrelic-infra.service
systemctl restart newrelic-infra.service
ready=false
for _attempt in 1 2 3 4 5 6; do
  if verify_agent; then ready=true; break; fi
  sleep 5
done
[[ $ready == true ]] || fail 'installation returned success but native agent verification failed'
printf '%s\n' 'Native Infrastructure installed. Account ingestion remains a separate verification gate.'
