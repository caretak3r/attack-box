#!/usr/bin/env bash
# Install only the host log-budget components; never alter ingress or bait.
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mode=${1:-}
bin_dir=${2:-}
[[ $# == 2 && ( $mode == --check || $mode == --apply ) ]] || { echo 'usage: install-log-budget.sh --check|--apply VERIFIED_BINARY_DIRECTORY' >&2; exit 2; }
python3 - "$bin_dir" <<'PY'
import hashlib,json,pathlib,struct,sys
root=pathlib.Path(sys.argv[1]); manifest=json.loads((root/'SHA256SUMS.json').read_text())
for name in ['attackbox-auditfilter','attackbox-hostcollector','attackbox-hostreader']:
 p=root/name
 if p.is_symlink() or not p.is_file(): raise SystemExit('binary must be regular: '+name)
 b=p.read_bytes()
 if hashlib.sha256(b).hexdigest()!=manifest.get(name): raise SystemExit('checksum mismatch: '+name)
 if len(b)<64 or b[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',b,18)[0]!=62: raise SystemExit('Linux amd64 ELF required')
 off=struct.unpack_from('<Q',b,32)[0];size,count=struct.unpack_from('<HH',b,54)
 if size<56 or count==0 or off+size*count>len(b): raise SystemExit('invalid ELF headers')
 if any(struct.unpack_from('<I',b,off+i*size)[0]==3 for i in range(count)): raise SystemExit('static binary required')
print('Three binary checksums and static Linux amd64 ELF headers verified')
PY
for unit in attackbox-auditfilter.service attackbox-hostcollector-snapshot.service attackbox-hostcollector-snapshot.timer; do
  [[ -f $repo_root/deploy/systemd/$unit ]] || { echo "missing $unit" >&2; exit 1; }
done
[[ -f $repo_root/deploy/newrelic/log-budget.conf ]] || { echo 'missing native budget drop-in' >&2; exit 1; }
[[ $mode == --apply ]] || exit 0
[[ $EUID == 0 && $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'apply requires Linux amd64 root' >&2; exit 1; }
config=/etc/newrelic-infra/logging.d/attackbox-host.yml
updater_was_active=false
if systemctl is-active --quiet falcoctl-artifact-follow.service; then updater_was_active=true; fi
[[ -s /etc/falco/falco_rules.yaml ]] || { echo 'installed Falco rules missing' >&2; exit 1; }
rules_sha=$(sha256sum /etc/falco/falco_rules.yaml)
filter_was_active=false
if systemctl is-active --quiet attackbox-auditfilter.service; then filter_was_active=true; fi
[[ -f $config && ! -L $config ]] || { echo 'native host logging config missing or symlink' >&2; exit 1; }
# Validate the route before any mutation. Repeated apply remains valid.
python3 - "$config" <<'PY'
import pathlib,re,sys
s=pathlib.Path(sys.argv[1]).read_text()
if len(re.findall(r'^\s+file: /var/log/(?:audit/audit.log|attackbox-audit/events.jsonl)\s*$',s,re.M))!=1: raise SystemExit('expected exactly one audit route')
PY
for unit in falco-modern-bpf auditd newrelic-infra attackbox-hostcollector attackbox-falco-adapter attackbox-egress-adapter; do
  systemctl is-active --quiet "$unit" || { echo "required unit inactive: $unit" >&2; exit 1; }
done
backup=$(mktemp -d /var/backups/attackbox-log-budget.XXXXXXXX)
chmod 0700 "$backup"
files=(/usr/local/bin/attackbox-auditfilter /usr/local/bin/attackbox-hostcollector /usr/local/bin/attackbox-hostreader
 /etc/systemd/system/attackbox-auditfilter.service /etc/systemd/system/attackbox-hostcollector-snapshot.service
 /etc/systemd/system/attackbox-hostcollector-snapshot.timer "$config" /etc/audit/auditd.conf /etc/systemd/system/newrelic-infra.service.d/attackbox-log-budget.conf /etc/systemd/system/falcoctl-artifact-follow.service)
for path in "${files[@]}"; do
  if [[ -e $path || -L $path ]]; then cp -a --parents "$path" "$backup"; else printf '%s\n' "$path" >> "$backup/absent"; fi
done
rollback() {
  code=$?
  trap - EXIT
  if ((code)); then
    echo "Install failed; restoring files from $backup" >&2
    systemctl stop attackbox-auditfilter.service || true
    for path in "${files[@]}"; do
      if [[ -e $backup$path || -L $backup$path ]]; then cp -a "$backup$path" "$path"; elif [[ -f $backup/absent ]] && grep -Fxq "$path" "$backup/absent"; then rm -f -- "$path"; fi
    done
    if [[ $filter_was_active == false ]]; then systemctl disable attackbox-auditfilter.service || true; fi
    systemctl daemon-reload
    if [[ $filter_was_active == true ]]; then systemctl restart attackbox-auditfilter.service || true; fi
    if [[ $updater_was_active == true ]]; then systemctl start falcoctl-artifact-follow.service || true; fi
    systemctl restart attackbox-hostcollector-snapshot.service attackbox-hostcollector-snapshot.timer attackbox-hostcollector.service attackbox-falco-adapter.service attackbox-egress-adapter.service newrelic-infra.service || true
    auditctl --signal reload || true
  fi
  exit "$code"
}
trap rollback EXIT
# Falco keeps the installed rules. Its optional online follower cannot reach
# its index in the locked-down campaign and otherwise retries every 45 seconds.
systemctl mask --now falcoctl-artifact-follow.service
[[ $(sha256sum /etc/falco/falco_rules.yaml) == "$rules_sha" ]] || { echo 'Falco rules changed during updater stop' >&2; exit 1; }
systemctl is-active --quiet falco-modern-bpf.service
for name in attackbox-auditfilter attackbox-hostcollector attackbox-hostreader; do
  install -m 0755 "$bin_dir/$name" "/usr/local/bin/.$name.new"
  mv -f "/usr/local/bin/.$name.new" "/usr/local/bin/$name"
done
for unit in attackbox-auditfilter.service attackbox-hostcollector-snapshot.service attackbox-hostcollector-snapshot.timer; do
  install -m 0644 "$repo_root/deploy/systemd/$unit" "/etc/systemd/system/$unit"
done
# Keep roughly 512 MiB of original audit logs locally. No raw events are deleted here.
python3 - <<'PY'
import pathlib,re
p=pathlib.Path('/etc/audit/auditd.conf');s=p.read_text()
for key,value in [('max_log_file','8'),('num_logs','64'),('max_log_file_action','ROTATE')]:
 s,n=re.subn(r'^'+key+r'\s*=.*$',key+' = '+value,s,flags=re.M)
 if n!=1: raise SystemExit('unexpected audit configuration: '+key)
p.write_text(s)
PY
install -d -m 0755 /etc/systemd/system/newrelic-infra.service.d
install -m 0644 "$repo_root/deploy/newrelic/log-budget.conf" /etc/systemd/system/newrelic-infra.service.d/attackbox-log-budget.conf
auditctl --signal reload
systemctl daemon-reload
systemctl restart attackbox-hostcollector-snapshot.service attackbox-hostcollector-snapshot.timer attackbox-hostcollector.service attackbox-falco-adapter.service attackbox-egress-adapter.service
systemctl enable attackbox-auditfilter.service
systemctl restart attackbox-auditfilter.service
# Require a durable output batch before moving the native input.
for attempt in {1..30}; do
  [[ -s /var/log/attackbox-audit/events.jsonl ]] && break
  sleep 1
done
[[ -s /var/log/attackbox-audit/events.jsonl ]]
systemctl is-active --quiet attackbox-auditfilter.service
python3 - "$config" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]);p.write_text(p.read_text().replace('file: /var/log/audit/audit.log','file: /var/log/attackbox-audit/events.jsonl'))
PY
systemctl restart newrelic-infra.service
for unit in attackbox-auditfilter attackbox-hostcollector attackbox-hostcollector-snapshot attackbox-falco-adapter attackbox-egress-adapter newrelic-infra; do systemctl is-active --quiet "$unit"; done
for attempt in {1..30}; do
  if curl --fail --silent --max-time 5 http://127.0.0.1:9465/metrics | grep -q '^attackbox_inventory_snapshot_valid 1$'; then break; fi
  sleep 1
done
curl --fail --silent --max-time 5 http://127.0.0.1:9465/metrics | grep -q '^attackbox_inventory_snapshot_valid 1$' 
printf 'Applied log budget. Backup: %s\nRemote receipt and daily consumption still require verification.\n' "$backup"
