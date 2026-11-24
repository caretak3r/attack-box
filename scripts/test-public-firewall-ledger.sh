#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck source=public-firewall-ledger.sh
. "$SCRIPT_DIR/public-firewall-ledger.sh"
root=$(mktemp -d "${TMPDIR:-/tmp}/public-fw-test.XXXXXXXX")
trap 'rm -rf -- "$root"' EXIT
trap 'exit 1' HUP INT TERM
fail() { printf 'FAIL: %s (%s)\n' "$*" "$case_dir" >&2; exit 1; }
reject() { if "$@"; then fail "unexpected success: $*"; fi; }

# Addresses below are JSON strings only. Neither callback has a network fallback.
bind=9.9.9.9
sequence=0
commit=0123456789012345678901234567890123456789
sha=0123456789012345678901234567890123456789012345678901234567890123
ssh='{"id":81,"ip_type":"v4","action":"accept","protocol":"tcp","port":"22","subnet":"192.0.2.10","subnet_size":32,"source":"","notes":"bootstrap ssh; lockdown removes it"}'
new_case() {
  case_dir=$root/$1
  mkdir -m 700 -- "$case_dir"
  inventory=$case_dir/rules
  journal=$case_dir/public-firewall-ledger.json
  posts=$case_dir/posts
  deletes=$case_dir/deletes
  : >"$posts"; : >"$deletes"
  printf '[%s]\n' "$ssh" >"$inventory"
  fault=normal
}
change_rules() {
  jq "$@" "$inventory" >"$case_dir/next" && mv -- "$case_dir/next" "$inventory"
}
api() {
  local method=$1 path=$2 body=${3-} ip=$bind attached=fw-1 members=1 size result
  case "$method $path" in
    'GET /instances/instance-1')
      case $fault in
        wrongip) ip=1.1.1.1 ;;
        wrongfw) attached=fw-2 ;;
        postmove) if [[ -s $posts ]]; then attached=fw-2; fi ;;
        deletemove) if [[ -s $deletes ]]; then ip=1.1.1.1; fi ;;
      esac
      jq -cn --arg ip "$ip" --arg fw "$attached" '{instance:{id:"instance-1", main_ip:$ip, firewall_group_id:$fw}}' ;;
    'GET /firewalls/fw-1')
      size=$(jq length "$inventory") || return 1
      if [[ $fault == shared ]]; then members=2; fi
      if [[ $fault == countdrift ]]; then size=$((size+1)); fi
      jq -cn --argjson m "$members" --argjson n "$size" '{firewall_group:{id:"fw-1",instance_count:$m,rule_count:$n}}' ;;
    'GET /firewalls/fw-1/rules?per_page=500')
      result=$(jq -c '{firewall_rules:., meta:{total:length,links:{prev:"",next:""}}}' "$inventory") || return 1
      case $fault in
        truncated) jq '.firewall_rules |= .[:-1]' <<<"$result" ;;
        missingmeta) jq 'del(.meta)' <<<"$result" ;;
        nextpage) jq '.meta.links.next = "cursor"' <<<"$result" ;;
        prevpage) jq '.meta.links.prev = "cursor"' <<<"$result" ;;
        dupkey) printf '{"meta":{},%s\n' "${result#\{}" ;;
        multijson) printf '%s\n%s\n' "$result" "$result" ;;
        prepostdrift)
          if [[ -f $journal ]]; then jq '.firewall_rules[0].subnet_size=24' <<<"$result"; else printf '%s\n' "$result"; fi ;;
        offlineafterpost|lostoffline)
          if [[ -s $posts ]]; then return 1; fi
          printf '%s\n' "$result" ;;
        failafterdelete)
          printf '%s\n' "$result"
          [[ ! -s $deletes ]] ;; # Even valid-looking JSON on failed GET is not evidence.
        *) printf '%s\n' "$result" ;;
      esac ;;
    'POST /firewalls/fw-1/rules')
      printf '%s\n' "$body" >>"$posts"
      jq -e '.phase == "intent" and .rule_id == null' "$journal" >/dev/null || return 1
      if [[ $fault == noresponse ]]; then return 1; fi
      change_rules --argjson body "$body" '. + [($body + {id:93,action:"accept"})]' || return 1
      case $fault in
        lost|lostoffline) return 1 ;;
        wrongid) printf '%s\n' '{"firewall_rule":{"id":96}}' ;;
        wrongssh) printf '%s\n' '{"firewall_rule":{"id":81}}' ;;
        invalidid) printf '%s\n' '{"firewall_rule":{"id":1.5}}' ;;
        *) printf '%s\n' '{"firewall_rule":{"id":93}}' ;;
      esac ;;
    *) return 1 ;;
  esac
}
del() {
  printf '%s\n' "$1" >>"$deletes"
  [[ $1 == /firewalls/fw-1/rules/93 ]] || return 1
  jq -e '.phase == "deleting" and .rule_id == 93' "$journal" >/dev/null || return 1
  case $fault in
    residual) change_rules '.[1].id=100 | .[1].port="80"' ;;
    faileddelete) return 1 ;;
    *) change_rules 'map(select(.id != 93))' || return 1
       [[ $fault != lostdelete ]] ;;
  esac
}
open_case() {
  public_firewall_open "$case_dir" instance-1 fw-1 "$bind" "$commit" "$sha" "${1-443}" "${2-81}" "${3-192.0.2.10/32}" >"$case_dir/out" 2>"$case_dir/err"
}
rollback_case() {
  public_firewall_rollback "$case_dir" >"$case_dir/out" 2>"$case_dir/err"
}
no_write() { [[ ! -s $posts && ! -s $deletes ]] || fail 'unexpected mutation'; }
closed() {
  jq -e --argjson ssh "$ssh" '. == [$ssh]' "$inventory" >/dev/null || fail 'SSH changed or residual ingress'
  jq -e '.phase=="closed" and .rule_id==93' "$journal" >/dev/null || fail 'absence not journaled'
  [[ $(cat "$deletes") == /firewalls/fw-1/rules/93 ]] || fail 'unexpected DELETE sequence'
}

new_case success
open_case || fail '443 cutover'
jq -se --arg token "$(jq -r .token "$journal")" '
  . == [{port:"443",ip_type:"v4",protocol:"tcp",subnet:"0.0.0.0",subnet_size:0,
         source:"",notes:("attackbox-public:"+$token+":443")}]' "$posts" >/dev/null || fail 'not one exact POST'
jq -e --argjson ssh "$ssh" 'length==2 and .[0]==$ssh and .[1].id==93' "$inventory" >/dev/null || fail 'open inventory'
jq -e --arg c "$commit" --arg s "$sha" --arg ip "$bind" '
  .version==2 and .phase=="open" and .commit==$c and .bundle_sha==$s and .ip==$ip and
  .ssh_id==81 and .management=="192.0.2.10/32" and .rule_id==93' "$journal" >/dev/null || fail 'incomplete audit identity'
reject open_case
rollback_case && rollback_case || fail 'idempotent closure'
closed

new_case args
for profile in '80,443,1234,3000,4891,5000,6333,6334,8000,8001,8002,8080,8500,8501,11434,19530' '443,443' '' '80'; do reject open_case "$profile"; done
reject open_case 443 81 192.0.2.0/24
reject open_case 443 82
reject open_case 443 81 192.0.2.11/32
no_write

for scenario in wrongip wrongfw shared countdrift missingmeta truncated nextpage prevpage dupkey multijson prepostdrift; do
  new_case "$scenario"; fault=$scenario
  reject open_case; no_write
done
for drift in \
  '[]' '.+[.[0]]' '.[0].source="alias"' '.[0].id="81"' '.[0].id=0' '.[0].subnet_size=24' \
  '.[0].notes=""' '.[0].protocol="udp"' '.[0].action="drop"' '.[0].ip_type="v6"' \
  '.+[ (.[0] | .id=94 | .port="443" | .subnet="0.0.0.0" | .subnet_size=0 | .notes="elsewhere") ]'; do
  new_case "drift-$((++sequence))"
  change_rules "$drift"; reject open_case; no_write
done

# Failed/ambiguous POSTs must not be retried. Only the unique full rule can be removed.
for scenario in lost invalidid; do
  new_case "$scenario"; fault=$scenario
  reject open_case; closed
  jq -se 'length==1' "$posts" >/dev/null || fail 'POST retried'
done
new_case uncertain; fault=noresponse
reject open_case; reject rollback_case
[[ ! -s $deletes ]] || fail 'unseen POST treated as absent'

for scenario in wrongid wrongssh postmove; do
  new_case "$scenario"; fault=$scenario
  reject open_case; reject rollback_case
  [[ ! -s $deletes ]] || fail 'deleted despite identity conflict'
done
new_case ack; fault=offlineafterpost
reject open_case
jq -e '.phase=="ack" and .rule_id==93' "$journal" >/dev/null || fail 'lost acknowledged ID'
[[ ! -s $deletes ]] || fail 'deleted without readback'
fault=normal; rollback_case || fail 'recovery after read outage'; closed
new_case lostoffline; fault=lostoffline
reject open_case
jq -e '.phase=="intent" and .rule_id==null' "$journal" >/dev/null || fail 'missing ambiguous intent'
[[ ! -s $deletes ]] || fail 'attempted DELETE with provider unavailable'
fault=normal; rollback_case || fail 'recovery by unique operation note'; closed

new_case tampered
open_case || fail 'setup for ledger checks'
cp -- "$journal" "$case_dir/original"
jq '.version=1' "$case_dir/original" >"$journal"
reject rollback_case
cp -- "$case_dir/original" "$journal"
mkdir -- "$case_dir/.public-firewall-lock"
reject rollback_case
rmdir -- "$case_dir/.public-firewall-lock"
[[ ! -s $deletes ]] || fail 'invalid version or stale lock authorized deletion'

for drift in '.[1].id=94' '.[1].port="80"' '.[1].notes="other"' '.[1].protocol="udp"' \
  '.[1].source="alias"' '.[1].action="drop"' '.[1].subnet_size=32' '.[0].subnet="192.0.2.12"' \
  '.+[(.[1] | .id=94)]'; do
  new_case "rollback-$((++sequence))"
  open_case || fail 'rollback setup'
  change_rules "$drift"; reject rollback_case
  [[ ! -s $deletes ]] || fail 'deleted despite policy or ownership drift'
done
for scenario in residual faileddelete failafterdelete deletemove; do
  new_case "$scenario"; open_case || fail 'post-delete setup'
  fault=$scenario; reject rollback_case
  jq -e '.phase=="deleting"' "$journal" >/dev/null || fail 'false confirmation of closure'
done
new_case lostdelete; open_case || fail 'lost DELETE setup'
fault=lostdelete; rollback_case || fail 'failed to reconcile absent rule after lost DELETE'; closed
printf '%s\n' 'public firewall ledger offline tests passed'
