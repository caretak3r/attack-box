#!/usr/bin/env bash
# Offline tests for scripts/vultr-launch.sh. curl, ssh and nc are stubs and the repo is a throwaway
# sandbox, so nothing here touches the network, Vultr or this working tree.
# shellcheck disable=SC2015  # "check && check || report" is the assertion style on purpose
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SRC=$HERE/vultr-launch.sh
FAKE_KEY=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
NR_KEY=0123456789abcdef0123456789abcdef01234567
K="VULTR_API_KEY=$FAKE_KEY"
SANDBOXES=$(mktemp -d)
trap 'rm -rf "$SANDBOXES"' EXIT
TESTS_RUN=0; TESTS_FAILED=0
T=; M=; OUT=; RC=0; TOKEN=

mode_of() { if [ "$(uname)" = Darwin ]; then stat -f %Lp "$1"; else stat -c %a "$1"; fi; }
has() { grep -Fq -- "$2" <<<"$1"; }
nonget() { jq -r 'select(.m != "GET") | "\(.m) \(.p)"' "$M/calls.jsonl"; }
ssh_idx() { # index of the first ssh call whose argv contains $1
  local i n; n=$(cat "$M/ssh.n" 2>/dev/null || echo 0)
  [ "$n" -gt 0 ] || return 1
  for i in $(seq 1 "$n"); do grep -Fq -- "$1" "$M/ssh.$i.argv" && { echo "$i"; return 0; }; done
  return 1
}

new_sandbox() { # sets T (sandbox repo) and M (mock state dir)
  T=$(mktemp -d "$SANDBOXES/sb.XXXXXX")
  mkdir -p "$T/scripts" "$T/cmd/x" "$T/internal/y" "$T/deploy" "$T/docker" "$T/home"
  cp "$SRC" "$T/scripts/vultr-launch.sh"
  cp "$HERE/local-ci.sh" "$T/scripts/local-ci.sh"
  local f
  for f in Dockerfile .dockerignore compose.yaml compose.gvisor.yaml scripts/deploy-ubuntu.sh cmd/x/main.go internal/y/y.go deploy/a docker/b; do
    echo "$f" >"$T/$f"
  done
  mkdir -p "$T/deploy/newrelic" "$T/.fixture-cli"
  cp "$HERE/bootstrap-infrastructure.sh" "$T/scripts/bootstrap-infrastructure.sh"
  printf '#!/bin/sh\nexit 0\n' >"$T/.fixture-cli/newrelic"
  tar -czf "$T/.fixture-cli/archive.tar.gz" -C "$T/.fixture-cli" newrelic
  printf 'NRCLI_VERSION=0.117.0\nNRCLI_LINUX_AMD64_SHA256=%s\n' "$(shasum -a 256 "$T/.fixture-cli/archive.tar.gz" | cut -d' ' -f1)" >"$T/deploy/newrelic/version.env"
  mkdir -p "$T/internal/vendor-fixture"
  printf 'module fixture.test/decoy\n\ngo 1.25.0\n\nrequire fixture.test/dependency v0.0.0\nreplace fixture.test/dependency => ./internal/vendor-fixture\n' >"$T/go.mod"
  printf 'module fixture.test/dependency\n\ngo 1.25.0\n' >"$T/internal/vendor-fixture/go.mod"
  printf 'package dependency\n\nconst Value = "committed dependency"\n' >"$T/internal/vendor-fixture/dependency.go"
  printf 'package main\n\nimport _ "fixture.test/dependency"\n\nfunc main() {}\n' >"$T/cmd/x/main.go"
  printf 'package y\n' >"$T/internal/y/y.go"
  (cd "$T" && export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
    && git init -q && git add -A && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -q -m init)
  local commit state
  commit=$(git -C "$T" rev-parse HEAD)
  state="$T/.git/attackbox-ci"
  mkdir "$state"
  printf '%s linux/amd64 sha256:%064d\n' "$commit" 0 >"$state/$commit-amd64.verified"
  M=$T/.mock; mkdir -p "$M" "$T/bin"; : >"$M/calls.jsonl"
  cat >"$T/bin/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$MOCK_DIR/curl.argv"
m=GET url= body= w=0 f=0 k=0 cfg= output=
for a in "$@"; do case $a in -fsS|-f) f=1 ;; esac; done
while [ $# -gt 0 ]; do
  case $1 in
    -o) output=$2; shift 2 ;;
    -X) m=$2; shift 2 ;;
    -w) w=1; shift 2 ;;
    --data-binary) body=$(cat); shift 2 ;;
    -K) cfg=$(cat "$2"); k=1; shift 2 ;;
    -H|-m) shift 2 ;;
    http*) url=$1; shift ;;
    *) shift ;;
  esac
done
if [[ $url == https://download.newrelic.com/install/newrelic-cli/* ]]; then
  cp "$MOCK_DIR/../.fixture-cli/archive.tar.gz" "$output"
  exit 0
fi
path=${url#"$MOCK_API"}
jq -cn --arg m "$m" --arg p "$path" --arg b "$body" --argjson k "$k" '{m:$m,p:$p,b:$b,k:($k==1)}' >>"$MOCK_DIR/calls.jsonl"
code=200 out=
case "$m $path" in
  "GET https://checkip.amazonaws.com") out=203.0.113.7 ;;
  "GET /plans?"*) out='{"plans":[{"id":"vc2-2c-4gb","vcpu_count":2,"ram":4096,"disk":80,"bandwidth":3072,"monthly_cost":20,"hourly_cost":0.027,"locations":["ewr","ord"]}]}' ;;
  "GET /regions/ewr/availability?"*) out='{"available_plans":["vc2-1c-1gb","vc2-2c-4gb"]}' ;;
  "GET /regions/ord/availability?"*) out='{"available_plans":["vc2-1c-1gb"]}' ;;
  "GET /regions?"*) out='{"regions":[{"id":"ewr","city":"New Jersey","country":"US"}]}' ;;
  "GET /os?"*) out='{"os":[{"id":1743,"name":"Ubuntu 22.04 LTS x64"},{"id":2284,"name":"Ubuntu 24.04 LTS x64"}]}' ;;
  "GET /account") out='{"account":{"name":"Acct Name","email":"owner@example.com","acls":["provisioning","firewall"],"balance":-5.5,"pending_charges":1.25}}' ;;
  "GET /instances?"*) out='{"instances":[]}' ;;
  "GET /firewalls?"*) out='{"firewall_groups":[]}' ;;
  "GET /ssh-keys?"*) out='{"ssh_keys":[]}' ;;
  "POST /ssh-keys") out='{"ssh_key":{"id":"key-1"}}'; code=201 ;;
  "POST /firewalls") out='{"firewall_group":{"id":"fw-1"}}'; code=201 ;;
  "POST /firewalls/fw-1/rules")
    id=$(( $(wc -l <"$MOCK_DIR/rules.jsonl" 2>/dev/null || echo 0) + 7 ))
    printf '%s' "$body" | jq -c --argjson id "$id" '. + {id:$id}' >>"$MOCK_DIR/rules.jsonl"
    out="{\"firewall_rule\":{\"id\":$id}}"; code=201 ;;
  "GET /firewalls/fw-1/rules?"*) out=$(jq -sc '{firewall_rules: .}' "$MOCK_DIR/rules.jsonl" 2>/dev/null || echo '{"firewall_rules":[]}') ;;
  "POST /instances") out='{"instance":{"id":"i-1","main_ip":"0.0.0.0","status":"pending","default_password":"HUNTER2-PW"}}'; code=202 ;;
  "GET /instances/i-1") out='{"instance":{"id":"i-1","status":"active","power_status":"running","server_status":"ok","main_ip":"198.51.100.9","plan":"vc2-2c-4gb","region":"ewr","label":"decoy"}}' ;;
  "GET /instances/i-1/bandwidth?"*) out='{"bandwidth":{"2026-11-22":{"incoming_bytes":10485760,"outgoing_bytes":2097152}}}' ;;
  "POST /snapshots") out='{"snapshot":{"id":"s-1"}}'; code=201 ;;
  "POST /instances/i-1/halt"|"DELETE "*) code=204 ;;
  *) out='{"error":"unmocked"}'; code=404 ;;
esac
if [ "$k" = 1 ]; then case $cfg in *"Authorization: Bearer $MOCK_KEY"*) ;; *) out='{"error":"Invalid API key"}'; code=401 ;; esac; fi
if [ "$f" = 1 ] && [ "$code" -ge 400 ]; then exit 22; fi
if [ "$w" = 1 ]; then printf '%s\n%s' "$out" "$code"; else printf '%s' "$out"; fi
EOF
  cat >"$T/bin/ssh" <<'EOF'
#!/usr/bin/env bash
n=$(( $(cat "$MOCK_DIR/ssh.n" 2>/dev/null || echo 0) + 1 )); echo "$n" >"$MOCK_DIR/ssh.n"
printf '%s\n' "$*" >"$MOCK_DIR/ssh.$n.argv"
cat >"$MOCK_DIR/ssh.$n.stdin"
case "$*" in
  *"ss -ltnH"*) printf 'LISTEN 0 4096 %s 0.0.0.0:*\n' ${MOCK_LISTEN:-127.0.0.1:8443} ;;
  *"systemd-run"*) [ -n "${MOCK_LOCKDOWN_FAILS:-}" ] || touch "$MOCK_DIR/ssh.down" ;;
esac
exit 0
EOF
  cat >"$T/bin/nc" <<'EOF'
#!/usr/bin/env bash
[ -e "$MOCK_DIR/ssh.down" ] && exit 1
exit 0
EOF
  chmod +x "$T/bin/curl" "$T/bin/ssh" "$T/bin/nc"
}

# run [VAR=value ...] -- ARGS...: run the sandbox copy of the script with a clean environment; sets OUT and RC.
run() {
  local envs=(APPROVE="$(git -C "$T" rev-parse HEAD)")
  while [ "$1" != -- ]; do envs+=("$1"); shift; done
  shift
  OUT=$(cd "$T" && env -i HOME="$T/home" PATH="$T/bin:/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin" \
    MOCK_DIR="$M" MOCK_API=http://mock.invalid/v2 MOCK_KEY="$FAKE_KEY" VULTR_API_URL=http://mock.invalid/v2 \
    GOPROXY=off GOSUMDB=off \
    VULTR_POLL_SECS=0 VULTR_WAIT_SECS=3 "${envs[@]}" "$BASH" "$T/scripts/vultr-launch.sh" "$@" 2>&1 </dev/null) && RC=0 || RC=$?
}

do_create() { # new sandbox holding a created decoy; extra args are env assignments (e.g. VULTR_PORTS=none)
  new_sandbox
  run "$K" "$@" -- plan
  [ "$RC" = 0 ] || { echo "$OUT"; return 1; }
  TOKEN=$(printf '%s\n' "$OUT" | sed -n 's/^Approval token: //p')
  run "$K" "$@" -- create --approve "$TOKEN" --accept-host-only-egress
  [ "$RC" = 0 ] || { echo "$OUT"; return 1; }
}

do_bootstrap() {
  do_create "$@" || return 1
  run "$K" ATTACKBOX_NR_LICENSE_KEY="$NR_KEY" NEW_RELIC_API_KEY=NRAK-$(printf '%024d' 0) -- bootstrap
  [ "$RC" = 0 ] || { echo "$OUT"; return 1; }
}

# ---- tests -----------------------------------------------------------------------------------

t_plan_is_read_only_and_leaks_nothing() {
  new_sandbox; run "$K" -- plan
  [ "$RC" = 0 ] || { echo "$OUT"; return 1; }
  has "$OUT" 'Approval token:' || return 1
  has "$OUT" 'Vultr Firewall filters inbound traffic only' || { echo "egress notice missing"; return 1; }
  [ -z "$(nonget)" ] || { echo "plan made a mutating call: $(nonget)"; return 1; }
  ! grep -q "$FAKE_KEY" "$M/curl.argv" || { echo "API key found in curl argv"; return 1; }
  if has "$OUT" "$FAKE_KEY" || has "$OUT" owner@example.com || has "$OUT" 'Acct Name'; then echo "secret or PII in output"; return 1; fi
  [ "$(jq -r 'select(.p=="/account") | .k' "$M/calls.jsonl")" = true ] || { echo "account call not authenticated"; return 1; }
  [ "$(jq -r 'select(.p|test("^/(plans|regions|os)")) | .k' "$M/calls.jsonl" | sort -u)" = false ] || { echo "key sent to a public endpoint"; return 1; }
  [ ! -e "$T/.vultr" ] || { echo "plan created local state"; return 1; }
}

t_plan_rejects_unknown_plan_and_region() {
  new_sandbox
  run "$K" VULTR_PLAN=vc2-9c-99gb -- plan; [ "$RC" != 0 ] && has "$OUT" 'unknown plan' || { echo "$OUT"; return 1; }
  run "$K" VULTR_REGION=sgp -- plan; [ "$RC" != 0 ] || { echo "plan accepted an unavailable region"; return 1; }
  run "$K" VULTR_REGION=ord -- plan; [ "$RC" != 0 ] && has "$OUT" 'not available in region ord' && has "$OUT" 'Vultr lists it in: ewr ord' || { echo "$OUT"; return 1; }
}

t_ports_are_allowlisted() {
  new_sandbox
  run "$K" VULTR_PORTS=22 -- plan; [ "$RC" != 0 ] && has "$OUT" 'not allowed' || { echo "22 accepted"; return 1; }
  run "$K" VULTR_PORTS=443,8080 -- plan; [ "$RC" != 0 ] || { echo "8080 accepted"; return 1; }
  run "$K" VULTR_PORTS= -- plan; [ "$RC" != 0 ] || { echo "empty ports accepted"; return 1; }
  run "$K" VULTR_PORTS=none -- plan; [ "$RC" = 0 ] || { echo "$OUT"; return 1; }
  run "$K" VULTR_PORTS=443,80,8000,11434 -- plan; [ "$RC" = 0 ] || { echo "$OUT"; return 1; }
}

t_create_needs_flag_and_exact_token() {
  new_sandbox
  run "$K" -- create; [ "$RC" != 0 ] && has "$OUT" '--accept-host-only-egress' || { echo "$OUT"; return 1; }
  run "$K" -- create --accept-host-only-egress; [ "$RC" != 0 ] && has "$OUT" 'approval token' || { echo "$OUT"; return 1; }
  run "$K" -- create --accept-host-only-egress --approve deadbeef; [ "$RC" != 0 ] || { echo "wrong token accepted"; return 1; }
  run "$K" VULTR_PORTS=none -- plan; TOKEN=$(printf '%s\n' "$OUT" | sed -n 's/^Approval token: //p')
  run "$K" -- create --accept-host-only-egress --approve "$TOKEN"; [ "$RC" != 0 ] || { echo "token for another config accepted"; return 1; }
  [ -z "$(nonget)" ] || { echo "mutating call before approval: $(nonget)"; return 1; }
  [ ! -e "$T/.vultr" ] || { echo "state created before approval"; return 1; }
}

t_create_builds_the_expected_requests() {
  do_create || return 1
  [ "$(nonget | tr '\n' ',')" = 'POST /ssh-keys,POST /firewalls,POST /firewalls/fw-1/rules,POST /instances,' ] || { echo "unexpected calls: $(nonget)"; return 1; }
  jq -e 'select(.p=="/firewalls/fw-1/rules") | .b | fromjson | .port=="22" and .subnet=="203.0.113.7" and .subnet_size==32 and .protocol=="tcp" and .ip_type=="v4"' "$M/calls.jsonl" >/dev/null || { echo "ssh rule is not 22 from the admin /32"; return 1; }
  jq -e 'select(.p=="/instances") | .b | fromjson
    | .plan=="vc2-2c-4gb" and .region=="ewr" and .os_id==2284 and .enable_ipv6==false and .backups=="disabled"
      and .ddos_protection==false and .firewall_group_id=="fw-1" and .sshkey_id==["key-1"] and (.hostname|startswith("srv-"))' "$M/calls.jsonl" >/dev/null || { echo "instance body is wrong"; return 1; }
  local ud; ud=$(jq -r 'select(.p=="/instances") | .b | fromjson | .user_data | @base64d' "$M/calls.jsonl")
  has "$ud" '#cloud-config' && has "$ud" 'ssh_pwauth: false' && has "$ud" 'BEGIN OPENSSH PRIVATE KEY' || { echo "user-data is wrong"; return 1; }
  if command -v ruby >/dev/null 2>&1; then
    local doc; doc=$(printf '%s' "$ud" | ruby -ryaml -rjson -e 'puts JSON.generate(YAML.safe_load(STDIN.read))') || { echo "user-data is not valid YAML"; return 1; }
    [ "$(jq -r .ssh_pwauth <<<"$doc")" = false ] || return 1
    [ "$(jq -r .ssh_keys.ed25519_private <<<"$doc")" = "$(cat "$T/.vultr/hostkey")" ] || { echo "host key did not survive the YAML round trip"; return 1; }
    [ "$(jq -r .ssh_keys.ed25519_public <<<"$doc")" = "$(cut -d' ' -f1,2 "$T/.vultr/hostkey.pub")" ] || return 1
  fi
  [ "$(jq -r '.instance_id+" "+.firewall_id+" "+.ssh_key_id+" "+.main_ip' "$T/.vultr/state.json")" = 'i-1 fw-1 key-1 198.51.100.9' ] || { echo "state ids wrong"; return 1; }
  grep -q 'HUNTER2-PW' "$T"/.vultr/* 2>/dev/null && { echo "default_password was stored"; return 1; }
  has "$OUT" 'HUNTER2-PW' && { echo "default_password was printed"; return 1; }
  grep -q "$FAKE_KEY" "$M/curl.argv" && { echo "API key found in curl argv"; return 1; }
  [ "$(cut -d' ' -f1 "$T/.vultr/known_hosts")" = 198.51.100.9 ] || { echo "known_hosts not pinned to the IP"; return 1; }
  [ "$(mode_of "$T/.vultr")" = 700 ] && [ "$(mode_of "$T/.vultr/state.json")" = 600 ] && [ "$(mode_of "$T/.vultr/bootstrap")" = 600 ] || { echo "loose permissions"; return 1; }
  local argv; argv=$(cat "$M/ssh.1.argv")
  has "$argv" 'StrictHostKeyChecking=yes' && has "$argv" 'HostKeyAlgorithms=ssh-ed25519' && has "$argv" 'ForwardAgent=no' && has "$argv" '-F /dev/null' || { echo "ssh options are not pinned: $argv"; return 1; }
  run "$K" -- plan; has "$OUT" 'already records instance i-1' || { echo "plan does not warn about existing state"; return 1; }
  run "$K" -- create --accept-host-only-egress --approve "$TOKEN"; [ "$RC" != 0 ] && has "$OUT" 'already recorded' || { echo "second create was allowed"; return 1; }
}

t_bootstrap_refuses_bad_inputs() {
  do_create || return 1
  local n commit record
  n=$(cat "$M/ssh.n")
  commit=$(git -C "$T" rev-parse HEAD)
  record="$T/.git/attackbox-ci/$commit-amd64.verified"
  run "$K" APPROVE= -- bootstrap
  [ "$RC" != 0 ] && has "$OUT" "set APPROVE=$commit" || { echo "unapproved bootstrap: $OUT"; return 1; }
  run "$K" PLATFORM=linux/arm64 -- bootstrap
  [ "$RC" != 0 ] && has "$OUT" 'requires PLATFORM=linux/amd64' || { echo "wrong platform accepted: $OUT"; return 1; }
  mv "$record" "$record.saved"
  run "$K" -- bootstrap
  mv "$record.saved" "$record"
  [ "$RC" != 0 ] && has "$OUT" 'no successful release-check' || { echo "missing release record accepted: $OUT"; return 1; }
  run "$K" -- bootstrap; [ "$RC" != 0 ] || { echo "ran without a New Relic key"; return 1; }
  run "$K" ATTACKBOX_NR_LICENSE_KEY=NRAK-$(printf '%036d' 0) -- bootstrap; [ "$RC" != 0 ] || { echo "User key accepted"; return 1; }
  run "$K" ATTACKBOX_NR_LICENSE_KEY=abc123 -- bootstrap; [ "$RC" != 0 ] || { echo "short key accepted"; return 1; }
  run "$K" ATTACKBOX_NR_LICENSE_KEY="${NR_KEY%?}G" -- bootstrap; [ "$RC" != 0 ] || { echo "non-hex key accepted"; return 1; }
  run "$K" ATTACKBOX_NR_LICENSE_KEY="$NR_KEY" NR_REGION=eu -- bootstrap; [ "$RC" != 0 ] && has "$OUT" 'US New Relic' || { echo "EU accepted"; return 1; }
  echo '# local edit' >>"$T/compose.yaml"
  run "$K" ATTACKBOX_NR_LICENSE_KEY="$NR_KEY" -- bootstrap; [ "$RC" != 0 ] && has "$OUT" 'checkout has tracked changes' || { echo "dirty bundle accepted"; return 1; }
  [ "$(cat "$M/ssh.n")" = "$n" ] || { echo "ssh was used despite a refused bootstrap"; return 1; }
}

t_bootstrap_ships_a_clean_bundle_and_key_on_stdin() {
  do_bootstrap || return 1
  local i
  i=$(ssh_idx 'tar -x -C /root/attackbox-src') || { echo "no bundle upload"; return 1; }
  local listing; listing=$(tar -tf "$M/ssh.$i.stdin")
  for f in go.mod cmd/x/main.go internal/y/y.go Dockerfile .dockerignore compose.yaml compose.gvisor.yaml scripts/deploy-ubuntu.sh scripts/bootstrap-infrastructure.sh deploy/newrelic/version.env bootstrap/newrelic-cli-linux-amd64.tar.gz deploy/a docker/b; do
    has "$listing" "$f" || { echo "bundle lacks $f"; return 1; }
  done
  tar -xOf "$M/ssh.$i.stdin" vendor/fixture.test/dependency/dependency.go | grep -Fq 'committed dependency' \
    || { echo "bundle lacks generated Go dependency"; return 1; }
  if grep -Eq '^\.env$|^\.vultr/|^\.mock/|^go\.sum$|^compose\.monitoring\.yaml$|install-monitoring\.sh|vultr-launch' <<<"$listing"; then echo "bundle contains files outside the allowlist"; return 1; fi
  i=$(ssh_idx '/etc/attackbox/shipper.env') || { echo "no shipper.env write"; return 1; }
  [ "$(cat "$M/ssh.$i.stdin")" = "ATTACKBOX_NR_LICENSE_KEY=$NR_KEY
ATTACKBOX_SPOOL_SOCKET=/run/attackbox/spool.sock
ATTACKBOX_RUNTIME_SOCKET=/run/attackbox/runtime.sock
ATTACKBOX_EGRESS_SOCKET=/run/attackbox/egress.sock" ] || { echo "shipper.env content is wrong"; return 1; }
  has "$(cat "$M/ssh.$i.argv")" 'test -e /etc/attackbox/shipper.env' || { echo 'operator config preservation missing'; return 1; }
  has "$(cat "$M/ssh.$i.argv")" 'umask 077' || { echo "shipper.env is not written with umask 077"; return 1; }
  grep -Fq -- "$NR_KEY" "$M"/ssh.*.argv && { echo "New Relic key found in ssh argv"; return 1; }
  has "$OUT" "$NR_KEY" && { echo "New Relic key printed"; return 1; }
  local a b c
  a=$(ssh_idx 'deploy-ubuntu.sh --dry-run') && b=$(ssh_idx 'deploy-ubuntu.sh --apply') && c=$(ssh_idx 'deploy-ubuntu.sh --verify') || { echo "a deploy step is missing"; return 1; }
  [ "$(cat "$M/ssh.$b.stdin")" = NRAK-$(printf '%024d' 0) ] || { echo "native User key missing from apply stdin"; return 1; }
  ! grep -Fq "NRAK-$(printf '%024d' 0)" "$M"/ssh.*.argv || { echo "native User key leaked into argv"; return 1; }
  [ "$a" -lt "$b" ] && [ "$b" -lt "$c" ] || { echo "deploy steps out of order"; return 1; }
  [ "$(jq -r .bootstrapped "$T/.vultr/state.json")" = "$(git -C "$T" rev-parse HEAD)" ] || { echo "verified commit not recorded"; return 1; }
}

t_lockdown_gates() {
  do_create || return 1
  run "$K" -- lockdown --console-confirmed; [ "$RC" != 0 ] && has "$OUT" 'bootstrap has not finished' || { echo "lockdown before bootstrap"; return 1; }
  run "$K" ATTACKBOX_NR_LICENSE_KEY="$NR_KEY" -- bootstrap; [ "$RC" = 0 ] || { echo "$OUT"; return 1; }
  run "$K" -- lockdown; [ "$RC" != 0 ] && has "$OUT" '--console-confirmed' || { echo "lockdown without console confirmation"; return 1; }
  run "$K" -- lockdown --console-confirmed; [ "$RC" != 0 ] && has "$OUT" 'nothing listens on a public address for port 443' || { echo "$OUT"; return 1; }
  ssh_idx systemd-run >/dev/null && { echo "sshd was touched despite the missing listener"; return 1; }
  [ -z "$(nonget | grep DELETE || true)" ] || { echo "resources deleted despite the missing listener"; return 1; }
}

t_lockdown_closes_ssh_then_deletes_the_ssh_rule_and_key() {
  do_bootstrap || return 1
  run "$K" MOCK_LISTEN="127.0.0.1:8443 0.0.0.0:443" MOCK_LOCKDOWN_FAILS=1 -- lockdown --console-confirmed
  [ "$RC" != 0 ] && has "$OUT" 'port 22 is still open' || { echo "$OUT"; return 1; }
  [ -z "$(nonget | grep DELETE || true)" ] && [ -e "$T/.vultr/bootstrap" ] || { echo "a failed lockdown removed the SSH way in"; return 1; }
  run "$K" MOCK_LISTEN="127.0.0.1:8443 0.0.0.0:443" -- lockdown --console-confirmed
  [ "$RC" = 0 ] || { echo "$OUT"; return 1; }
  local i; i=$(ssh_idx systemd-run) || { echo "no detached lockdown"; return 1; }
  has "$(cat "$M/ssh.$i.argv")" '--disable-ssh --console-confirmed' || return 1
  [ "$(nonget | grep DELETE | tr '\n' ',')" = 'DELETE /firewalls/fw-1/rules/7,DELETE /ssh-keys/key-1,' ] || { echo "unexpected deletes: $(nonget | grep DELETE)"; return 1; }
  [ "$(jq -r .locked "$T/.vultr/state.json")" = yes ] || return 1
  [ ! -e "$T/.vultr/bootstrap" ] && [ ! -e "$T/.vultr/known_hosts" ] || { echo "local SSH keys were kept"; return 1; }
  run "$K" -- ssh true; [ "$RC" != 0 ] || { echo "ssh helper works after lockdown"; return 1; }
}

t_open_needs_lockdown_and_yes() {
  do_bootstrap || return 1
  run "$K" -- open --yes; [ "$RC" != 0 ] && has "$OUT" 'run lockdown first' || { echo "open before lockdown"; return 1; }
  run "$K" MOCK_LISTEN=0.0.0.0:443 -- lockdown --console-confirmed; [ "$RC" = 0 ] || { echo "$OUT"; return 1; }
  run "$K" -- open; [ "$RC" != 0 ] || { echo "open without --yes"; return 1; }
  run "$K" -- open --yes; [ "$RC" = 0 ] || { echo "$OUT"; return 1; }
  jq -e 'select(.m=="POST" and .p=="/firewalls/fw-1/rules") | .b | fromjson | select(.port=="443") | .subnet=="0.0.0.0" and .subnet_size==0 and .protocol=="tcp"' "$M/calls.jsonl" >/dev/null || { echo "443 rule is wrong"; return 1; }
  run "$K" -- open --yes; [ "$RC" = 0 ] && has "$OUT" 'already open' || { echo "open is not idempotent"; return 1; }
  [ "$(jq -r 'select(.m=="POST" and .p=="/firewalls/fw-1/rules") | (.b|fromjson|.port)' "$M/calls.jsonl" | sort | tr '\n' ' ')" = '22 443 ' ] || { echo "rules created: $(nonget)"; return 1; }
}

t_closed_ingress_build_cannot_open() {
  do_bootstrap VULTR_PORTS=none || return 1
  run "$K" -- lockdown --console-confirmed; [ "$RC" = 0 ] || { echo "$OUT"; return 1; }
  run "$K" -- open --yes; [ "$RC" != 0 ] && has "$OUT" 'no public ports' || { echo "$OUT"; return 1; }
}

t_status_and_kill() {
  do_create || return 1
  run "$K" -- status; [ "$RC" = 0 ] && has "$OUT" 'active/running/ok' && has "$OUT" 'out 2 MiB' && has "$OUT" 'billing' || { echo "$OUT"; return 1; }
  run "$K" -- kill --snapshot; [ "$RC" = 0 ] || { echo "$OUT"; return 1; }
  [ "$(nonget | tail -n 2 | tr '\n' ',')" = 'POST /instances/i-1/halt,POST /snapshots,' ] || { echo "kill calls: $(nonget)"; return 1; }
}

t_destroy_deletes_only_recorded_ids() {
  do_create || return 1
  run "$K" -- destroy; [ "$RC" != 0 ] && [ -e "$T/.vultr" ] || { echo "destroy ran without --yes"; return 1; }
  run "$K" -- destroy --yes; [ "$RC" = 0 ] || { echo "$OUT"; return 1; }
  [ "$(nonget | grep DELETE | tr '\n' ',')" = 'DELETE /instances/i-1,DELETE /firewalls/fw-1,DELETE /ssh-keys/key-1,' ] || { echo "deletes: $(nonget | grep DELETE)"; return 1; }
  [ ! -e "$T/.vultr" ] || { echo "local state kept"; return 1; }
  run "$K" -- destroy --yes; [ "$RC" != 0 ] || { echo "destroy with no state succeeded"; return 1; }
}

t_key_loading() {
  new_sandbox
  printf 'VULTR_API_KEY="%s"\n' "$FAKE_KEY" >"$T/.env"; chmod 644 "$T/.env"
  run -- plan; [ "$RC" = 0 ] || { echo "$OUT"; return 1; }
  [ "$(mode_of "$T/.env")" = 600 ] || { echo ".env was left readable"; return 1; }
  run -- plan; [ "$RC" = 0 ] || return 1
  has "$OUT" "$FAKE_KEY" && { echo "key printed"; return 1; }
  run VULTR_API_KEY=WRONGKEYWRONGKEY -- plan; [ "$RC" != 0 ] && has "$OUT" 'rejected the key' || { echo "environment key did not take precedence"; return 1; }
  printf 'VULTR_API_KEY="abc\\"def"\n' >"$T/.env"
  run -- plan; [ "$RC" != 0 ] && has "$OUT" 'unexpected characters' || { echo "odd key accepted"; return 1; }
  rm -f "$T/.env"
  run -- plan; [ "$RC" != 0 ] && has "$OUT" 'VULTR_API_KEY is not set' || { echo "$OUT"; return 1; }
}

# ---- harness ---------------------------------------------------------------------------------

run_test() {
  TESTS_RUN=$((TESTS_RUN + 1))
  printf '● %s\n' "$1"
  if "$1"; then printf '✓ PASS: %s\n' "$1"; else TESTS_FAILED=$((TESTS_FAILED + 1)); printf '✗ FAIL: %s\n' "$1"; fi
}

for t in t_plan_is_read_only_and_leaks_nothing t_plan_rejects_unknown_plan_and_region t_ports_are_allowlisted \
  t_create_needs_flag_and_exact_token t_create_builds_the_expected_requests t_bootstrap_refuses_bad_inputs \
  t_bootstrap_ships_a_clean_bundle_and_key_on_stdin t_lockdown_gates t_lockdown_closes_ssh_then_deletes_the_ssh_rule_and_key \
  t_open_needs_lockdown_and_yes t_closed_ingress_build_cannot_open t_status_and_kill t_destroy_deletes_only_recorded_ids t_key_loading; do
  case $t in *"${ONLY:-}"*) run_test "$t" ;; esac
done
printf '\n%s of %s passed\n' "$((TESTS_RUN - TESTS_FAILED))" "$TESTS_RUN"
[ "$TESTS_FAILED" = 0 ]
