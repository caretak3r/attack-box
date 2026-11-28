#!/usr/bin/env bash
# Launch the Attack Box decoy on Vultr from the Mac. Runbook: docs/vultr-launch.md
# Read-only: plan, status, ssh. They change things: create, bootstrap, lockdown, open, kill, destroy.
# The decoy never holds a Vultr key. Only resource IDs recorded in .vultr/state.json are ever touched.
set -euo pipefail
umask 077

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
STATE_DIR=${VULTR_STATE_DIR:-$ROOT/.vultr}
STATE=$STATE_DIR/state.json
API=${VULTR_API_URL:-https://api.vultr.com/v2}
PLAN=${VULTR_PLAN:-vc2-2c-4gb}
REGION=${VULTR_REGION:-ewr}
PORTS=${VULTR_PORTS-443}
POLL=${VULTR_POLL_SECS:-10}
OS_NAME='Ubuntu 24.04 LTS x64'
API_CODE=
# Source ships from a commit. Go dependencies are generated from that source.
BUNDLE=(go.mod cmd internal Dockerfile .dockerignore compose.yaml compose.gvisor.yaml docker deploy scripts/deploy-ubuntu.sh)

log()  { printf '● %s\n' "$*" >&2; }
ok()   { printf '✓ %s\n' "$*" >&2; }
warn() { printf '○ %s\n' "$*" >&2; }
die()  { printf '✗ %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1"; }

usage() {
  cat <<'EOF'
Usage: scripts/vultr-launch.sh <command> [options]

Read-only:
  plan                  Check the key, catalog and inputs. Print what create would build, its cost and approval token.
  status                Instance state, firewall rules, 7-day bandwidth, billing.
  ssh [command]         SSH to the decoy with the pinned key (only before lockdown).
Changes Vultr or the decoy:
  create --approve TOKEN --accept-host-only-egress
  bootstrap             Deploy an approved linux/amd64 release. Use make deploy after make release-check.
  lockdown --console-confirmed
                        Turn sshd off, delete the SSH firewall rule and the account SSH key.
  open --yes            Open the approved public ports. This is the final step.
  kill [--snapshot]     Power the instance off. A powered-off instance still bills.
  destroy --yes         Delete the instance, firewall group and SSH key recorded in the state file.

Environment:
  VULTR_PLAN (vc2-2c-4gb)  VULTR_REGION (ewr)  VULTR_PORTS (443; list from 80,443,8000,11434; none = closed ingress)
  ADMIN_CIDR (one IPv4 /32; default: detected)
  VULTR_API_KEY (or in .env)
EOF
}


# ---- key, API, state -------------------------------------------------------------------------

load_key() {
  local f=$ROOT/.env mode
  if [ -z "${VULTR_API_KEY:-}" ]; then
    [ -f "$f" ] || die "VULTR_API_KEY is not set and $f does not exist"
    if [ "$(uname)" = Darwin ]; then mode=$(stat -f %Lp "$f"); else mode=$(stat -c %a "$f"); fi
    if [ "$mode" != 600 ]; then chmod 600 "$f"; warn ".env had mode $mode; it is now 600"; fi
    VULTR_API_KEY=$(sed -n -E 's/^(export[[:space:]]+)?VULTR_API_KEY=//p' "$f" | tail -n 1 | tr -d "\"' \r")
  fi
  [ -n "$VULTR_API_KEY" ] || die "no VULTR_API_KEY in the environment or $f"
  # The key goes into a curl config line: refuse anything that could break out of it.
  [[ $VULTR_API_KEY =~ ^[A-Za-z0-9._-]+$ ]] || die "VULTR_API_KEY has unexpected characters"
}

# The key travels to curl through a config file descriptor, never argv.
curl_key() {
  curl -sS -m 60 -K <(printf 'header = "Authorization: Bearer %s"\n' "$VULTR_API_KEY") \
    -H 'Content-Type: application/json' -w '\n%{http_code}' "$@"
}

# api METHOD PATH [JSON]: body on stdout. On failure: message, status 1. API_CODE keeps the HTTP code.
api() {
  local m=$1 p=$2 body=${3:-} out
  if [ -n "$body" ]; then
    out=$(printf '%s' "$body" | curl_key -X "$m" --data-binary @- "$API$p") || { warn "curl failed: $m $p"; return 1; }
  else
    out=$(curl_key -X "$m" "$API$p") || { warn "curl failed: $m $p"; return 1; }
  fi
  API_CODE=${out##*$'\n'}
  out=${out%$'\n'*}
  case $API_CODE in
    2??) printf '%s' "$out" ;;
    *) warn "$m $p -> HTTP $API_CODE: $(jq -r '.error // empty' <<<"$out" 2>/dev/null | head -c 300)"; return 1 ;;
  esac
}

del() { api DELETE "$1" >/dev/null || [ "$API_CODE" = 404 ]; }
pub() { curl -fsS -m 60 "$API$1" || { warn "GET $1 failed"; return 1; }; }

st()     { [ -f "$STATE" ] && jq -r --arg k "$1" '.[$k] // empty' "$STATE" || true; }
st_set() { jq --arg k "$1" --arg v "$2" '.[$k]=$v' "$STATE" >"$STATE.tmp" && mv "$STATE.tmp" "$STATE"; }

# wait_until CMD [ARGS]: retry every POLL seconds until CMD succeeds or VULTR_WAIT_SECS (default 900) pass.
wait_until() {
  local t=0 step=$POLL
  [ "$step" -ge 1 ] || step=1
  until "$@"; do
    t=$((t + step))
    [ "$t" -lt "${VULTR_WAIT_SECS:-900}" ] || return 1
    sleep "$POLL"
  done
}

# ---- inputs ----------------------------------------------------------------------------------

check_ports() {
  local p
  [ -n "$PORTS" ] || die "VULTR_PORTS is empty (use none for a closed-ingress build)"
  [ "$PORTS" = none ] && return 0
  for p in ${PORTS//,/ }; do
    case $p in 80|443|8000|11434) ;; *) die "port $p is not allowed. Allowed: 80 443 8000 11434, or none" ;; esac
  done
}

# Sets PLAN_JSON, REGION_NAME, OS_ID, MONTHLY. Public endpoints: the key is not sent.
catalog() {
  local hit where
  PLAN_JSON=$(pub '/plans?per_page=500' | jq -c --arg p "$PLAN" '.plans[] | select(.id==$p)') || die "cannot read the plan catalog"
  [ -n "$PLAN_JSON" ] || die "unknown plan: $PLAN"
  hit=$(pub "/regions/$REGION/availability?type=all" | jq -r --arg p "$PLAN" '(.available_plans // []) | index($p) // empty') \
    || die "cannot read availability for region $REGION"
  if [ -z "$hit" ]; then
    where=$(jq -r '(.locations // []) | join(" ")' <<<"$PLAN_JSON")
    die "plan $PLAN is not available in region $REGION. Vultr lists it in: ${where:-no region right now (inventory empty or the API is degraded; retry later)}"
  fi
  REGION_NAME=$(pub '/regions?per_page=500' | jq -r --arg r "$REGION" '.regions[] | select(.id==$r) | "\(.city), \(.country)"') || die "cannot read regions"
  OS_ID=$(pub '/os?per_page=500' | jq -r --arg n "$OS_NAME" '[.os[] | select(.name==$n)][0].id // empty') || die "cannot read the OS list"
  [ -n "$OS_ID" ] || die "OS not found: $OS_NAME"
  MONTHLY=$(jq -r .monthly_cost <<<"$PLAN_JSON")
}

# The approval binds to everything that costs money or opens ports.
token() { printf '%s|%s|%s|%s|%s' "$PLAN" "$REGION" "$OS_ID" "$PORTS" "$MONTHLY" | shasum -a 256 | cut -c1-8; }

admin_cidr() {
  local c=${ADMIN_CIDR:-} re='^([0-9]{1,3}\.){3}[0-9]{1,3}/32$'
  if [ -z "$c" ]; then
    c=$(curl -4 -fsS -m 10 https://checkip.amazonaws.com | tr -d '[:space:]') || die "cannot detect your public IP; set ADMIN_CIDR=<ipv4>/32"
    c=$c/32
  fi
  [[ $c =~ $re ]] || die "ADMIN_CIDR must be one IPv4 address with /32 (got: $c)"
  printf '%s' "$c"
}



# 0 when compose publishes port $1 on a non-loopback address.
published() {
  grep -Eqs "^[[:space:]]*-[[:space:]]*\"?(0\.0\.0\.0:)?$1:[0-9]+" "$ROOT/compose.yaml" "$ROOT/compose.public.yaml"
}

# ---- decoy access ----------------------------------------------------------------------------

# cloud-config for the decoy. The pinned host key lets this Mac verify the server on the first connection.
userdata() {
  cat <<EOF
#cloud-config
hostname: $1
manage_etc_hosts: localhost
ssh_pwauth: false
ssh_deletekeys: true
ssh_genkeytypes: [ed25519]
ssh_keys:
  ed25519_private: |
$(sed 's/^/    /' "$STATE_DIR/hostkey")
  ed25519_public: $(cut -d' ' -f1,2 "$STATE_DIR/hostkey.pub")
EOF
}

# sshq CMD...: run as root on the decoy with the pinned host key. Stdin passes through.
sshq() {
  ssh -F /dev/null -i "$STATE_DIR/bootstrap" -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$STATE_DIR/known_hosts" -o GlobalKnownHostsFile=/dev/null \
    -o HostKeyAlgorithms=ssh-ed25519 -o ConnectTimeout=10 -o ServerAliveInterval=30 \
    -o ControlPath=none -o ForwardAgent=no "root@$(st main_ip)" "$@"
}

instance_ready() { # sets MAIN_IP
  local j
  j=$(api GET "/instances/$1" | jq -c .instance) || return 1
  [ "$(jq -r '"\(.status)/\(.power_status)"' <<<"$j")" = active/running ] || return 1
  MAIN_IP=$(jq -r .main_ip <<<"$j")
  [ "$MAIN_IP" != 0.0.0.0 ]
}

ssh_ready() {
  local err
  if err=$(sshq true 2>&1); then return 0; fi
  case $err in
    *'identification has changed'*|*'Host key verification failed'*)
      die "the server does not present the pinned SSH host key (cloud-init did not apply ssh_keys, or this is not our server). Run destroy --yes and retry. ssh said: $err" ;;
  esac
  return 1
}

port22_closed() { ! nc -z -w 5 "$1" 22 && sleep "$POLL" && ! nc -z -w 5 "$1" 22; }

canaries() {
  log "post-deploy canaries"
  sshq 'bash -s' <<'EOS' || true
echo "services : $(systemctl is-active attackbox attackbox-shipper falco-modern-bpf attackbox-falco-adapter attackbox-egress-adapter | tr '\n' ' ')"
if [ -r /sys/kernel/btf/vmlinux ]; then echo "btf      : yes"; else echo "btf      : NO (Falco modern eBPF needs it)"; fi
echo "listeners: $(ss -ltnH | awk '{print $4}' | sort -u | tr '\n' ' ')"
echo "kernel   : $(uname -r)"
EOS
}

# ---- commands --------------------------------------------------------------------------------

cmd_plan() {
  local acct cidr n_inst n_fw n_key cur p
  need jq; need curl; need shasum
  load_key; check_ports; catalog
  acct=$(api GET /account) || die "the Vultr API rejected the key (is this Mac's IP allowed in the key's access control?)"
  n_inst=$(api GET '/instances?per_page=500' | jq '.instances | length') || die "cannot list instances"
  n_fw=$(api GET '/firewalls?per_page=500' | jq '.firewall_groups | length') || die "cannot list firewall groups"
  n_key=$(api GET '/ssh-keys?per_page=500' | jq '.ssh_keys | length') || die "cannot list SSH keys"
  cidr=$(admin_cidr)
  cur=$(st instance_id)

  printf 'Vultr decoy plan (read-only: nothing is created)\n\n'
  printf 'Account      %s\n' "$(jq -r '.account | "balance \(.balance), pending charges \(.pending_charges), permissions: \(.acls | join(" "))"' <<<"$acct")"
  printf 'In account   %s instances, %s firewall groups, %s SSH keys; local state: %s\n' "$n_inst" "$n_fw" "$n_key" "${cur:-none}"
  printf 'Plan         %s\n' "$(jq -r '"\(.id): \(.vcpu_count) vCPU, \(.ram) MB RAM, \(.disk) GB SSD, \(.bandwidth) GB transfer"' <<<"$PLAN_JSON")"
  printf 'Price        $%s/month ($%s/hour). Billed hourly. A powered-off instance still bills.\n' "$MONTHLY" "$(jq -r .hourly_cost <<<"$PLAN_JSON")"
  printf 'Region       %s (%s)\n' "$REGION" "$REGION_NAME"
  printf 'Image        %s (os_id %s)\n' "$OS_NAME" "$OS_ID"
  printf 'Network      IPv4 only, backups off, DDoS add-on off. SSH from %s only, until lockdown.\n' "$cidr"
  if [ "$PORTS" = none ]; then printf 'Ingress      none (closed-ingress build)\n\n'; else printf 'Ingress      tcp %s, opened last by: open --yes\n\n' "$PORTS"; fi

  printf 'Checks\n'
  if jq -e '.account.acls | index("provisioning") != null and index("firewall") != null' <<<"$acct" >/dev/null; then
    printf '✓ the key may provision instances and manage firewalls\n'
  else
    printf '✗ the key lacks the provisioning or firewall permission: create will fail\n'
  fi
  [ -z "$cur" ] || printf '○ the state file already records instance %s: create will refuse until destroy --yes\n' "$cur"
  if [ "$PORTS" != none ]; then
    for p in ${PORTS//,/ }; do
      published "$p" || printf '○ port %s: compose publishes loopback only (IMPROVE.md I01). Today this is a closed-ingress build; lockdown refuses while port %s is approved.\n' "$p" "$p"
    done
  fi
  printf '✗ Vultr Firewall filters inbound traffic only (docs.vultr.com: "Outbound traffic is not filtered by Vultr Firewall").\n'
  printf '  The plan asks for provider outbound rules that root on the decoy cannot change. On Vultr the host nftables\n'
  printf '  policy is the only egress control, and host root can remove it. Watch outbound bytes: scripts/vultr-launch.sh status\n'

  printf '\nApproval token: %s\n' "$(token)"
  printf 'To build:\n  VULTR_PLAN=%s VULTR_REGION=%s VULTR_PORTS=%s scripts/vultr-launch.sh create --approve %s --accept-host-only-egress\n' \
    "$PLAN" "$REGION" "$PORTS" "$(token)"
}

cmd_create() {
  local approve='' accept=false cidr label host key fw rule body id
  while [ $# -gt 0 ]; do
    case $1 in
      --approve) [ $# -ge 2 ] || die "--approve needs a value"; approve=$2; shift 2 ;;
      --accept-host-only-egress) accept=true; shift ;;
      *) die "unknown option: $1" ;;
    esac
  done
  need jq; need curl; need ssh; need ssh-keygen; need base64; need shasum; need openssl
  load_key; check_ports; catalog
  [ "$accept" = true ] || die "create needs --accept-host-only-egress: Vultr Firewall filters inbound traffic only, so the host nftables policy is the only egress control (docs/vultr-launch.md)"
  [ "$approve" = "$(token)" ] || die "the approval token does not match this configuration; run: scripts/vultr-launch.sh plan"
  [ -z "$(st instance_id)$(st firewall_id)$(st ssh_key_id)" ] || die "resources are already recorded in $STATE; run destroy --yes first"
  cidr=$(admin_cidr)

  mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
  [ -f "$STATE" ] || echo '{}' >"$STATE"
  rm -f "$STATE_DIR/bootstrap" "$STATE_DIR/bootstrap.pub" "$STATE_DIR/hostkey" "$STATE_DIR/hostkey.pub" "$STATE_DIR/known_hosts"
  ssh-keygen -q -t ed25519 -N '' -C bootstrap -f "$STATE_DIR/bootstrap"
  ssh-keygen -q -t ed25519 -N '' -C '' -f "$STATE_DIR/hostkey"
  label=decoy-$(date -u +%Y%m%d-%H%M)
  host=srv-$(openssl rand -hex 3)
  st_set label "$label"; st_set region "$REGION"; st_set plan "$PLAN"; st_set ports "$PORTS"; st_set admin_cidr "$cidr"

  log "uploading the one-time SSH key"
  key=$(api POST /ssh-keys "$(jq -n --arg n "$label" --arg k "$(cat "$STATE_DIR/bootstrap.pub")" '{name:$n,ssh_key:$k}')" | jq -er .ssh_key.id) \
    || die "SSH key upload failed; run destroy --yes to clean up"
  st_set ssh_key_id "$key"
  log "creating the firewall group: inbound SSH from $cidr only"
  fw=$(api POST /firewalls "$(jq -n --arg d "$label" '{description:$d}')" | jq -er .firewall_group.id) \
    || die "firewall group create failed; run destroy --yes to clean up"
  st_set firewall_id "$fw"
  rule=$(api POST "/firewalls/$fw/rules" "$(jq -n --arg ip "${cidr%/*}" \
    '{ip_type:"v4",protocol:"tcp",subnet:$ip,subnet_size:32,port:"22",notes:"bootstrap ssh; lockdown removes it"}')" | jq -er .firewall_rule.id) \
    || die "firewall rule create failed; run destroy --yes to clean up"
  st_set ssh_rule_id "$rule"

  body=$(jq -n --arg region "$REGION" --arg plan "$PLAN" --argjson os "$OS_ID" --arg label "$label" --arg host "$host" \
    --arg key "$key" --arg fw "$fw" --arg ud "$(userdata "$host" | base64 | tr -d '\n')" \
    '{region:$region,plan:$plan,os_id:$os,label:$label,hostname:$host,sshkey_id:[$key],firewall_group_id:$fw,
      enable_ipv6:false,backups:"disabled",ddos_protection:false,activation_email:false,user_data:$ud,tags:["decoy"]}')
  log "creating $PLAN in $REGION ($REGION_NAME). Billing starts now: \$$(jq -r .hourly_cost <<<"$PLAN_JSON")/hour"
  id=$(api POST /instances "$body" | jq -er .instance.id) || die "instance create failed; run destroy --yes to clean up"
  st_set instance_id "$id"

  log "waiting for the instance (Vultr updates packages before SSH starts; 3 to 8 minutes)"
  wait_until instance_ready "$id" || die "the instance is not active yet; check: scripts/vultr-launch.sh status"
  st_set main_ip "$MAIN_IP"
  printf '%s %s\n' "$MAIN_IP" "$(cut -d' ' -f1,2 "$STATE_DIR/hostkey.pub")" >"$STATE_DIR/known_hosts"
  log "waiting for SSH with the pinned host key"
  wait_until ssh_ready || die "SSH did not come up; check the Vultr console, or run destroy --yes"
  ok "instance $id is up at $MAIN_IP. Next: scripts/vultr-launch.sh bootstrap"
}

cmd_bootstrap() (
  local commit stage run
  [ $# -eq 0 ] || die 'bootstrap does not accept arguments; use COMMIT and APPROVE'
  [[ ${PLATFORM:-linux/amd64} == linux/amd64 ]] || die 'the Vultr bootstrap requires PLATFORM=linux/amd64'
  commit=$(cd "$ROOT" && PLATFORM=linux/amd64 bash scripts/local-ci.sh authorize-deploy)
  run="cd /root/attackbox-src && ATTACKBOX_RELEASE_VERSION=$commit ./scripts/deploy-ubuntu.sh"
  local files=("${BUNDLE[@]}")
  need jq; need git; need go; need tar; need ssh
  [ -n "$(st instance_id)" ] && [ -n "$(st main_ip)" ] || die "no instance recorded; run create first"
  [ "$(st locked)" != yes ] || die "the decoy is locked down: destroy it and create a new one to change it"
  if git -C "$ROOT" cat-file -e "$commit:go.sum" 2>/dev/null; then files+=(go.sum); fi

  stage=$(mktemp -d "$STATE_DIR/bundle.XXXXXX")
  trap 'rm -rf -- "$stage"' EXIT
  git -C "$ROOT" archive --format=tar "$commit" -- "${files[@]}" | tar -xf - -C "$stage"
  log "preparing Go dependencies from commit $commit"
  (cd "$stage" && GOWORK=off GOFLAGS= GOTOOLCHAIN=local go mod vendor)
  if [ -d "$stage/vendor" ]; then files+=(vendor); fi

  log "shipping the bundle from commit $commit"
  tar -cf - -C "$stage" "${files[@]}" \
    | sshq 'rm -rf /root/attackbox-src && install -d -m 0700 /root/attackbox-src && tar -x -C /root/attackbox-src'

  log "preflight (no changes)"
  sshq "$run --dry-run"
  log "apply: Docker, gVisor, Falco, firewall, bait image (10 to 20 minutes)"
  sshq "$run --apply"
  log "verify from inside gVisor"
  sshq "$run --verify"

  log "deployment test gate: running synthetic scenario check through SSH local forward"
  local model local_port forward_pid scenario_output gate_rc wait_secs
  model=$(grep -Eo 'ATTACKBOX_MODELS:[[:space:]]*"[^"]+' "$stage/compose.yaml" | sed 's/.*"\([^,]*\).*/\1/' | head -n1)
  [[ -n $model ]] || die 'could not detect model from compose.yaml'
  local_port=18443
  scenario_output=$STATE_DIR/scenario-$commit.jsonl
  rm -f -- "$scenario_output"
  ssh -N -L "127.0.0.1:$local_port:127.0.0.1:8443" \
    -F /dev/null -i "$STATE_DIR/bootstrap" -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$STATE_DIR/known_hosts" -o GlobalKnownHostsFile=/dev/null \
    -o HostKeyAlgorithms=ssh-ed25519 -o ConnectTimeout=10 -o ServerAliveInterval=10 \
    -o ControlPath=none -o ForwardAgent=no -o ExitOnForwardFailure=yes \
    "root@$(st main_ip)" </dev/null >"$STATE_DIR/forward.log" 2>&1 &
  forward_pid=$!
  trap 'kill "$forward_pid" 2>/dev/null || true; wait "$forward_pid" 2>/dev/null || true; rm -rf -- "$stage"' EXIT
  wait_secs=0
  while [ "$wait_secs" -lt 15 ]; do
    if ! kill -0 "$forward_pid" 2>/dev/null; then
      wait "$forward_pid" 2>/dev/null || true
      die "deployment test gate failed: SSH forward exited before local port was ready"
    fi
    if nc -z 127.0.0.1 "$local_port" 2>/dev/null; then break; fi
    sleep 1
    wait_secs=$((wait_secs + 1))
  done
  if [ "$wait_secs" -ge 15 ]; then
    kill "$forward_pid" 2>/dev/null || true
    wait "$forward_pid" 2>/dev/null || true
    die "deployment test gate failed: local port $local_port did not become ready within 15 seconds"
  fi
  gate_rc=0
  # Port 8443 is nginx: it rejects the traversal and oversized cases before the bait.
  (cd "$ROOT" && go run ./cmd/attackbox-scenarios -target "https://127.0.0.1:$local_port" -self-signed -proxy \
    -model "$model" -commit "${commit:0:12}" -run-id "bootstrap-$commit" -output "$scenario_output") || gate_rc=$?
  kill "$forward_pid" 2>/dev/null || true
  wait "$forward_pid" 2>/dev/null || true
  if [ "$gate_rc" != 0 ]; then
    die "deployment test gate failed: scenario check exit $gate_rc; see $scenario_output or stderr above"
  fi
  [ -f "$scenario_output" ] || die "deployment test gate: scenario output file was not created"
  chmod 0600 "$scenario_output"
  ok "deployment test gate passed: all scenarios verified; manifest at $scenario_output"

  canaries
  st_set bootstrapped "$commit"
  ok "bootstrap finished. Check evidence streams and the heartbeat, then: lockdown --console-confirmed"
)


cmd_lockdown() {
  local ports ip fw p listeners
  need jq; need ssh; need nc; load_key
  [ "${1:-}" = --console-confirmed ] || die "lockdown needs --console-confirmed: open this instance's web console in the Vultr portal first and confirm you can reach it (recovery without SSH is the console or a rebuild)"
  [ -n "$(st bootstrapped)" ] || die "bootstrap has not finished; run it first"
  [ "$(st locked)" != yes ] || die "already locked down"
  ports=$(st ports); ip=$(st main_ip); fw=$(st firewall_id)

  if [ "$(st ssh_off)" != yes ]; then
    if [ "$ports" != none ]; then
      listeners=$(sshq 'ss -ltnH' | awk '{print $4}')
      for p in ${ports//,/ }; do
        grep -Eq "^(0\.0\.0\.0|\*|\[::\]):$p\$" <<<"$listeners" \
          || die "nothing listens on a public address for port $p (compose publishes loopback only; docs/vultr-launch.md). Nothing was changed"
      done
    fi
    # Detached: stopping sshd can end this very session. The deploy script re-verifies before it disables SSH.
    log "starting the lockdown on the decoy (detached)"
    sshq "systemd-run --quiet --collect --no-block --unit=abx-lockdown /bin/bash -c 'exec >/var/log/attackbox-lockdown.log 2>&1; cd /root/attackbox-src && ./scripts/deploy-ubuntu.sh --apply --disable-ssh --console-confirmed && { systemctl disable --now ssh.socket; systemctl mask ssh.socket; }'"
    log "waiting for port 22 to close (re-verification first; a few minutes)"
    wait_until port22_closed "$ip" \
      || die "port 22 is still open, so the deploy script did not finish. SSH and the firewall rule stay. Read the log: scripts/vultr-launch.sh ssh 'tail -n 60 /var/log/attackbox-lockdown.log'"
    st_set ssh_off yes
  fi
  if [ -n "$(st ssh_rule_id)" ]; then del "/firewalls/$fw/rules/$(st ssh_rule_id)"; st_set ssh_rule_id ''; fi
  if [ -n "$(st ssh_key_id)" ]; then del "/ssh-keys/$(st ssh_key_id)"; st_set ssh_key_id ''; fi
  rm -f "$STATE_DIR/bootstrap" "$STATE_DIR/bootstrap.pub" "$STATE_DIR/hostkey" "$STATE_DIR/hostkey.pub" "$STATE_DIR/known_hosts"
  st_set locked yes
  ok "locked down: sshd off, SSH firewall rule and account SSH key deleted, local keys removed"
  warn "next: confirm the heartbeat and evidence streams are healthy, then: scripts/vultr-launch.sh open --yes"
}

cmd_open() {
  local ports fw p n
  need jq; load_key
  [ "${1:-}" = --yes ] || die "open exposes the decoy to the Internet: rerun with --yes"
  [ "$(st locked)" = yes ] || die "run lockdown first: SSH must be closed before any port opens"
  ports=$(st ports); fw=$(st firewall_id)
  [ "$ports" != none ] || die "the approved profile has no public ports (closed-ingress build)"
  for p in ${ports//,/ }; do
    n=$(api GET "/firewalls/$fw/rules?per_page=500" | jq --arg p "$p" '[.firewall_rules[] | select(.port==$p)] | length') || die "cannot list firewall rules"
    if [ "$n" -gt 0 ]; then warn "tcp/$p already open"; continue; fi
    api POST "/firewalls/$fw/rules" "$(jq -n --arg p "$p" '{ip_type:"v4",protocol:"tcp",subnet:"0.0.0.0",subnet_size:0,port:$p,notes:("public "+$p)}')" >/dev/null
    ok "inbound tcp/$p is open to 0.0.0.0/0"
  done
  st_set opened yes
  warn "test from a separate host, not this Mac: the Mac must not touch the live decoy"
}

cmd_status() {
  local id fw
  need jq; load_key
  id=$(st instance_id); fw=$(st firewall_id)
  [ -n "$id" ] || die "no instance recorded in $STATE"
  api GET "/instances/$id" | jq -r '.instance | "instance   \(.id)  \(.status)/\(.power_status)/\(.server_status)  \(.main_ip)  \(.plan)  \(.region)  \(.label)"'
  printf 'local      bootstrapped=%s ssh_off=%s locked=%s opened=%s ports=%s\n' "$(st bootstrapped)" "$(st ssh_off)" "$(st locked)" "$(st opened)" "$(st ports)"
  api GET "/firewalls/$fw/rules?per_page=500" | jq -r '.firewall_rules[] | "rule       \(.id)  \(.protocol) \(.port)  from \(.subnet)/\(.subnet_size)  \(.notes)"'
  api GET "/instances/$id/bandwidth?date_range=7" | jq -r '.bandwidth | to_entries[] | "bandwidth  \(.key)  in \((.value.incoming_bytes / 1048576) | floor) MiB  out \((.value.outgoing_bytes / 1048576) | floor) MiB"'
  api GET /account | jq -r '.account | "billing    balance \(.balance), pending charges \(.pending_charges)"'
  printf 'note       outbound bytes far above your baseline mean the egress policy failed: kill, then rebuild\n'
}

cmd_ssh() {
  [ -n "$(st main_ip)" ] || die "no instance recorded"
  [ "$(st locked)" != yes ] || die "locked down: SSH is closed. Use the Vultr console"
  sshq "$@"
}

cmd_kill() {
  local id
  need jq; load_key
  id=$(st instance_id)
  [ -n "$id" ] || die "no instance recorded in $STATE"
  api POST "/instances/$id/halt" >/dev/null
  ok "power-off requested for $id. It still bills: destroy --yes stops billing"
  if [ "${1:-}" = --snapshot ]; then
    api POST /snapshots "$(jq -n --arg i "$id" --arg d "forensic $(st label)" '{instance_id:$i,description:$d}')" >/dev/null
    ok "forensic snapshot requested. Do not download it"
  fi
  warn "if telemetry looks malicious, also lock the decoy to prevent further evidence egress"
}

cmd_destroy() {
  local id fw key
  need jq; load_key
  [ "${1:-}" = --yes ] || die "destroy deletes the instance, firewall group and SSH key recorded in the state file: rerun with --yes"
  [ -f "$STATE" ] || die "no state file at $STATE: nothing to destroy"
  id=$(st instance_id); fw=$(st firewall_id); key=$(st ssh_key_id)
  if [ -n "$id" ]; then del "/instances/$id"; ok "instance $id deleted"; fi
  if [ -n "$fw" ]; then
    # Vultr refuses to delete a firewall group while an instance is attached.
    wait_until del "/firewalls/$fw" || die "firewall group $fw is still attached; run destroy --yes again in a minute"
    ok "firewall group $fw deleted"
  fi
  if [ -n "$key" ]; then del "/ssh-keys/$key"; ok "SSH key $key deleted"; fi
  rm -rf "$STATE_DIR"
  ok "local state removed"
}

case ${1:-} in
  plan) shift; cmd_plan "$@" ;;
  create) shift; cmd_create "$@" ;;
  bootstrap) shift; cmd_bootstrap "$@" ;;
  lockdown) shift; cmd_lockdown "$@" ;;
  open) shift; cmd_open "$@" ;;
  status) shift; cmd_status "$@" ;;
  ssh) shift; cmd_ssh "$@" ;;
  kill) shift; cmd_kill "$@" ;;
  destroy) shift; cmd_destroy "$@" ;;
  -h|--help|help) usage ;;
  *) usage >&2; exit 2 ;;
esac
