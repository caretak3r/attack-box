#!/usr/bin/env bash
# Source only, from the trusted isolated-443 operator. Never source the legacy launcher.
# public_firewall_open DIR INSTANCE FIREWALL BIND_IPV4 COMMIT BUNDLE_SHA256 443 SSH_RULE_ID MGMT_IPV4/32
# public_firewall_rollback DIR   (idempotent after confirmed closure; keep the ledger)
#
# The caller must verify separate /32 management-policy approval, console access, signed
# release and staged TLS/telemetry receipt bound to these arguments. Serialize *all*
# provider edits/attachments, not just this directory: Vultr has no conditional rule DELETE.
# Supply trusted Bash functions api GET|POST PATH [JSON] and del PATH, pinned to the
# approved account and origin, bounded responses/timeouts, no redirects or write retries.
# A non-2xx/transport error must return nonzero. Never trace authenticated transport.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  printf '%s\n' 'Source this library from the approved operator; it is not a cutover command.' >&2
  exit 2
fi

_public_fw_error() {
  printf '%s\n' "Firewall state is unconfirmed: $1" >&2
  printf '%s\n' "Preserve $2/public-firewall-ledger.json; after restoring provider access and verifying the target, source this library and call public_firewall_rollback with that state directory. Never assume ingress is closed." >&2
}

# Sync file and directory before returning; create uses a hard link for no-clobber.
_public_fw_write() {
  local data=$1 mode=$2 path=$3
  printf '%s\n' "$data" | python3 -I -c '
import os, sys, tempfile
mode, path = sys.argv[1:]
directory = os.path.dirname(path)
fd, tmp = tempfile.mkstemp(prefix=".public-fw-", dir=directory)
try:
    with os.fdopen(fd, "wb") as f:
        f.write(sys.stdin.buffer.read()); f.flush(); os.fsync(f.fileno())
    if mode == "create":
        os.link(tmp, path); os.unlink(tmp)
    else:
        os.replace(tmp, path)
    d = os.open(directory, os.O_RDONLY)
    try: os.fsync(d)
    finally: os.close(d)
finally:
    if os.path.exists(tmp): os.unlink(tmp)
' "$mode" "$path"
}

_public_fw_lock() {
  local dir=$1
  python3 -I -c 'import os,stat,sys; s=os.lstat(sys.argv[1]); sys.exit(not (stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode)==0o700 and s.st_uid==os.geteuid()))' "$dir" || return 1
  if ! mkdir -- "$dir/.public-firewall-lock" 2>/dev/null; then
    printf '%s\n' "Ledger locked: $dir/.public-firewall-lock. If and only if no ledger operation is running, remove this empty directory with rmdir and retry rollback." >&2
    return 1
  fi
}

# Validate a single JSON document, including duplicate keys and integer identities.
# Provider strings are never used as commands, paths, jq programs, or error messages.
_public_fw_check() {
  python3 -I -c '
import ipaddress, json, re, secrets, sys

def require(condition):
    if not condition:
        raise ValueError("unexpected data")

def unique(pairs):
    out = dict(pairs)
    require(len(out) == len(pairs))
    return out

def parse(text):
    return json.loads(text, object_pairs_hook=unique, parse_constant=lambda _: require(False))

def rid(value):
    return type(value) is int and 0 < value <= 9007199254740991

def complete(reply, name):
    rows, meta = reply[name], reply["meta"]
    require(type(rows) is list and len(rows) <= 500 and type(meta["total"]) is int and
            meta["total"] == len(rows) and meta["links"]["next"] == meta["links"]["prev"] == "")
    return rows

def check_state(s):
    require(set(s) == set("version instance firewall ip commit bundle_sha token ssh_id management phase rule_id".split()))
    require(type(s["version"]) is int and s["version"] == 2)
    for key in ("instance", "firewall"):
        require(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", s[key]))
    bind = ipaddress.IPv4Address(s["ip"])
    require(str(bind) == s["ip"] and bind.is_global and not bind.is_multicast)
    mgmt = ipaddress.IPv4Network(s["management"], strict=True)
    require(str(mgmt) == s["management"] and mgmt.prefixlen == 32 and
            not (mgmt.network_address.is_unspecified or mgmt.network_address.is_multicast))
    require(re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", s["commit"]))
    for key in ("bundle_sha", "token"):
        require(re.fullmatch(r"[0-9a-f]{64}", s[key]))
    require(rid(s["ssh_id"]))
    if s["phase"] == "intent":
        require(s["rule_id"] is None)
    else:
        require(s["phase"] in ("ack", "open", "deleting", "closed") and
                rid(s["rule_id"]) and (s["phase"] == "ack" or s["rule_id"] != s["ssh_id"]))

def check():
    op, *args = sys.argv[1:]
    if op == "plan":
        instance, firewall, ip, commit, sha, ports, ssh_id, management = args
        require(ports == "443" and re.fullmatch(r"[1-9][0-9]{0,15}", ssh_id))
        s = dict(version=2, instance=instance, firewall=firewall, ip=ip, commit=commit,
                 bundle_sha=sha, token=secrets.token_hex(32), ssh_id=int(ssh_id),
                 management=management, phase="intent", rule_id=None)
        check_state(s)
        print(json.dumps(s, separators=(",", ":")))
        return
    s = parse(args[0])
    check_state(s)
    if op == "state":
        return
    note = "attackbox-public:" + s["token"] + ":443"
    public = dict(ip_type="v4", protocol="tcp", port="443", subnet="0.0.0.0",
                  subnet_size=0, source="", notes=note)
    if op == "body":
        print(json.dumps(public, separators=(",", ":")))
        return
    reply = parse(sys.stdin.read())
    if op == "instance":
        row = reply["instance"]
        require((row["id"], row["firewall_group_id"], row["main_ip"]) ==
                (s["instance"], s["firewall"], s["ip"]))
    elif op == "group":
        row = reply["firewall_group"]
        require(row["id"] == s["firewall"])
        if "instance_count" in row:
            require(type(row["instance_count"]) is int and row["instance_count"] == 1)
        if "rule_count" in row:
            require(type(row["rule_count"]) is int and row["rule_count"] in (1, 2))
        print(row.get("rule_count", 0))
    elif op == "attachments":
        rows = complete(reply, "instances")
        ids = [r["id"] for r in rows]
        require(all(type(i) is str and i for i in ids) and len(set(ids)) == len(ids))
        require([r["id"] for r in rows if r["firewall_group_id"] == s["firewall"]] == [s["instance"]])
    elif op == "post":
        n = reply["firewall_rule"]["id"]
        require(rid(n))  # Record even a conflicting SSH ID; inventory will forbid DELETE.
        print(n)
    elif op == "rules":
        rows = complete(reply, "firewall_rules")
        require(len(rows) in (1, 2) and int(args[1]) in (0, len(rows)))
        ssh = dict(public, action="accept", id=s["ssh_id"], port="22",
                   subnet=s["management"].split("/")[0], subnet_size=32,
                   notes="bootstrap ssh; lockdown removes it")
        found_ssh, owned = False, None
        for row in rows:
            n = row["id"]
            require(rid(n) and type(row["subnet_size"]) is int)
            require(row.pop("direction", "in") == "in" and row.pop("type", "v4") == "v4" and
                    row.pop("loadbalancer_id", "") == "")
            cidr = s["management"] if n == s["ssh_id"] else "0.0.0.0/0"
            require(row["source"] in ("", cidr))
            row["source"] = ""
            if row == ssh:
                require(not found_ssh)
                found_ssh = True
            else:
                require(owned is None and n != s["ssh_id"] and
                        (s["rule_id"] is None or n == s["rule_id"]) and
                        row == dict(public, id=n, action="accept"))
                owned = n
        require(found_ssh)
        print("absent" if owned is None else owned)
    else:
        require(False)

try:
    check()
except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
    sys.exit("Firewall identity, complete inventory, or ledger validation failed.")
' "$@"
}

# Every read must succeed. An empty/partial/error response is not a closed firewall.
_public_fw_snapshot() {
  local state=$1 instance=$2 fw=$3 count
  api GET "/instances/$instance" | _public_fw_check instance "$state" || return 1
  count=$(api GET "/firewalls/$fw" | _public_fw_check group "$state") || return 1
  api GET '/instances?per_page=500' | _public_fw_check attachments "$state" || return 1
  api GET "/firewalls/$fw/rules?per_page=500" | _public_fw_check rules "$state" "$count"
}

# Caller holds the directory lock. Persist each transition before relying on it.
_public_fw_mark() {
  local updated
  updated=$(jq -ce --arg phase "$1" --argjson id "$2" '.phase=$phase | .rule_id=$id' <<<"$state") || return 1
  _public_fw_write "$updated" replace "$ledger" || return 1
  state=$updated
}

_public_fw_close_locked() {
  local observed phase current
  observed=$(_public_fw_snapshot "$state" "$instance" "$fw") || return 1
  phase=$(jq -er .phase <<<"$state") || return 1
  if [[ $observed == absent ]]; then
    case $phase in
      closed) return 0 ;;
      deleting) _public_fw_mark closed "$(jq -er .rule_id <<<"$state")"; return ;;
      *) return 1 ;; # Unseen or delayed POST, not proof of rollback.
    esac
  fi
  [[ $phase != closed ]] || return 1
  _public_fw_mark deleting "$observed" || return 1
  current=$(_public_fw_snapshot "$state" "$instance" "$fw") || return 1
  [[ $current == "$observed" ]] || return 1
  # A lost DELETE response can be resolved only by a fresh, successful full read.
  del "/firewalls/$fw/rules/$observed" >/dev/null || :
  current=$(_public_fw_snapshot "$state" "$instance" "$fw") || return 1
  [[ $current == absent ]] || return 1
  _public_fw_mark closed "$observed"
}

public_firewall_open() (
  set -o pipefail
  umask 077
  [[ $# == 9 ]] && declare -F api del >/dev/null || return 1
  local dir=$1 instance=$2 fw=$3 ledger=$1/public-firewall-ledger.json state id body observed
  state=$(_public_fw_check plan "${@:2}") || return 1
  _public_fw_lock "$dir" || return 1
  trap 'rmdir -- "$dir/.public-firewall-lock"' EXIT
  trap 'exit 1' HUP INT TERM
  [[ ! -e $ledger && ! -L $ledger ]] || { _public_fw_error 'ledger already exists' "$dir"; return 1; }
  observed=$(_public_fw_snapshot "$state" "$instance" "$fw") && [[ $observed == absent ]] || return 1
  body=$(_public_fw_check body "$state") || return 1
  _public_fw_write "$state" create "$ledger" || return 1
  observed=$(_public_fw_snapshot "$state" "$instance" "$fw") && [[ $observed == absent ]] || return 1
  if id=$(api POST "/firewalls/$fw/rules" "$body" | _public_fw_check post "$state"); then
    _public_fw_mark ack "$id" || { _public_fw_error 'cannot persist POST identity' "$dir"; return 1; }
    if observed=$(_public_fw_snapshot "$state" "$instance" "$fw") && [[ $observed == "$id" ]]; then
      _public_fw_mark open "$id" && return 0
    fi
  fi
  if _public_fw_close_locked; then
    printf '%s\n' 'Cutover failed; verified rollback to the recorded SSH /32.' >&2
  else
    _public_fw_error 'POST uncertain or final inventory changed' "$dir"
  fi
  return 1
)

public_firewall_rollback() (
  set -o pipefail
  umask 077
  [[ $# == 1 ]] && declare -F api del >/dev/null || return 1
  local dir=$1 ledger=$1/public-firewall-ledger.json state instance fw
  _public_fw_lock "$dir" || return 1
  trap 'rmdir -- "$dir/.public-firewall-lock"' EXIT
  trap 'exit 1' HUP INT TERM
  [[ -f $ledger && ! -L $ledger ]] && state=$(cat -- "$ledger") && _public_fw_check state "$state" ||
    { _public_fw_error 'missing or invalid ledger' "$dir"; return 1; }
  instance=$(jq -er .instance <<<"$state") && fw=$(jq -er .firewall <<<"$state") || return 1
  _public_fw_close_locked || { _public_fw_error 'cannot prove safe rollback' "$dir"; return 1; }
  printf '%s\n' 'Verified recorded bootstrap SSH /32 only; no public TCP/443 rule remains.'
)
