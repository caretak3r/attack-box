#!/usr/bin/env bash
set -euo pipefail
action=${1:-}
[[ $action == prepare || $action == ready || $action == cleanup ]] || { echo 'usage: prepare-socket.sh prepare|ready|cleanup' >&2; exit 2; }
dir=/run/attackbox-public-otel
socket=$dir/otlp.sock
state=/run/attackbox-public-otel-state
marker=$state/uid
pending=$state/uid.pending
uid=$(id -u abx-public-otel)
if getent passwd abx-otel >/dev/null; then
  private_uid=$(id -u abx-otel)
else
  result=$?
  [[ $result == 2 ]] || { echo 'cannot inspect private collector identity' >&2; exit 1; }
  private_uid=
fi
[[ $uid =~ ^[0-9]+$ && $uid != 0 && $uid != 65532 && $uid != "$private_uid" ]] || { echo 'invalid public collector UID' >&2; exit 1; }
unique_uid=$(getent passwd | awk -F: -v uid="$uid" '$3 == uid { count++; if ($1 == "abx-public-otel") own++ } END { if (count == 1 && own == 1) print "yes" }')
[[ $unique_uid == yes ]] || { echo 'public collector UID is shared or unverifiable' >&2; exit 1; }
if [[ $action == ready ]]; then
  [[ $EUID == "$uid" ]] || { echo 'ready must run as the public collector' >&2; exit 1; }
  for ((attempt=0; attempt<100; attempt++)); do
    [[ -S $socket && ! -L $socket ]] && break
    sleep 0.1
  done
  [[ -S $socket && ! -L $socket && $(stat -c '%u' "$socket") == "$uid" ]] || { echo 'public collector socket missing or unowned' >&2; exit 1; }
  chmod 0220 "$socket"
  exit
fi
[[ $EUID -eq 0 ]] || { echo 'root required' >&2; exit 1; }
if ! mkdir -m 700 -- "$state" 2>/dev/null; then
  [[ -d $state && ! -L $state ]] || { echo 'refuse unsafe collector state directory' >&2; exit 1; }
fi
[[ $(stat -c '%u:%g:%a' "$state") == 0:0:700 && ! -L $state/lock ]] || { echo 'unsafe collector state ownership' >&2; exit 1; }
exec 9>"$state/lock"
flock -x 9
[[ ! -e $pending && ! -L $pending ]] || { echo 'collector UID change needs manual verification' >&2; exit 1; }
owns_uid=false
if [[ -e $marker || -L $marker ]]; then
  [[ -f $marker && ! -L $marker && $(stat -c '%u:%g:%a' "$marker") == 0:0:600 && $(cat "$marker") == "$uid" ]] || { echo 'invalid collector UID ownership marker' >&2; exit 1; }
  owns_uid=true
fi
nft list set inet attackbox collector_uids >/dev/null
has_uid=false
if nft_output=$(LC_ALL=C nft get element inet attackbox collector_uids "{ $uid }" 2>&1); then
  has_uid=true
elif [[ $nft_output != $'Error: Could not process rule: No such file or directory\n'* ]] || ! nft list set inet attackbox collector_uids >/dev/null; then
  echo 'cannot inspect collector UID membership' >&2
  exit 1
fi
if $has_uid && ! $owns_uid; then
  echo 'refuse unowned collector UID membership' >&2
  exit 1
fi
case $action in
  prepare)
    [[ ! -L $dir ]] || { echo 'refuse symlinked socket directory' >&2; exit 1; }
    if [[ -e $dir ]]; then
      [[ -d $dir && $(stat -c '%u' "$dir") == "$uid" ]] || { echo 'refuse unowned socket directory' >&2; exit 1; }
    fi
    if [[ -e $socket || -L $socket ]]; then
      [[ -S $socket && ! -L $socket && $(stat -c '%u' "$socket") == "$uid" ]] || { echo 'refuse unowned socket path' >&2; exit 1; }
      timeout 2 perl -MIO::Socket::UNIX -MSocket=SOCK_STREAM -e '
        my $s = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $ARGV[0]);
        exit 1 if $s;
        exit($!{ECONNREFUSED} ? 0 : 2);
      ' "$socket" || { echo 'refuse live or unverifiable socket' >&2; exit 1; }
      rm -- "$socket"
    fi
    install -d -o abx-public-otel -g abx-bait -m 2710 "$dir"
    if ! $has_uid; then
      # shortcut: an interrupted nft change needs manual UID verification; use tagged nft elements for automatic recovery.
      if $owns_uid; then
        mv -- "$marker" "$pending"
      else
        (umask 077; printf '%s\n' "$uid" >"$pending")
      fi
      nft create element inet attackbox collector_uids "{ $uid }"
      mv -- "$pending" "$marker"
    fi
    ;;
  cleanup)
    if $owns_uid; then
      if $has_uid; then
        mv -- "$marker" "$pending"
        nft delete element inet attackbox collector_uids "{ $uid }"
        rm -- "$pending"
      else
        rm -- "$marker"
      fi
    fi
    ;;
esac
