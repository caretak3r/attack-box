#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

docker run -i --rm --pull=never --platform=linux/amd64 --network=none \
  --mount "type=bind,source=$root/deploy/public-otel/prepare-socket.sh,target=/prepare-socket.sh,readonly" \
  --entrypoint /bin/bash ubuntu:24.04 -s <<'LINUX'
set -euo pipefail
fail() { echo "public collector socket: $*" >&2; exit 1; }
groupadd --gid 65532 abx-bait
useradd --system --no-create-home abx-public-otel
public_uid=$(id -u abx-public-otel)
mkdir -p /tmp/mock-bin /tmp/nft
: > /tmp/nft/table
cat > /tmp/mock-bin/nft <<'MOCK'
#!/bin/bash
set -euo pipefail
[[ ${3:-} == inet && ${4:-} == attackbox && ${5:-} == collector_uids ]] || exit 1
case "$1 ${2:-}" in
  'list set') [[ -f /tmp/nft/table ]] ;;
  'get element'|'add element'|'create element'|'delete element')
    uid=${6#\{ }
    uid=${uid% \}}
    [[ $uid =~ ^[0-9]+$ ]] || exit 1
    case $1 in
      get)
        if [[ -f /tmp/nft/fail-get ]]; then
          printf 'Error: Could not process rule: Operation not permitted\n' >&2
          exit 1
        fi
        if [[ -f /tmp/nft/race-on-get ]]; then
          rm -- /tmp/nft/race-on-get
          : > "/tmp/nft/$uid"
          printf 'Error: Could not process rule: No such file or directory\nget element\n' >&2
          exit 1
        fi
        if [[ ! -f /tmp/nft/$uid ]]; then
          printf 'Error: Could not process rule: No such file or directory\nget element\n' >&2
          exit 1
        fi
        ;;
      add|create)
        [[ $1 == add || ! -e /tmp/nft/$uid ]] || exit 1
        : > "/tmp/nft/$uid"
        if [[ -f /tmp/nft/fail-after-add ]]; then rm -- /tmp/nft/fail-after-add; exit 1; fi
        ;;
      delete)
        rm -- "/tmp/nft/$uid"
        if [[ -f /tmp/nft/fail-after-delete ]]; then
          rm -- /tmp/nft/fail-after-delete
          : > "/tmp/nft/$uid"
          exit 1
        fi
        ;;
    esac
    ;;
  *) exit 1 ;;
esac
MOCK
chmod +x /tmp/mock-bin/nft
export PATH=/tmp/mock-bin:$PATH
: > "/tmp/nft/$public_uid"
if bash /prepare-socket.sh prepare >/dev/null 2>&1; then fail 'adopted an unowned collector UID'; fi
if bash /prepare-socket.sh cleanup >/dev/null 2>&1; then fail 'removed an unowned collector UID'; fi
[[ -f /tmp/nft/$public_uid ]] || fail 'unowned collector UID was removed'
rm -- "/tmp/nft/$public_uid"
: > /tmp/nft/race-on-get
if bash /prepare-socket.sh prepare >/dev/null 2>&1; then fail 'adopted a collector UID inserted during startup'; fi
if bash /prepare-socket.sh cleanup >/dev/null 2>&1; then fail 'removed an ambiguously owned collector UID'; fi
[[ -f /tmp/nft/$public_uid && -f /run/attackbox-public-otel-state/uid.pending ]] || fail 'concurrent UID insertion was not preserved'
rm -- "/tmp/nft/$public_uid" /run/attackbox-public-otel-state/uid.pending
: > /tmp/nft/fail-after-add
if bash /prepare-socket.sh prepare >/dev/null 2>&1; then fail 'ambiguous nft add reported success'; fi
if bash /prepare-socket.sh cleanup >/dev/null 2>&1; then fail 'ambiguous nft add was automatically removed'; fi
[[ -f /tmp/nft/$public_uid ]] || fail 'ambiguous nft add was not preserved'
rm -- "/tmp/nft/$public_uid" /run/attackbox-public-otel-state/uid.pending
bash /prepare-socket.sh prepare
[[ -f /tmp/nft/$public_uid ]] || fail 'startup required the optional private collector'
: > /tmp/nft/fail-get
if bash /prepare-socket.sh cleanup >/dev/null 2>&1; then fail 'treated an nft query failure as an absent UID'; fi
[[ -f /tmp/nft/$public_uid && -f /run/attackbox-public-otel-state/uid ]] || fail 'nft query failure lost UID ownership'
rm -- /tmp/nft/fail-get
perl -MIO::Socket::UNIX -MSocket=SOCK_STREAM -e 'my $s = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => $ARGV[0], Listen => 1) or die $!; sleep 30' /run/attackbox-public-otel/otlp.sock &
socket_pid=$!
for ((attempt=0; attempt<100; attempt++)); do
  [[ -S /run/attackbox-public-otel/otlp.sock ]] && break
  sleep 0.05
done
[[ -S /run/attackbox-public-otel/otlp.sock ]] || fail 'test socket did not start'
chown abx-public-otel:abx-bait /run/attackbox-public-otel/otlp.sock
if bash /prepare-socket.sh prepare >/dev/null 2>&1; then fail 'removed a live socket'; fi
[[ -S /run/attackbox-public-otel/otlp.sock && -f /tmp/nft/$public_uid ]] || fail 'live socket refusal changed state'
if bash /prepare-socket.sh ready >/dev/null 2>&1; then fail 'ready ran with root privileges'; fi
runuser -u abx-public-otel -- bash /prepare-socket.sh ready
[[ $(stat -c '%a' /run/attackbox-public-otel/otlp.sock) == 220 ]] || fail 'socket permissions are not 0220'
kill "$socket_pid"
wait "$socket_pid" 2>/dev/null || true
[[ -S /run/attackbox-public-otel/otlp.sock ]] || fail 'socket fixture did not remain after exit'
bash /prepare-socket.sh prepare
[[ ! -e /run/attackbox-public-otel/otlp.sock && -f /tmp/nft/$public_uid ]] || fail 'owned stale socket was not recovered'
bash /prepare-socket.sh cleanup
[[ ! -e /tmp/nft/$public_uid ]] || fail 'cleanup without the private collector failed'
useradd --system --no-create-home abx-otel
private_uid=$(id -u abx-otel)
: > "/tmp/nft/$private_uid"
bash /prepare-socket.sh prepare
[[ $(stat -c '%U:%G:%a' /run/attackbox-public-otel) == abx-public-otel:abx-bait:2710 ]] || fail 'wrong socket directory ownership'
[[ -f /tmp/nft/$public_uid && -f /tmp/nft/$private_uid ]] || fail 'collector UID membership missing'
rm -- "/tmp/nft/$public_uid"
bash /prepare-socket.sh prepare
[[ -f /tmp/nft/$public_uid && -f /tmp/nft/$private_uid ]] || fail 'nft reload lost collector UID membership'
rm -- "/tmp/nft/$public_uid"
: > /tmp/nft/fail-after-add
if bash /prepare-socket.sh prepare >/dev/null 2>&1; then fail 'ambiguous nft reload reported success'; fi
if bash /prepare-socket.sh cleanup >/dev/null 2>&1; then fail 'ambiguous nft reload removed membership'; fi
[[ -f /tmp/nft/$public_uid && -f /tmp/nft/$private_uid ]] || fail 'ambiguous nft reload changed membership'
rm -- "/tmp/nft/$public_uid" /run/attackbox-public-otel-state/uid.pending
bash /prepare-socket.sh prepare
bash /prepare-socket.sh prepare
: > /tmp/nft/fail-after-delete
if bash /prepare-socket.sh cleanup >/dev/null 2>&1; then fail 'ambiguous nft delete reported success'; fi
if bash /prepare-socket.sh cleanup >/dev/null 2>&1; then fail 'ambiguous nft delete removed membership'; fi
[[ -f /tmp/nft/$public_uid && -f /tmp/nft/$private_uid ]] || fail 'ambiguous nft delete changed membership'
rm -- "/tmp/nft/$public_uid" /run/attackbox-public-otel-state/uid.pending
bash /prepare-socket.sh prepare
bash /prepare-socket.sh cleanup
[[ ! -e /tmp/nft/$public_uid && -f /tmp/nft/$private_uid ]] || fail 'cleanup changed another collector UID'
: > /run/attackbox-public-otel/otlp.sock
if bash /prepare-socket.sh prepare >/dev/null 2>&1; then fail 'accepted a non-socket path'; fi
[[ -f /run/attackbox-public-otel/otlp.sock && ! -e /tmp/nft/$public_uid ]] || fail 'invalid socket path changed state'
rm /run/attackbox-public-otel/otlp.sock
rmdir /run/attackbox-public-otel
mkdir /run/attackbox-public-otel
chown root:root /run/attackbox-public-otel
if bash /prepare-socket.sh prepare >/dev/null 2>&1; then fail 'adopted an unowned socket directory'; fi
[[ $(stat -c '%u:%g' /run/attackbox-public-otel) == 0:0 ]] || fail 'unowned socket directory changed'
rmdir /run/attackbox-public-otel
ln -s /tmp /run/attackbox-public-otel
if bash /prepare-socket.sh prepare >/dev/null 2>&1; then fail 'accepted a symlinked directory'; fi
[[ ! -e /tmp/nft/$public_uid && -f /tmp/nft/$private_uid ]] || fail 'symlink refusal changed firewall state'
rm /run/attackbox-public-otel
rm /tmp/nft/table
if bash /prepare-socket.sh prepare >/dev/null 2>&1; then fail 'accepted a missing firewall set'; fi
[[ ! -e /tmp/nft/$public_uid && -f /tmp/nft/$private_uid ]] || fail 'missing firewall changed UID state'
: > /tmp/nft/table
usermod --non-unique --uid "$private_uid" abx-public-otel
if bash /prepare-socket.sh cleanup >/dev/null 2>&1; then fail 'accepted a shared collector UID'; fi
[[ -f /tmp/nft/$private_uid ]] || fail 'UID collision removed the private collector'
usermod --uid "$public_uid" abx-public-otel
useradd --system --no-create-home --non-unique --uid "$public_uid" another-collector
if bash /prepare-socket.sh prepare >/dev/null 2>&1; then fail 'accepted a UID shared with another account'; fi
[[ ! -e /tmp/nft/$public_uid && -f /tmp/nft/$private_uid ]] || fail 'shared UID changed collector membership'
echo 'public collector socket: isolation and cleanup checks passed'
LINUX
