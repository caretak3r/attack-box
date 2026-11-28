#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
candidate_root=${ATTACKBOX_PUBLIC_CANDIDATE_ROOT:-$root}
runtime_files=(
  compose.public.yaml deploy/public-compose.sh deploy/public-otel/config.yaml deploy/public-otel/prepare-socket.sh
  deploy/otel/version.env deploy/systemd/attackbox-public-otel.service
  deploy/systemd/attackbox-public.service scripts/verify-public-bundle.sh
)
for file in "${runtime_files[@]}"; do
  [[ -f $candidate_root/$file && ! -L $candidate_root/$file ]] || {
    printf 'public host stage test: candidate runtime file missing: %s\n' "$candidate_root/$file" >&2
    exit 1
  }
done
fixture=$(mktemp -d "${TMPDIR:-/tmp}/attackbox-public-fixture.XXXXXXXX")
cleanup_fixture() {
  local result=$? failed=0 file dir
  trap - EXIT
  for file in "${runtime_files[@]}"; do rm -f -- "$fixture/$file" || failed=1; done
  for dir in deploy/public-otel deploy/otel deploy/systemd deploy scripts ''; do
    [[ ! -d $fixture/$dir ]] || rmdir -- "$fixture/$dir" || failed=1
  done
  if ((failed)); then printf 'public host stage test: fixture cleanup failed\n' >&2; exit 1; fi
  exit "$result"
}
trap cleanup_fixture EXIT
mkdir -p "$fixture/deploy/public-otel" "$fixture/deploy/otel" "$fixture/deploy/systemd" "$fixture/scripts"
for file in "${runtime_files[@]}"; do cp -- "$candidate_root/$file" "$fixture/$file"; done

docker run -i --rm --pull=never --platform=linux/amd64 --network=none \
  --mount "type=bind,source=$root/scripts/public-host-stage.sh,target=/candidate,readonly" \
  --mount "type=bind,source=$fixture,target=/candidate-src,readonly" \
  --entrypoint /bin/bash ubuntu:24.04 -s <<'LINUX'
set -euo pipefail
fail() { printf 'public host stage test: %s\n' "$*" >&2; exit 1; }
expect_failure() {
  local wanted=$1 output
  shift
  if output=$("$@" 2>&1); then fail "unexpected success: $wanted"; fi
  [[ $output == *"$wanted"* ]] || fail "wrong failure for $wanted: $output"
  failure_output=$output
}

commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
image=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
container=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
network=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
host=public-stage.test
# This IPv4 exists only in the mocked `ip` output (Docker network=none).
public_ip=93.184.216.34
runtime_files=(
  compose.public.yaml deploy/public-compose.sh deploy/public-otel/config.yaml deploy/public-otel/prepare-socket.sh
  deploy/otel/version.env deploy/systemd/attackbox-public-otel.service
  deploy/systemd/attackbox-public.service scripts/verify-public-bundle.sh
)
payload=(manifest image.tar otelcol-contrib "${runtime_files[@]}")
mkdir -p /tmp/mock /root/input /root/fixture/deploy/{public-otel,otel,systemd} /root/fixture/scripts \
  /root/release/deploy/{public-otel,otel,systemd} /root/release/scripts \
  /usr/local/bin /usr/local/libexec /etc/docker /opt/attackbox /etc/systemd/system
chmod 0700 /root/input
chmod 0755 /root/release /root/release/deploy /root/release/deploy/{public-otel,otel,systemd} /root/release/scripts
for file in "${runtime_files[@]}"; do
  cp "/candidate-src/$file" "/root/fixture/$file"
  cp "/candidate-src/$file" "/root/release/$file"
done
chmod 0755 /root/release/scripts/verify-public-bundle.sh
printf 'private path\n' >/opt/attackbox/private-marker
printf 'private uid\n' >/tmp/mock/nft-private
printf '%s\n' "$host" >/tmp/mock/hostname
printf '{"runtimes":{"runsc":{"runtimeArgs":["--host-uds=open"]}}}\n' >/etc/docker/daemon.json
cert_fixture() { printf '%s\n' '-----BEGIN CERTIFICATE-----' "$1" '-----END CERTIFICATE-----'; }
cert_fixture b2xk >/root/input/cert.pem
cert_fixture bmV3 >/root/input/renew.pem
cert_fixture cHJpdmF0ZQ== >/root/input/proxy.pem
printf 'not a public key source\n' >/root/input/proxy.key
printf 'synthetic private key\n' >/root/input/key.pem
chmod 0600 /root/input/{cert.pem,key.pem}

cat >/usr/local/bin/hostname <<'MOCK'
#!/bin/bash
cat /tmp/mock/hostname
MOCK
cat >/usr/local/bin/ip <<'MOCK'
#!/bin/bash
case "$*" in
  '-4 -o addr show scope global') printf '2: eth0    inet 93.184.216.34/24 scope global eth0\n' ;;
  '-4 route get 93.184.216.34')
    if [[ ! -e /tmp/mock/bad-route ]]; then printf 'local 93.184.216.34 dev lo src 93.184.216.34 uid 0\n'
    else printf '93.184.216.34 via 93.184.216.1 dev eth0\n'; fi ;;
  *) exit 1 ;;
esac
MOCK
cat >/usr/local/bin/ss <<'MOCK'
#!/bin/bash
printf 'LISTEN 0 128 127.0.0.1:443 0.0.0.0:*\n'
if [[ -e /tmp/mock/listener ]]; then
  port=443
  [[ ! -e /tmp/mock/listener-port ]] || port=$(cat /tmp/mock/listener-port)
  printf 'LISTEN 0 128 %s:%s 0.0.0.0:*\n' "$(cat /tmp/mock/listener)" "$port"
fi
MOCK
cat >/usr/local/bin/openssl <<'MOCK'
#!/bin/bash
set -euo pipefail
case $1 in
  verify)
    [[ " $* " == *' -verify_hostname api.example.test '* && " $* " == *' -CAfile /etc/ssl/certs/ca-certificates.crt '* &&
       " $* " == *' -purpose sslserver '* && " $* " == *' -untrusted '* && ! -e /tmp/mock/ca-refused ]]
    ;;
  pkey)
    if [[ " $* " == *' -passin pass: -pubout '* ]]; then
      if grep -q 'wrong' "$3"; then printf 'wrong SPKI\n'; else printf 'public SPKI\n'; fi
    else
      [[ $# == 7 && $6 == -out && $3 == /dev/fd/8 ]]
      cat "$3" >"$7"
    fi
    ;;
  x509)
    if [[ ${2:-} == -in ]]; then data=$(cat "$3"); else data=$(cat); fi
    case " $* " in
      *' -pubkey '*)
        if [[ $data == *cHJpdmF0ZQ==* ]]; then printf 'proxy SPKI\n'; else printf 'public SPKI\n'; fi ;;
      *' -ext subjectAltName '*) printf 'DNS:api.example.test\n' ;;
      *' -outform DER '*) [[ -n $data ]]; printf '%s' "$data" ;;
      *) exit 1 ;;
    esac
    ;;
  s_client)
    [[ " $* " == *' -connect 93.184.216.34:443 -servername api.example.test '* && " $* " == *' -verify_hostname api.example.test -verify_return_error '* &&
       " $* " == *' -CAfile /etc/ssl/certs/ca-certificates.crt '* && ! -e /tmp/mock/live-untrusted ]]
    cat /tmp/mock/served-cert
    ;;
  *) exit 1 ;;
esac
MOCK
cat >/usr/local/bin/git <<'MOCK'
#!/bin/bash
set -euo pipefail
case " $* " in
  *' rev-parse --show-toplevel '*) printf '%s\n' /root/release ;;
  *' rev-parse --verify --end-of-options '*) printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;
  *' -c gpg.minTrustLevel=fully verify-commit '*) ;;
  *' --no-pager show '*)
    selector=${!#}
    path=${selector#*:}
    [[ $path != "$selector" && -f /root/release/$path && ! -L /root/release/$path ]]
    cat "/root/release/$path"
    ;;
  *) exit 1 ;;
esac
MOCK
cat >/usr/local/bin/getent <<'MOCK'
#!/bin/bash
set -euo pipefail
kind=${1:-}
name=${2:-}
case "$kind:$name" in
  passwd:)
    printf 'abx-otel:x:997:997::/nonexistent:/usr/sbin/nologin\n'
    [[ ! -e /tmp/mock/account ]] || printf 'abx-public-otel:x:998:998::/nonexistent:/usr/sbin/nologin\n'
    ;;
  passwd:abx-public-otel)
    [[ -e /tmp/mock/account ]] || exit 2
    printf 'abx-public-otel:x:998:998::/nonexistent:/usr/sbin/nologin\n'
    ;;
  passwd:abx-otel) printf 'abx-otel:x:997:997::/nonexistent:/usr/sbin/nologin\n' ;;
  group:)
    printf 'abx-bait:x:65532:\nabx-otel:x:997:\n'
    [[ ! -e /tmp/mock/group ]] || printf 'abx-public-otel:x:998:\n'
    ;;
  group:abx-bait) printf 'abx-bait:x:65532:\n' ;;
  group:abx-public-otel)
    [[ -e /tmp/mock/group ]] || exit 2
    printf 'abx-public-otel:x:998:\n'
    ;;
  *) exit 2 ;;
esac
MOCK
cat >/usr/local/bin/id <<'MOCK'
#!/bin/bash
case "${1:-}:${2:-}" in
  -u:abx-otel|-g:abx-otel) printf '997\n' ;;
  -u:abx-public-otel|-g:abx-public-otel) [[ -e /tmp/mock/account ]] && printf '998\n' ;;
  *) exit 1 ;;
esac
MOCK
cat >/usr/local/bin/useradd <<'MOCK'
#!/bin/bash
[[ $* == *'abx-public-otel'* && ! -e /tmp/mock/account ]]
touch /tmp/mock/account /tmp/mock/group
MOCK
cat >/usr/local/bin/userdel <<'MOCK'
#!/bin/bash
[[ $1 == abx-public-otel && -e /tmp/mock/account ]]
rm /tmp/mock/account
MOCK
cat >/usr/local/bin/groupdel <<'MOCK'
#!/bin/bash
[[ $1 == abx-public-otel && -e /tmp/mock/group ]]
rm /tmp/mock/group
MOCK
cat >/usr/local/bin/pgrep <<'MOCK'
#!/bin/bash
[[ ! -e /tmp/mock/pgrep-unknown ]] || exit 2
exit 1
MOCK
cat >/usr/local/bin/nft <<'MOCK'
#!/bin/bash
set -euo pipefail
case "$1 $2 ${3:-} ${4:-} ${5:-}" in
  'list set inet attackbox collector_uids')
    printf 'set %s { elements = { 192.0.2.1 } }\n' "$5"
    ;;
  'list chain inet attackbox output_policy')
    if [[ -e /tmp/mock/nft-policy-accept ]]; then
      printf 'type filter hook output priority filter; policy accept;\n'
    else
      printf 'type filter hook output priority filter; policy drop;\n'
    fi
    if [[ -e /tmp/mock/nft-policy-invalid ]]; then
      printf 'meta skuid @collector_uids ip daddr 192.0.2.9 tcp dport 443 accept\n'
    fi
    ;;
  'get element inet attackbox collector_uids')
    if [[ -e /tmp/mock/nft-query-error ]]; then
      printf 'Error: Could not process rule: Operation not permitted\n' >&2
      exit 1
    fi
    if [[ ! -e /tmp/mock/nft-public ]]; then
      printf 'Error: Could not process rule: No such file or directory\nget element\n' >&2
      exit 1
    fi
    ;;
  'delete element inet attackbox collector_uids')
    rm -f /tmp/mock/nft-public
    [[ ! -e /tmp/mock/nft-error-after-delete ]] || touch /tmp/mock/nft-query-error
    ;;
  *) exit 1 ;;
esac
MOCK
cat >/usr/local/bin/docker <<'MOCK'
#!/bin/bash
set -euo pipefail
last=${!#}
case "$1" in
  info)
    [[ $* == *'index .Runtimes "runsc"'* && $* == *'.Args'* ]] || exit 1
    [[ -e /tmp/mock/runsc-uds-missing ]] || printf '%s\n' '--host-uds=open'
    ;;
  cp)
    [[ $# == 3 && $2 == attackbox-proxy:/etc/nginx/ssl/server.crt && $3 == - ]]
    tar -C /root/input -cf - proxy.pem ;;
  kill)
    [[ $* == "kill --signal HUP $(cat /tmp/mock/container)" ]]
    if [[ ! -e /tmp/mock/ignore-hup ]] || ! grep -q bmV3 /etc/attackbox-public/tls/fullchain.pem; then
      cp /etc/attackbox-public/tls/fullchain.pem /tmp/mock/served-cert
    fi ;;
  container) exit 1 ;;
  inspect)
    case "$last" in
      attackbox-bait|attackbox-proxy)
        case "$*" in
          *'/etc/nginx/ssl/server.crt'*) printf '/root/input/proxy.pem\n' ;;
          *'/etc/nginx/ssl/server.key'*) printf '/root/input/proxy.key\n' ;;
          *) printf 'running healthy runsc\n' ;;
        esac ;;
      "$(cat /tmp/mock/container 2>/dev/null || true)")
        if [[ $* == *'.Mounts'* ]]; then
          printf '%s\n' 'bind /run/attackbox-public-otel /run/attackbox-public-otel false' 'bind /etc/attackbox-public/tls /run/secrets false' \
            'bind /var/lib/attackbox-public-capture/requests /var/lib/attackbox-public-capture true'
          [[ ! -e /tmp/mock/foreign-mount ]] || printf 'bind /opt/attackbox /unexpected false\n'
        elif [[ $* == *'.HostConfig.LogConfig.Type'* ]]; then
          if [[ -e /tmp/mock/wrong-isolation ]]; then printf 'runc journald\n'; else
            printf 'runsc none false true 65532:65532 2000000000 536870912 128 ALL none nnp %s\n' "$(cat /tmp/mock/network)"
          fi
        elif [[ $* == *'--format {{.Image}} '* ]]; then
          if [[ -e /tmp/mock/foreign-image ]]; then printf 'sha256:%064d\n' 0; else printf 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n'; fi
        else
          printf 'running healthy sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n'
        fi
        ;;
      *) exit 1 ;;
    esac
    ;;
  image)
    case ${2:-} in
      ls)
        [[ ! -e /tmp/mock/image-api-error ]] || exit 1
        [[ ! -e /tmp/mock/image ]] || printf 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n'
        ;;
      inspect)
        [[ ! -e /tmp/mock/image-api-error ]] || exit 1
        [[ -e /tmp/mock/image ]] || exit 1
        [[ $* != *'--format'* ]] || printf 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n'
        ;;
      rm) [[ -e /tmp/mock/image ]]; rm /tmp/mock/image ;;
      *) exit 1 ;;
    esac
    ;;
  load)
    [[ ${2:-} == --input && -f ${3:-} ]]
    touch /tmp/mock/image
    if [[ -e /tmp/mock/fail-image-api-after-load ]]; then touch /tmp/mock/image-api-error; fi
    [[ ! -e /tmp/mock/ambiguous-load ]]
    ;;
  compose)
    if [[ ${2:-} == version ]]; then
      [[ ! -e /tmp/mock/compose-unavailable ]] || exit 1
      printf '2.0\n'
      exit 0
    fi
    project=
    previous=
    for argument in "$@"; do
      if [[ $previous == --project-name ]]; then project=$argument; break; fi
      previous=$argument
    done
    [[ $project == "$(cat /etc/attackbox-public/project-id)" ]]
    case " $* " in
      *' up -d --no-build --wait '*)
        printf '%s\n' cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc >/tmp/mock/container
        cp /etc/attackbox-public/tls/fullchain.pem /tmp/mock/served-cert
        printf '%s\n' dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd >/tmp/mock/network
        ;;
      *' ps -q public '*) cat /tmp/mock/container ;;
      *' down '*)
        rm -f /tmp/mock/container
        if [[ -e /tmp/mock/fail-network-after-down ]]; then touch /tmp/mock/network-api-error; else rm -f /tmp/mock/network; fi
        ;;
      *) exit 1 ;;
    esac
    ;;
  wait)
    [[ $last == cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc ]]
    while [[ -e /tmp/mock/container ]]; do sleep 0.02; done
    printf '0\n'
    ;;
  ps)
    [[ ! -e /tmp/mock/container-api-error ]] || exit 1
    if [[ $* == 'ps -q --no-trunc' ]]; then
      [[ ! -e /tmp/mock/docker-listener ]] || printf '%064d\n' 1
    elif [[ $* == *'{{.Names}}'* ]]; then
      [[ ! -e /tmp/mock/legacy-container ]] || printf 'attackbox-public\n'
    else
      [[ $* == *'--no-trunc'* ]] || exit 1
      [[ ! -e /tmp/mock/container ]] || cat /tmp/mock/container
    fi
    ;;
  volume) ;;
  network)
    [[ ! -e /tmp/mock/network-api-error ]] || exit 1
    expected=
    [[ ! -f /etc/attackbox-public/project-id ]] || expected=$(cat /etc/attackbox-public/project-id)_public
    case ${2:-} in
      ls)
        [[ ! -e /tmp/mock/legacy-network ]] || printf 'attackbox-public-net\n'
        [[ ! -e /tmp/mock/network ]] || printf '%s\n' "$expected"
        ;;
      inspect)
        [[ $last == "$expected" && -e /tmp/mock/network ]] || exit 1
        if [[ $* == *'.Labels'* ]]; then
          [[ -e /tmp/mock/foreign-network-label ]] || printf '%s\n' "${expected%_public}"
        elif [[ $* == *'--format'* ]]; then cat /tmp/mock/network; fi
        ;;
      *) exit 1 ;;
    esac
    ;;
  port)
    if [[ $last == "$(printf '%064d' 1)" && -e /tmp/mock/docker-listener ]]; then
      port=443
      [[ ! -e /tmp/mock/docker-listener-port ]] || port=$(cat /tmp/mock/docker-listener-port)
      printf '9443/tcp -> 0.0.0.0:%s\n' "$port"
    else
      [[ -e /tmp/mock/container && $last == "$(cat /tmp/mock/container)" ]]
      if [[ -e /tmp/mock/partial-bindings ]]; then
        printf '8443/tcp -> 93.184.216.34:443\n'
      else
        printf '20080/tcp -> 93.184.216.34:80\n21234/tcp -> 93.184.216.34:1234\n23000/tcp -> 93.184.216.34:3000\n24000/tcp -> 93.184.216.34:4000\n28000/tcp -> 93.184.216.34:8000\n28080/tcp -> 93.184.216.34:8080\n28188/tcp -> 93.184.216.34:8188\n28888/tcp -> 93.184.216.34:8888\n31434/tcp -> 93.184.216.34:11434\n8443/tcp -> 93.184.216.34:443\n'
        [[ ! -e /tmp/mock/extra-publication ]] || printf '9000/tcp -> 93.184.216.34:9000\n'
      fi
    fi
    ;;
  *) exit 1 ;;
esac
MOCK
cp /usr/local/bin/docker /usr/bin/docker
cat >/usr/bin/systemd-notify <<'MOCK'
#!/bin/bash
exit 0
MOCK
cat >/usr/local/bin/systemctl <<'MOCK'
#!/bin/bash
set -euo pipefail
case "$1" in
  is-active)
    unit=${3:-}
    case $unit in
      attackbox.service) ;;
      attackbox-public-otel.service) [[ -e /tmp/mock/otel-active ]] ;;
      attackbox-public.service) [[ -e /tmp/mock/public-active ]] ;;
      *) exit 1 ;;
    esac
    ;;
  cat) exit 1 ;;
  daemon-reload) [[ ! -e /tmp/mock/fail-reload ]] ;;
  enable)
    [[ ${2:-} == --now && ${3:-} == attackbox-public.service ]]
    touch /tmp/mock/otel-active /tmp/mock/nft-public
    install -d -o 998 -g 65532 -m 2710 /run/attackbox-public-otel
    install -d -o 0 -g 0 -m 700 /run/attackbox-public-otel-state
    install -o 0 -g 0 -m 600 /dev/null /run/attackbox-public-otel-state/lock
    printf '998\n' >/run/attackbox-public-otel-state/uid
    chmod 0600 /run/attackbox-public-otel-state/uid
    if [[ -e /tmp/mock/fail-dependency ]]; then touch /tmp/mock/otel-restarting; exit 1; fi
    NOTIFY_SOCKET=/tmp/mock-notify /usr/local/libexec/attackbox-public-compose up >/tmp/mock/helper.log 2>&1 &
    printf '%s\n' "$!" >/tmp/mock/helper-pid
    for ((attempt=0; attempt<100; attempt++)); do
      [[ -e /tmp/mock/container && -e /tmp/mock/network ]] && break
      kill -0 "$(cat /tmp/mock/helper-pid)" 2>/dev/null || exit 1
      sleep 0.02
    done
    [[ -e /tmp/mock/container && -e /tmp/mock/network ]]
    touch /tmp/mock/public-active
    [[ ! -e /tmp/mock/fail-public-start ]]
    ;;
  stop)
    printf '%s\n' "${2:-}" >>/tmp/mock/stops
    if [[ ${2:-} == attackbox-public-otel.service ]]; then
      [[ -e /tmp/mock/ignore-otel-stop ]] || rm -f /tmp/mock/otel-restarting /tmp/mock/otel-active
      exit 0
    fi
    [[ ${2:-} == attackbox-public.service ]]
    /usr/local/libexec/attackbox-public-compose down
    if [[ -f /tmp/mock/helper-pid ]]; then
      wait "$(cat /tmp/mock/helper-pid)" 2>/dev/null || true
    fi
    rm -f /tmp/mock/helper-pid /tmp/mock/public-active
    [[ -e /tmp/mock/otel-restarting ]] || rm -f /tmp/mock/otel-active
    ;;
  disable) [[ ${2:-} == attackbox-public.service ]] ;;
  show)
    if [[ $* == *'--property=LoadState'* ]]; then
      [[ ! -e /tmp/mock/systemd-api-error ]] || exit 1
      if [[ -e /tmp/mock/legacy-unit ]]; then printf 'loaded\n'; else printf 'not-found\n'; fi
    else
      [[ $2 == --all && $3 == --property=Id,LoadState,ActiveState,FragmentPath,DropInPaths,NeedDaemonReload ]]
      unit=${!#}; path=/etc/systemd/system/$unit; load=loaded; active=inactive; dropins=; reload=no
      [[ -f $path ]] || { load=not-found; path=; }
      case $unit in
        attackbox-public.service) [[ ! -e /tmp/mock/public-active ]] || active=active ;;
        attackbox-public-otel.service)
          [[ ! -e /tmp/mock/otel-active ]] || active=active
          [[ ! -e /tmp/mock/otel-restarting ]] || active=activating
          [[ ! -e /tmp/mock/foreign-fragment ]] || path=/usr/lib/systemd/system/attackbox-otel.service
          [[ ! -e /tmp/mock/foreign-dropin ]] || dropins=/run/systemd/system/attackbox-public-otel.service.d/extra.conf
          [[ ! -e /tmp/mock/stale-fragment ]] || reload=yes
          ;;
        *) exit 1 ;;
      esac
      printf 'Id=%s\nLoadState=%s\nActiveState=%s\nFragmentPath=%s\nDropInPaths=%s\nNeedDaemonReload=%s\n' \
        "$unit" "$load" "$active" "$path" "$dropins" "$reload"
      [[ $load != not-found ]] || exit 4
    fi
    ;;
  *) exit 1 ;;
esac
MOCK
chmod +x /usr/local/bin/{hostname,ip,ss,openssl,git,getent,id,useradd,userdel,groupdel,pgrep,nft,docker,systemctl} /usr/bin/docker /usr/bin/systemd-notify

printf 'synthetic collector binary\n' >/root/fixture/otelcol-contrib
printf 'synthetic image archive\n' >/root/fixture/image.tar
printf 'commit=%s\nplatform=linux/amd64\nimage=%s\n' "$commit" "$image" >/root/fixture/manifest
chmod 0755 /root/fixture/otelcol-contrib
(cd /root/fixture && sha256sum "${payload[@]}" >SHA256SUMS && tar -cf /root/input/public-bundle.tar "${payload[@]}" SHA256SUMS)
chmod 0600 /root/input/public-bundle.tar
bundle_sha=$(sha256sum /root/input/public-bundle.tar | cut -d' ' -f1)
verifier_sha=$(sha256sum /root/release/scripts/verify-public-bundle.sh | cut -d' ' -f1)
script=/candidate
common=(--bundle /root/input/public-bundle.tar --bundle-sha "$bundle_sha" --commit "$commit" \
  --verifier /root/release/scripts/verify-public-bundle.sh --verifier-sha "$verifier_sha" --release-repo /root/release \
  --expected-hostname "$host" --public-fqdn api.example.test --public-ip "$public_ip" --host-id synthetic-host --campaign-id synthetic-campaign \
  --tls-cert /root/input/cert.pem --tls-key /root/input/key.pem)

bash "$script" check "${common[@]}" >/tmp/check.out
grep -Fq 'check passed' /tmp/check.out
[[ ! -e /var/lib/attackbox-public && ! -e /tmp/mock/account && ! -e /tmp/mock/image ]] || fail 'read-only check changed public state'
cmp /candidate-src/deploy/public-compose.sh /root/fixture/deploy/public-compose.sh
cmp /candidate-src/deploy/systemd/attackbox-public.service /root/fixture/deploy/systemd/attackbox-public.service
mv /usr/bin/docker /tmp/docker-bin.saved
expect_failure '/usr/bin/docker is required' bash "$script" check "${common[@]}"
mv /tmp/docker-bin.saved /usr/bin/docker
mv /usr/bin/systemd-notify /tmp/systemd-notify.saved
expect_failure '/usr/bin/systemd-notify is required' bash "$script" check "${common[@]}"
mv /tmp/systemd-notify.saved /usr/bin/systemd-notify
touch /tmp/mock/compose-unavailable
expect_failure 'Docker Compose is unavailable' bash "$script" check "${common[@]}"
rm /tmp/mock/compose-unavailable
mv /usr/local/bin/docker /tmp/docker.saved
printf '#!/bin/bash\nexit 74\n' >/usr/local/bin/docker
chmod 0755 /usr/local/bin/docker
bash "$script" check "${common[@]}" >/tmp/check-docker-path.out
mv /tmp/docker.saved /usr/local/bin/docker
expect_failure 'bundle SHA-256' bash "$script" check --bundle /root/input/public-bundle.tar --bundle-sha bad --commit "$commit" \
  --verifier /root/release/scripts/verify-public-bundle.sh --verifier-sha "$verifier_sha" --release-repo /root/release \
  --expected-hostname "$host" --public-fqdn api.example.test --public-ip "$public_ip" --host-id synthetic-host --campaign-id synthetic-campaign \
  --tls-cert /root/input/cert.pem --tls-key /root/input/key.pem
truncate -s 1073741825 /root/input/oversized.tar
oversized=("${common[@]}")
for ((index=0; index<${#oversized[@]}; index++)); do
  [[ ${oversized[$index]} != --bundle ]] || oversized[$((index+1))]=/root/input/oversized.tar
done
expect_failure 'bundle exceeds 1 GiB' bash "$script" check "${oversized[@]}"
[[ ! -e /var/lib/attackbox-public ]] || fail 'oversized bundle changed public state'
rm /root/input/oversized.tar
cp /root/input/cert.pem /tmp/untrusted-cert.pem
chmod 0600 /tmp/untrusted-cert.pem
unsafe=("${common[@]}")
for ((index=0; index<${#unsafe[@]}; index++)); do
  [[ ${unsafe[$index]} != --tls-cert ]] || unsafe[$((index+1))]=/tmp/untrusted-cert.pem
done
expect_failure 'group/world-writable parent' bash "$script" check "${unsafe[@]}"
printf 'wrong-host.test\n' >/tmp/mock/hostname
expect_failure 'host name mismatch' bash "$script" check "${common[@]}"
printf '%s\n' "$host" >/tmp/mock/hostname
cp /etc/docker/daemon.json /tmp/daemon.saved
printf '{"runtimes":{"runsc":{"runtimeArgs":[]},"other":{"runtimeArgs":["--host-uds=open"]}}}\n' >/etc/docker/daemon.json
touch /tmp/mock/runsc-uds-missing
expect_failure 'runsc host UDS support is not enabled' bash "$script" check "${common[@]}"
rm /tmp/mock/runsc-uds-missing
mv /tmp/daemon.saved /etc/docker/daemon.json
touch /tmp/mock/nft-policy-invalid
expect_failure 'collector must have no egress; output_policy chain must be default-drop' bash "$script" check "${common[@]}"
rm /tmp/mock/nft-policy-invalid
touch /tmp/mock/nft-policy-accept
expect_failure 'collector must have no egress; output_policy chain must be default-drop' bash "$script" check "${common[@]}"
rm /tmp/mock/nft-policy-accept
ln -s /tmp /etc/attackbox-public
expect_failure 'public install path already exists' bash "$script" check "${common[@]}"
rm /etc/attackbox-public
for addr in "$public_ip" '0.0.0.0' '[::]' '*'; do
  printf '%s\n' "$addr" >/tmp/mock/listener
  expect_failure 'listener already owns' bash "$script" check "${common[@]}"
done
rm /tmp/mock/listener
touch /tmp/mock/docker-listener
expect_failure 'Docker publication already owns' bash "$script" check "${common[@]}"
rm /tmp/mock/docker-listener
printf '%s\n' "$public_ip" >/tmp/mock/listener
printf '8000\n' >/tmp/mock/listener-port
expect_failure 'listener already owns port 8000' bash "$script" check "${common[@]}"
rm /tmp/mock/listener /tmp/mock/listener-port
touch /tmp/mock/docker-listener
printf '11434\n' >/tmp/mock/docker-listener-port
expect_failure 'Docker publication already owns' bash "$script" check "${common[@]}"
rm /tmp/mock/docker-listener /tmp/mock/docker-listener-port
for addr in 127.0.0.2 10.1.2.3 0.0.0.0 224.0.0.1 198.51.100.1; do
  expect_failure 'globally routable' bash "$script" check "${common[@]}" --public-ip "$addr"
done
expect_failure 'not present on the host' bash "$script" check "${common[@]}" --public-ip 93.184.216.35
touch /tmp/mock/bad-route
expect_failure 'does not route locally' bash "$script" check "${common[@]}"
rm /tmp/mock/bad-route
expect_failure 'wrong for requested FQDN' bash "$script" check "${common[@]}" --public-fqdn other.example.test
expect_failure 'private proxy SPKI' bash "$script" check "${common[@]}" --tls-cert /root/input/proxy.pem
touch /tmp/mock/ca-refused
expect_failure 'untrusted' bash "$script" check "${common[@]}"
rm /tmp/mock/ca-refused
printf 'wrong key' >/root/input/wrong.key; chmod 600 /root/input/wrong.key
expect_failure 'do not match' bash "$script" check "${common[@]}" --tls-key /root/input/wrong.key
touch /tmp/mock/container-api-error
expect_failure 'cannot inspect Docker containers' bash "$script" check "${common[@]}"
rm /tmp/mock/container-api-error
touch /tmp/mock/network-api-error
expect_failure 'cannot inspect Docker networks' bash "$script" check "${common[@]}"
rm /tmp/mock/network-api-error
touch /tmp/mock/systemd-api-error
expect_failure 'cannot inspect public service' bash "$script" check "${common[@]}"
rm /tmp/mock/systemd-api-error
touch /tmp/mock/legacy-container
expect_failure 'legacy public container name already exists' bash "$script" check "${common[@]}"
rm /tmp/mock/legacy-container
touch /tmp/mock/legacy-network
expect_failure 'legacy public network already exists' bash "$script" check "${common[@]}"
rm /tmp/mock/legacy-network
touch /tmp/mock/legacy-unit
expect_failure 'public service already exists' bash "$script" check "${common[@]}"
rm /tmp/mock/legacy-unit
expect_failure 'stage requires --approve' bash "$script" stage "${common[@]}" --approve "$(printf '%064d' 0)"
[[ ! -e /var/lib/attackbox-public-capture ]] || fail 'refused stage created the capture directory'
mkdir -m 0755 /var/lib/attackbox-public-capture
expect_failure 'public capture root must be a root-only 0700 directory' bash "$script" check "${common[@]}"
chmod 0700 /var/lib/attackbox-public-capture
mkdir -m 0700 /var/lib/attackbox-public-capture/requests
expect_failure 'public capture directory must be 65532:65532 mode 0700' bash "$script" check "${common[@]}"
rmdir /var/lib/attackbox-public-capture/requests /var/lib/attackbox-public-capture

touch /tmp/mock/fail-public-start
expect_failure 'public service failed to start' bash "$script" stage "${common[@]}" --approve "$bundle_sha"
rm /tmp/mock/fail-public-start
if [[ -e /var/lib/attackbox-public || -e /etc/attackbox-public || -e /tmp/mock/account || -e /tmp/mock/image || -e /tmp/mock/container || -e /tmp/mock/network || -e /tmp/mock/nft-public ]]; then
  printf '%s\n' "$failure_output" >&2
  for path in /var/lib/attackbox-public /etc/attackbox-public /tmp/mock/account /tmp/mock/image /tmp/mock/container /tmp/mock/network /tmp/mock/nft-public; do
    [[ ! -e $path ]] || printf 'remaining: %s\n' "$path" >&2
  done
  fail 'partial stage did not roll back public objects'
fi
[[ -f /opt/attackbox/private-marker && -f /tmp/mock/nft-private ]] || fail 'partial rollback changed private state'

# A dependency can fail before the application starts, yet remain in auto-restart.
: >/tmp/mock/stops
touch /tmp/mock/fail-dependency
expect_failure 'public service failed to start' bash "$script" stage "${common[@]}" --approve "$bundle_sha"
[[ ! -e /var/lib/attackbox-public && ! -e /tmp/mock/otel-restarting &&
   $(cat /tmp/mock/stops) == $'attackbox-public.service\nattackbox-public-otel.service' ]] || fail 'automatic rollback left the restarting dependency'
: >/tmp/mock/stops
touch /tmp/mock/ignore-otel-stop
expect_failure 'public service failed to start' bash "$script" stage "${common[@]}" --approve "$bundle_sha"
[[ $failure_output == *'public Collector is not stopped'* && -f /var/lib/attackbox-public/ledger/bundle_sha &&
   -f /tmp/mock/otel-restarting && ! -e /var/lib/attackbox-public/ledger/collector_service.stopped ]] || fail 'unconfirmed Collector stop lost rollback ownership'
[[ $(cat /tmp/mock/stops) == $'attackbox-public.service\nattackbox-public-otel.service' ]] || fail 'wrong units stopped on dependency failure'
rm /tmp/mock/ignore-otel-stop /tmp/mock/fail-dependency
: >/tmp/mock/stops
for foreign in foreign-fragment foreign-dropin stale-fragment; do
  touch "/tmp/mock/$foreign"
  expect_failure 'refuse unverified systemd unit' bash "$script" rollback --approve "$bundle_sha"
  [[ ! -s /tmp/mock/stops && -e /tmp/mock/otel-restarting ]] || fail 'rollback stopped an unverified Collector'
  rm "/tmp/mock/$foreign"
done
otel_unit=/etc/systemd/system/attackbox-public-otel.service
printf '\n# changed\n' >>"$otel_unit"
expect_failure 'refuse changed owned file' bash "$script" rollback --approve "$bundle_sha"
[[ ! -s /tmp/mock/stops ]] || fail 'rollback stopped a Collector with a changed ledger hash'
install -m 0644 "/root/release/deploy/systemd/${otel_unit##*/}" "$otel_unit"
touch /tmp/mock/fail-reload
expect_failure 'systemd reload failed during rollback' bash "$script" rollback --approve "$bundle_sha"
[[ $(cat /tmp/mock/stops) == attackbox-public-otel.service && ! -e /tmp/mock/otel-restarting && ! -e $otel_unit ]] || fail 'retry did not stop only the owned Collector'
rm /tmp/mock/fail-reload
mkdir -m 0700 /run/attackbox-public-otel
expect_failure 'removed runtime directory was recreated' bash "$script" rollback --approve "$bundle_sha"
rmdir /run/attackbox-public-otel
bash "$script" rollback --approve "$bundle_sha" >/dev/null
[[ $(cat /tmp/mock/stops) == attackbox-public-otel.service && ! -e /var/lib/attackbox-public ]] || fail 'repeat rollback tried to stop a missing unit'

for check in 'partial-bindings:ports are not bound exactly' 'extra-publication:ports are not bound exactly' 'foreign-mount:public mounts must contain only' \
  'wrong-isolation:live public isolation differs' 'live-untrusted:live public HTTPS failed'; do
  touch "/tmp/mock/${check%%:*}"
  expect_failure "${check#*:}" bash "$script" stage "${common[@]}" --approve "$bundle_sha"
  [[ ! -e /var/lib/attackbox-public && ! -e /tmp/mock/container && ! -e /tmp/mock/image ]] || fail 'failed live proof left installation'
  rm "/tmp/mock/${check%%:*}"
done

bash "$script" stage "${common[@]}" --approve "$bundle_sha" >/tmp/stage.out
project=$(cat /etc/attackbox-public/project-id)
[[ $project =~ ^attackbox-public-[0-9a-f]{24}$ ]] || fail 'canonical project identity is invalid'
[[ $(stat -c '%u:%g:%a' /etc/attackbox-public/project-id) == 0:0:600 ]] || fail 'canonical project identity mode is unsafe'
[[ $(stat -c '%u:%g:%a' /etc/attackbox-public) == 0:0:700 && $(stat -c '%u:%g:%a' /etc/attackbox-public/tls) == 0:65532:750 ]] || fail 'public TLS mount lacks a protected host ancestor or container access'
[[ $(stat -c '%u:%g:%a' /etc/attackbox-public/tls/fullchain.pem) == 0:65532:440 ]] || fail 'TLS certificate ownership is not container-readable'
[[ $(stat -c '%u:%g:%a' /etc/attackbox-public/tls/privkey.pem) == 0:65532:440 ]] || fail 'TLS key ownership is not container-readable'
if setpriv --reuid=65532 --regid=65532 --clear-groups -- head -c 1 /etc/attackbox-public/tls/privkey.pem >/dev/null 2>&1; then
  fail 'host bait UID can read the staged TLS key by its host path'
fi
otel_user=(setpriv --reuid=998 --regid=998 --clear-groups --)
config=/etc/attackbox-public-otel/config.yaml
[[ $(stat -c '%u:%g:%a' "${config%/*}") == 0:0:700 && $(stat -c '%u:%g:%a' "$config") == 0:0:644 &&
   ! -e ${config%/*}/license.key ]] || fail 'Collector config source permissions changed'
if "${otel_user[@]}" head -c 1 "$config" >/dev/null 2>&1; then fail 'Collector can read its config through the host path'; fi
# Model PID 1 delivering the synthetic config; use the actual unit argv under the service UID.
cred_dir=$(mktemp -d /run/test-otel-creds.XXXXXXXX)
cred=$(awk -F'[:=]' -v config="$config" '$1 == "LoadCredential" && $3 == config {print $2}' "$otel_unit")
[[ $cred =~ ^[a-zA-Z0-9_.-]+$ && $cred != . && $cred != .. ]] || fail 'unit does not deliver the staged Collector config'
install -o 998 -g 998 -m 0400 "$config" "$cred_dir/$cred"
chown 998:998 "$cred_dir"; chmod 0500 "$cred_dir"
read -r binary argument extra < <(sed -n 's/^ExecStart=//p' "$otel_unit")
[[ -z $extra && $argument == --config=* ]] || fail 'missing Collector config argument'
"${otel_user[@]}" test -x "$binary" || fail 'Collector executable is inaccessible'
consumer=${argument#--config=}
"${otel_user[@]}" cat "${consumer//%d/$cred_dir}" | cmp - "$config" || fail 'Collector cannot read the delivered config'
rm -- "$cred_dir/$cred"; rmdir -- "$cred_dir"
socket=/run/attackbox-public-otel/otlp.sock
"${otel_user[@]}" perl -MSocket -e 'socket(my $s, AF_UNIX, SOCK_STREAM, 0) or die $!; bind($s, sockaddr_un($ARGV[0])) or die $!' "$socket"
read -r helper action < <(sed -n 's/^ExecStartPost=//p' "$otel_unit")
"${otel_user[@]}" "$helper" "$action" || fail 'unprivileged socket readiness failed'
[[ $(stat -c '%u:%g:%a' "$socket") == 998:65532:220 ]] || fail 'ready socket is not writable by the bait group'
rm -- "$socket"
# shortcut: hard links test inode permissions only, verify bind mounts with gVisor on Linux.
ln /etc/attackbox-public/tls/fullchain.pem /tmp/mounted-cert
ln /etc/attackbox-public/tls/privkey.pem /tmp/mounted-key
setpriv --reuid=65532 --regid=65532 --clear-groups -- head -c 1 /tmp/mounted-cert >/dev/null
setpriv --reuid=65532 --regid=65532 --clear-groups -- head -c 1 /tmp/mounted-key >/dev/null
rm /tmp/mounted-cert /tmp/mounted-key
[[ $(stat -c '%u:%g:%a' /var/lib/attackbox-public-capture) == 0:0:700 &&
   $(stat -c '%u:%g:%a' /var/lib/attackbox-public-capture/requests) == 65532:65532:700 ]] || fail 'capture directory ownership is unsafe'
if setpriv --reuid=65532 --regid=65532 --clear-groups -- ls /var/lib/attackbox-public-capture/requests >/dev/null 2>&1; then
  fail 'host bait UID can reach raw captures by their host path'
fi
printf '{"target":"/fixture"}\n' >/var/lib/attackbox-public-capture/requests/capture-20000101.jsonl
[[ $(cat /var/lib/attackbox-public/ledger/file.tls_key.gid):$(cat /var/lib/attackbox-public/ledger/file.tls_key.mode) == 65532:440 ]] || fail 'TLS ownership is absent from the ledger'
! grep -q ATTACKBOX_PUBLIC_PROJECT /etc/attackbox-public/runtime.env || fail 'runtime environment duplicates canonical project identity'
[[ -e /tmp/mock/container && -e /tmp/mock/network && -e /tmp/mock/image && -e /tmp/mock/nft-public ]] || fail 'successful stage omitted public resources'
[[ -f /opt/attackbox/private-marker && -f /tmp/mock/nft-private ]] || fail 'stage changed private state'
cert=/etc/attackbox-public/tls/fullchain.pem
ledger=/var/lib/attackbox-public/ledger
renew=(bash "$script" renew --approve "$bundle_sha" --tls-cert /root/input/renew.pem)
[[ $(cat "$ledger/bind_ip") == "$public_ip" && $(cat "$ledger/public_fqdn") == api.example.test ]] || fail 'TLS identity differs from approved request'
touch /tmp/mock/ignore-hup
expect_failure 'restoring prior chain' "${renew[@]}"
cmp "$cert" /root/input/cert.pem && cmp "$cert" /tmp/mock/served-cert || fail 'failed renewal did not restore the served chain'
[[ $(cat "$ledger/file.tls_cert.sha") == "$(sha256sum "$cert" | cut -d' ' -f1)" && ! -e $ledger/renew.pending ]] || fail 'failed renewal lost rollback ownership'
rm /tmp/mock/ignore-hup
printf 'foreign cert' >/etc/attackbox-public/.renew-new.pem
expect_failure 'refuse unowned renewal file' "${renew[@]}"
rm /etc/attackbox-public/.renew-new.pem
# Reconstruct a crash immediately after atomic chain replacement, before HUP.
old=$(cat "$ledger/file.tls_cert.sha")
new=$(sha256sum /root/input/renew.pem | cut -d' ' -f1)
(umask 077; printf '%s:%s\n' "$old" "$new" >"$ledger/renew.pending")
ln "$cert" /etc/attackbox-public/.renew-old.pem
install -o 0 -g 65532 -m 0440 /root/input/renew.pem /etc/attackbox-public/.renew-new.pem
mv -fT /etc/attackbox-public/.renew-new.pem "$cert"
printf 'foreign' >>/etc/attackbox-public/.renew-old.pem
expect_failure 'refuse unowned renewal file' "${renew[@]}"
[[ -f $ledger/renew.pending && $(cat "$ledger/file.tls_cert.sha") == "$old" ]] || fail 'tainted recovery destroyed the journal'
install -o 0 -g 65532 -m 0440 /root/input/cert.pem /etc/attackbox-public/.renew-old.pem
bash "$script" renew --approve "$bundle_sha" --tls-cert /root/input/cert.pem >/dev/null
[[ ! -e $ledger/renew.pending && ! -e /etc/attackbox-public/.renew-old.pem ]] || fail 'interrupted renewal was not recovered'
cmp "$cert" /root/input/cert.pem && cmp "$cert" /tmp/mock/served-cert || fail 'recovery did not serve original certificate'
"${renew[@]}" >/dev/null
"${renew[@]}" >/dev/null
cmp "$cert" /root/input/renew.pem && cmp "$cert" /tmp/mock/served-cert || fail 'new chain was not served'
[[ $(cat "$ledger/file.tls_cert.sha") == "$(sha256sum "$cert" | cut -d' ' -f1)" && ! -e $ledger/renew.pending ]] || fail 'successful renewal lost rollback ownership'
[[ $(cat /tmp/mock/container) == "$container" && $(cat /tmp/mock/network) == "$(printf '%064d' 0 | tr 0 d)" ]] || fail 'renewal replaced the public container or network'
# A restart of attackbox-public.service recreates the container and the network with new IDs.
printf '%064d\n' 0 | tr 0 e >/tmp/mock/container
printf '%064d\n' 0 | tr 0 f >/tmp/mock/network
"${renew[@]}" >/dev/null || fail 'renewal refused the recreated public container'
touch /tmp/mock/foreign-image
expect_failure 'not the single container with the ledger image' "${renew[@]}"
expect_failure 'not the single container with the ledger image' bash "$script" rollback --approve "$bundle_sha"
rm /tmp/mock/foreign-image
touch /tmp/mock/foreign-network-label
expect_failure 'does not carry the project label' bash "$script" rollback --approve "$bundle_sha"
rm /tmp/mock/foreign-network-label
[[ -e /tmp/mock/container && -e /var/lib/attackbox-public ]] || fail 'ownership refusal mutated the staged project'
printf 'taint' >>"$cert"
expect_failure 'refuse changed owned file' "${renew[@]}"
expect_failure 'refuse changed owned file' bash "$script" rollback --approve "$bundle_sha"
install -o 0 -g 65532 -m 0440 /root/input/renew.pem "$cert"

cp /etc/attackbox-public-otel/config.yaml /tmp/config.saved
printf 'changed\n' >>/etc/attackbox-public-otel/config.yaml
expect_failure 'refuse changed owned file' bash "$script" rollback --approve "$bundle_sha"
[[ -e /tmp/mock/container && -e /var/lib/attackbox-public ]] || fail 'changed-file refusal mutated the staged project'
install -o root -g root -m 0644 /tmp/config.saved /etc/attackbox-public-otel/config.yaml
cp /etc/attackbox-public/project-id /tmp/project.saved
printf 'attackbox-public-000000000000000000000000\n' >/etc/attackbox-public/project-id
chmod 0600 /etc/attackbox-public/project-id
expect_failure 'refuse changed owned file' bash "$script" rollback --approve "$bundle_sha"
cmp /tmp/project.saved /var/lib/attackbox-public/ledger/project >/dev/null || fail 'ledger lost canonical project identity'
install -o root -g root -m 0600 /tmp/project.saved /etc/attackbox-public/project-id
expect_failure 'approval does not match' bash "$script" rollback --approve "$(printf '%064d' 0)"
printf 'stale\n' >/var/lib/attackbox-public/ledger/.status.999
chmod 0600 /var/lib/attackbox-public/ledger/.status.999
expect_failure 'unexpected ledger entry retained' bash "$script" rollback --approve "$bundle_sha"
[[ -f /var/lib/attackbox-public/ledger/bundle_sha && -e /tmp/mock/container ]] || fail 'stale ledger refusal lost approval or changed the project'
rm /var/lib/attackbox-public/ledger/.status.999
touch /tmp/mock/fail-network-after-down
expect_failure 'cannot inspect Docker networks' bash "$script" rollback --approve "$bundle_sha"
[[ -f /var/lib/attackbox-public/ledger/bundle_sha && -e /tmp/mock/network ]] || fail 'network inventory failure lost ownership evidence'
rm /tmp/mock/fail-network-after-down /tmp/mock/network-api-error
touch /tmp/mock/nft-error-after-delete
expect_failure 'cannot inspect public Collector UID' bash "$script" rollback --approve "$bundle_sha"
[[ -f /var/lib/attackbox-public/ledger/bundle_sha && -e /tmp/mock/account ]] || fail 'nft query failure lost approval or account evidence'
rm /tmp/mock/nft-error-after-delete /tmp/mock/nft-query-error
touch /tmp/mock/pgrep-unknown
expect_failure 'processes remain or cannot be inspected' bash "$script" rollback --approve "$bundle_sha"
[[ -f /var/lib/attackbox-public/ledger/bundle_sha && -e /tmp/mock/account ]] || fail 'unknown pgrep result lost approval or account evidence'
rm /tmp/mock/pgrep-unknown
bash "$script" rollback --approve "$bundle_sha" >/tmp/rollback.out
[[ ! -e /var/lib/attackbox-public && ! -e /var/lib/attackbox-public.rollback."$bundle_sha" && ! -e /opt/attackbox-public && ! -e /etc/attackbox-public && ! -e /etc/attackbox-public-otel ]] || fail 'rollback retained public install paths'
for path in /usr/local/libexec/attackbox-public-otel /usr/local/libexec/attackbox-public-otel-socket \
  /usr/local/libexec/attackbox-public-compose /etc/systemd/system/attackbox-public.service \
  /etc/systemd/system/attackbox-public-otel.service /run/attackbox-public-otel /run/attackbox-public-otel-state; do
  [[ ! -e $path && ! -L $path ]] || fail "rollback retained public object: $path"
done
[[ ! -e /tmp/mock/account && ! -e /tmp/mock/group && ! -e /tmp/mock/image && ! -e /tmp/mock/container && ! -e /tmp/mock/network && ! -e /tmp/mock/nft-public ]] || fail 'rollback retained public resources'
[[ -f /opt/attackbox/private-marker && -f /tmp/mock/nft-private ]] || fail 'rollback changed private UID or path state'
[[ -f /var/lib/attackbox-public-capture/requests/capture-20000101.jsonl ]] || fail 'rollback removed retained raw captures'

touch /tmp/mock/ambiguous-load /tmp/mock/fail-image-api-after-load
expect_failure 'verified public image load failed' bash "$script" stage "${common[@]}" --approve "$bundle_sha"
[[ -f /var/lib/attackbox-public/ledger/bundle_sha && -e /tmp/mock/image ]] || fail 'unavailable Docker image inventory lost ambiguous ownership'
[[ $failure_output == *'cannot inspect Docker images'* ]] || fail 'unavailable Docker image inventory was not reported'
rm /tmp/mock/image /tmp/mock/image-api-error /tmp/mock/fail-image-api-after-load /tmp/mock/ambiguous-load
bash "$script" rollback --approve "$bundle_sha" >/tmp/rollback-after-unavailable.out

touch /tmp/mock/ambiguous-load
expect_failure 'verified public image load failed' bash "$script" stage "${common[@]}" --approve "$bundle_sha"
[[ -f /var/lib/attackbox-public/ledger/bundle_sha && -e /tmp/mock/image && ! -e /var/lib/attackbox-public/ledger/image.loaded ]] || fail 'ambiguous image load was not retained'
expect_failure 'image load outcome is ambiguous' bash "$script" rollback --approve "$bundle_sha"
[[ -f /opt/attackbox/private-marker && -f /tmp/mock/nft-private ]] || fail 'ambiguous image refusal changed private state'
printf '%s\n' 'public host stage test: candidate bundle, mocked signature, ownership and rollback checks passed'
LINUX
