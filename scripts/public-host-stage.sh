#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset VULTR_API_KEY NEW_RELIC_API_KEY ATTACKBOX_NR_LICENSE_KEY NEW_RELIC_LICENSE_KEY
unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
export DOCKER_HOST=unix:///var/run/docker.sock LC_ALL=C
unset COMPOSE_FILE COMPOSE_PROFILES COMPOSE_PROJECT_NAME

STATE=/var/lib/attackbox-public
LEDGER=$STATE/ledger
WORK=$STATE/work
TLS_DIR=/etc/attackbox-public/tls
RENEW_OLD=/etc/attackbox-public/.renew-old.pem
RENEW_NEW=/etc/attackbox-public/.renew-new.pem
SYSTEM_CA=/etc/ssl/certs/ca-certificates.crt
PUBLIC_USER=abx-public-otel
PUBLIC_GROUP=abx-public-otel

usage() {
  cat >&2 <<'USAGE'
usage:
  public-host-stage.sh check|stage --bundle PATH --bundle-sha SHA256 --commit COMMIT \
    --verifier PATH --verifier-sha SHA256 --release-repo PATH \
    --expected-hostname NAME --public-fqdn NAME --public-ip IPV4 --host-id ID --campaign-id ID \
    --tls-cert PATH --tls-key PATH --license-file PATH [--approve SHA256]
  public-host-stage.sh renew --approve SHA256 --tls-cert PATH
  public-host-stage.sh rollback --approve SHA256
USAGE
}

fail() { printf 'public-host-stage: %s\n' "$*" >&2; exit 1; }
note() { printf 'public-host-stage: %s\n' "$*"; }
hash_file() { sha256sum "$1" | cut -d' ' -f1; }
docker() {
  if [[ $action == renew ]]; then timeout -k 1 12 /usr/bin/docker "$@"; else /usr/bin/docker "$@"; fi
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

safe_regular_file() {
  local path=$1 label=$2 resolved
  [[ $path == /* && -f $path && ! -L $path ]] || fail "$label must be an absolute regular file"
  resolved=$(readlink -e -- "$path") || fail "cannot resolve $label"
  [[ $resolved == "$path" ]] || fail "$label must not traverse symlinks or aliases"
}

safe_existing_dir() {
  local path=$1 label=$2 resolved
  [[ $path == /* && -d $path && ! -L $path ]] || fail "$label must be an absolute directory"
  resolved=$(readlink -e -- "$path") || fail "cannot resolve $label"
  [[ $resolved == "$path" ]] || fail "$label must not traverse symlinks or aliases"
}
safe_root_ancestry() {
  local current=$1 label=$2 mode parent
  while :; do
    [[ -d $current && ! -L $current && $(stat -c '%u' "$current") == 0 ]] || fail "$label has an untrusted parent: $current"
    mode=$(stat -c '%a' "$current")
    (( (8#$mode & 022) == 0 )) || fail "$label has a group/world-writable parent: $current"
    [[ $current == / ]] && break
    parent=${current%/*}
    [[ -n $parent ]] || parent=/
    current=$parent
  done
}

safe_root_source_file() {
  local path=$1 label=$2 parent mode
  safe_regular_file "$path" "$label"
  [[ $(stat -c '%u' "$path") == 0 ]] || fail "$label must be root-owned"
  mode=$(stat -c '%a' "$path")
  (( (8#$mode & 022) == 0 )) || fail "$label must not be group/world writable"
  parent=${path%/*}
  [[ -n $parent ]] || parent=/
  safe_root_ancestry "$parent" "$label"
}

safe_root_source_dir() {
  local path=$1 label=$2
  safe_existing_dir "$path" "$label"
  safe_root_ancestry "$path" "$label"
}


safe_root_parent() {
  local path=$1 parent mode
  parent=${path%/*}
  [[ -n $parent ]] || parent=/
  safe_existing_dir "$parent" "destination parent $parent"
  [[ $(stat -c '%u:%g' "$parent") == 0:0 ]] || fail "destination parent is not root-owned: $parent"
  mode=$(stat -c '%a' "$parent")
  (( (8#$mode & 022) == 0 )) || fail "destination parent is group/world writable: $parent"
}

validate_ipv4() {
  [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  awk -v ip="$1" 'BEGIN {
    n=split(ip, a, "."); if (n != 4) exit 1
    for (i=1; i<=4; i++) if (a[i] !~ /^[0-9]+$/ || a[i] > 255 || (length(a[i]) > 1 && substr(a[i],1,1) == "0")) exit 1
    if (a[1]==0 || a[1]==10 || a[1]==127 || a[1]>=224 ||
        (a[1]==100 && a[2]>=64 && a[2]<=127) || (a[1]==169 && a[2]==254) ||
        (a[1]==172 && a[2]>=16 && a[2]<=31) || (a[1]==192 && (a[2]==168 ||
        (a[2]==0 && (a[3]==0 || a[3]==2)) || (a[2]==88 && a[3]==99))) ||
        (a[1]==198 && (a[2]==18 || a[2]==19 || (a[2]==51 && a[3]==100))) ||
        (a[1]==203 && a[2]==0 && a[3]==113)) exit 1
  }'
}

validate_token() {
  [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || fail "$2 must be 1-64 safe identifier characters"
}


validate_public_fqdn() {
  local label='[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
  [[ ${#1} -le 253 && $1 =~ ^($label\.)+$label$ && ${1##*.} =~ [a-z] ]] ||
    fail 'public FQDN must be a canonical lowercase DNS hostname'
}

certificate_pubkey() { openssl x509 -in "$1" -noout -pubkey; }

verify_tls_pair() {
  local cert=$1 key=$2 private_cert cert_pub key_pub private_pub
  [[ $(stat -c %s "$cert") -le 1048576 ]] || fail 'public certificate chain exceeds 1 MiB'
  awk '
    /^-----BEGIN CERTIFICATE-----$/ && !inside {inside=1; next}
    /^-----END CERTIFICATE-----$/ && inside {inside=0; count++; next}
    inside && /^[a-zA-Z0-9+\/=]+$/ {next}
    !inside && /^[[:space:]]*$/ {next}
    {bad=1}
    END {exit (bad || inside || !count)}
  ' "$cert" || fail 'expected only PEM certificates in the public fullchain'
  openssl x509 -in "$cert" -noout -ext subjectAltName | grep -q 'DNS:' || fail 'public certificate lacks a DNS SAN'
  openssl verify -no-CApath -no-CAstore -CAfile "$SYSTEM_CA" -purpose sslserver \
    -verify_hostname "$public_fqdn" -untrusted "$cert" "$cert" >/dev/null || fail 'public certificate is untrusted or wrong for requested FQDN'
  private_cert=$(docker inspect --type container --format '{{range .Mounts}}{{if and (eq .Type "bind") (eq .Destination "/etc/nginx/ssl/server.crt") (not .RW)}}{{.Source}}{{end}}{{end}}' attackbox-proxy) || fail 'cannot inspect private proxy certificate mount'
  safe_regular_file "$private_cert" 'private proxy mounted certificate'
  safe_root_ancestry "${private_cert%/*}" 'private proxy mounted certificate'
  cert_pub=$(certificate_pubkey "$cert") && [[ -n $cert_pub ]] || fail 'cannot read public certificate SPKI'
  private_pub=$(certificate_pubkey "$private_cert") && [[ -n $private_pub ]] || fail 'cannot read private proxy certificate SPKI'
  local mounted_pub private_key
  mounted_pub=$(docker cp attackbox-proxy:/etc/nginx/ssl/server.crt - | tar -xO | openssl x509 -noout -pubkey) && [[ -n $mounted_pub ]] || fail 'cannot read mounted private proxy certificate SPKI'
  [[ $cert_pub != "$mounted_pub" ]] || fail 'private proxy SPKI must never be reused'
  private_key=$(docker inspect --type container --format '{{range .Mounts}}{{if and (eq .Type "bind") (eq .Destination "/etc/nginx/ssl/server.key") (not .RW)}}{{.Source}}{{end}}{{end}}' attackbox-proxy) || fail 'cannot identify private proxy key mount'
  [[ $private_key == /* && -f $private_key && ! $key -ef $private_key ]] || fail 'private proxy key is not a public key source'
  [[ $cert_pub != "$private_pub" ]] || fail 'private proxy SPKI must never be reused'
  key_pub=$(openssl pkey -in "$key" -passin pass: -pubout) && [[ -n $key_pub ]] || fail 'cannot read dedicated TLS key'
  [[ $cert_pub == "$key_pub" ]] || fail 'TLS certificate and private key do not match'
}

leaf_pin() { openssl x509 "$@" -outform DER | sha256sum | cut -d' ' -f1; }

live_tls_matches() {
  local wanted=$1 presented handshake
  [[ $wanted =~ ^[a-f0-9]{64}$ ]] || return 1
  handshake=$(timeout -k 1 5 openssl s_client -connect "$public_ip:443" -servername "$public_fqdn" \
    -bind "$public_ip:0" -no-CApath -no-CAstore -CAfile "$SYSTEM_CA" -verify_hostname "$public_fqdn" -verify_return_error \
    -purpose sslserver </dev/null 2>/dev/null) || return 1
  presented=$(leaf_pin <<<"$handshake") && [[ $presented == "$wanted" ]]
}

verify_host_identity() {
  local actual found route
  actual=$(hostname --fqdn) || fail 'cannot read host name'
  [[ $actual == "$expected_hostname" ]] || fail "host name mismatch: expected $expected_hostname"
  found=$(ip -4 -o addr show scope global | awk -v wanted="$public_ip" '{split($4,a,"/"); if (a[1] == wanted) seen++} END {if (seen==1) print "yes"}')
  [[ $found == yes ]] || fail "assigned public IP is not present on the host: $public_ip"
  route=$(ip -4 route get "$public_ip") || fail 'cannot verify local route to assigned public IP'
  [[ "$route " == "local $public_ip dev lo "* ]] || fail 'assigned public IP does not route locally'
}

verify_private_health() {
  local name state
  systemctl is-active --quiet attackbox.service || fail 'private attackbox.service is not active'
  for name in attackbox-bait attackbox-proxy; do
    state=$(docker inspect --type container --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}} {{.HostConfig.Runtime}}' "$name" 2>/dev/null) || fail "private container is missing: $name"
    [[ $state == 'running healthy runsc' ]] || fail "private container is not healthy under runsc: $name"
  done
}

verify_runsc() {
  local args
  args=$(docker info --format '{{with index .Runtimes "runsc"}}{{range .Args}}{{println .}}{{end}}{{end}}') || fail 'cannot inspect Docker runsc runtime'
  printf '%s\n' "$args" | grep -Eq '^--host-uds=(open|create)$' || fail 'runsc host UDS support is not enabled'
}

verify_firewall() {
  local set_name chain
  for set_name in collector_uids nr_otlp_ipv4 nr_otlp_ipv6; do
    nft list set inet attackbox "$set_name" >/dev/null || fail "required nft set is missing: $set_name"
  done
  chain=$(nft list chain inet attackbox output_policy) || fail 'required nft output chain is unavailable'
  printf '%s\n' "$chain" | awk '
    {$1=$1}
    /^type filter hook output priority [^;]+; policy drop;$/ {policy=1}
    /^(meta )?skuid @collector_uids ip daddr @nr_otlp_ipv4 tcp dport 443 accept$/ {ipv4=1}
    /^(meta )?skuid @collector_uids ip6 daddr @nr_otlp_ipv6 tcp dport 443 accept$/ {ipv6=1}
    END {exit !(policy && ipv4 && ipv6)}
  ' || fail 'UID-scoped fixed OTLP egress rules or default-drop policy are missing'
}

verify_ports_free() {
  local ids id mappings
  ss -H -ltn | awk -v bind="$public_ip" '
    $4 ~ /:443$/ {addr=$4; sub(/:443$/, "", addr); gsub(/^\[|\]$/, "", addr)
      if (addr==bind || addr=="*" || addr=="0.0.0.0" || addr=="::" || addr=="::ffff:"bind) exit 1}
  ' || fail "a wildcard or $public_ip listener already owns port 443"
  # Docker may publish DNAT without a listening userland proxy.
  ids=$(docker ps -q --no-trunc) || fail 'cannot inspect Docker containers'
  while IFS= read -r id; do
    [[ -n $id ]] || continue
    [[ $id =~ ^[0-9a-f]{64}$ ]] || fail 'invalid running container ID'
    mappings=$(docker port "$id") || fail 'cannot inspect existing Docker publications'
    if grep -Eq "/tcp -> (0\\.0\\.0\\.0|\\[::\\]|\\[::ffff:${public_ip//./\\.}\\]|${public_ip//./\\.}):443$" <<<"$mappings"; then
      fail "a Docker publication already owns $public_ip:443"
    fi
  done <<<"$ids"
}

public_paths=(
  /var/lib/attackbox-public
  /opt/attackbox-public
  /etc/attackbox-public
  /etc/attackbox-public-otel
  /usr/local/libexec/attackbox-public-otel
  /usr/local/libexec/attackbox-public-otel-socket
  /usr/local/libexec/attackbox-public-compose
  /etc/systemd/system/attackbox-public.service
  /etc/systemd/system/attackbox-public-otel.service
  /run/attackbox-public-otel
  /run/attackbox-public-otel-state
)

docker_network_present() {
  local target=$1 networks name
  networks=$(docker network ls --format '{{.Name}}') || { printf 'public-host-stage: cannot inspect Docker networks\n' >&2; return 2; }
  while IFS= read -r name; do
    [[ $name == "$target" ]] && return 0
  done <<<"$networks"
  return 1
}

verify_public_absent() {
  local path result containers state
  for path in "${public_paths[@]}"; do
    safe_root_parent "$path"
    [[ ! -e $path && ! -L $path ]] || fail "public install path already exists: $path"
  done
  for path in /var/lib/attackbox-public.rollback.*; do
    [[ ! -e $path && ! -L $path ]] || fail "unfinished public rollback ledger exists: $path"
  done
  if getent passwd "$PUBLIC_USER" >/dev/null 2>&1; then fail "$PUBLIC_USER account already exists"; else result=$?; [[ $result == 2 ]] || fail "cannot inspect $PUBLIC_USER account"; fi
  if getent group "$PUBLIC_GROUP" >/dev/null 2>&1; then fail "$PUBLIC_GROUP group already exists"; else result=$?; [[ $result == 2 ]] || fail "cannot inspect $PUBLIC_GROUP group"; fi
  containers=$(docker ps -a --format '{{.Names}}') || fail 'cannot inspect Docker containers'
  while IFS= read -r path; do
    [[ $path != attackbox-public ]] || fail 'legacy public container name already exists'
  done <<<"$containers"
  if docker_network_present attackbox-public-net; then
    fail 'legacy public network already exists'
  else
    result=$?
    [[ $result == 1 ]] || fail 'cannot inspect Docker networks'
  fi
  for path in attackbox-public.service attackbox-public-otel.service; do
    state=$(systemctl show --property=LoadState --value "$path") || fail "cannot inspect public service: $path"
    [[ $state == not-found ]] || fail "public service already exists: $path"
  done
  return 0
}

verify_common_inputs() {
  local command bait_group
  [[ $EUID -eq 0 ]] || fail 'root is required'
  [[ $(uname -s)/$(uname -m) == Linux/x86_64 ]] || fail 'Linux amd64 is required'
  for command in awk chmod chown cmp cp cut docker flock getent git grep groupdel head hostname id install ip ln mkdir mktemp mv nft od openssl perl pgrep readlink rm rmdir sed sha256sum sort ss stat systemctl tar timeout tr useradd userdel wc; do
    require_command "$command"
  done
  [[ -x /usr/bin/docker ]] || fail '/usr/bin/docker is required'
  [[ -x /usr/bin/systemd-notify ]] || fail '/usr/bin/systemd-notify is required'
  docker compose version --short >/dev/null 2>&1 || fail 'Docker Compose is unavailable'
  [[ $bundle_sha =~ ^[0-9a-f]{64}$ ]] || fail 'bundle SHA-256 must be 64 lowercase hex characters'
  [[ $verifier_sha =~ ^[0-9a-f]{64}$ ]] || fail 'verifier SHA-256 must be 64 lowercase hex characters'
  [[ $commit =~ ^[0-9a-f]{40}$ ]] || fail 'release commit must be 40 lowercase hex characters'
  validate_ipv4 "$public_ip" || fail 'public IP must be globally routable canonical IPv4'
  validate_public_fqdn "$public_fqdn"
  validate_token "$expected_hostname" 'expected hostname'
  validate_token "$host_id" 'host ID'
  validate_token "$campaign_id" 'campaign ID'
  safe_regular_file "$bundle" 'bundle'
  safe_root_source_file "$verifier" 'trusted verifier'
  safe_root_source_file "$tls_cert" 'TLS certificate'
  safe_root_source_file "$tls_key" 'TLS private key'
  [[ $(stat -c '%a:%h' "$tls_key") =~ ^(400|600):1$ ]] || fail 'dedicated TLS key must be 0400/0600 with no hard links'
  safe_root_source_file "$license_file" 'license file'
  [[ -s $license_file ]] || fail 'license file is empty'
  safe_root_source_dir "$release_repo" 'approved release repository'
  [[ $(hash_file "$verifier") == "$verifier_sha" ]] || fail 'trusted verifier checksum mismatch'
  verify_tls_pair "$tls_cert" "$tls_key"
  verify_host_identity
  verify_private_health
  verify_runsc
  verify_firewall
  bait_group=$(getent group abx-bait) || fail 'private abx-bait group is missing'
  [[ $(getent group | awk -F: '$3 == 65532 {count++; if ($1 == "abx-bait") own++} END {if (count == 1 && own == 1) print "yes"}') == yes ]] || fail 'private abx-bait group must uniquely own GID 65532'
  verify_ports_free
  verify_public_absent
}

copy_input() {
  local source=$1 destination=$2 mode=$3
  [[ ! -e $destination && ! -L $destination ]] || fail "snapshot destination already exists: $destination"
  install -o root -g root -m "$mode" "$source" "$destination"
}

snapshot_bundle() {
  local source=$1 destination=$2 size
  [[ ! -e $destination && ! -L $destination ]] || fail 'bundle snapshot destination already exists'
  size=$(stat -c '%s' "$source") || fail 'cannot inspect bundle size'
  [[ $size =~ ^[0-9]+$ && $size -le 1073741824 ]] || fail 'bundle exceeds 1 GiB'
  head -c 1073741825 "$source" >"$destination" || fail 'cannot snapshot bundle'
  [[ $(wc -c <"$destination") -le 1073741824 ]] || fail 'bundle exceeds 1 GiB'
}

verify_release_source() {
  local root resolved committed=$WORK/committed-verifier
  root=$(git -C "$release_repo" rev-parse --show-toplevel) || fail 'approved release repository is not readable'
  resolved=$(readlink -e -- "$root") || fail 'cannot resolve release repository root'
  [[ $resolved == "$release_repo" ]] || fail 'release repository path is not its exact root'
  resolved=$(git -C "$release_repo" rev-parse --verify --end-of-options "$commit^{commit}") || fail 'release commit is absent'
  [[ $resolved == "$commit" ]] || fail 'release commit did not resolve exactly'
  git -C "$release_repo" -c gpg.minTrustLevel=fully verify-commit "$commit" >/dev/null 2>&1 || fail 'release commit signature is missing or untrusted'
  git -C "$release_repo" --no-pager show "$commit:scripts/verify-public-bundle.sh" >"$committed" || fail 'release commit lacks the trusted verifier'
  [[ $(hash_file "$committed") == "$verifier_sha" ]] || fail 'trusted verifier differs from the signed release commit'
  cmp -s "$committed" "$verifier" || fail 'external verifier differs from signed release bytes'
}

required_payload=(
  manifest image.tar otelcol-contrib compose.public.yaml
  deploy/public-compose.sh deploy/public-otel/config.yaml deploy/public-otel/prepare-socket.sh
  deploy/otel/version.env deploy/systemd/attackbox-public-otel.service
  deploy/systemd/attackbox-public.service scripts/verify-public-bundle.sh SHA256SUMS
)
signed_runtime_files=(
  compose.public.yaml deploy/public-compose.sh deploy/public-otel/config.yaml deploy/public-otel/prepare-socket.sh
  deploy/otel/version.env deploy/systemd/attackbox-public-otel.service
  deploy/systemd/attackbox-public.service scripts/verify-public-bundle.sh
)


verify_payload_contract() {
  local member signed
  for member in "${required_payload[@]}"; do
    [[ -f $WORK/extract/$member && ! -L $WORK/extract/$member ]] || fail "verified bundle lacks required regular member: $member"
  done
  mkdir -m 0700 -- "$WORK/signed" "$WORK/signed/deploy" "$WORK/signed/deploy/public-otel" \
    "$WORK/signed/deploy/otel" "$WORK/signed/deploy/systemd" "$WORK/signed/scripts"
  for member in "${signed_runtime_files[@]}"; do
    signed=$WORK/signed/$member
    git -C "$release_repo" --no-pager show "$commit:$member" >"$signed" || fail "signed release commit lacks runtime member: $member"
    cmp -s "$signed" "$WORK/extract/$member" || fail "bundle runtime differs from signed release bytes: $member"
  done
}

prepare_verified_work() {
  local output
  mkdir -m 0700 -- "$WORK/extract"
  snapshot_bundle "$bundle" "$WORK/bundle.snapshot"
  copy_input "$tls_cert" "$WORK/tls-cert" 0600
  # Pin the source inode across validation and encode that single key only.
  (
    exec 8<"$tls_key"
    [[ $(stat -Lc '%u:%a:%h' /dev/fd/8) =~ ^0:(400|600):1$ ]] || fail 'dedicated source key changed permissions'
    verify_tls_pair "$WORK/tls-cert" /dev/fd/8
    openssl pkey -in /dev/fd/8 -passin pass: -out "$WORK/tls-key"
  )
  copy_input "$license_file" "$WORK/license" 0600
  verify_tls_pair "$WORK/tls-cert" "$WORK/tls-key"
  verify_release_source
  [[ $(hash_file "$WORK/bundle.snapshot") == "$bundle_sha" ]] || fail 'bundle snapshot checksum mismatch'
  output=$(bash "$WORK/committed-verifier" "$WORK/bundle.snapshot" "$bundle_sha" "$commit") || fail 'trusted bundle verification failed'
  [[ $output =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'trusted verifier returned an invalid image identity'
  verified_image=$output
  tar --no-same-owner --no-same-permissions -xf "$WORK/bundle.snapshot" -C "$WORK/extract" || fail 'verified bundle extraction failed'
  verify_payload_contract
}

docker_image_present() {
  local target=$1 images id
  images=$(docker image ls --all --no-trunc --format '{{.ID}}') || return 2
  while IFS= read -r id; do
    [[ $id == "$target" ]] && return 0
  done <<<"$images"
  return 1
}

verify_image_absent() {
  local result
  if docker_image_present "$verified_image"; then
    fail "verified image already exists: $verified_image"
  else
    result=$?
    [[ $result == 1 ]] || fail 'cannot inspect Docker images'
  fi
}

verify_project_absent() {
  local project=$1 output result
  output=$(docker ps -a --no-trunc --filter "label=com.docker.compose.project=$project" --format '{{.ID}}') || fail 'cannot inspect public Compose project containers'
  [[ -z $output ]] || fail "Compose project already owns containers: $project"
  output=$(docker volume ls --filter "label=com.docker.compose.project=$project" --format '{{.Name}}') || fail 'cannot inspect public Compose project volumes'
  [[ -z $output ]] || fail "Compose project already owns volumes: $project"
  if docker_network_present "${project}_public"; then
    fail "Compose project network already exists: ${project}_public"
  else
    result=$?
    [[ $result == 1 ]] || fail 'cannot inspect Docker networks'
  fi
  return 0
}
marker() { printf '%s/%s' "$LEDGER" "$1"; }

mark() {
  local name=$1 value=${2:-yes} path
  path=$(marker "$name")
  if [[ -e $path || -L $path ]]; then
    [[ -f $path && ! -L $path && $(stat -c '%u:%g:%a' "$path") == 0:0:600 && $(cat "$path") == "$value" ]] || { printf 'public-host-stage: invalid ledger marker: %s\n' "$name" >&2; return 1; }
    return 0
  fi
  (umask 077; printf '%s\n' "$value" >"$path") || return 1
  chown root:root "$path" && chmod 0600 "$path"
}

has_marker() { [[ -f $(marker "$1") && ! -L $(marker "$1") ]]; }
marker_value() { cat "$(marker "$1")"; }

replace_marker() {
  local name=$1 value=$2 path tmp
  path=$(marker "$name")
  tmp=$LEDGER/."$name".$$
  (umask 077; printf '%s\n' "$value" >"$tmp")
  chown root:root "$tmp"
  chmod 0600 "$tmp"
  mv -f -- "$tmp" "$path"
}

file_keys=(compose runtime_env project_id tls_cert tls_key collector_config collector_env collector_license collector_binary socket_helper compose_helper public_unit otel_unit)
file_paths=(
  /opt/attackbox-public/compose.yaml
  /etc/attackbox-public/runtime.env
  /etc/attackbox-public/project-id
  /etc/attackbox-public/tls/fullchain.pem
  /etc/attackbox-public/tls/privkey.pem
  /etc/attackbox-public-otel/config.yaml
  /etc/attackbox-public-otel/environment
  /etc/attackbox-public-otel/license.key
  /usr/local/libexec/attackbox-public-otel
  /usr/local/libexec/attackbox-public-otel-socket
  /usr/local/libexec/attackbox-public-compose
  /etc/systemd/system/attackbox-public.service
  /etc/systemd/system/attackbox-public-otel.service
)
file_uids=(0 0 0 0 0 0 0 0 0 0 0 0 0)
file_gids=(0 0 0 65532 65532 0 0 0 0 0 0 0 0)
file_modes=(644 600 600 440 440 644 600 600 755 755 755 644 644)

dir_keys=(opt_dir etc_dir tls_dir otel_etc_dir)
dir_paths=(/opt/attackbox-public /etc/attackbox-public /etc/attackbox-public/tls /etc/attackbox-public-otel)
dir_uids=(0 0 0 0)
dir_gids=(0 0 65532 0)
dir_modes=(755 700 750 700)

record_file() {
  local key=$1 source=$2 uid=$3 gid=$4 mode=$5
  mark "file.$key.sha" "$(hash_file "$source")" || fail "cannot record $key hash"
  mark "file.$key.uid" "$uid" || fail "cannot record $key owner"
  mark "file.$key.gid" "$gid" || fail "cannot record $key group"
  mark "file.$key.mode" "$mode" || fail "cannot record $key mode"
}

create_owned_dir() {
  local key=$1 path=$2 uid=$3 gid=$4 mode=$5
  mark "dir.$key.uid" "$uid" || fail "cannot record directory owner: $path"
  mark "dir.$key.gid" "$gid" || fail "cannot record directory group: $path"
  mark "dir.$key.mode" "$mode" || fail "cannot record directory mode: $path"
  mark "dir.$key.creating" || fail "cannot record directory intent: $path"
  mkdir -- "$path"
  chown "$uid:$gid" "$path"
  chmod "$mode" "$path"
  mark "dir.$key.created" || fail "cannot record directory ownership: $path"
}

install_owned_file() {
  local key=$1 source=$2 path=$3 expected uid gid mode
  expected=$(marker_value "file.$key.sha")
  uid=$(marker_value "file.$key.uid")
  gid=$(marker_value "file.$key.gid")
  mode=$(marker_value "file.$key.mode")
  mark "file.$key.installing" || fail "cannot record file intent: $path"
  install -o "$uid" -g "$gid" -m "$mode" "$source" "$path"
  [[ $(hash_file "$path") == "$expected" && $(stat -c '%u:%g:%a' "$path") == "$uid:$gid:$mode" ]] || fail "installed file ownership or hash mismatch: $path"
  mark "file.$key.installed" || fail "cannot record file ownership: $path"
}

validate_account() {
  local uid=$1 gid=$2 passwd group unique_uid unique_gid
  passwd=$(getent passwd "$PUBLIC_USER") || return 1
  group=$(getent group "$PUBLIC_GROUP") || return 1
  [[ $passwd == "$PUBLIC_USER:x:$uid:$gid:"*":/nonexistent:/usr/sbin/nologin" ]] || return 1
  [[ $group == "$PUBLIC_GROUP:x:$gid:" ]] || return 1
  unique_uid=$(getent passwd | awk -F: -v uid="$uid" -v name="$PUBLIC_USER" '$3 == uid {count++; if ($1 == name) own++} END {if (count == 1 && own == 1) print "yes"}')
  unique_gid=$(getent group | awk -F: -v gid="$gid" -v name="$PUBLIC_GROUP" '$3 == gid {count++; if ($1 == name) own++} END {if (count == 1 && own == 1) print "yes"}')
  [[ $unique_uid == yes && $unique_gid == yes ]]
}

create_account() {
  local uid gid
  mark account.intent || fail 'cannot record account creation intent'
  useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$PUBLIC_USER"
  uid=$(id -u "$PUBLIC_USER")
  gid=$(id -g "$PUBLIC_USER")
  [[ $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ && $uid != 0 && $gid != 0 && $uid != 65532 && $gid != 65532 ]] || fail 'public Collector account has an unsafe identity'
  validate_account "$uid" "$gid" || fail 'public Collector account is shared or has unexpected fields'
  mark account.uid "$uid" || fail 'cannot record public Collector UID'
  mark account.gid "$gid" || fail 'cannot record public Collector GID'
}

write_runtime_inputs() {
  printf '%s\n' "$project" >"$WORK/project-id"
  cat >"$WORK/runtime.env" <<EOF_RUNTIME
ATTACKBOX_PUBLIC_IMAGE=$verified_image
ATTACKBOX_PUBLIC_BIND_IP=$public_ip
ATTACKBOX_HOST_ID=$host_id
ATTACKBOX_CAMPAIGN_ID=$campaign_id
EOF_RUNTIME
  cat >"$WORK/collector.env" <<EOF_COLLECTOR
ATTACKBOX_HOST_ID=$host_id
ATTACKBOX_HOST_NAME=$expected_hostname
ATTACKBOX_CAMPAIGN_ID=$campaign_id
ATTACKBOX_PUBLIC_RELEASE_VERSION=$commit
EOF_COLLECTOR
  chmod 0600 "$WORK/project-id" "$WORK/runtime.env" "$WORK/collector.env"
}

check_tls_directory() {
  local path
  for path in "$TLS_DIR"/* "$TLS_DIR"/.[!.]* "$TLS_DIR"/..?*; do
    [[ -e $path || -L $path ]] || continue
    [[ $path == "$TLS_DIR/fullchain.pem" || $path == "$TLS_DIR/privkey.pem" ]] ||
      { printf 'public-host-stage: unexpected public TLS mount entry\n' >&2; return 1; }
  done
}

verify_public_bindings() {
  local container=$1 actual mounts isolation network
  check_tls_directory || fail 'refusing non-dedicated public TLS directory'
  actual=$(docker port "$container") || fail 'cannot inspect public port bindings'
  [[ $actual == "8443/tcp -> $public_ip:443" ]] || fail "public ports are not bound exactly to $public_ip:443"
  mounts=$(docker inspect --type container --format '{{range .Mounts}}{{println .Type .Source .Destination .RW}}{{end}}' "$container" | sed '/^$/d' | sort) || fail 'cannot inspect public mounts'
  [[ $mounts == $'bind /etc/attackbox-public/tls /run/secrets false\nbind /run/attackbox-public-otel /run/attackbox-public-otel false' ]] || fail 'public mounts must contain only read-only public TLS and socket directories'
  network=$(marker_value project.network_id)
  isolation=$(docker inspect --type container --format \
    '{{.HostConfig.Runtime}} {{.HostConfig.LogConfig.Type}} {{.HostConfig.Privileged}} {{.HostConfig.ReadonlyRootfs}} {{.Config.User}} {{.HostConfig.NanoCpus}} {{.HostConfig.Memory}} {{.HostConfig.PidsLimit}} {{range .HostConfig.CapDrop}}{{.}}{{end}} {{if .HostConfig.CapAdd}}extra{{else}}none{{end}} {{range .HostConfig.SecurityOpt}}{{if or (eq . "no-new-privileges:true") (eq . "no-new-privileges")}}nnp{{end}}{{end}} {{range .NetworkSettings.Networks}}{{.NetworkID}}{{end}}' "$container") || fail 'cannot inspect live public isolation'
  [[ $isolation == "runsc none false true 65532:65532 2000000000 536870912 128 ALL none nnp $network" ]] || fail 'live public isolation differs from signed resource and network contract'
}

capture_project_inventory() {
  local ids count network volumes
  ids=$(docker ps -a --no-trunc --filter "label=com.docker.compose.project=$project" --format '{{.ID}}') || return 1
  count=$(printf '%s\n' "$ids" | awk 'NF {n++} END {print n+0}')
  if [[ $count -eq 1 && $ids =~ ^[0-9a-f]{64}$ ]]; then mark project.container_id "$ids" || return 1; fi
  network=$(docker network inspect --format '{{.Id}}' "${project}_public" 2>/dev/null || true)
  if [[ $network =~ ^[0-9a-f]{64}$ ]]; then mark project.network_id "$network" || return 1; fi
  volumes=$(docker volume ls --filter "label=com.docker.compose.project=$project" --format '{{.Name}}') || return 1
  [[ $count -eq 1 && $ids =~ ^[0-9a-f]{64}$ && $network =~ ^[0-9a-f]{64}$ && -z $volumes ]]
}

cleanup_work() {
  local member
  [[ -d $WORK && ! -L $WORK ]] || return 0
  rm -f -- "$WORK/bundle.snapshot" "$WORK/tls-cert" "$WORK/tls-key" "$WORK/license" "$WORK/committed-verifier" \
    "$WORK/project-id" "$WORK/runtime.env" "$WORK/collector.env" "$WORK/cert.pub" "$WORK/key.pub" "$WORK/expected-ports" "$WORK/actual-ports"
  for member in "${required_payload[@]}"; do rm -f -- "$WORK/extract/$member"; done
  for member in "${signed_runtime_files[@]}"; do rm -f -- "$WORK/signed/$member"; done
  rmdir -- "$WORK/extract/deploy/public-otel" "$WORK/extract/deploy/otel" "$WORK/extract/deploy/systemd" \
    "$WORK/extract/deploy" "$WORK/extract/scripts" "$WORK/extract" 2>/dev/null || true
  rmdir -- "$WORK/signed/deploy/public-otel" "$WORK/signed/deploy/otel" "$WORK/signed/deploy/systemd" \
    "$WORK/signed/deploy" "$WORK/signed/scripts" "$WORK/signed" 2>/dev/null || true
  rmdir -- "$WORK"
}

prevalidate_file_state() {
  local index key path mode expected uid gid
  for ((index=0; index<${#file_keys[@]}; index++)); do
    key=${file_keys[$index]}; path=${file_paths[$index]}
    if has_marker "file.$key.removed"; then
      [[ ! -e $path && ! -L $path ]] || { printf 'public-host-stage: removed file path was recreated: %s\n' "$path" >&2; return 1; }
    elif has_marker "file.$key.installed" || has_marker "file.$key.installing"; then
      if [[ -e $path || -L $path ]]; then
        [[ -f $path && ! -L $path ]] || { printf 'public-host-stage: owned file changed type: %s\n' "$path" >&2; return 1; }
        expected=$(marker_value "file.$key.sha")
        if [[ $key == tls_cert ]] && has_marker renew.pending; then
          local pending actual
          pending=$(marker_value renew.pending)
          [[ $pending =~ ^[0-9a-f]{64}:[0-9a-f]{64}$ ]] || return 1
          [[ $expected == "${pending%:*}" || $expected == "${pending#*:}" ]] || return 1
          actual=$(hash_file "$path") || return 1
          [[ $actual == "${pending%:*}" || $actual == "${pending#*:}" ]] || { printf 'public-host-stage: refuse changed renewal certificate\n' >&2; return 1; }
          expected=$actual
        fi
        uid=$(marker_value "file.$key.uid")
        gid=$(marker_value "file.$key.gid")
        mode=$(marker_value "file.$key.mode")
        [[ $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ && $mode =~ ^[0-7]{3,4}$ ]] || return 1
        [[ $(hash_file "$path") == "$expected" && $(stat -c '%u:%g:%a' "$path") == "$uid:$gid:$mode" ]] || { printf 'public-host-stage: refuse changed owned file: %s\n' "$path" >&2; return 1; }
      elif has_marker "file.$key.installed" && ! has_marker "file.$key.removing"; then
        printf 'public-host-stage: owned file disappeared without removal evidence: %s\n' "$path" >&2
        return 1
      fi
    elif [[ -e $path || -L $path ]]; then
      printf 'public-host-stage: refuse unowned public path: %s\n' "$path" >&2
      return 1
    fi
  done
}

prevalidate_dir_state() {
  local index key path mode uid gid
  for ((index=0; index<${#dir_keys[@]}; index++)); do
    key=${dir_keys[$index]}; path=${dir_paths[$index]}
    if has_marker "dir.$key.removed"; then
      [[ ! -e $path && ! -L $path ]] || { printf 'public-host-stage: removed directory was recreated: %s\n' "$path" >&2; return 1; }
    elif has_marker "dir.$key.created" || has_marker "dir.$key.creating"; then
      if [[ -e $path || -L $path ]]; then
        uid=$(marker_value "dir.$key.uid")
        gid=$(marker_value "dir.$key.gid")
        mode=$(marker_value "dir.$key.mode")
        [[ $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ && $mode =~ ^[0-7]{3,4}$ ]] || return 1
        [[ -d $path && ! -L $path && $(stat -c '%u:%g:%a' "$path") == "$uid:$gid:$mode" ]] || { printf 'public-host-stage: refuse changed owned directory: %s\n' "$path" >&2; return 1; }
        if [[ $key == tls_dir ]]; then check_tls_directory || return 1; fi
      elif has_marker "dir.$key.created" && ! has_marker "dir.$key.removing"; then
        printf 'public-host-stage: owned directory disappeared without removal evidence: %s\n' "$path" >&2
        return 1
      fi
    elif [[ -e $path || -L $path ]]; then
      printf 'public-host-stage: refuse unowned public directory: %s\n' "$path" >&2
      return 1
    fi
  done
}

prevalidate_project_state() {
  local current expected project volumes count result
  has_marker public_start.intent || return 0
  project=$(marker_value project)
  if has_marker project.down; then
    current=$(docker ps -a --no-trunc --filter "label=com.docker.compose.project=$project" --format '{{.ID}}') || return 1
    [[ -z $current ]] || { printf 'public-host-stage: removed public project containers were recreated\n' >&2; return 1; }
    if docker_network_present "${project}_public"; then
      printf 'public-host-stage: removed public project network was recreated\n' >&2
      return 1
    else
      result=$?
      [[ $result == 1 ]] || return 1
    fi
    volumes=$(docker volume ls --filter "label=com.docker.compose.project=$project" --format '{{.Name}}') || return 1
    [[ -z $volumes ]] || { printf 'public-host-stage: removed public project volumes were recreated\n' >&2; return 1; }
    return 0
  fi
  current=$(docker ps -a --no-trunc --filter "label=com.docker.compose.project=$project" --format '{{.ID}}') || return 1
  if has_marker project.container_id; then
    expected=$(marker_value project.container_id)
    if has_marker project.removing; then
      [[ -z $current || $current == "$expected" ]] || { printf 'public-host-stage: public project container identity changed\n' >&2; return 1; }
    else
      [[ $current == "$expected" ]] || { printf 'public-host-stage: public project container identity changed\n' >&2; return 1; }
    fi
  elif has_marker project.removing; then
    count=$(printf '%s\n' "$current" | awk 'NF {n++} END {print n+0}')
    [[ $count -le 1 ]] || return 1
  fi
  if has_marker project.network_id; then
    expected=$(marker_value project.network_id)
    if docker_network_present "${project}_public"; then
      current=$(docker network inspect --format '{{.Id}}' "${project}_public") || return 1
    else
      result=$?
      [[ $result == 1 ]] || return 1
      current=
    fi
    if has_marker project.removing; then
      [[ -z $current || $current == "$expected" ]] || { printf 'public-host-stage: public project network identity changed\n' >&2; return 1; }
    else
      [[ $current == "$expected" ]] || { printf 'public-host-stage: public project network identity changed\n' >&2; return 1; }
    fi
  fi
  volumes=$(docker volume ls --filter "label=com.docker.compose.project=$project" --format '{{.Name}}') || return 1
  [[ -z $volumes ]] || { printf 'public-host-stage: unexpected public project volume exists\n' >&2; return 1; }
}

prevalidate_rollback() {
  local uid gid image result
  [[ -d $STATE && ! -L $STATE && $(stat -c '%u:%g:%a' "$STATE") == 0:0:700 ]] || { printf 'public-host-stage: unsafe public state directory\n' >&2; return 1; }
  [[ -d $LEDGER && ! -L $LEDGER && $(stat -c '%u:%g:%a' "$LEDGER") == 0:0:700 ]] || { printf 'public-host-stage: unsafe public ledger directory\n' >&2; return 1; }
  validate_ledger_directory "$LEDGER" || return 1
  has_marker bundle_sha || { printf 'public-host-stage: public ledger lacks bundle identity\n' >&2; return 1; }
  [[ $(marker_value bundle_sha) =~ ^[0-9a-f]{64}$ && $(marker_value bundle_sha) == "$approve" ]] || { printf 'public-host-stage: rollback approval does not match installed bundle\n' >&2; return 1; }
  prevalidate_file_state || return 1
  if has_marker collector_start.intent; then owned_unit_state attackbox-public-otel.service otel_unit >/dev/null || return 1; fi
  if has_marker public_start.intent; then owned_unit_state attackbox-public.service public_unit >/dev/null || return 1; fi
  prevalidate_dir_state || return 1
  if has_marker account.uid; then
    uid=$(marker_value account.uid); gid=$(marker_value account.gid)
    [[ $uid =~ ^[0-9]+$ && $gid =~ ^[0-9]+$ ]] || return 1
    if has_marker account.removed; then
      getent passwd "$PUBLIC_USER" >/dev/null 2>&1 && { printf 'public-host-stage: removed account was recreated\n' >&2; return 1; }
      getent group "$PUBLIC_GROUP" >/dev/null 2>&1 && { printf 'public-host-stage: removed account group was recreated\n' >&2; return 1; }
    elif has_marker account.user_removed; then
      getent passwd "$PUBLIC_USER" >/dev/null 2>&1 && { printf 'public-host-stage: removed account was recreated\n' >&2; return 1; }
      if getent group "$PUBLIC_GROUP" >/dev/null 2>&1; then
        [[ $(getent group "$PUBLIC_GROUP") == "$PUBLIC_GROUP:x:$gid:" ]] || { printf 'public-host-stage: refuse changed public Collector group\n' >&2; return 1; }
      elif ! has_marker account.removing; then
        printf 'public-host-stage: public Collector group disappeared without removal evidence\n' >&2
        return 1
      fi
    elif has_marker account.removing; then
      if getent passwd "$PUBLIC_USER" >/dev/null 2>&1; then
        validate_account "$uid" "$gid" || { printf 'public-host-stage: refuse changed public Collector account\n' >&2; return 1; }
      elif getent group "$PUBLIC_GROUP" >/dev/null 2>&1; then
        [[ $(getent group "$PUBLIC_GROUP") == "$PUBLIC_GROUP:x:$gid:" ]] || return 1
      fi
    else
      validate_account "$uid" "$gid" || { printf 'public-host-stage: refuse changed public Collector account\n' >&2; return 1; }
    fi
  elif has_marker account.intent; then
    if getent passwd "$PUBLIC_USER" >/dev/null 2>&1 || getent group "$PUBLIC_GROUP" >/dev/null 2>&1; then
      printf 'public-host-stage: account creation outcome is ambiguous\n' >&2
      return 1
    fi
  fi
  if has_marker image; then
    image=$(marker_value image)
    [[ $image =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
    if docker_image_present "$image"; then
      if has_marker image.removed; then printf 'public-host-stage: removed image identity was recreated\n' >&2; return 1; fi
      if has_marker image.intent && ! has_marker image.loaded; then
        printf 'public-host-stage: image load outcome is ambiguous; refusing to remove the image\n' >&2
        return 1
      fi
      [[ $(docker image inspect --format '{{.Id}}' "$image") == "$image" ]] || return 1
    else
      result=$?
      [[ $result == 1 ]] || { printf 'public-host-stage: cannot inspect Docker images\n' >&2; return 1; }
      if has_marker image.loaded && ! has_marker image.removing && ! has_marker image.removed; then
        printf 'public-host-stage: owned image disappeared without removal evidence\n' >&2
        return 1
      fi
    fi
  fi
  prevalidate_project_state || return 1
  return 0
}

# The installer/rollback checked the fragment's ledger hash. Reject a different loaded definition.
owned_unit_state() {
  local unit=$1 key=$2 path=/etc/systemd/system/$1 properties field value
  local id= load= active= fragment=unknown dropins=unknown reload= status=0
  properties=$(systemctl show --all --property=Id,LoadState,ActiveState,FragmentPath,DropInPaths,NeedDaemonReload "$unit") || status=$?
  while IFS='=' read -r field value; do
    case $field in
      Id) id=$value ;; LoadState) load=$value ;; ActiveState) active=$value ;;
      FragmentPath) fragment=$value ;; DropInPaths) dropins=$value ;; NeedDaemonReload) reload=$value ;;
    esac
  done <<<"$properties"
  if [[ $id == "$unit" && -z $dropins ]] && has_marker "file.$key.installed"; then
    if [[ $status == 0 && $load == loaded && $fragment == "$path" && $reload == no && -f $path && ! -L $path ]]; then
      case $active in
        active|activating|deactivating|reloading|inactive|failed|refreshing|maintenance) printf '%s\n' "$active"; return ;;
      esac
    elif has_marker "file.$key.removing" && [[ ! -e $path && ! -L $path && ( $active == inactive || $active == failed ) &&
        ( ( ( $status == 0 || $status == 4 ) && $load == not-found && -z $fragment ) ||
          ( $status == 0 && $load == loaded && $fragment == "$path" ) ) ]]; then
      printf '%s\n' "$active"
      return
    fi
  fi
  printf 'public-host-stage: refuse unverified systemd unit: %s\n' "$unit" >&2
  return 1
}

stop_public_resources() {
  local failed=0 project image bind host campaign output collector_state project_failed result
  if has_marker public_start.intent; then
    if ! has_marker project.down && has_marker project && has_marker image && has_marker host_id && has_marker campaign_id; then
      project=$(marker_value project); image=$(marker_value image); bind=$(marker_value bind_ip); host=$(marker_value host_id); campaign=$(marker_value campaign_id)
      if ! has_marker project.removing; then mark project.removing || return 1; fi
    fi
    if ! has_marker public_service.stopped; then
      if ! systemctl stop attackbox-public.service; then printf 'public-host-stage: failed to stop public service\n' >&2; failed=1; else mark public_service.stopped || failed=1; fi
    fi
    if ! has_marker public_service.disabled; then
      if ! systemctl disable attackbox-public.service; then printf 'public-host-stage: failed to disable public service\n' >&2; failed=1; else mark public_service.disabled || failed=1; fi
    fi
    if ! has_marker project.down && has_marker project.removing; then
      project_failed=0
      if ! ATTACKBOX_PUBLIC_IMAGE="$image" ATTACKBOX_PUBLIC_BIND_IP="$bind" ATTACKBOX_HOST_ID="$host" ATTACKBOX_CAMPAIGN_ID="$campaign" /usr/local/libexec/attackbox-public-compose down; then
        printf 'public-host-stage: verified Compose helper failed to remove public project\n' >&2
        project_failed=1
      fi
      if ! output=$(docker ps -a --no-trunc --filter "label=com.docker.compose.project=$project" --format '{{.ID}}'); then project_failed=1; fi
      [[ -z $output ]] || { printf 'public-host-stage: public project containers remain\n' >&2; project_failed=1; }
      if docker_network_present "${project}_public"; then
        printf 'public-host-stage: public project network remains\n' >&2
        project_failed=1
      else
        result=$?
        [[ $result == 1 ]] || project_failed=1
      fi
      if ! output=$(docker volume ls --filter "label=com.docker.compose.project=$project" --format '{{.Name}}'); then project_failed=1; fi
      [[ -z $output ]] || { printf 'public-host-stage: public project volumes remain\n' >&2; project_failed=1; }
      if (( project_failed == 0 )); then mark project.down || failed=1; else failed=1; fi
    fi
  fi
  if has_marker collector_start.intent; then
    collector_state=$(owned_unit_state attackbox-public-otel.service otel_unit) || return 1
    if [[ $collector_state != inactive && $collector_state != failed ]]; then
      systemctl stop attackbox-public-otel.service || { printf 'public-host-stage: failed to stop public Collector\n' >&2; return 1; }
      collector_state=$(owned_unit_state attackbox-public-otel.service otel_unit) || return 1
      [[ $collector_state == inactive || $collector_state == failed ]] || { printf 'public-host-stage: public Collector is not stopped\n' >&2; return 1; }
    fi
    mark collector_service.stopped || failed=1
  fi
  (( failed == 0 ))
}

cleanup_collector_runtime() {
  local uid=$1 failed=0 rc nft_output
  if ! has_marker account.removing && has_marker collector_start.intent && [[ -x /usr/local/libexec/attackbox-public-otel-socket ]]; then
    if ! /usr/local/libexec/attackbox-public-otel-socket cleanup; then printf 'public-host-stage: public Collector UID cleanup failed\n' >&2; failed=1; fi
  fi
  if nft_output=$(LC_ALL=C nft get element inet attackbox collector_uids "{ $uid }" 2>&1); then
    printf 'public-host-stage: public Collector UID remains in nft set\n' >&2; failed=1
  elif [[ $nft_output != $'Error: Could not process rule: No such file or directory\n'* ]] || ! nft list set inet attackbox collector_uids >/dev/null; then
    printf 'public-host-stage: cannot inspect public Collector UID membership\n' >&2; failed=1
  fi
  if has_marker account.removing; then
    # Runtime cleanup finished before account removal. Never adopt a recreated runtime directory.
    local dir
    for dir in /run/attackbox-public-otel /run/attackbox-public-otel-state; do
      [[ ! -e $dir && ! -L $dir ]] || { printf 'public-host-stage: removed runtime directory was recreated: %s\n' "$dir" >&2; return 1; }
    done
    return "$failed"
  fi
  if [[ -e /run/attackbox-public-otel || -L /run/attackbox-public-otel ]]; then
    if [[ -d /run/attackbox-public-otel && ! -L /run/attackbox-public-otel && $(stat -c '%u' /run/attackbox-public-otel) == "$uid" ]]; then
      if [[ -e /run/attackbox-public-otel/otlp.sock || -L /run/attackbox-public-otel/otlp.sock ]]; then
        if [[ -S /run/attackbox-public-otel/otlp.sock && ! -L /run/attackbox-public-otel/otlp.sock && $(stat -c '%u' /run/attackbox-public-otel/otlp.sock) == "$uid" ]]; then
          timeout 2 perl -MIO::Socket::UNIX -MSocket=SOCK_STREAM -e 'my $s=IO::Socket::UNIX->new(Type=>SOCK_STREAM,Peer=>$ARGV[0]); exit 1 if $s; exit($!{ECONNREFUSED}?0:2)' /run/attackbox-public-otel/otlp.sock
          rc=$?
          if [[ $rc -eq 0 ]]; then rm -- /run/attackbox-public-otel/otlp.sock || failed=1; else printf 'public-host-stage: refuse live or unverifiable public Collector socket\n' >&2; failed=1; fi
        else
          printf 'public-host-stage: refuse changed public Collector socket\n' >&2; failed=1
        fi
      fi
      rmdir -- /run/attackbox-public-otel 2>/dev/null || { printf 'public-host-stage: public Collector runtime directory is not empty\n' >&2; failed=1; }
    else
      printf 'public-host-stage: refuse unowned public Collector runtime directory\n' >&2; failed=1
    fi
  fi
  if [[ -e /run/attackbox-public-otel-state || -L /run/attackbox-public-otel-state ]]; then
    if [[ -d /run/attackbox-public-otel-state && ! -L /run/attackbox-public-otel-state && $(stat -c '%u:%g:%a' /run/attackbox-public-otel-state) == 0:0:700 ]]; then
      if [[ -e /run/attackbox-public-otel-state/uid.pending || -L /run/attackbox-public-otel-state/uid.pending ]]; then
        printf 'public-host-stage: interrupted nft UID mutation retained for manual verification\n' >&2; failed=1
      fi
      if [[ -e /run/attackbox-public-otel-state/uid || -L /run/attackbox-public-otel-state/uid ]]; then
        printf 'public-host-stage: public Collector UID ownership marker remains\n' >&2; failed=1
      fi
      if [[ -e /run/attackbox-public-otel-state/lock || -L /run/attackbox-public-otel-state/lock ]]; then
        if [[ -f /run/attackbox-public-otel-state/lock && ! -L /run/attackbox-public-otel-state/lock && $(stat -c '%u:%g' /run/attackbox-public-otel-state/lock) == 0:0 ]]; then
          rm -- /run/attackbox-public-otel-state/lock || failed=1
        else
          printf 'public-host-stage: refuse changed Collector state lock\n' >&2; failed=1
        fi
      fi
      rmdir -- /run/attackbox-public-otel-state 2>/dev/null || { printf 'public-host-stage: Collector state evidence retained\n' >&2; failed=1; }
    else
      printf 'public-host-stage: refuse unowned Collector state directory\n' >&2; failed=1
    fi
  fi
  (( failed == 0 ))
}

remove_owned_file() {
  local key=$1 path=$2 expected
  has_marker "file.$key.installed" || has_marker "file.$key.installing" || return 0
  has_marker "file.$key.removed" && return 0
  mark "file.$key.removing" || return 1
  if [[ -e $path || -L $path ]]; then
    [[ -f $path && ! -L $path ]] || return 1
    expected=$(marker_value "file.$key.sha")
    [[ $(hash_file "$path") == "$expected" ]] || return 1
    rm -- "$path" || return 1
  fi
  mark "file.$key.removed"
}

remove_owned_dir() {
  local key=$1 path=$2
  has_marker "dir.$key.created" || has_marker "dir.$key.creating" || return 0
  has_marker "dir.$key.removed" && return 0
  mark "dir.$key.removing" || return 1
  if [[ -e $path || -L $path ]]; then
    [[ -d $path && ! -L $path ]] || return 1
    rmdir -- "$path" || return 1
  fi
  mark "dir.$key.removed"
}

remove_image() {
  local image result
  has_marker image.loaded || return 0
  has_marker image.removed && return 0
  image=$(marker_value image)
  mark image.removing || return 1
  if docker_image_present "$image"; then
    docker image rm "$image" >/dev/null || return 1
  else
    result=$?
    [[ $result == 1 ]] || { printf 'public-host-stage: cannot inspect Docker images\n' >&2; return 1; }
  fi
  mark image.removed
}

remove_account() {
  local uid gid rc
  has_marker account.uid || return 0
  has_marker account.removed && return 0
  uid=$(marker_value account.uid); gid=$(marker_value account.gid)
  if ! has_marker account.user_removed; then
    if getent passwd "$PUBLIC_USER" >/dev/null 2>&1; then
      validate_account "$uid" "$gid" || return 1
      set +e
      pgrep -u "$uid" >/dev/null 2>&1
      rc=$?
      set -e
      [[ $rc -eq 1 ]] || { printf 'public-host-stage: public Collector processes remain or cannot be inspected\n' >&2; return 1; }
      mark account.removing || return 1
      userdel "$PUBLIC_USER" || return 1
    elif ! has_marker account.removing; then
      return 1
    fi
    mark account.user_removed || return 1
  fi
  if ! has_marker account.group_removed; then
    if getent group "$PUBLIC_GROUP" >/dev/null 2>&1; then
      [[ $(getent group "$PUBLIC_GROUP") == "$PUBLIC_GROUP:x:$gid:" ]] || return 1
      groupdel "$PUBLIC_GROUP" || return 1
    elif ! has_marker account.removing; then
      return 1
    fi
    mark account.group_removed || return 1
  fi
  mark account.removed
}

ledger_entry_known() {
  local name=$1 key suffix
  case $name in
    bundle_sha|commit|verifier_sha|status|project|image|bind_ip|host_id|campaign_id|expected_hostname|public_fqdn|renew.pending|\
account.intent|account.uid|account.gid|account.removing|account.user_removed|account.group_removed|account.removed|\
image.intent|image.loaded|image.removing|image.removed|collector_start.intent|collector_service.stopped|\
collector_service.disabled|public_start.intent|public_service.stopped|public_service.disabled|\
project.container_id|project.network_id|project.removing|project.down) return 0 ;;
  esac
  for key in "${file_keys[@]}"; do
    for suffix in sha uid gid mode installing installed removing removed; do [[ $name == "file.$key.$suffix" ]] && return 0; done
  done
  for key in "${dir_keys[@]}"; do
    for suffix in uid gid mode creating created removing removed; do [[ $name == "dir.$key.$suffix" ]] && return 0; done
  done
  return 1
}

validate_ledger_directory() {
  local directory=$1 entry name
  [[ -d $directory && ! -L $directory && $(stat -c '%u:%g:%a' "$directory") == 0:0:700 ]] || return 1
  for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
    [[ -e $entry || -L $entry ]] || continue
    name=${entry##*/}
    [[ -f $entry && ! -L $entry && $(stat -c '%u:%g:%a' "$entry") == 0:0:600 ]] || return 1
    ledger_entry_known "$name" || { printf 'public-host-stage: unexpected ledger entry retained: %s\n' "$name" >&2; return 1; }
  done
}

finalize_tombstone() {
  local tomb=$1 sha=$2 entry
  [[ $tomb == "/var/lib/attackbox-public.rollback.$sha" && -d $tomb && ! -L $tomb && $(stat -c '%u:%g:%a' "$tomb") == 0:0:700 ]] || return 1
  if [[ -e $tomb/ledger || -L $tomb/ledger ]]; then
    validate_ledger_directory "$tomb/ledger" || return 1
    if [[ -e $tomb/ledger/bundle_sha || -L $tomb/ledger/bundle_sha ]]; then
      [[ -f $tomb/ledger/bundle_sha && ! -L $tomb/ledger/bundle_sha && $(cat "$tomb/ledger/bundle_sha") == "$sha" ]] || return 1
    fi
    for entry in "$tomb/ledger"/* "$tomb/ledger"/.[!.]* "$tomb/ledger"/..?*; do
      [[ -e $entry || -L $entry ]] || continue
      rm -- "$entry" || return 1
    done
    rmdir -- "$tomb/ledger" || return 1
  fi
  rmdir -- "$tomb"
}

remove_ledger() {
  local sha tomb
  sha=$(marker_value bundle_sha)
  [[ $sha =~ ^[0-9a-f]{64}$ ]] || return 1
  validate_ledger_directory "$LEDGER" || return 1
  tomb=/var/lib/attackbox-public.rollback.$sha
  [[ ! -e $tomb && ! -L $tomb ]] || return 1
  mv -- "$STATE" "$tomb" || return 1
  finalize_tombstone "$tomb" "$sha"
}

rollback_transaction() {
  local failed=0 index uid reload_needed=false
  prevalidate_rollback || return 1
  recover_renewal false || return 1
  if has_marker file.public_unit.installed || has_marker file.public_unit.installing || has_marker file.otel_unit.installed || has_marker file.otel_unit.installing; then
    reload_needed=true
  fi
  if ! stop_public_resources; then return 1; fi
  if has_marker account.uid; then
    uid=$(marker_value account.uid)
    if ! cleanup_collector_runtime "$uid"; then return 1; fi
  fi
  if ! remove_image; then printf 'public-host-stage: failed to remove owned public image\n' >&2; return 1; fi
  if ! remove_account; then printf 'public-host-stage: failed to remove owned public Collector account\n' >&2; return 1; fi
  for ((index=${#file_keys[@]}-1; index>=0; index--)); do
    if ! remove_owned_file "${file_keys[$index]}" "${file_paths[$index]}"; then printf 'public-host-stage: failed to remove owned file: %s\n' "${file_paths[$index]}" >&2; failed=1; fi
  done
  if (( failed != 0 )); then return 1; fi
  if $reload_needed; then systemctl daemon-reload || { printf 'public-host-stage: systemd reload failed during rollback\n' >&2; return 1; }; fi
  for ((index=${#dir_keys[@]}-1; index>=0; index--)); do
    if ! remove_owned_dir "${dir_keys[$index]}" "${dir_paths[$index]}"; then printf 'public-host-stage: failed to remove owned directory: %s\n' "${dir_paths[$index]}" >&2; failed=1; fi
  done
  if (( failed != 0 )); then return 1; fi
  if [[ -d $WORK && ! -L $WORK ]]; then cleanup_work || { printf 'public-host-stage: failed to remove private transaction snapshot\n' >&2; return 1; }; fi
  replace_marker status rolled-back || return 1
  remove_ledger || { printf 'public-host-stage: failed to remove public ledger\n' >&2; return 1; }
}

stage_in_progress=false
stage_exit() {
  local rc=$?
  trap - EXIT
  if $stage_in_progress && (( rc != 0 )); then
    set +e
    printf 'public-host-stage: stage failed; attempting selective public rollback\n' >&2
    if ! rollback_transaction; then printf 'public-host-stage: rollback incomplete; retained %s for evidence and retry\n' "$STATE" >&2; fi
  fi
  exit "$rc"
}

run_check() {
  local tmp
  verify_common_inputs
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/attackbox-public-check.XXXXXXXX")
  chmod 0700 "$tmp"
  WORK=$tmp/work
  mkdir -m 0700 -- "$WORK"
  trap 'set +e; cleanup_work; rmdir -- "$tmp" 2>/dev/null || true' EXIT
  prepare_verified_work
  verify_image_absent
  cleanup_work
  rmdir -- "$tmp"
  trap - EXIT
  note 'check passed: signed release, bundle snapshot, host identity, TLS pair, private health, runsc UDS, required nft rules, collisions and public-only paths'
  note 'not checked: complete host egress policy, provider firewall, live TLS, public ingress or New Relic ingestion'
}

run_stage() {
  local suffix index uid
  [[ $approve == "$bundle_sha" ]] || fail 'stage requires --approve equal to the exact bundle SHA-256'
  verify_common_inputs
  mkdir -m 0700 -- "$STATE" || fail 'public state path appeared during preflight'
  chown root:root "$STATE"
  mkdir -m 0700 -- "$LEDGER" "$WORK"
  chown root:root "$LEDGER" "$WORK"
  stage_in_progress=true
  trap stage_exit EXIT
  mark bundle_sha "$bundle_sha" || fail 'cannot record bundle identity'
  mark commit "$commit" || fail 'cannot record release commit'
  mark verifier_sha "$verifier_sha" || fail 'cannot record verifier identity'
  mark status staging || fail 'cannot record transaction state'
  prepare_verified_work
  verify_image_absent
  suffix=$(od -An -N12 -tx1 /dev/urandom | tr -d '[:space:]')
  [[ $suffix =~ ^[0-9a-f]{24}$ ]] || fail 'failed to generate public Compose project identity'
  project=attackbox-public-$suffix
  verify_project_absent "$project"
  mark project "$project" || fail 'cannot record Compose project identity'
  mark image "$verified_image" || fail 'cannot record public image identity'
  mark bind_ip "$public_ip" || fail 'cannot record public bind identity'
  mark public_fqdn "$public_fqdn" || fail 'cannot record public TLS identity'
  mark host_id "$host_id" || fail 'cannot record host identity'
  mark campaign_id "$campaign_id" || fail 'cannot record campaign identity'
  mark expected_hostname "$expected_hostname" || fail 'cannot record hostname identity'
  write_runtime_inputs

  record_file compose "$WORK/extract/compose.public.yaml" 0 0 644
  record_file runtime_env "$WORK/runtime.env" 0 0 600
  record_file project_id "$WORK/project-id" 0 0 600
  record_file tls_cert "$WORK/tls-cert" 0 65532 440
  record_file tls_key "$WORK/tls-key" 0 65532 440
  record_file collector_config "$WORK/extract/deploy/public-otel/config.yaml" 0 0 644
  record_file collector_env "$WORK/collector.env" 0 0 600
  record_file collector_license "$WORK/license" 0 0 600
  record_file collector_binary "$WORK/extract/otelcol-contrib" 0 0 755
  record_file socket_helper "$WORK/extract/deploy/public-otel/prepare-socket.sh" 0 0 755
  record_file compose_helper "$WORK/extract/deploy/public-compose.sh" 0 0 755
  record_file public_unit "$WORK/extract/deploy/systemd/attackbox-public.service" 0 0 644
  record_file otel_unit "$WORK/extract/deploy/systemd/attackbox-public-otel.service" 0 0 644

  for ((index=0; index<${#dir_keys[@]}; index++)); do
    create_owned_dir "${dir_keys[$index]}" "${dir_paths[$index]}" "${dir_uids[$index]}" "${dir_gids[$index]}" "${dir_modes[$index]}"
  done
  create_account
  install_owned_file compose "$WORK/extract/compose.public.yaml" /opt/attackbox-public/compose.yaml
  install_owned_file runtime_env "$WORK/runtime.env" /etc/attackbox-public/runtime.env
  install_owned_file project_id "$WORK/project-id" /etc/attackbox-public/project-id
  install_owned_file tls_cert "$WORK/tls-cert" /etc/attackbox-public/tls/fullchain.pem
  install_owned_file tls_key "$WORK/tls-key" /etc/attackbox-public/tls/privkey.pem
  install_owned_file collector_config "$WORK/extract/deploy/public-otel/config.yaml" /etc/attackbox-public-otel/config.yaml
  install_owned_file collector_env "$WORK/collector.env" /etc/attackbox-public-otel/environment
  install_owned_file collector_license "$WORK/license" /etc/attackbox-public-otel/license.key
  install_owned_file collector_binary "$WORK/extract/otelcol-contrib" /usr/local/libexec/attackbox-public-otel
  install_owned_file socket_helper "$WORK/extract/deploy/public-otel/prepare-socket.sh" /usr/local/libexec/attackbox-public-otel-socket
  install_owned_file compose_helper "$WORK/extract/deploy/public-compose.sh" /usr/local/libexec/attackbox-public-compose
  install_owned_file public_unit "$WORK/extract/deploy/systemd/attackbox-public.service" /etc/systemd/system/attackbox-public.service
  install_owned_file otel_unit "$WORK/extract/deploy/systemd/attackbox-public-otel.service" /etc/systemd/system/attackbox-public-otel.service

  verify_image_absent
  mark image.intent || fail 'cannot record image load intent'
  docker load --input "$WORK/extract/image.tar" >/dev/null || fail 'verified public image load failed'
  [[ $(docker image inspect --format '{{.Id}}' "$verified_image") == "$verified_image" ]] || fail 'loaded public image identity differs from verified manifest'
  mark image.loaded || fail 'cannot record loaded image ownership'

  systemctl daemon-reload
  owned_unit_state attackbox-public.service public_unit >/dev/null || fail 'public application unit identity mismatch'
  owned_unit_state attackbox-public-otel.service otel_unit >/dev/null || fail 'public Collector unit identity mismatch'
  mark collector_start.intent || fail 'cannot record dependency-owned Collector start intent'
  mark public_start.intent || fail 'cannot record public application start intent'
  if ! systemctl enable --now attackbox-public.service; then capture_project_inventory || true; fail 'public service failed to start'; fi
  systemctl is-active --quiet attackbox-public.service || fail 'public service is not active'
  systemctl is-active --quiet attackbox-public-otel.service || fail 'public Collector dependency is not active'
  uid=$(marker_value account.uid)
  nft get element inet attackbox collector_uids "{ $uid }" >/dev/null 2>&1 || fail 'public Collector UID was not installed in nft set'
  capture_project_inventory || fail 'public Compose project inventory is incomplete'
  [[ $(docker inspect --type container --format '{{.State.Status}} {{.State.Health.Status}} {{.Image}}' "$(marker_value project.container_id)") == "running healthy $verified_image" ]] || fail 'public container is not healthy with the verified image'
  verify_public_bindings "$(marker_value project.container_id)"
  live_tls_matches "$(leaf_pin -in "$TLS_DIR/fullchain.pem")" || fail 'live public HTTPS failed system trust, SNI or exact leaf pin'
  verify_private_health
  replace_marker status staged
  cleanup_work
  stage_in_progress=false
  trap - EXIT
  note "staged public project $project on $public_ip:443; verified local TLS trust, hostname and leaf pin"
  note 'not claimed: provider firewall state, public ingress or New Relic ingestion'
}

reload_and_check() {
  local container=$1 pin=$2 attempt
  timeout -k 1 8 /usr/bin/docker kill --signal HUP "$container" >/dev/null || return 1
  for attempt in 1 2 3 4 5; do
    live_tls_matches "$pin" && return 0
    sleep 0.2
  done
  return 1
}

check_renew_slot() {
  local path=$1 expected=$2
  [[ -e $path || -L $path ]] || return 0
  [[ -n $expected && -f $path && ! -L $path && $(stat -c '%u:%g:%a' "$path") == 0:65532:440 && $(hash_file "$path") == "$expected" ]] ||
    { printf 'public-host-stage: refuse unowned renewal file: %s\n' "$path" >&2; return 1; }
}

# The ledger hash is the commit point. After an interruption recover only
# the two exact, pre-authorized versions, never an arbitrary changed file.
recover_renewal() {
  local live=$1 pending old= new= expected current
  if has_marker renew.pending; then
    pending=$(marker_value renew.pending) || return 1
    [[ $pending =~ ^[0-9a-f]{64}:[0-9a-f]{64}$ ]] || return 1
    old=${pending%:*}; new=${pending#*:}
  fi
  check_renew_slot "$RENEW_OLD" "$old" && check_renew_slot "$RENEW_NEW" "$new" || return 1
  [[ -n $old ]] || return 0
  expected=$(marker_value file.tls_cert.sha) || return 1
  current=$(hash_file "$TLS_DIR/fullchain.pem") || return 1
  if [[ $expected == "$old" && $current == "$new" ]]; then
    [[ -f $RENEW_OLD ]] && mv -fT -- "$RENEW_OLD" "$TLS_DIR/fullchain.pem" || return 1
  else
    [[ $current == "$expected" && ( $expected == "$old" || $expected == "$new" ) ]] || return 1
  fi
  if $live; then
    reload_and_check "$(marker_value project.container_id)" "$(leaf_pin -in "$TLS_DIR/fullchain.pem")" || return 1
  fi
  rm -f -- "$RENEW_NEW" "$RENEW_OLD" && rm -- "$(marker renew.pending)"
}

renew_exit() {
  local rc=$?
  trap - EXIT
  if ((rc)); then
    if ! prevalidate_rollback || ! recover_renewal true; then
      printf 'public-host-stage: renewal recovery incomplete; retain ledger and retry renew or rollback\n' >&2
    fi
  fi
  exit "$rc"
}

run_renew() {
  local current next id pin
  prevalidate_rollback || fail 'renewal requires intact ledger-owned public resources'
  [[ $(marker_value status) == staged ]] && ! has_marker project.removing || fail 'renewal requires a staged public project'
  public_ip=$(marker_value bind_ip); expected_hostname=$(marker_value expected_hostname); public_fqdn=$(marker_value public_fqdn)
  validate_ipv4 "$public_ip" || fail 'invalid staged bind address'
  validate_public_fqdn "$public_fqdn"
  verify_host_identity
  verify_private_health
  verify_firewall
  id=$(marker_value project.container_id)
  [[ $id =~ ^[a-f0-9]{64}$ ]] || fail 'missing staged container identity'
  [[ $(docker inspect --type container --format '{{.State.Status}} {{.State.Health.Status}} {{.Image}}' "$id") == "running healthy $(marker_value image)" ]] || fail 'renewal requires the healthy staged image'
  verify_public_bindings "$id"
  recover_renewal true || fail 'interrupted renewal needs recovery'
  safe_root_source_file "$tls_cert" 'renewal fullchain'
  verify_tls_pair "$tls_cert" "$TLS_DIR/privkey.pem"
  next=$(hash_file "$tls_cert"); current=$(marker_value file.tls_cert.sha)
  pin=$(leaf_pin -in "$tls_cert")
  if [[ $next == "$current" ]]; then
    live_tls_matches "$pin" || fail 'installed certificate is not served with valid trust'
    note 'public fullchain already installed and verified'; return
  fi
  [[ $pin != "$(leaf_pin -in "$TLS_DIR/fullchain.pem")" ]] || fail 'renewal requires a newly issued leaf'
  mark renew.pending "$current:$next" || fail 'cannot record renewal intent'
  trap renew_exit EXIT
  ln -- "$TLS_DIR/fullchain.pem" "$RENEW_OLD"
  install -o 0 -g 65532 -m 0440 -- "$tls_cert" "$RENEW_NEW"
  check_renew_slot "$RENEW_NEW" "$next"
  verify_tls_pair "$RENEW_NEW" "$TLS_DIR/privkey.pem"
  mv -fT -- "$RENEW_NEW" "$TLS_DIR/fullchain.pem"
  reload_and_check "$id" "$pin" || fail 'renewed public HTTPS failed trust, SNI or exact leaf pin; restoring prior chain'
  replace_marker file.tls_cert.sha "$next"
  recover_renewal false || fail 'renewal cleanup incomplete'
  trap - EXIT
  note 'renewed and verified public fullchain; staged key and Docker identities unchanged'
}

run_rollback() {
  local tomb
  [[ $approve =~ ^[0-9a-f]{64}$ ]] || fail 'rollback requires the exact bundle SHA-256 in --approve'
  [[ $EUID -eq 0 ]] || fail 'root is required'
  for command in awk cat chmod chown cut docker flock getent groupdel mv nft perl pgrep rm rmdir sha256sum stat systemctl timeout userdel; do
    require_command "$command"
  done
  tomb=/var/lib/attackbox-public.rollback.$approve
  if [[ ! -e $STATE && ! -L $STATE && ( -e $tomb || -L $tomb ) ]]; then
    finalize_tombstone "$tomb" "$approve" || fail "rollback tombstone is unsafe; retained $tomb"
    note 'rollback finalized its durable public-only ledger'
    return
  fi
  [[ -x /usr/bin/docker ]] || fail '/usr/bin/docker is required'
  rollback_transaction || fail "rollback incomplete; retained $STATE for evidence and retry"
  note 'rollback removed only ledger-owned public objects; private services and paths were not changed'
}

action=${1:-}
[[ $action == check || $action == stage || $action == renew || $action == rollback ]] || { usage; exit 2; }
shift
bundle= bundle_sha= commit= verifier= verifier_sha= release_repo= expected_hostname= public_fqdn= public_ip= host_id= campaign_id= tls_cert= tls_key= license_file= approve=
while (($#)); do
  case $1 in
    --bundle|--bundle-sha|--commit|--verifier|--verifier-sha|--release-repo|--expected-hostname|--public-fqdn|--public-ip|--host-id|--campaign-id|--tls-cert|--tls-key|--license-file|--approve)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      case $1 in
        --bundle) bundle=$2 ;; --bundle-sha) bundle_sha=$2 ;; --commit) commit=$2 ;;
        --verifier) verifier=$2 ;; --verifier-sha) verifier_sha=$2 ;; --release-repo) release_repo=$2 ;;
        --expected-hostname) expected_hostname=$2 ;; --public-ip) public_ip=$2 ;; --host-id) host_id=$2 ;;
        --public-fqdn) public_fqdn=$2 ;;
        --campaign-id) campaign_id=$2 ;; --tls-cert) tls_cert=$2 ;; --tls-key) tls_key=$2 ;;
        --license-file) license_file=$2 ;; --approve) approve=$2 ;;
      esac
      shift 2 ;;
    *) usage; exit 2 ;;
  esac
done

[[ $EUID -eq 0 ]] || fail 'root is required'
# A directory FD serializes all four operations without creating host state.
exec 9</var/lib
flock -xn 9 || fail 'another host transaction is active'
systemctl() {
  if [[ $action == renew ]]; then timeout -k 1 12 systemctl "$@" 9<&-; else command systemctl "$@" 9<&-; fi
}
if [[ $action == rollback || $action == renew ]]; then
  [[ -z $bundle$bundle_sha$commit$verifier$verifier_sha$release_repo$expected_hostname$public_fqdn$public_ip$host_id$campaign_id$tls_key$license_file && $approve =~ ^[a-f0-9]{64}$ ]] || { usage; exit 2; }
  if [[ $action == renew && -n $tls_cert ]]; then run_renew
  elif [[ $action == rollback && -z $tls_cert ]]; then run_rollback
  else usage; exit 2; fi
else
  [[ -n $bundle && -n $bundle_sha && -n $commit && -n $verifier && -n $verifier_sha && -n $release_repo && -n $expected_hostname && -n $public_fqdn && -n $public_ip && -n $host_id && -n $campaign_id && -n $tls_cert && -n $tls_key && -n $license_file ]] || { usage; exit 2; }
  [[ $action == stage || -z $approve ]] || { usage; exit 2; }
  if [[ $action == check ]]; then run_check; else run_stage; fi
fi
