#!/usr/bin/env bash
set -Eeuo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
helper="$script_dir/../deploy/public-compose.sh"
root=$(cd -- "$script_dir/.." && pwd -P)

# The image must already exist locally; this test never pulls it.
docker run --rm --network none --pull never --platform linux/amd64 --user 0 \
  --mount "type=bind,source=$helper,destination=/public-compose.sh,readonly" \
  -i ubuntu:24.04 bash -s <<'TEST'
set -Eeuo pipefail
export FAKE_LOG=/tmp/docker-argv
export FAKE_EXIT=0
export ATTACKBOX_PUBLIC_BIND_IP=0.0.0.0 DOCKER_HOST=tcp://invalid.invalid:2375
cat > /usr/bin/docker <<'DOCKER'
#!/usr/bin/env bash
printf '%s\n' "$@" >> "$FAKE_LOG"
[[ -z ${ATTACKBOX_PUBLIC_BIND_IP+x} && $DOCKER_HOST == unix:///var/run/docker.sock ]] || exit 89
[[ $FAKE_EXIT == 0 ]] || exit "$FAKE_EXIT"
case " $* " in
  *' ps -q public '*) printf '%s\n' "${FAKE_ID-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}" ;;
  ' wait '*)
    : > /tmp/wait-started
    while [[ ! -e /tmp/wait-release ]]; do sleep 0.05; done
    printf '0\n'
    ;;
esac
DOCKER
cat > /usr/bin/systemd-notify <<'NOTIFY'
#!/usr/bin/env bash
printf '%s\n' "$@" > /tmp/notify-argv
NOTIFY
chmod +x /usr/bin/docker /usr/bin/systemd-notify

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

reject() {
  : > "$FAKE_LOG"
  if /public-compose.sh "$@" >/dev/null 2>&1; then
    fail "accepted invalid input: $*"
  fi
  [[ ! -s $FAKE_LOG ]] || fail "Docker invoked for invalid input: $*"
}

mkdir -m 700 /etc/attackbox-public
identity=/etc/attackbox-public/project-id
project=attackbox-public-0123456789abcdef01234567
export ATTACKBOX_PUBLIC_PROJECT=attackbox-public-aaaaaaaaaaaaaaaaaaaaaaaa
for action in up down; do
  rm -f "$identity"
  reject "$action"
  for token in '' attackbox-public attackbox-public-0123456789abcdef0123456 \
    attackbox-public-0123456789abcdef012345678 \
    attackbox-public-0123456789ABCDEF01234567 \
    attackbox-public-0123456789abcdef0123456g \
    $'attackbox-public-0123456789abcdef01234567\n'; do
    printf '%s\n' "$token" > "$identity"
    chmod 600 "$identity"
    reject "$action"
  done
  printf '%s' "$project" > "$identity"
  chmod 600 "$identity"
  reject "$action"
  printf '%s\n' "$project" > "$identity"
  chmod 644 "$identity"
  reject "$action"
  chmod 600 "$identity"
  chown 65532:65532 "$identity"
  reject "$action"
  chown 0:0 "$identity"
  chmod 777 /etc/attackbox-public
  reject "$action"
  chmod 700 /etc/attackbox-public
  mv "$identity" /tmp/project-id
  ln -s /tmp/project-id "$identity"
  reject "$action"
  rm "$identity"
  mv /tmp/project-id "$identity"
  reject "$action" extra
  if [[ $action == up ]]; then
    unset NOTIFY_SOCKET
    reject "$action"
    export NOTIFY_SOCKET=/tmp/fake-notify
    rm -f /tmp/wait-started /tmp/wait-release /tmp/notify-argv
    : > "$FAKE_LOG"
    /public-compose.sh up >/tmp/up-output 2>&1 &
    pid=$!
    for ((attempt=0; attempt<200; attempt++)); do
      [[ -e /tmp/wait-started && -e /tmp/notify-argv ]] && break
      if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" || true
        fail 'public supervisor exited before the container'
      fi
      sleep 0.05
    done
    [[ -e /tmp/wait-started && -e /tmp/notify-argv ]] || fail 'public supervisor did not wait and notify'
    [[ $(cat /tmp/notify-argv) == --ready ]] || fail 'incorrect readiness notification'
    : > /tmp/wait-release
    if wait "$pid"; then fail 'clean container exit reported as a successful service'; fi
  else
    : > "$FAKE_LOG"
    /public-compose.sh down
  fi
  {
    printf '%s\n' compose --env-file /etc/attackbox-public/runtime.env \
      --project-name "$project" -f /opt/attackbox-public/compose.yaml "$action"
    if [[ $action == up ]]; then
      printf '%s\n' -d --no-build --wait
      printf '%s\n' compose --env-file /etc/attackbox-public/runtime.env \
        --project-name "$project" -f /opt/attackbox-public/compose.yaml ps -q public \
        wait 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    fi
  } > /tmp/expected-argv
  cmp -s /tmp/expected-argv "$FAKE_LOG" || fail "unexpected Docker argv for $action"

  export FAKE_EXIT=37
  if /public-compose.sh "$action" >/dev/null 2>&1; then
    fail "Docker failure ignored for $action"
  else
    status=$?
    [[ $status -eq 37 ]] || fail "wrong Docker failure status for $action: $status"
  fi
  export FAKE_EXIT=0
done
export FAKE_ID=not-a-container
rm -f /tmp/notify-argv
if /public-compose.sh up >/dev/null 2>&1; then fail 'invalid container identity reported success'; fi
[[ ! -e /tmp/notify-argv ]] || fail 'invalid container identity reported readiness'
unset FAKE_ID
reject
reject invalid
printf 'public compose helper tests passed\n'
TEST

tmp=$(mktemp -d "${TMPDIR:-/tmp}/attackbox-compose-test.XXXXXXXX")
project1=
project2=
owned1=false
owned2=false
cleanup() {
  local result=$? failed=0
  trap - EXIT
  if $owned1; then docker compose --project-name "$project1" -f "$tmp/compose.yaml" down >/dev/null || failed=1; fi
  if $owned2; then docker compose --project-name "$project2" -f "$tmp/compose.yaml" down >/dev/null || failed=1; fi
  rm -f -- "$tmp/compose.yaml" || failed=1
  rmdir -- "$tmp" || failed=1
  if ((failed)); then echo 'test project cleanup failed' >&2; exit 1; fi
  exit "$result"
}
trap cleanup EXIT
project1=attackbox-public-$(openssl rand -hex 12)
project2=attackbox-public-$(openssl rand -hex 12)
[[ $project1 != "$project2" ]] || { echo 'test project collision' >&2; exit 1; }
for project in "$project1" "$project2"; do
  network=$(env ATTACKBOX_PUBLIC_IMAGE=attackbox-public:local ATTACKBOX_PUBLIC_BIND_IP=93.184.216.34 \
    ATTACKBOX_HOST_ID=ci-host ATTACKBOX_CAMPAIGN_ID=ci-campaign \
    docker compose --project-name "$project" -f "$root/compose.public.yaml" config --format json |
    jq -er 'select(.services.public as $s |
      ($s.ports | length) == 1 and
      ($s.ports[0] | .host_ip == "93.184.216.34" and (.published|tostring) == "443" and .target == 8443 and .protocol == "tcp") and
      ([$s.volumes[] | [.type,.source,.target,(.read_only // false)]] | sort) ==
      [["bind","/etc/attackbox-public/tls","/run/secrets",true],["bind","/run/attackbox-public-otel","/run/attackbox-public-otel",true],
       ["bind","/var/lib/attackbox-public-capture/requests","/var/lib/attackbox-public-capture",false]] and
      $s.logging.driver == "none" and $s.runtime == "runsc" and $s.read_only and $s.user == "65532:65532" and
      ($s.cpus|tonumber) == 2 and ($s.mem_limit|tonumber) == 536870912 and $s.pids_limit == 128 and
      $s.environment.ATTACKBOX_PUBLIC_OTEL_SOCKET == "/run/attackbox-public-otel/otlp.sock" and
      $s.environment.ATTACKBOX_PUBLIC_TLS_CERT == "/run/secrets/fullchain.pem" and
      $s.environment.ATTACKBOX_PUBLIC_TLS_KEY == "/run/secrets/privkey.pem" and
      $s.environment.ATTACKBOX_PUBLIC_CAPTURE_DIR == "/var/lib/attackbox-public-capture") | .networks.public.name')
  [[ $network == "${project}_public" ]] || { echo 'public Compose network is not project-scoped' >&2; exit 1; }
done
cat > "$tmp/compose.yaml" <<'YAML'
services:
  public:
    image: ubuntu:24.04
    platform: linux/amd64
    pull_policy: never
    command: ["sleep", "300"]
    networks: [public]
networks:
  public:
    internal: true
YAML
for project in "$project1" "$project2"; do
  existing=$(docker ps -aq --filter "label=com.docker.compose.project=$project") || exit 1
  [[ -z $existing ]] || { echo 'test project already has containers' >&2; exit 1; }
  if docker network inspect "${project}_public" >/dev/null 2>&1; then
    echo 'test project network already exists' >&2
    exit 1
  fi
done
owned1=true
docker compose --project-name "$project1" -f "$tmp/compose.yaml" up -d --no-build --wait >/dev/null
owned2=true
docker compose --project-name "$project2" -f "$tmp/compose.yaml" up -d --no-build --wait >/dev/null
sentinel=$(docker compose --project-name "$project2" -f "$tmp/compose.yaml" ps -q public)
[[ $sentinel =~ ^[0-9a-f]{64}$ ]] || { echo 'sentinel container identity is invalid' >&2; exit 1; }
docker compose --project-name "$project1" -f "$tmp/compose.yaml" down >/dev/null
owned1=false
[[ $(docker inspect --format '{{.State.Running}}' "$sentinel") == true ]] || { echo 'other project container stopped' >&2; exit 1; }
docker network inspect "${project2}_public" >/dev/null || { echo 'other project network removed' >&2; exit 1; }
printf 'public compose project isolation passed\n'
