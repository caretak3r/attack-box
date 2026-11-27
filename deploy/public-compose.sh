#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
# Compose's caller environment takes precedence over --env-file.
unset ATTACKBOX_PUBLIC_IMAGE ATTACKBOX_PUBLIC_BIND_IP ATTACKBOX_HOST_ID ATTACKBOX_CAMPAIGN_ID
unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH COMPOSE_FILE COMPOSE_PROFILES
export DOCKER_HOST=unix:///var/run/docker.sock

if [[ $# -ne 1 ]] || [[ $1 != up && $1 != down ]]; then
  printf 'usage: %s {up|down}\n' "$0" >&2
  exit 2
fi

state=/etc/attackbox-public
identity=$state/project-id
if [[ $EUID -ne 0 || ! -d $state || -L $state || $(stat -c '%u:%g' "$state") != 0:0 ]]; then
  printf 'unsafe public deployment directory\n' >&2
  exit 1
fi
mode=$(stat -c '%a' "$state")
if [[ ! $mode =~ ^[0-7]{3,4}$ ]] || (( (8#$mode & 0022) != 0 )); then
  printf 'unsafe public deployment directory permissions\n' >&2
  exit 1
fi
if [[ ! -f $identity || -L $identity || $(stat -c '%u:%g:%a' "$identity") != 0:0:600 || $(wc -c < "$identity") -ne 42 ]]; then
  printf 'invalid or missing public project identity\n' >&2
  exit 1
fi
IFS= read -r project < "$identity"
if [[ ! $project =~ ^attackbox-public-[0-9a-f]{24}$ ]]; then
  printf 'invalid public project identity\n' >&2
  exit 1
fi
compose=(/usr/bin/docker compose --env-file /etc/attackbox-public/runtime.env \
  --project-name "$project" -f /opt/attackbox-public/compose.yaml)

if [[ $1 == up ]]; then
  [[ -n ${NOTIFY_SOCKET:-} ]] || { printf 'public service requires systemd notification\n' >&2; exit 1; }
  "${compose[@]}" up -d --no-build --wait
  container=$("${compose[@]}" ps -q public)
  [[ $container =~ ^[0-9a-f]{64}$ ]] || { printf 'public container identity is unavailable\n' >&2; exit 1; }
  /usr/bin/systemd-notify --ready
  /usr/bin/docker wait "$container" >/dev/null
  printf 'public container exited\n' >&2
  exit 1
else
  exec "${compose[@]}" down
fi
