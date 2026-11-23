#!/usr/bin/env bash
# Run by systemd as root. Keep directory inodes across Collector restarts.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'root required' >&2; exit 1; }
case ${1:-} in
  prepare)
    for path in /run/attackbox-otel /run/attackbox-otel/bait /run/attackbox-otel/shipper; do
      [[ ! -L $path ]] || { echo "refuse symlink: $path" >&2; exit 1; }
    done
    install -d -o root -g root -m 0755 /run/attackbox-otel
    install -d -o abx-otel -g abx-bait -m 2710 /run/attackbox-otel/bait
    install -d -o abx-otel -g abx-ship -m 2710 /run/attackbox-otel/shipper
    for path in /run/attackbox-otel/{bait,shipper}/otlp.sock; do
      [[ ! -e $path && ! -L $path ]] && continue
      [[ -S $path && ! -L $path ]] || { echo "refuse non-socket: $path" >&2; exit 1; }
      rm -- "$path"
    done
    ;;
  ready)
    for path in /run/attackbox-otel/{bait,shipper}/otlp.sock; do
      for ((attempt=0; attempt<100; attempt++)); do
        [[ -S $path && ! -L $path ]] && break
        sleep 0.1
      done
      [[ -S $path && ! -L $path ]] || { echo "socket missing: $path" >&2; exit 1; }
      # Directory setgid assigns the role group. No read or world permission.
      chmod 0220 "$path"
    done
    ;;
  *) echo 'usage: prepare-sockets.sh prepare|ready' >&2; exit 2 ;;
esac
