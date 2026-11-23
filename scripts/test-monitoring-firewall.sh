#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
export SCRIPT_DIR
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# Load only the pure optional-profile function; never execute deployment main.
sed -n '/^populate_otlp_sets() {/,/^}/p' "$SCRIPT_DIR/deploy-ubuntu.sh" > "$work/function.sh"
# shellcheck source=/dev/null
source "$work/function.sh"
logfile="$work/nft.log"
mode=missing
id() { [[ "$mode" != missing ]] || return 1; printf '%s\n' "${test_uid:-997}"; }
dig() {
    [[ "$*" == '+short otlp.nr-data.net '* ]] || return 1
    [[ "$mode" != no_dns ]] || return 0
    if [[ "$*" == *' AAAA' ]]; then printf '%s\n' '2600:1234::1'; else printf '%s\n' 'otlp-edge.example.' '192.0.2.12'; fi
}
nft() { printf '%s\n' "$*" >> "$logfile"; }
err() { printf '%s\n' "$*" >&2; }
populate_otlp_sets
[[ ! -f "$logfile" ]]
mode=enabled
populate_otlp_sets
grep -Fxq 'add element inet attackbox nr_otlp_ipv4 { 192.0.2.12 }' "$logfile"
grep -Fxq 'add element inet attackbox nr_otlp_ipv6 { 2600:1234::1 }' "$logfile"
grep -Fxq 'add element inet attackbox collector_uids { 997 }' "$logfile"
[[ $(wc -l < "$logfile") -eq 3 ]]
: > "$logfile"
mode=no_dns
if populate_otlp_sets; then exit 1; fi
[[ ! -s "$logfile" ]]
mode=enabled
test_uid=0
if populate_otlp_sets; then exit 1; fi
[[ ! -s "$logfile" ]]
printf 'PASS: missing profile, scoped UID/IP sets, failed DNS and root UID rejection\n'
