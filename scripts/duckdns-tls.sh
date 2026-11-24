#!/usr/bin/env bash
# Run on the operator Mac, not on the decoy. lego 5 handles both issuance and renewal.
set +x
set -euo pipefail
umask 077
name=${1:-}
if [[ $# != 1 || ! $name =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.duckdns\.org$ ]]; then
    echo 'Usage: duckdns-tls.sh NAME.duckdns.org' >&2; exit 2
fi
scripts=$(cd "$(dirname "$0")" && pwd)
ip=$(jq -er '.main_ip | select(type == "string" and length > 0)' "${VULTR_STATE_DIR:-$scripts/../.vultr}/state.json")
if [[ $(dig +short +time=5 +tries=2 "$name" A) != "$ip" ]]; then
    echo 'DuckDNS A record does not match the recorded VPS. No changes made.' >&2; exit 1
fi
txt=$(dig +time=5 +tries=2 +noall +comments +answer "_acme-challenge.$name" TXT)
if [[ $txt != *'status: NOERROR,'* && $txt != *'status: NXDOMAIN,'* ]] ||
    awk '$4 == "TXT" && $5 != "\"\"" {used=1} END {exit !used}' <<<"$txt"; then
    echo 'Cannot confirm an unused DuckDNS TXT record. No changes made.' >&2; exit 1
fi
mkdir -p "$HOME/.local/share/attackbox-acme"
cd "$HOME/.local/share/attackbox-acme"
csr="$PWD/$name.csr"
pending=
if [[ ! -e $csr ]]; then
    pending=$(mktemp .request.XXXXXXXX)
    trap 'rm -f -- "$pending"' EXIT
    bash "$scripts/vultr-launch.sh" ssh "openssl req -new -sha256 -key /opt/attackbox/secrets/server.key -subj /CN=$name -addext subjectAltName=DNS:$name" >"$pending"
    csr=$pending
fi
openssl req -in "$csr" -noout -verify
subject=$(openssl req -in "$csr" -noout -subject -nameopt RFC2253)
san=$(openssl req -in "$csr" -noout -text | awk '/X509v3 Subject Alternative Name:/ {getline; sub(/^[[:space:]]+/, ""); print}')
if [[ $subject != "subject=CN=$name" || $san != "DNS:$name" ]]; then
    echo 'CSR must contain only the requested hostname.' >&2; exit 1
fi
if [[ -n $pending ]]; then
    csr="$PWD/$name.csr"
    ln "$pending" "$csr"
fi
token=$(security find-generic-password -a "$(id -un)" -s attackbox-duckdns -w)
[[ -n $token ]] || { echo 'Empty DuckDNS token in Keychain.' >&2; exit 1; }
DUCKDNS_TOKEN="$token" DUCKDNS_PROPAGATION_TIMEOUT=240 lego --log.format text run --server letsencrypt \
    --account-id attackbox --dns duckdns --path "$PWD" --csr "$csr" 2>&1 |
    while IFS= read -r line; do printf '%s\n' "${line//"$token"/[redacted]}"; done
unset token
# Always reconcile, including after a prior successful renewal but failed SSH delivery.
bash "$scripts/vultr-launch.sh" ssh "set -- '$name'
$(cat "$scripts/install-proxy-chain.sh")" <"certificates/$name.crt"
