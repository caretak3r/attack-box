#!/usr/bin/env bash
# Run on the Ubuntu VPS. Read a public PEM chain from stdin; keep the key in place.
set -euo pipefail
umask 077
name=${1:?expected TLS hostname}
cd /opt/attackbox/secrets
exec 9<.
flock -w 15 9
next=$(mktemp .server.crt.XXXXXXXX)
trap 'rm -f -- "$next"' EXIT
cat >"$next"
ca=/etc/ssl/certs/ca-certificates.crt
openssl verify -CAfile "$ca" -purpose sslserver -verify_hostname "$name" -untrusted "$next" "$next"
if ! openssl x509 -in "$next" -noout -pubkey | cmp -s - <(openssl pkey -in server.key -pubout); then
    echo 'Chain does not match the proxy key; nothing installed.' >&2; exit 1
fi
expected=$(openssl x509 -in "$next" -noout -sha256 -fingerprint)
serves_chain() {
    local seen
    seen=$(timeout 5 openssl s_client -connect 127.0.0.1:8443 -servername "$name" -CAfile "$ca" \
        -verify_hostname "$name" -verify_return_error </dev/null 2>/dev/null |
        openssl x509 -noout -sha256 -fingerprint 2>/dev/null) && [[ $seen == "$expected" ]]
}
if cmp -s "$next" server.crt && serves_chain; then
    echo 'Proxy already serves the trusted chain.'; exit 0
fi
[[ $(docker inspect -f '{{.State.Running}}' attackbox-proxy) == true ]] || { echo 'Proxy is not running.' >&2; exit 1; }
chown 65532:65532 "$next"
chmod 0400 "$next"
cp -p -- server.crt server.crt.previous
mv -fT -- "$next" server.crt
# Compose bind-mounts the individual file. Restart nginx to bind the new inode.
if docker restart attackbox-proxy >/dev/null; then
    for ((i=0; i<10; i++)); do
        if serves_chain; then printf 'Verified %s: %s\n' "$name" "$expected"; exit 0; fi
        sleep 1
    done
fi
mv -fT -- server.crt.previous server.crt
docker restart attackbox-proxy >/dev/null
echo 'New chain failed its live TLS check. Restored the previous certificate.' >&2
exit 1
