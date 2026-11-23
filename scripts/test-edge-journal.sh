#!/usr/bin/env bash
# Linux host-only fixture: temporary runsc proxy, loopback ports, existing TLS files.
# Does not change production containers, firewall rules, or agent configuration.
set -euo pipefail
config=${1:?absolute candidate nginx configuration required}
name="attackbox-edge-verify-$$"
created=false
cleanup() { if [[ "$created" == true ]]; then docker rm -f "$name" >/dev/null 2>&1 || true; fi; }
trap cleanup EXIT
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
docker run --rm -d --name "$name" --runtime runsc --network attackbox_external --network attackbox_internal \
    --add-host bait:172.30.0.2 --user 65532:65532 --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true --memory 128m --cpus 0.5 --pids-limit 50 \
    --log-driver journald --log-opt tag=attackbox-edge-verify \
    --publish 127.0.0.1:18080:8080 --publish 127.0.0.1:18443:8443 \
    --tmpfs /var/cache/nginx:rw,noexec,nosuid,nodev,size=16m,mode=0770,uid=65532,gid=65532 \
    --tmpfs /var/run:rw,noexec,nosuid,nodev,size=4m,mode=0770,uid=65532,gid=65532 \
    --mount "type=bind,source=$config,target=/etc/nginx/nginx.conf,readonly" \
    --mount type=bind,source=/opt/attackbox/secrets/server.crt,target=/etc/nginx/ssl/server.crt,readonly \
    --mount type=bind,source=/opt/attackbox/secrets/server.key,target=/etc/nginx/ssl/server.key,readonly \
    cgr.dev/chainguard/nginx@sha256:c1642395cc75f39c931d66d939f7e78cbdf671d6cfd821616632b0639c3c6d63 >/dev/null
created=true
ready=false
for _ in {1..30}; do
    if curl -ksS --max-time 2 https://127.0.0.1:18443/nginx-health >/dev/null 2>&1; then ready=true; break; fi
    sleep .2
done
if [[ "$ready" != true ]]; then docker logs "$name" >&2; exit 1; fi
curl -ksS --max-time 5 -o /dev/null -w 'models_status=%{http_code}\n' "https://127.0.0.1:18443/v1/models?campaign=$name"
python3 -c 'import sys;sys.stdout.buffer.write(b"x"*(1048576+1))' |
    curl -ksS --max-time 5 --data-binary @- -o /dev/null -w 'oversize_status=%{http_code}\n' https://127.0.0.1:18443/v1/chat/completions
python3 - <<'PY'
import ssl,socket
c=ssl._create_unverified_context().wrap_socket(socket.create_connection(('127.0.0.1',18443)),server_hostname='localhost')
c.sendall(b'GET /edge-verification HTTP/1.1\r\nBroken\r\n\r\n')
print('malformed_status='+c.recv(128).split(b'\r\n')[0].decode())
c.close()
PY
# Query the real Docker journal route, independent of docker logs output.
journalctl --no-pager -o json CONTAINER_NAME="$name" --since "$started" |
    python3 -c 'import sys,json
rows=[json.loads(x) for x in sys.stdin]
messages=[json.loads(x["MESSAGE"]) for x in rows if x.get("MESSAGE", "").startswith("{\"component\"")]
assert any(x["status"]==200 and x["bait_request_id"].startswith("req_") for x in messages), messages
assert any(x["status"]==413 for x in messages), messages
assert any(x["status"]==400 for x in messages), messages
assert all(x.get("_SYSTEMD_UNIT")=="docker.service" for x in rows), {x.get("_SYSTEMD_UNIT") for x in rows}
print(json.dumps({"verified_statuses":[200,400,413],"systemd_unit":"docker.service","records":messages}))'
