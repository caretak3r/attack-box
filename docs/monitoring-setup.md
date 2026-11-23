# Host Infrastructure and optional service monitoring

Status: native New Relic Infrastructure 2.1.1 installed on `srv-000000` on 2026-11-23. Its host entity reports to account 0. Go tracing and the readiness collector were deployed at 12:21 UTC and verified in account 0. The raw evidence route remains separate. Source root: `/Users/rohit/attack-box`. The host installation paths below are absolute VPS paths.

## Components and trust

| Component | Input and output | Limits and failure behavior |
|---|---|---|
| Native New Relic Infrastructure | Host, process and Docker metrics; selected host logs | Default bootstrap component. Root-owned ingest configuration, mode `0600`; private status endpoint `127.0.0.1:18003`. |
| Go bait and shipper | Official OTel SDK 1.46.0; OTLP gRPC over separate Unix sockets | 1,024 queued spans, 128 per batch, one-second flush, two-second export timeout, three-second shutdown. Overflow and failed export counters. Spans are not durable. |
| Host OTel Collector 0.165.0 | Role-specific trace sockets; readiness and Collector Prometheus scrapes; HTTPS OTLP to US New Relic | 192 MiB memory limiter, 320 MiB service limit, 16 MiB export queue, 900,000-byte export batches. Retry expires after five minutes. Queue is memory-only. |
| Go readiness collector | Root-owned inventory snapshot; fixed loopback probes; `/metrics` on `127.0.0.1:9465` | 64 MiB service limit; 15-second refresh; 90-second stale limit. Dynamic user. No Docker socket. |
| Snapshot helper | Fixed `systemctl show` and `docker inspect` commands; `/run/attackbox-monitoring/inventory.json` | Root one-shot; four concurrent commands; two seconds per command; 64 KiB maximum snapshot; timer every 15 seconds. No environment, mounts or secret fields. |

The Collector runs as `abx-otel`. Its only remote destination is the configured New Relic OTLP endpoint. The base firewall gives this UID HTTPS access to `nr_otlp_ipv4` and `nr_otlp_ipv6`. Update the base firewall and refresh helper before installation. DNS refresh currently adds addresses; a ruleset reload clears stale addresses. No public OTLP listener is added.

Bait can access only `/run/attackbox-otel/bait/otlp.sock`. The host shipper uses `/run/attackbox-otel/shipper/otlp.sock`, restricted to `abx-ship`. The Collector removes producer resource identities and sets trusted role, host, campaign and instance values. It restricts span names and attributes. This limits identity forgery; a compromised producer can still submit false data within its permitted role. Socket directories remain stable when the Collector restarts.

The non-secret Collector configuration is `/etc/attackbox-otel/config.yaml`, in a root-owned `0755` directory. Do not place it beneath the protected `/etc/attackbox` directory: the Collector user cannot traverse that path.

The ingest key stays in `/etc/attackbox/otel-license.key`, owned by root with mode `0600`. Systemd passes it as a credential. It is never mounted into bait. Do not put a key in a command argument, source archive or dashboard. The existing evidence shipper key remains in `/etc/attackbox/shipper.env`.

## Native Infrastructure bootstrap

The user approved the official guided installation with `newrelic install -y`. Supply `NEW_RELIC_API_KEY` at runtime; set `NEW_RELIC_ACCOUNT_ID=0` and region US. The provisioning key must not enter the source bundle, process arguments, agent configuration or logs. The agent uses a separate ingest key in `/etc/newrelic-infra.yml`. Keep that file root-owned with mode `0600`.

The default bootstrap installs the pinned CLI and invokes the guided installer. The installer can create golden-signal alert conditions and a logs integration. Preserve the Go evidence route. Use explicit host-log paths; exclude Docker log wildcards and CLI logs from automatic discovery to prevent duplicate attack records. Native Infrastructure owns host resource metrics. The optional OTel configuration has no host-metric receiver.

Verify `systemctl is-active newrelic-infra` and `curl -fsS http://127.0.0.1:18003/v1/status`. Then verify the host entity and `host.*` metrics in the account. Local health alone is insufficient. Current Infrastructure data uses dimensional metrics; an empty `SystemSample` query does not establish a failure. See `/Users/rohit/attack-box/newrelic/queries.md`.

## Configuration

`ATTACKBOX_OTEL_SOCKET` enables tracing. An empty value disables it. When enabled, `ATTACKBOX_HOST_ID` and `ATTACKBOX_SERVICE_INSTANCE_ID` are required. `ATTACKBOX_CONTAINER_ID` and `ATTACKBOX_CAMPAIGN_ID` are optional SDK inputs. Generic `OTEL_*` endpoint, header, resource and sampler values cannot override the trusted SDK configuration. The Collector profile requires all identity fields shown in `/Users/rohit/attack-box/deploy/otel/monitoring.env.example`.

Use one trusted host ID for host metrics, services and evidence `sensor_id`. For the current campaign, use `srv-000000` only after checking the shipper identity. Use stable instance IDs for each service and a release version that identifies the reviewed source. Set `ATTACKBOX_BAIT_CONTAINER_ID` to the actual full Docker ID after container creation; do not invent it. An empty container ID gives no verified container relationship. Refresh that value after container replacement, then restart the Collector. Host/service joins do not prove native container entity creation.

The source creates fresh request traces and ignores client trace headers. Raw evidence receives `trace.id` and `span.id`. Exported log copies also receive `export.trace.id` and `export.span.id` for the shipper batch. Batches have separate traces; they are not children of an arbitrary attack. Existing log `service.name=attackbox` remains compatible with Live Watch. Trace service names are `attackbox-bait` and `attackbox-shipper`.

## Prepare a reviewed release

Run from the source root. Use Go 1.25 or a compatible later version. Do not replace the existing running binaries during preparation.

```sh
cd /Users/rohit/attack-box
GOTOOLCHAIN=go1.25.11 go test -race ./...
GOTOOLCHAIN=go1.25.11 go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /tmp/attackbox-hostcollector-linux-amd64 ./cmd/attackbox-hostcollector
shasum -a 256 /tmp/attackbox-hostcollector-linux-amd64
bash /Users/rohit/attack-box/scripts/install-monitoring.sh --check
python3 /Users/rohit/attack-box/newrelic/render_ecosystem.py --account-id 0 --sensor-id srv-000000 --output /tmp/attackbox-nr-ecosystem
```

The renderer makes three local assets: a dashboard, a workload mutation and disabled alert condition inputs. It makes no network request. Use a new output directory on each run. Before import, verify the account and sensor values. The native map can show only entities and relationships that New Relic has created. Keep unsupported components in the inventory table.

Build the bait image and shipper binary from the same reviewed release. Keep the current binaries, Compose configuration, firewall and unit files for rollback. The existing production deploy path requires a committed clean source bundle; do not bypass that gate with an unreviewed working tree.

## Authorized host installation

Production deployment requires approval of the concrete release. Keep public ingress closed during this procedure.

1. Update the base firewall template and `/usr/local/sbin/attackbox-deploy` from the reviewed release. Preserve existing containment and SSH rules. Verify the three Collector sets and UID-specific HTTPS rule. The installer does not replace the firewall.
2. Stage the pinned Collector archive on the host. Use `--archive` because the contained host may not reach GitHub. The installer verifies the release SHA256 before execution. Stage the built host collector and record its SHA256.
3. Create `/etc/attackbox/monitoring.env` from the example. Replace all placeholders. Set root ownership and mode `0600`. Securely provision `/etc/attackbox/otel-license.key` with the same ownership and mode. Do not print it.
4. Run the installer with `--check` first. Then use `--apply` with the verified archive and host collector binary plus SHA256. Use `--archive /root/attackbox-release/collector.tar.gz --hostcollector-binary /root/attackbox-release/attackbox-hostcollector --hostcollector-sha256 SHA256_FROM_BUILD`; replace the checksum placeholder with the recorded value. The apply path installs the Collector, snapshot timer and readiness service. It stages a shipper tracing drop-in. It does not restart bait or shipper.
5. Install the new shipper binary, then restart `attackbox-shipper.service`. Confirm evidence continues to arrive. Install the new bait image and activate the optional monitoring Compose profile with the supplied bait systemd drop-in. The staged drop-in is `/etc/attackbox/otel/bait-otel.conf`. Activate it at `/etc/systemd/system/attackbox.service.d/otel.conf`, then run `systemctl daemon-reload` and restart `attackbox.service`. Check all Compose files and trusted identity configuration before recreating the container. Keep the host trace directory mount read-only.
6. Update the actual bait container ID in `/etc/attackbox/monitoring.env`. Restart the Collector. Confirm socket group permissions after restart and verify bait reconnects under runsc. The local SDK tests do not prove gVisor socket behavior.
7. Check loopback readiness and all telemetry in New Relic. Import the dashboard and workload only after the entities exist. Review and enable alert conditions in an approved policy. Configure and test a notification destination separately.

## Verification and interpretation

`systemctl is-active` proves unit state only. `http://127.0.0.1:13133/` proves the Collector process responds; it does not prove export. `http://127.0.0.1:9465/metrics` reports inventory and local readiness. Never expose those endpoints publicly.

The inventory always emits ten expected units and two expected containers. `1` means yes, `0` means no, and `-1` means unknown or unsupported. Only bait, proxy, Collector and the readiness collector have readiness probes. Bait and proxy share one end-to-end model probe. An active Compose oneshot does not establish healthy containers. No dynamic extra-service discovery is implemented.

`attackbox_component_coverage_verified` remains `-1` for every component. The collector cannot certify its own remote evidence coverage. The proposed durable audit/journal reader, source rotation handling, audit loss counters, automatic canary receipts, native proxy spans and inventory drift detection remain separate work.

In New Relic, confirm host metrics with `sensor_id`, distinct service entities, trusted `host.id`, and both trace service names. Send a known benign request. Query its evidence and trace IDs. Compare exact captured byte counts and hashes where full evidence applies. Verify `export.trace.id` identifies the corresponding shipper batch. A successful SDK export or HTTP 202 does not prove the account indexed the data.

Test these failures with ingress closed: stop a producer; stop the snapshot timer for more than 90 seconds; restart the Collector; block a test export route; overload a bounded test queue. Confirm unknown/failed state and loss counters. Raw evidence has its own queue and loss limits; traces must not block it. Check export errors and queue metrics under `otelcol_exporter*`. Check SDK `otel_*` counters in bait and shipper heartbeat logs.

Alert inputs use no gap fill and a 180-second loss-of-signal interval. Loss-of-signal starts only after the first signal. Validate every expected component first. If all telemetry stops, dashboard rows can disappear after the query window; server-side missing-signal conditions must still alert. Test alert delivery independently. Do not claim full coverage from a green map.

## Rollback

Keep the evidence shipper running. Remove only the optional bait/shipper tracing drop-ins and Compose overlay activation; reload systemd and restart the affected services with their previous reviewed configuration. Stop and disable the optional host collector, snapshot timer and OTel Collector. Do not delete evidence queues or raw archives. Remove the Collector UID from the firewall allowlist after its process stops. Retain prior configuration and diagnostic evidence for review. A Collector restart discards its memory queue; report the gap.


