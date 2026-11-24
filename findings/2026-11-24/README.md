# Security watch debrief — 24 November 2026

**Watch: running · 87 snapshots · last observation Nov 24 05:09:27 EST / 10:09:27 UTC**

Coverage: Nov 23 21:53:16 EST / 02:53:16 UTC to Nov 24 05:09:27 EST / 10:09:27 UTC. Planned final collection: 05:58 Eastern / 10:58 UTC. The first snapshot includes a five-minute baseline.

## Assessment

**No public-source requests were recorded in the collected HTTP evidence.** The proxy recorded 1745 requests, including 1745 from private, loopback or link-local addresses. These observations do not establish an attack or compromise.

Public ingress was closed at setup. The watcher does not re-check the provider firewall. Silence during this watch is therefore not evidence that an internet-facing service resisted attack.

## What took place

The proxy recorded **1745 HTTP requests**: 0 with public-source addresses, 1745 with private/local addresses and 0 with unparseable source addresses.

The model-list endpoint received **1745 requests**. This endpoint lists the models that the simulated AI service advertises. Requests here can be inventory checks or reconnaissance; the route alone does not show the caller's purpose.

**Working interpretation:** all recorded HTTP activity targeted the model list from private/local addresses. This is consistent with routine service polling. The samples do not verify who made the requests or why.

## Service response and containment

Recorded HTTP outcomes: **1745 successful responses (2xx)**, 0 redirects (3xx), 0 client-error responses (4xx), and 0 server-error responses (5xx). A 2xx status does not prove an exploit worked. This summary does not inspect response bodies or link status totals to individual routes.

Firewall logs contained **16471 host-output deny records**, **0 container-egress deny records**, and **1 metadata-access deny records**. These are logged packet denials, not unique sessions or attackers. They can include routine blocked traffic. The aggregates do not link a deny record to an HTTP request or prove that all unwanted traffic was blocked.

No timestamped Falco events were counted inside the collection windows. The bounded file tail can miss events, so this does not rule out process activity.

## Host and logging health

At the latest snapshot, **12 of 12 expected components reported running**; running-state values were available for 12. Running state does not prove full application or logging health.

Root disk use was **12%**. Available memory was **6.85 GiB**. 

The telemetry exporter reported a queue size of **602** at the latest snapshot. A nonzero queue can be transient; one sample does not prove a delivery fault. The watcher does not query New Relic for receipt. Export counters and a running collector are not end-to-end delivery proof.

Failed systemd units were reported **84 times across snapshots**. One persistent failure can appear repeatedly. These counts are not distinct outages and do not identify a security incident.

## Evidence gaps and next checks

- The runtime-sensor read reached its 1,000-row tail limit in 87 snapshots. Older events can fall outside the view.
- Some runtime-sensor rows could not be parsed or timed. Re-reading an old tail can count the same problem again.
- Collection warnings are present. Their exact labels and occurrence counts are in the technical evidence below.
- Confirm current ingress policy before describing this as a public attack campaign.
- Use the original private logs and New Relic traces to establish actor sequences, payloads, exact responses and any exploit outcome. This aggregate report cannot establish them.
- Check the latest observation time. The collector requires Mac power and connectivity; a stopped process can leave a running state.

## Recent observation timeline

Each row is one collection window. Rows are not linked attacker sessions. The table shows the latest 12 windows; totals above cover the full watch.

| Window end (EST / UTC) | Observed activity | Collection status |
| --- | --- | --- |
| Nov 24 04:14:18 EST / 09:14:18 UTC | 20 HTTP requests (0 public-source); 212 host-output denies; 0 container-egress denies; 0 metadata denies; 0 runtime events | 1 collection/health warnings |
| Nov 24 04:19:18 EST / 09:19:18 UTC | 20 HTTP requests (0 public-source); 193 host-output denies; 0 container-egress denies; 0 metadata denies; 0 runtime events | 1 collection/health warnings |
| Nov 24 04:24:19 EST / 09:24:19 UTC | 20 HTTP requests (0 public-source); 183 host-output denies; 0 container-egress denies; 0 metadata denies; 0 runtime events | 1 collection/health warnings |
| Nov 24 04:29:20 EST / 09:29:20 UTC | 20 HTTP requests (0 public-source); 181 host-output denies; 0 container-egress denies; 0 metadata denies; 0 runtime events | 1 collection/health warnings |
| Nov 24 04:34:21 EST / 09:34:21 UTC | 20 HTTP requests (0 public-source); 196 host-output denies; 0 container-egress denies; 0 metadata denies; 0 runtime events | 1 collection/health warnings |
| Nov 24 04:39:22 EST / 09:39:22 UTC | 20 HTTP requests (0 public-source); 183 host-output denies; 0 container-egress denies; 0 metadata denies; 0 runtime events | 1 collection/health warnings |
| Nov 24 04:44:22 EST / 09:44:22 UTC | 20 HTTP requests (0 public-source); 183 host-output denies; 0 container-egress denies; 0 metadata denies; 0 runtime events | 1 collection/health warnings |
| Nov 24 04:49:23 EST / 09:49:23 UTC | 21 HTTP requests (0 public-source); 194 host-output denies; 0 container-egress denies; 0 metadata denies; 0 runtime events | 1 collection/health warnings |
| Nov 24 04:54:24 EST / 09:54:24 UTC | 20 HTTP requests (0 public-source); 181 host-output denies; 0 container-egress denies; 0 metadata denies; 0 runtime events | 1 collection/health warnings |
| Nov 24 04:59:25 EST / 09:59:25 UTC | 20 HTTP requests (0 public-source); 187 host-output denies; 0 container-egress denies; 0 metadata denies; 0 runtime events | 1 collection/health warnings |
| Nov 24 05:04:26 EST / 10:04:26 UTC | 20 HTTP requests (0 public-source); 223 host-output denies; 0 container-egress denies; 0 metadata denies; 0 runtime events | 1 collection/health warnings |
| Nov 24 05:09:27 EST / 10:09:27 UTC | 20 HTTP requests (0 public-source); 181 host-output denies; 0 container-egress denies; 0 metadata denies; 0 runtime events | 1 collection/health warnings |

This debrief uses fixed narrative rules and numeric observations. It does not execute captured text, contact observed sources or change the VPS. Raw requests, response bodies, addresses, identities and captured instructions are excluded from the public report.

<details>
<summary>Technical evidence: exact counters, collection warnings and latest metrics</summary>

## Activity totals

Failed-service counts are sample occurrences. Falco parse errors can include repeated old records. These are not unique attacks.

- `failed_service_sample_occurrences`: 84
- `falco_time_unparsed`: 87
- `falco_unparsed`: 87
- `http_private_source`: 1745
- `http_status:200`: 1745
- `http_total`: 1745
- `kernel:METADATA-BLOCK-OUT:`: 1
- `kernel:OUTPUT-DROP:`: 16471
- `route:/v1/models`: 1745

## Collection warnings

Counts below are occurrences across samples.

- `falco_1000_row_tail_bound`: 87

## Latest health and telemetry snapshot

Counters below are cumulative source counters, not window totals. Component values of -1 mean unknown. A stale idle-source cursor alone does not prove failure.

| Metric | Value |
| --- | ---: |
| `MemAvailable_KiB` | 7.182916e+06 |
| `MemTotal_KiB` | 8.12576e+06 |
| `SwapFree_KiB` | 8.388604e+06 |
| `attackbox_component_observed{component="attackbox-bait"}` | 1 |
| `attackbox_component_observed{component="attackbox-egress-adapter.service"}` | 1 |
| `attackbox_component_observed{component="attackbox-falco-adapter.service"}` | 1 |
| `attackbox_component_observed{component="attackbox-hostcollector.service"}` | 1 |
| `attackbox_component_observed{component="attackbox-otel.service"}` | 1 |
| `attackbox_component_observed{component="attackbox-proxy"}` | 1 |
| `attackbox_component_observed{component="attackbox-shipper.service"}` | 1 |
| `attackbox_component_observed{component="attackbox.service"}` | 1 |
| `attackbox_component_observed{component="auditd.service"}` | 1 |
| `attackbox_component_observed{component="containerd.service"}` | 1 |
| `attackbox_component_observed{component="docker.service"}` | 1 |
| `attackbox_component_observed{component="falco-modern-bpf.service"}` | 1 |
| `attackbox_component_probe_failed{component="attackbox-bait"}` | 0 |
| `attackbox_component_probe_failed{component="attackbox-egress-adapter.service"}` | -1 |
| `attackbox_component_probe_failed{component="attackbox-falco-adapter.service"}` | -1 |
| `attackbox_component_probe_failed{component="attackbox-hostcollector.service"}` | 0 |
| `attackbox_component_probe_failed{component="attackbox-otel.service"}` | 0 |
| `attackbox_component_probe_failed{component="attackbox-proxy"}` | 0 |
| `attackbox_component_probe_failed{component="attackbox-shipper.service"}` | -1 |
| `attackbox_component_probe_failed{component="attackbox.service"}` | -1 |
| `attackbox_component_probe_failed{component="auditd.service"}` | -1 |
| `attackbox_component_probe_failed{component="containerd.service"}` | -1 |
| `attackbox_component_probe_failed{component="docker.service"}` | -1 |
| `attackbox_component_probe_failed{component="falco-modern-bpf.service"}` | -1 |
| `attackbox_component_ready{component="attackbox-bait"}` | 1 |
| `attackbox_component_ready{component="attackbox-egress-adapter.service"}` | -1 |
| `attackbox_component_ready{component="attackbox-falco-adapter.service"}` | -1 |
| `attackbox_component_ready{component="attackbox-hostcollector.service"}` | 1 |
| `attackbox_component_ready{component="attackbox-otel.service"}` | 1 |
| `attackbox_component_ready{component="attackbox-proxy"}` | 1 |
| `attackbox_component_ready{component="attackbox-shipper.service"}` | -1 |
| `attackbox_component_ready{component="attackbox.service"}` | -1 |
| `attackbox_component_ready{component="auditd.service"}` | -1 |
| `attackbox_component_ready{component="containerd.service"}` | -1 |
| `attackbox_component_ready{component="docker.service"}` | -1 |
| `attackbox_component_ready{component="falco-modern-bpf.service"}` | -1 |
| `attackbox_component_running{component="attackbox-bait"}` | 1 |
| `attackbox_component_running{component="attackbox-egress-adapter.service"}` | 1 |
| `attackbox_component_running{component="attackbox-falco-adapter.service"}` | 1 |
| `attackbox_component_running{component="attackbox-hostcollector.service"}` | 1 |
| `attackbox_component_running{component="attackbox-otel.service"}` | 1 |
| `attackbox_component_running{component="attackbox-proxy"}` | 1 |
| `attackbox_component_running{component="attackbox-shipper.service"}` | 1 |
| `attackbox_component_running{component="attackbox.service"}` | 1 |
| `attackbox_component_running{component="auditd.service"}` | 1 |
| `attackbox_component_running{component="containerd.service"}` | 1 |
| `attackbox_component_running{component="docker.service"}` | 1 |
| `attackbox_component_running{component="falco-modern-bpf.service"}` | 1 |
| `attackbox_container_health{component="attackbox-bait"}` | 1 |
| `attackbox_container_health{component="attackbox-proxy"}` | 1 |
| `attackbox_container_restarts{component="attackbox-bait"}` | 0 |
| `attackbox_container_restarts{component="attackbox-proxy"}` | 0 |
| `attackbox_container_runtime_approved{component="attackbox-bait"}` | 1 |
| `attackbox_container_runtime_approved{component="attackbox-proxy"}` | 1 |
| `attackbox_inventory_snapshot_age_seconds` | 6.718398276 |
| `attackbox_inventory_snapshot_valid` | 1 |
| `egress_cursor_age_seconds` | 1 |
| `falco_cursor_age_seconds` | 58445 |
| `falco_source_age_seconds` | 58445 |
| `load_1m` | 0.15 |
| `otelcol_exporter_queue_capacity` | 3.3554432e+07 |
| `otelcol_exporter_queue_size` | 602 |
| `otelcol_exporter_sent_spans` | 56584 |
| `otelcol_receiver_refused_spans` | 0 |
| `root_disk_used_percent` | 12 |
| `shipper_checkpoint_age_seconds` | 1 |

</details>
