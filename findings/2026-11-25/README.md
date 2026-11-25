# Security debrief — 25 November 2026

Updated from New Relic at Nov 25 17:18:29 EST / 22:18:29 UTC. HTTP and connection totals cover the Eastern calendar day through Nov 25 17:17:28 EST / 22:17:28 UTC. The end time trails the query by one minute. Later runs re-query the full day to include delayed arrivals.

## What we observed

The HTTPS decoy on port 443 recorded **187 request span records with a recorded transport peer**, representing **187 distinct span IDs**. Distinct counts can be estimates above 50,000 IDs. These are telemetry observations, not confirmed attackers or exploits. Operator probes can be present. The captured metadata cannot identify the purpose of a caller.

**1976 additional request spans without a recorded peer are excluded from the visitor table.** Older versions exported loopback health checks as request spans and older releases did not record transport peers. Do not classify all of these records as visitors or discard them all as health checks. Current loopback health checks are excluded by the service.

| Method | Route category | HTTP status | Span records |
| --- | --- | ---: | ---: |
| `GET` | `/unmatched` | 400 | 8 |
| `GET` | `/unmatched` | 404 | 84 |
| `GET` | `/v1/models` | 200 | 57 |
| `GET` | `other` | 200 | 7 |
| `POST` | `/unmatched` | 404 | 4 |
| `POST` | `/v1/completions` | 200 | 9 |
| `POST` | `/v1/completions` | 404 | 9 |
| `POST` | `other` | 200 | 7 |
| `_OTHER` | `/unmatched` | 400 | 1 |
| `_OTHER` | `/unmatched` | 404 | 1 |

## Connection activity and service response

A request to `/unmatched` reached an unrecognized route. A 404 response shows that the route was not served; the route category does not preserve the attempted path or prove an exploit attempt. A 2xx response shows HTTP success, not successful execution of an attack.

- `tls_failed`: 40 connection span records.
- `no_data`: 35 connection span records.
- `no_request`: 47 connection span records.
- `not_tls`: 13 connection span records.

TLS failures, empty connections and plaintext on a TLS port are consistent with scanning, client errors or operator tests. They do not identify a tool, actor or exploit. Connections that end before HTTP do not have an HTTP response to inspect.

## Telemetry receipt and limits

Latest public-service heartbeat received in New Relic: **Nov 25 17:16:34 EST / 22:16:34 UTC**.

- `attackbox.otel_dropped_spans_total`: 0 in the latest received heartbeat.
- `attackbox.otel_export_failed_spans_total`: 0 in the latest received heartbeat.
- `attackbox.rate_limited_requests`: 0 in the latest received heartbeat.

The public profile records request metadata and response status. It does not retain request or response bodies. This evidence cannot reconstruct prompts, exact replies, tool instructions, attacker sessions or exploit success. The private proxy has a separate capture path; its counts below do not measure public HTTPS traffic.

Public-service and host health use separate collection paths. This report does not verify the provider firewall, complete packet capture or all New Relic pipelines. Raw addresses, identities, credentials, payloads and captured instructions are excluded. No captured command is executed and no observed destination is contacted.

The local publisher checks every five minutes. It commits only this daily report, with ordinary hooks and signing. Read the update and observation times: Mac sleep, power loss or network loss stops publication.

---

<details>
<summary>Host and private-proxy evidence</summary>

# Host and private-proxy watch

**Watch: running · 125 snapshots · last observation Nov 25 17:15:19 EST / 22:15:19 UTC**

Coverage: Nov 25 06:48:39 EST / 11:48:39 UTC to Nov 25 17:15:19 EST / 22:15:19 UTC. Planned final collection: Nov 25 18:53:39 EST / 23:53:39 UTC. The first snapshot includes a five-minute baseline.

## Assessment

**No public-source requests were recorded in the collected HTTP evidence.** The proxy recorded 2514 requests, including 2514 from private, loopback or link-local addresses. These observations do not establish an attack or compromise.

These HTTP counts cover the private proxy, not the separate public decoy. The watcher does not re-check the provider firewall. Private-proxy silence does not measure public traffic.

## What took place

The proxy recorded **2514 HTTP requests**: 0 with public-source addresses, 2514 with private/local addresses and 0 with unparseable source addresses.

The model-list endpoint received **2506 requests**. This endpoint lists the models that the simulated AI service advertises. Requests here can be inventory checks or reconnaissance; the route alone does not show the caller's purpose.

Other requested surfaces:

- `other`: 8 requests.

These route categories do not reveal payloads, exploit techniques or a sequence of actions by one caller.

## Service response and containment

Recorded HTTP outcomes: **2514 successful responses (2xx)**, 0 redirects (3xx), 0 client-error responses (4xx), and 0 server-error responses (5xx). A 2xx status does not prove an exploit worked. This summary does not inspect response bodies or link status totals to individual routes.

Firewall logs contained **567 host-output deny records**, **96 container-egress deny records**, and **7 metadata-access deny records**. These are logged packet denials, not unique sessions or attackers. They can include routine blocked traffic. The aggregates do not link a deny record to an HTTP request or prove that all unwanted traffic was blocked.

The runtime sensor recorded **584 timestamped Falco events** inside the collection windows. Review the original rule and process context before treating these as execution, persistence or compromise.

## Host and logging health

At the latest snapshot, **13 of 13 expected components reported running**; running-state values were available for 13. Running state does not prove full application or logging health.

Root disk use was **16%**.

Available memory was **6.75 GiB**.

The telemetry exporter reported a queue size of **0** at the latest snapshot. A nonzero queue can be transient; one sample does not prove a delivery fault. The watcher does not query New Relic for receipt. Export counters and a running collector are not end-to-end delivery proof.

Failed systemd units were reported **246 times across snapshots**. One persistent failure can appear repeatedly. These counts are not distinct outages and do not identify a security incident.

## Evidence gaps and next checks

- The runtime-sensor read reached its 1,000-row tail limit in 125 snapshots. Older events can fall outside the view.
- Some runtime-sensor rows could not be parsed or timed. Re-reading an old tail can count the same problem again.
- Collection warnings are present. Their exact labels and occurrence counts are in the technical evidence below.
- The legacy watcher expects twelve components. The audit filter adds a thirteenth. This count warning alone is not an outage; check individual running-state values.
- Confirm current ingress policy before describing this as a public attack campaign.
- Use the original private logs and New Relic traces to establish actor sequences, payloads, exact responses and any exploit outcome. This aggregate report cannot establish them.
- Check the latest observation time. The collector requires Mac power and connectivity; a stopped process can leave a running state.

## Recent observation timeline

Each row is one collection window. Rows are not linked attacker sessions. The table shows the latest 12 windows; totals above cover the full watch.

| Window end (EST / UTC) | Observed activity | Collection status |
| --- | --- | --- |
| Nov 25 16:20:10 EST / 21:20:10 UTC | 21 HTTP requests (0 public-source); 17 host-output denies; 0 container-egress denies; 0 metadata denies; 73 runtime events | 2 collection/health warnings |
| Nov 25 16:25:11 EST / 21:25:11 UTC | 20 HTTP requests (0 public-source); 1 host-output denies; 4 container-egress denies; 0 metadata denies; 0 runtime events | 2 collection/health warnings |
| Nov 25 16:30:12 EST / 21:30:12 UTC | 20 HTTP requests (0 public-source); 1 host-output denies; 3 container-egress denies; 0 metadata denies; 0 runtime events | 2 collection/health warnings |
| Nov 25 16:35:12 EST / 21:35:12 UTC | 20 HTTP requests (0 public-source); 1 host-output denies; 0 container-egress denies; 0 metadata denies; 0 runtime events | 2 collection/health warnings |
| Nov 25 16:40:13 EST / 21:40:13 UTC | 20 HTTP requests (0 public-source); 0 host-output denies; 1 container-egress denies; 0 metadata denies; 0 runtime events | 2 collection/health warnings |
| Nov 25 16:45:14 EST / 21:45:14 UTC | 20 HTTP requests (0 public-source); 0 host-output denies; 0 container-egress denies; 0 metadata denies; 0 runtime events | 2 collection/health warnings |
| Nov 25 16:50:15 EST / 21:50:15 UTC | 20 HTTP requests (0 public-source); 1 host-output denies; 0 container-egress denies; 0 metadata denies; 0 runtime events | 2 collection/health warnings |
| Nov 25 16:55:16 EST / 21:55:16 UTC | 20 HTTP requests (0 public-source); 2 host-output denies; 0 container-egress denies; 0 metadata denies; 0 runtime events | 2 collection/health warnings |
| Nov 25 17:00:16 EST / 22:00:16 UTC | 20 HTTP requests (0 public-source); 0 host-output denies; 0 container-egress denies; 0 metadata denies; 0 runtime events | 2 collection/health warnings |
| Nov 25 17:05:17 EST / 22:05:17 UTC | 20 HTTP requests (0 public-source); 0 host-output denies; 1 container-egress denies; 0 metadata denies; 0 runtime events | 2 collection/health warnings |
| Nov 25 17:10:18 EST / 22:10:18 UTC | 20 HTTP requests (0 public-source); 0 host-output denies; 1 container-egress denies; 0 metadata denies; 0 runtime events | 2 collection/health warnings |
| Nov 25 17:15:19 EST / 22:15:19 UTC | 20 HTTP requests (0 public-source); 1 host-output denies; 0 container-egress denies; 0 metadata denies; 0 runtime events | 2 collection/health warnings |

This debrief uses fixed narrative rules and numeric observations. It does not execute captured text, contact observed sources or change the VPS. Raw requests, response bodies, addresses, identities and captured instructions are excluded from the public report.

<details>
<summary>Technical evidence: exact counters, collection warnings and latest metrics</summary>

## Activity totals

Failed-service counts are sample occurrences. Falco parse errors can include repeated old records. These are not unique attacks.

- `docker_non_proxy_rows`: 42
- `failed_service_sample_occurrences`: 246
- `falco_events`: 584
- `falco_time_unparsed`: 80
- `falco_unparsed`: 125
- `http_private_source`: 2514
- `http_status:200`: 2514
- `http_total`: 2514
- `kernel:CONTAINER-EGRESS-BLOCK:`: 96
- `kernel:METADATA-BLOCK-OUT:`: 7
- `kernel:OUTPUT-DROP:`: 567
- `proxy_non_access_rows`: 9
- `route:/v1/models`: 2506
- `route:other`: 8

## Collection warnings

Counts below are occurrences across samples.

- `component_count_not_12`: 125
- `falco_1000_row_tail_bound`: 125

## Latest health and telemetry snapshot

Counters below are cumulative source counters, not window totals. Component values of -1 mean unknown. A stale idle-source cursor alone does not prove failure.

| Metric | Value |
| --- | ---: |
| `MemAvailable_KiB` | 7.079652e+06 |
| `MemTotal_KiB` | 8.12576e+06 |
| `SwapFree_KiB` | 8.38808e+06 |
| `attackbox_component_observed{component="attackbox-auditfilter.service"}` | 1 |
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
| `attackbox_component_probe_failed{component="attackbox-auditfilter.service"}` | -1 |
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
| `attackbox_component_ready{component="attackbox-auditfilter.service"}` | -1 |
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
| `attackbox_component_running{component="attackbox-auditfilter.service"}` | 1 |
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
| `attackbox_inventory_snapshot_age_seconds` | 34.196281727 |
| `attackbox_inventory_snapshot_valid` | 1 |
| `egress_cursor_age_seconds` | 172 |
| `falco_cursor_age_seconds` | 3490 |
| `falco_source_age_seconds` | 3490 |
| `load_1m` | 0.03 |
| `otelcol_exporter_queue_capacity` | 3.3554432e+07 |
| `otelcol_exporter_queue_size` | 0 |
| `otelcol_exporter_sent_spans` | 143143 |
| `otelcol_receiver_refused_spans` | 0 |
| `root_disk_used_percent` | 16 |
| `shipper_checkpoint_age_seconds` | 10 |

</details>

</details>
