# Analyst assessment — 25 November 2026

Review time: 09:45 Eastern / 14:45 UTC. This is a point-in-time review. The adjacent daily debrief updates automatically.

## Situation

The public decoy is listening on HTTPS port 443. A read-only check of the attached provider firewall found public IPv4 access to TCP 443 and restricted administrator access to TCP 22. The other host listeners inspected were on loopback. This check confirms the policy and listener configuration at review time; the watcher does not continuously verify the provider policy.

The public container and its telemetry collector were active. The private proxy, bait, shipper, audit filter and host collector were also active. The latest host snapshot showed all thirteen expected private-stack and host components running, with root disk use at 14%. These checks do not prove that every pipeline is complete.

## What the traffic shows

The first published daily query returned 1,996 public-service request span records, with 1,996 distinct span IDs. Most did not contain a recorded transport peer. These totals span the Eastern calendar day and include multiple process lifetimes. They must not be described as 1,996 attackers or malicious requests.

Review of the recorded deployment fixes confirmed that older public versions exported four loopback health checks each minute as request spans. The current release excludes those requests. The daily debrief now separates records with a transport peer from unaddressed records. Older releases also lacked peer capture for external requests, so an absent peer does not prove a health check. Operator probes remain possible in the peer-attributed group.

The service returned synthetic success responses from model-list and completion routes. It also returned 400 or 404 responses on unrecognized route categories. The observed connection outcomes included TLS failures, connections with no data, connections with no HTTP request, and plaintext on the TLS port.

This pattern is consistent with a mixture of API checks, route discovery, general scanning and incompatible clients. The available aggregates do not establish which explanation applies to a given caller. They do not identify an exploit, an attacker tool, successful code execution or compromise.

## What the service did

The decoy returned synthetic responses or HTTP errors. No real model or tool execution is part of this service. At the first publication, the latest public heartbeat received in New Relic reported zero dropped spans, zero export-failed spans and zero rate-limited requests for that process lifetime. These counters reset on restart and do not prove complete capture for the full day.

The host watcher also counted firewall packet denials and timestamped Falco events. Those counts are not linked to public HTTP requests. They can include operator work and routine blocked activity. No attack chain can be inferred from their proximity in time.

## Evidence limits that matter

- **Public bodies are absent.** The public profile retains request metadata and response status. It cannot show the submitted prompt, exact synthetic reply, payload or follow-up instruction. The private proxy uses a separate capture path.
- **Host reads are bounded.** Falco reads reached their 1,000-row tail limit. Old malformed rows can be counted again. Counts can omit events during bursts or rotation.
- **A legacy warning is stale.** The host watcher expects twelve components. The audit filter is the thirteenth. Its component-count warning alone is not an outage.
- **Failed-unit counts repeat.** A persistent failed unit appears in each snapshot. The inspected failed-unit names included the masked artifact updater and a firmware refresh job. These are not repeated attacks. The Falco engine remained active.
- **Receipt checks are specific.** Public spans and a recent public heartbeat were present in New Relic. This does not verify every log partition, audit event or private trace.

The next useful evidence is a reviewed sequence of public requests and connection outcomes, with operator activity accounted for. The current public metadata can support a timeline of routes and status codes. Payload-level attack analysis requires a separately approved public capture change.

No captured command was executed. No observed destination was contacted. No ingress rule or VPS deployment was changed during this review.
