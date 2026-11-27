# Daily findings — 2026-11-27 UTC

Window: 2026-11-27 00:00:00 to 2026-11-27 20:40:44 UTC (end exclusive).
Partial day. The next refresh replaces these totals.

## Public request capture

| Observation | Count |
|---|---:|
| Capture records | 3235 |
| Known operator or host | 100 |
| Local or unknown peer | 0 |
| Outside HTTP requests | 3135 |
| Distinct outside addresses | 545 |

## Outside request details

| Observation | Count |
|---|---:|
| Environment-file requests | 356 |
| Version-control probes | 108 |
| WordPress probes | 32 |
| AI discovery probes on unmatched routes | 153 |
| Model-list requests | 149 |
| Generation or chat requests | 118 |
| HTTP 2xx | 867 |
| HTTP 4xx | 2229 |
| HTTP 5xx | 0 |
| Other HTTP status | 39 |

## Host security logs

| Observation | Count |
|---|---:|
| Retained Falco events | 146 |
| OUTPUT-DROP: | 1195 |
| CONTAINER-EGRESS-BLOCK: | 2472 |
| METADATA-BLOCK: | 0 |
| METADATA-BLOCK-OUT: | 56 |

Request categories select known routes and probes. They do not cover every request. HTTP status counts cover every outside request. Addresses are not people.

Host counts come from the retained Falco file and kernel journal. They are not linked to individual requests. Counts exclude undated Falco rows and connections that ended before HTTP. Retention and capture gaps can reduce totals. These logs do not establish exploit success.

<!-- end daily totals -->
