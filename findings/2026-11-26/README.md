# Daily findings — 2026-11-26 UTC

Window: 2026-11-26 00:00:00 to 2026-11-27 00:00:00 UTC (end exclusive).

[View in historical archive](https://silent.engineer/attack-box/findings/?day=2026-11-26) | [All findings](https://silent.engineer/attack-box/findings/)

## Public request capture

| Observation | Count |
|---|---:|
| Capture records | 1610 |
| Known operator or host | 184 |
| Local or unknown peer | 0 |
| Outside HTTP requests | 1426 |
| Distinct outside addresses | 466 |

## Outside request details

| Observation | Count |
|---|---:|
| Environment-file requests | 129 |
| Version-control probes | 30 |
| WordPress probes | 18 |
| AI discovery probes on unmatched routes | 40 |
| Model-list requests | 21 |
| Generation or chat requests | 36 |
| HTTP 2xx | 310 |
| HTTP 4xx | 1108 |
| HTTP 5xx | 0 |
| Other HTTP status | 8 |

## Host security logs

| Observation | Count |
|---|---:|
| Retained Falco events | 219 |
| OUTPUT-DROP: | 1296 |
| CONTAINER-EGRESS-BLOCK: | 1214 |
| METADATA-BLOCK: | 0 |
| METADATA-BLOCK-OUT: | 11 |

Request categories select known routes and probes. They do not cover every request. HTTP status counts cover every outside request. Addresses are not people.

Host counts come from the retained Falco file and kernel journal. They are not linked to individual requests. Counts exclude undated Falco rows and connections that ended before HTTP. Retention and capture gaps can reduce totals. These logs do not establish exploit success.

<!-- end daily totals -->
