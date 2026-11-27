# Daily findings — 2026-11-27 UTC

Window: 2026-11-27 00:00:00 to 2026-11-27 21:40:27 UTC (end exclusive).
Partial day. The next refresh replaces these totals.

[View in historical archive](https://silent.engineer/attack-box/findings/?day=2026-11-27) | [All findings](https://silent.engineer/attack-box/findings/)

## Public request capture

| Observation | Count |
|---|---:|
| Capture records | 3531 |
| Known operator or host | 117 |
| Local or unknown peer | 0 |
| Outside HTTP requests | 3414 |
| Distinct outside addresses | 559 |

## Outside request details

| Observation | Count |
|---|---:|
| Environment-file requests | 564 |
| Version-control probes | 111 |
| WordPress probes | 35 |
| AI discovery probes on unmatched routes | 153 |
| Model-list requests | 155 |
| Generation or chat requests | 118 |
| HTTP 2xx | 1059 |
| HTTP 4xx | 2310 |
| HTTP 5xx | 0 |
| Other HTTP status | 45 |

## Host security logs

| Observation | Count |
|---|---:|
| Retained Falco events | 146 |
| OUTPUT-DROP: | 1234 |
| CONTAINER-EGRESS-BLOCK: | 2724 |
| METADATA-BLOCK: | 0 |
| METADATA-BLOCK-OUT: | 56 |

Request categories select known routes and probes. They do not cover every request. HTTP status counts cover every outside request. Addresses are not people.

Host counts come from the retained Falco file and kernel journal. They are not linked to individual requests. Counts exclude undated Falco rows and connections that ended before HTTP. Retention and capture gaps can reduce totals. These logs do not establish exploit success.

<!-- end daily totals -->
