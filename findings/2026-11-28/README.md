# Daily findings — 2026-11-28 UTC

Window: 2026-11-28 00:00:00 to 2026-11-28 05:43:38 UTC (end exclusive).
Partial day. The next refresh replaces these totals.

[View in historical archive](https://silent.engineer/attack-box/findings/?day=2026-11-28) | [All findings](https://silent.engineer/attack-box/findings/)

## Public request capture

| Observation | Count |
|---|---:|
| Capture records | 1934 |
| Known operator or host | 111 |
| Local or unknown peer | 0 |
| Outside HTTP requests | 1823 |
| Distinct outside addresses | 177 |

## Outside request details

| Observation | Count |
|---|---:|
| Environment-file requests | 851 |
| Version-control probes | 30 |
| WordPress probes | 27 |
| AI discovery probes on unmatched routes | 58 |
| Model-list requests | 49 |
| Generation or chat requests | 54 |
| HTTP 2xx | 973 |
| HTTP 4xx | 825 |
| HTTP 5xx | 0 |
| Other HTTP status | 25 |

## Host security logs

| Observation | Count |
|---|---:|
| Retained Falco events | 146 |
| OUTPUT-DROP: | 304 |
| CONTAINER-EGRESS-BLOCK: | 1237 |
| METADATA-BLOCK: | 0 |
| METADATA-BLOCK-OUT: | 0 |

Request categories select known routes and probes. They do not cover every request. HTTP status counts cover every outside request. Addresses are not people.

Host counts come from the retained Falco file and kernel journal. They are not linked to individual requests. Counts exclude undated Falco rows and connections that ended before HTTP. Retention and capture gaps can reduce totals. These logs do not establish exploit success.

<!-- end daily totals -->

## Case study

[Twelve chat requests on one port](chat-body-limit.md): eight exceeded the request-body limit; four received synthetic success responses.
