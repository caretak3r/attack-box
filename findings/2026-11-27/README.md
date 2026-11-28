# Daily findings — 2026-11-27 UTC

Window: 2026-11-27 00:00:00 to 2026-11-28 00:00:00 UTC (end exclusive).

[View in historical archive](https://silent.engineer/attack-box/findings/?day=2026-11-27) | [All findings](https://silent.engineer/attack-box/findings/)

## Public request capture

| Observation | Count |
|---|---:|
| Capture records | 4476 |
| Known operator or host | 159 |
| Local or unknown peer | 0 |
| Outside HTTP requests | 4317 |
| Distinct outside addresses | 606 |

## Outside request details

| Observation | Count |
|---|---:|
| Environment-file requests | 905 |
| Version-control probes | 124 |
| WordPress probes | 51 |
| AI discovery probes on unmatched routes | 161 |
| Model-list requests | 182 |
| Generation or chat requests | 172 |
| HTTP 2xx | 1462 |
| HTTP 4xx | 2800 |
| HTTP 5xx | 0 |
| Other HTTP status | 55 |

## Host security logs

| Observation | Count |
|---|---:|
| Retained Falco events | 1232 |
| OUTPUT-DROP: | 2084 |
| CONTAINER-EGRESS-BLOCK: | 3238 |
| METADATA-BLOCK: | 0 |
| METADATA-BLOCK-OUT: | 188 |

Request categories select known routes and probes. They do not cover every request. HTTP status counts cover every outside request. Addresses are not people.

Host counts come from the retained Falco file and kernel journal. They are not linked to individual requests. Counts exclude undated Falco rows and connections that ended before HTTP. Retention and capture gaps can reduce totals. These logs do not establish exploit success.

<!-- end daily totals -->

## Case study

[One Ollama client’s prompt journey](ollama-prompt-journey.md): a cross-model generation check followed by repeated chat turns.
