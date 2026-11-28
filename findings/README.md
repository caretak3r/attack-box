# Peer journeys

Daily folders contain traffic totals for all outside peers. These case reports follow one anonymized TCP peer at a time. Each has a chronological ledger, not just a summary of a day.

| Case | Listener and observation | Report |
|---|---|---|
| A · November 26–27, 2026 | Ollama, TCP 11434. Ten discovery requests, three generations, and 30 chat requests. | [43-request journey](2026-11-27/ollama-prompt-journey.md) · [cleared prompt text](2026-11-27/cleared-prompts.json) |
| B · November 28, 2026 | OpenAI-compatible chat, TCP 4000. Eight size rejections and four synthetic successes. | [12-request journey](2026-11-28/chat-body-limit.md) |

[Read the cases in the Findings archive](https://silent.engineer/attack-box/findings/).

## What a case report includes

Report the observed host form and listener, request times in UTC, methods, safe paths, query presence, and response statuses. List the safe header names and values that distinguish requests. For retained bodies, show declared and retained sizes, body fields, model, message counts, and cleared excerpts. Distinguish absent fields from unknown values and bodies the gateway never retained. Keep raw captures, source addresses, credential values, private hostnames, and unreviewed free text out of public findings. Client-supplied headers and history are not proof of identity or execution.
