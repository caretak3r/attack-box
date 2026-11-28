# One Ollama client: from a poem prompt to repeated chat turns

One TCP peer sent 43 requests to the simulated Ollama listener on port 11434 on November 26–27, 2026. Ten requests checked the model list or version. The other 33 carried prompts. Every request received HTTP 200. The public gateway did not run a model or execute a command.

## What the client sent

Each `P` number identifies one distinct prompt text, in order of first appearance. For generation, it represents the `prompt` field. For chat, it represents the **last user message**, not the system message or the entire conversation. Reusing an ID means the decoded text was identical, including case and whitespace. All 33 bodies parsed as JSON; none had the capture truncation flag. Times below are UTC and come from the host capture.

```mermaid
flowchart TD
  A[Nov 26: list models and check version] --> B[Same poem-related prompt on three models]
  B --> C[Nearly 16 hours without a recorded request]
  C --> D[Nov 27: one coding-language prompt on Llama]
  D --> E[DeepSeek: greeting, then the same follow-up six times]
  E --> F["Switch between Llama and DeepSeek; reuse a short command-related prompt"]
  F --> G[Send longer chat contexts and fenced-text follow-ups]
```

| Capture time | Model | Last user prompt in request order | Evidence |
|---|---|---|---|
| Nov 26 23:46:32–34 | Llama, DeepSeek, Qwen | P1 → P1 → P1 | The same 47-character prompt contained the word for a poem. Only the model changed among the three model selections. |
| Nov 27 15:40:08 | Llama | P2 | One 100-character message mentioned a programming language. No system message accompanied it. |
| 15:54:13–25 | DeepSeek | P3 → P4 × 6 | P3 was exactly `hi` (lowercase, no punctuation). P4 was the same 153-character command-related text each time. The supplied history grew from 4 to 14 messages across the six repeats. |
| 16:11:33–16:13:24 | Llama, then DeepSeek | P5 → P3 → P5 → P3 → P5 → P3 → P5 → P6 → P7 → P7 | P5 was a 27-character command-related message. P6 was five characters. P7 mentioned a task and a command and contained a code fence. |
| 16:17:13–16:17:36 | Llama | P5 → P3 → P8 → P9 | P8 was three characters. P9 was 222 characters and mentioned a command. Its request contained two consecutive user messages after a system message. |
| 16:22:59–16:24:08 | Llama | P5 → P9 → P10 → P11 → P12 | P11 was the longest final user message: 4,139 characters. P10 and P12 contained code fences and mentioned a command. |
| 16:24:29–37 | DeepSeek | P5 → P13 → P14 | P13 was 331 characters and mentioned a command. The 84-character P14 also contained a code fence. |

Model names in the capture: `llama3.3:70b`, `deepseek-r1:70b`, and `qwen2.5-coder:32b`. Qwen appeared only in the generation burst. The table omits the ten requests without prompts.

**Quoted wording:** Five requests had the exact final user message `hi` (P3). Wording is withheld for the other 13 distinct prompts across 28 requests. The descriptions in the table are not quotations.
The [publication-ready prompt file](cleared-prompts.json) lists the cleared wording and the five UTC timestamps.

## Interpretation and limits

The first burst is consistent with comparing models on the same input. The later chat requests show repeated prompts and client-supplied history, not 30 unrelated questions. Neither a command reference nor a code fence proves that the client requested execution. An assistant-role message in a later request is text the client supplied, not independent evidence of what the gateway previously returned.

The host capture and 43 distinct New Relic request spans agree on the route totals and response statuses. Only the host capture supplies the request bodies. The capture does not contain response bodies. A shared TCP peer does not identify a person or establish a single continuous session.

## Private transcript

In the operator's loopback dashboard, filter by the source address and port 11434. Select a request time to open its body. For chat, inspect the full `messages` array to distinguish the current user text from prior turns and system instructions. This public report omits the source address and unreviewed prompt text. The original evidence is subject to the host's seven-day retention.
