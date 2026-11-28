# Twelve chat requests on one port: which ones got through?

On November 28, one TCP peer made 12 requests to `POST /v1/chat/completions` on port 4000. The first four received HTTP 413 (content too large). The fifth received HTTP 200. The peer kept sending requests for another 28 minutes, with both outcomes on the same route.

```mermaid
flowchart LR
  A[Four requests too large] --> B[First HTTP 200]
  B --> C[Three more HTTP 413s]
  C --> D[One HTTP 200 then one HTTP 413]
  D --> E[Last two requests both HTTP 200]
```

| UTC, November 28 | What the gateway recorded |
|---|---|
| 05:00:37–05:01:49 | Four requests, four size rejections. |
| 05:03:37 | First HTTP 200. The body was 64,757 bytes: just 779 bytes below the limit. |
| 05:03:52–05:10:23 | Three size rejections on the same port and route. |
| 05:14:13–05:16:19 | A 3,477-byte request received HTTP 200. The next request received HTTP 413. |
| 05:29:42–05:31:28 | The last two requests received HTTP 200. Their bodies were 14,585 and 2,744 bytes. |

**What explained the split?** The gateway's body limit was 65,536 bytes. All eight rejected requests had reported sizes above that limit: 65,633 to 121,353 bytes. The smallest rejection was only 97 bytes over. Every request carried a recognized credential source, so credential presence alone did not distinguish success from rejection. No credential value was needed for this analysis.

The four accepted requests all named `local-instruct-8b`. Their final user messages were distinct: 5, 923, 9,451 and 548 characters, respectively. These are message lengths, not whole-request sizes. Even the five-character final message arrived inside a 64,757-byte body. None matched the benign phrase catalog used for this review. Their wording is withheld. The host retained no request body for the eight size rejections.

## Host, target, and headers

All 12 requests used HTTP/1.1. The `Host` field named the decoy's IPv4 literal with port 4000. Each target was exactly `/v1/chat/completions`, with **no query string**. The same TCP peer sent all 12. A peer address cannot establish the identity of a person or machine behind it.

Every request advertised a Go HTTP client in `User-Agent` and sent `Content-Type: application/json`, `Content-Length`, `Accept-Encoding: gzip`, and `Authorization: Bearer [redacted]`. None sent `Cookie` or `X-API-Key`. The first header profile requested `Accept: text/event-stream` (SSE); the other requested `Accept: application/json` (JSON). The ledger identifies which appeared on each request. A header is not evidence about the format of a rejected body or the validity of a credential.

## Request ledger: all 12 requests

`Declared` is the request's `Content-Length`, in bytes. `Retained` counts body bytes in the host capture. A dash means the gateway rejected the request before capture; it does **not** mean the client sent an empty prompt. The final-user length counts characters, not bytes in the entire JSON request.

| UTC | Accept | Declared | Retained | HTTP | Body profile | Final user (characters) |
|---|---|---:|---:|---:|---|---:|
| 05:00:37.169 | SSE | 70,056 | — | 413 | not retained | — |
| 05:01:30.388 | SSE | 67,161 | — | 413 | not retained | — |
| 05:01:40.565 | SSE | 66,074 | — | 413 | not retained | — |
| 05:01:49.183 | SSE | 90,291 | — | 413 | not retained | — |
| 05:03:37.446 | SSE | 64,757 | 64,757 | 200 | streaming | 5 |
| 05:03:52.704 | SSE | 78,035 | — | 413 | not retained | — |
| 05:03:53.827 | SSE | 65,633 | — | 413 | not retained | — |
| 05:10:23.143 | SSE | 118,872 | — | 413 | not retained | — |
| 05:14:13.773 | JSON | 3,477 | 3,477 | 200 | non-streaming | 923 |
| 05:16:19.920 | SSE | 121,353 | — | 413 | not retained | — |
| 05:29:42.198 | JSON | 14,585 | 14,585 | 200 | non-streaming | 9,451 |
| 05:31:28.163 | JSON | 2,744 | 2,744 | 200 | non-streaming | 548 |

**What was inside the four retained bodies?** Each was a JSON object. All four had `model`, `messages`, `max_tokens`, and `stream`.

- **05:03:37:** `stream: true`, `max_tokens: 32768`, `stream_options`, and **31 tool definitions**. The message array contained one system message and three user messages; its final user text was only five characters. The 64,757 bytes describe the whole request, including definitions and earlier messages.
- **05:14:13, 05:29:42, and 05:31:28:** `stream: false`, `max_tokens: 1500`, and a `thinking` field. Each message array contained one system message and one user message. None supplied a `tools` field. The middle request had the longest final user message (9,451 characters), not the largest body.

No retained request included an assistant-role or tool-role message. The gateway did not execute these tools. No body fields, model name, or intent can be recovered for the eight rejected requests from the capture. Raw prompts, full user-agent strings, and the destination address are not published.

**Evidence and limits.** The host capture and 12 distinct New Relic request span IDs agree: eight HTTP 413s and four HTTP 200s. The review ends at 05:42:19 UTC. The size pattern explains what the gateway accepted. It does not establish deliberate limit testing, the peer's identity, or an exploit. HTTP 200 describes a synthetic service response, not model or tool execution. Exact response bodies were not recorded.
