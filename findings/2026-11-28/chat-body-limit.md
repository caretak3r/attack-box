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

**Evidence and limits.** The host capture and 12 distinct New Relic request span IDs agree: eight HTTP 413s and four HTTP 200s. The review ends at 05:42:19 UTC. The size pattern explains what the gateway accepted. It does not establish deliberate limit testing, the peer's identity, or an exploit. HTTP 200 describes a synthetic service response, not model or tool execution. Exact response bodies were not recorded.
