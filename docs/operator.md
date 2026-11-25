# Inspect public HTTPS traffic

For a release with structured request spans, open **Query your data** in New Relic. Select the ingest account. Run this NRQL query:

```sql
FROM Span SELECT timestamp, `client.address` AS 'client_ip',
  `http.request.method`, `http.route`, `http.response.status_code`,
  `attackbox.probe.class`, `attackbox.request.query_params`,
  `attackbox.request.content_type`, `http.request.body.size`,
  `gen_ai.request.model`, `attackbox.request.stream`, `trace.id`
WHERE `service.name` = 'attackbox-public-443' AND name = 'public.request'
  AND `attackbox.request.content_type` IS NOT NULL
SINCE 1 hour ago LIMIT 100
```

`client_ip` is the IPv4 peer of the TCP connection, not an identity from an HTTP header. The listener ignores `Forwarded` and `X-Forwarded-For`. A VPN or NAT exposes its exit IP. A public proxy exposes its own IP. A local or private peer leaves the field empty. Older releases did not export this field. They cannot supply past addresses.

`http.route` is a route label, not a raw URL. The content type is a fixed category without parameters. For a known length, the size is the declared body length in bytes. For an unknown length, the size is available only if the handler reads the body to its end. On a validated request, the span can include the recognized model and an explicit Boolean streaming flag. `attackbox.request.query_params` is the number of query pairs, up to 64. The span does not contain their names or values.

The container healthcheck connects from loopback. The service does not trace it and does not count it. Releases before `public.connection` spans exported four healthcheck requests each minute without `client_ip`. To exclude them from older data, add ``AND `client.address` IS NOT NULL``.

## Route families

The gateway answers a request by the end of its path. It does not learn routes from traffic. The first request to a supported variant gets a synthetic answer.

|Path ends with|Method|Answer format|
|---|---|---|
|`/models`|GET|OpenAI model list|
|`/chat/completions`, `/completions`|POST|OpenAI completion, with SSE when `stream` is true|
|`/embeddings`|POST|OpenAI embedding list|
|`/messages`|POST|Anthropic message, with SSE when `stream` is true|
|`/api/tags`|GET|Ollama model list|
|`/api/chat`, `/api/generate`|POST|Ollama answer, NDJSON unless `stream` is false|

Before the ending, the path can contain up to four tokens from this list: `v1`, `v2`, `v3`, `api`, `openai`, `azure`, `llm`, `ai`, `proxy`, `gateway`, `inference`, `litellm`, `ollama`, `anthropic`, `deployments/{deployment}`, and `engines/{model}`. For example, `/v1/api/completions` and `/litellm/anthropic/v1/messages` match, and `http.route` contains that path. A deployment or engine name replaces its token with `{deployment}` or `{model}`. Other paths return 404 with `http.route` set to `/unmatched`. A wrong method on a matched path returns 405.

## Unmatched requests

A request with `http.route` set to `/unmatched` also has `attackbox.probe.class`. The class comes from a fixed list: `proxy`, `root`, `env_file`, `vcs`, `wordpress`, `actuator`, `cgi`, `admin`, `php`, `discovery`, `config_file`, `llm_api`, and `other`. Run this query to see what scanners look for:

```sql
FROM Span SELECT count(*)
WHERE `service.name` = 'attackbox-public-443' AND name = 'public.request' AND `http.route` = '/unmatched'
FACET `attackbox.probe.class` SINCE 1 day ago
```

## Local request capture

The service writes each request line that reaches the gateway to `/var/lib/attackbox-public-capture/requests/capture-YYYYMMDD.jsonl` on the host. Each JSON line contains the time, peer IP, method, raw request target with its query string, `Host`, `User-Agent`, route label, status, probe class, listener port (443), protocol version, bounded request headers, and bounded request body. The service clips the target at 2048 bytes, text header fields at 256 bytes, header names at 64 bytes, and header values at 512 bytes. It stores at most 48 header pairs sorted by canonical name and value order. It records the first 16 KiB of the request body, counts the total bytes read (capped at 64 KiB), and hashes all bytes read with SHA-256. JSON encoding escapes control characters and invalid UTF-8.

The service keeps 7 UTC days and writes at most 256 MiB each day. `public.health` counts written lines in `attackbox.captured_requests` and lost lines in `attackbox.capture_dropped`. The parent directory is root-only. A stage creates the directory once. A rollback keeps it. The capture stays on the host and is never sent to New Relic.

The service scrubs credentials from headers and bodies before writing them. Header scrubbing replaces the value of `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, and any header whose lowercase name contains `key`, `token`, `secret`, `auth`, `password`, `session`, or `cookie` with `[redacted len=N sha256=XXXXXXXXXXXX]`. When the value starts with `Bearer `, `Basic `, `Token `, or `Digest `, the prefix stays and the rest is scrubbed. `User-Agent` and `Host` stay unmodified. Body scrubbing replaces `sk-`/`sk_` style keys of 16+ characters, AWS access key IDs (`AKIA` + 16 uppercase alphanumerics), GitHub tokens (`gh[pousr]_` + 20+ chars), JWTs, and the string value of JSON members or form/query pairs whose key contains `password`, `passwd`, `secret`, `token`, `api_key`, `apikey`, or `authorization` (case-insensitive).

Treat the capture as hostile data. Read it as root with a tool that prints text, such as `jq -r '.target'`. Do not open its URLs or run its contents.

## Connections without a request

A connection that closes before a request reaches the gateway produces a `public.connection` span. Port scans, TLS failures, and plain HTTP on port 443 are examples. Run this query:

```sql
FROM Span SELECT count(*)
WHERE `service.name` = 'attackbox-public-443' AND name = 'public.connection'
FACET `client.address`, `attackbox.connection.outcome`, `attackbox.tls.sni`
SINCE 1 day ago LIMIT 100
```

|`attackbox.connection.outcome`|Meaning|
|---|---|
|`no_data`|The client closed the connection before it sent a byte.|
|`not_tls`|The first byte was not a TLS handshake record. Plain HTTP is an example.|
|`tls_failed`|The TLS handshake started but did not complete.|
|`no_request`|The TLS handshake completed, but no valid request reached the gateway.|

`attackbox.tls.sni` is `none` if the ClientHello has no server name, `match` if the name matches the certificate, and `other` for a different name. The field is empty if no ClientHello arrived. The span starts when the service accepts the connection and ends when the connection closes.

The service sends at most one connection span each second, with a burst of 16. The `public.health` span counts all such connections in `attackbox.pre_http_connections`. It counts connections that the listener rejects at its 128-connection limit in `attackbox.rejected_connections`. Both counters start at zero when the service starts.

The service does not export prompts, bodies, credentials, query names or values, raw paths, arbitrary headers, or received bytes. HTTP parser failures after a TLS handshake produce a `no_request` connection span, not a request span. The rate limiter counts requests it rejects before the gateway. Those requests are not captured. Bounded queues can lose spans.

Before live export, confirm who can query spans and how long the account retains exact IP addresses. Use a client with a known egress IP to check the public path after an approved deployment. Do not use a forwarded header as proof.
