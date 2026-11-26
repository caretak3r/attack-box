# Inspect public HTTPS traffic

The isolated public gateway publishes six TCP ports on the public IPv4 address. Port 443 uses TLS and maps to container port 8443. Ports 80, 1234, 8000, 8080, and 11434 use plain HTTP. Each plain port maps to container port 20000 plus the public port. All ports give the same synthetic responses, and each record keeps the port that the request used.

For a release with structured request spans, open **Query your data** in New Relic. Select the ingest account. Run this NRQL query:

```sql
FROM Span SELECT timestamp, `client.address` AS 'client_ip',
  `http.request.method`, `http.route`, `http.response.status_code`,
  `attackbox.probe.class`, `attackbox.request.query_params`,
  `attackbox.request.content_type`, `http.request.body.size`,
  `gen_ai.request.model`, `attackbox.request.stream`,
  `attackbox.credential.source`, `attackbox.credential.type`, `attackbox.credential.value`, `trace.id`
WHERE `service.name` = 'attackbox-public-443' AND name = 'public.request'
  AND `attackbox.request.content_type` IS NOT NULL
SINCE 1 hour ago LIMIT 100
```

`client_ip` is the IPv4 peer of the TCP connection, not an identity from an HTTP header. The listener ignores `Forwarded` and `X-Forwarded-For`. A VPN or NAT exposes its exit IP. A public proxy exposes its own IP. A local or private peer leaves the field empty. Older releases did not export this field. They cannot supply past addresses.

`http.route` is a route label, not a raw URL. The content type is a fixed category without parameters. For a known length, the size is the declared body length in bytes. For an unknown length, the size is available only if the handler reads the body to its end. On a validated request that names a model, the span contains that model from the fixed list below and an explicit Boolean streaming flag. `attackbox.request.query_params` is the number of query pairs, up to 64. The span does not contain query names or values, except a credential value.

## Models

The gateway serves these model names: `local-instruct-8b`, `gpt-4o`, `gpt-4o-mini`, `gpt-4.1`, `gpt-4.1-mini`, `o3-mini`, `gpt-3.5-turbo`, `claude-3-5-sonnet-20241022`, `claude-3-7-sonnet-20250219`, `claude-sonnet-4-20250514`, `claude-3-5-haiku-20241022`, `llama3.1:8b`, `qwen2.5:7b`, `deepseek-r1:8b`, `mistral:7b`, `llama3.3:70b`, `deepseek-r1:70b`, `qwen2.5-coder:32b`, `text-embedding-3-small`, `text-embedding-3-large`, and `nomic-embed-text`. `/models` lists all of them. `/api/tags` lists the local names with an Ollama tag. A client can add `:latest` to a name. A request without a model uses `local-instruct-8b`. Other names return 404. The answer names the requested model.

## Credentials

The operator decided to export credentials as the client sends them. The request span contains the first credential found, in this order: the `Authorization`, `Proxy-Authorization`, `X-Api-Key`, `Api-Key`, and `X-Goog-Api-Key` headers, then the query parameters `key`, `api_key`, `apikey`, `api-key`, `access_token`, and `token`. `attackbox.credential.source` is the lowercase header name or `query`. `attackbox.credential.value` is the value without its `Authorization` or `Proxy-Authorization` scheme word. A Basic value stays base64. A value that is not 1 to 512 printable ASCII bytes is not exported, but its source and type are. `attackbox.credential.type` comes from the value prefix:

|Type|Prefix|
|---|---|
|`anthropic`|`sk-ant-`|
|`openai`|`sk-`|
|`google`|`AIza`|
|`aws`|`AKIA`, `ASIA`|
|`huggingface`, `groq`, `xai`, `replicate`|`hf_`, `gsk_`, `xai-`, `r8_`|
|`jwt`|`eyJ`|
|`github`|`github_pat_`, `ghp_`, `gho_`, `ghu_`, `ghs_`|
|`basic`|`Authorization: Basic`|
|`token`|any other value|

```sql
FROM Span SELECT count(*), latest(`client.address`)
WHERE `service.name` = 'attackbox-public-443' AND `attackbox.credential.type` IS NOT NULL
FACET `attackbox.credential.type`, `attackbox.credential.value` SINCE 7 days ago LIMIT 100
```

Anyone who can query the account can read these values. They are probably stolen from other people. Do not use them.

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
|`/api/show`|POST|Ollama model details|
|`/api/pull`|POST|Ollama progress lines, NDJSON unless `stream` is false|
|`/api/create`|POST|Ollama `success` status|
|`/api/delete`|DELETE|Empty 200|
|`/api/embed`, `/api/embeddings`|POST|Ollama embedding|

Before the ending, the path can contain up to four tokens from this list: `v1`, `v2`, `v3`, `api`, `openai`, `azure`, `llm`, `ai`, `proxy`, `gateway`, `inference`, `litellm`, `ollama`, `anthropic`, `deployments/{deployment}`, and `engines/{model}`. For example, `/v1/api/completions` and `/litellm/anthropic/v1/messages` match, and `http.route` contains that path. A deployment or engine name replaces its token with `{deployment}` or `{model}`. Other paths return 404 with `http.route` set to `/unmatched`. A wrong method on a matched path returns 405.

The Ollama routes from `/api/show` to `/api/embeddings` read the model from `model` or from `name`. `/api/show`, `/api/delete`, `/api/embed`, and `/api/embeddings` return 404 for a name that is not in the model list. `/api/pull` reports a listed model as up to date. For another name it answers `pull model manifest: file does not exist`. The gateway stores nothing. A name from `/api/create` or `/api/pull` does not appear in `/api/tags`, and a deleted model stays in the list. The requested name is in the local request capture only.

## Key on port 443

On port 443, a route family returns 401 with a JSON error until the request contains a credential. Each credential source in the Credentials section is sufficient. The gateway does not examine the value. Thus a client that wants an answer shows the key that it has. The span keeps the route label and has `http.response.status_code` set to 401. The plain ports do not ask for a credential. An unmatched path on port 443 returns 404 without a credential. The container healthcheck sends a fixed credential.

## Fake env file

A `GET` or `HEAD` request for an env file gets a small text file on every port. Such a path contains `/.env` or ends with `.env`. The file contains a fake `OPENAI_API_KEY` and an `OPENAI_BASE_URL` that points to the host and port from the `Host` header. If that header is not a plain name or an IPv4 address, the file has no base URL. The key has the form of an OpenAI key, but no service accepts it. The gateway makes the key from the client IP and from a random value that changes when the service starts. Thus each client gets its own key, and the same client gets the same key until the next start.

The span has `http.route` set to `/.env`, no `attackbox.probe.class`, and the key in `attackbox.canary.key`. Run this query to find a client that sends such a key back:

```sql
FROM Span SELECT count(*), latest(`client.address`), latest(`server.port`)
WHERE `service.name` = 'attackbox-public-443'
  AND `attackbox.credential.value` IN (
    FROM Span SELECT uniques(`attackbox.canary.key`, 10000)
    WHERE `service.name` = 'attackbox-public-443' AND `http.route` = '/.env' SINCE 30 days ago)
FACET `attackbox.credential.value` SINCE 30 days ago
```

To find the client that fetched a key, select `client.address` from the spans that have that value in `attackbox.canary.key`.

## Port answers

Four plain ports also answer like the server that usually listens on that port. The route families above stay the same on every port. Ports 80 and 443 have no port answers.

|Port|Looks like|`GET` paths|Unmatched request|`Server` header|
|---|---|---|---|---|
|11434|Ollama|`/` returns `Ollama is running`. `/api/version` returns JSON. `/api/ps` shows `llama3.3:70b` as loaded.|404 text|none|
|1234|LM Studio|`/api/v0/models` returns the local model names.|200 with a JSON error that contains the method and the path|none|
|8000|vLLM|`/health` returns an empty 200. `/version` returns JSON.|404 `{"detail":"Not Found"}`|`uvicorn`|
|8080|llama.cpp|`/` returns a small HTML page. `/health` returns `{"status":"ok"}`.|404 JSON error|`llama.cpp`|

A port answer path sets `http.route` to that path, for example `/` or `/health`, and such a request has no `attackbox.probe.class`. Use `server.port` to tell the ports apart. All spans keep `attackbox.persona` set to `cloud-gateway`. On port 1234 an unmatched request has `http.route` set to `/unmatched` and status 200. The version numbers are fixed text.

## Unmatched requests

A request with `http.route` set to `/unmatched` also has `attackbox.probe.class`. The class comes from a fixed list: `proxy`, `root`, `env_file`, `vcs`, `wordpress`, `actuator`, `cgi`, `admin`, `php`, `discovery`, `config_file`, `llm_api`, and `other`. An `env_file` request with `GET` or `HEAD` gets the fake env file and is not unmatched. Run this query to see what scanners look for:

```sql
FROM Span SELECT count(*)
WHERE `service.name` = 'attackbox-public-443' AND name = 'public.request' AND `http.route` = '/unmatched'
FACET `attackbox.probe.class` SINCE 1 day ago
```

## Local request capture

The service writes each request line that reaches the gateway to `/var/lib/attackbox-public-capture/requests/capture-YYYYMMDD.jsonl` on the host. Each JSON line contains the time, peer IP, method, raw request target with its query string, `Host`, `User-Agent`, route label, status, probe class, listener port (443), protocol version, request headers, and request body. The service clips the target at 2048 bytes, text header fields at 256 bytes, header names at 64 bytes, and header values at 512 bytes. It stores at most 48 header pairs sorted by canonical name and value order. It records the request body up to the 64 KiB request limit, counts the bytes read, and hashes them with SHA-256. JSON encoding escapes control characters and invalid UTF-8.

The service keeps 7 UTC days and writes at most 256 MiB each day. `public.health` counts written lines in `attackbox.captured_requests` and lost lines in `attackbox.capture_dropped`. The parent directory is root-only. A stage creates the directory once. A rollback keeps it. The capture stays on the host. Only the credential fields above go to New Relic.

The service does not redact the capture. Headers and bodies keep credentials, cookies, and prompts as sent.

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

`attackbox.tls.sni` is `none` if the ClientHello has no server name, `match` if the name matches the certificate, and `other` for a different name. It is `unknown` if no ClientHello was parsed, which is always true on the plain-HTTP ports. The service reads the name from every ClientHello, including resumed sessions. The span starts when the service accepts the connection and ends when the connection closes.

The service sends at most one connection span each second, with a burst of 16. The `public.health` span counts all such connections in `attackbox.pre_http_connections`. It counts connections that the listener rejects at its 128-connection limit in `attackbox.rejected_connections`. Both counters start at zero when the service starts.

The service does not export prompts, bodies, query names or values other than a credential, raw paths, arbitrary headers, or received bytes. HTTP parser failures after a TLS handshake produce a `no_request` connection span, not a request span. The rate limiter counts requests it rejects before the gateway. Those requests are not captured. Bounded queues can lose spans.

Before live export, confirm who can query spans and how long the account retains exact IP addresses. Use a client with a known egress IP to check the public path after an approved deployment. Do not use a forwarded header as proof.
