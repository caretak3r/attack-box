# Inspect public HTTPS traffic

For a release with structured request spans, open **Query your data** in New Relic. Select the ingest account. Run this NRQL query:

```sql
FROM Span SELECT timestamp, `client.address` AS 'client_ip',
  `http.request.method`, `http.route`, `http.response.status_code`,
  `attackbox.request.content_type`, `http.request.body.size`,
  `gen_ai.request.model`, `attackbox.request.stream`, `trace.id`
WHERE `service.name` = 'attackbox-public-443' AND name = 'public.request'
  AND `attackbox.request.content_type` IS NOT NULL
SINCE 1 hour ago LIMIT 100
```

`client_ip` is the IPv4 peer of the TCP connection, not an identity from an HTTP header. The listener ignores `Forwarded` and `X-Forwarded-For`. A VPN or NAT exposes its exit IP. A public proxy exposes its own IP. A local or private peer leaves the field empty. Older releases did not export this field. They cannot supply past addresses.

`http.route` is a route template, not a raw URL. The content type is a fixed category without parameters. For a known length, the size is the declared body length in bytes. For an unknown length, the size is available only if the handler reads the body to its end. On a validated completion, the span can include the recognized model and an explicit Boolean streaming flag.

The container healthcheck connects from loopback. The service does not trace it and does not count it. Releases before `public.connection` spans exported four healthcheck requests each minute without `client_ip`. To exclude them from older data, add ``AND `client.address` IS NOT NULL``.

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

The service does not export prompts, bodies, credentials, query values, arbitrary headers, or received bytes. HTTP parser failures after a TLS handshake produce a `no_request` connection span, not a request span. The rate limiter counts requests it rejects before the gateway. Bounded queues can lose spans.

Before live export, confirm who can query spans and how long the account retains exact IP addresses. Use a client with a known egress IP to check the public path after an approved deployment. Do not use a forwarded header as proof.
