# Live dashboard

`attackbox-live` shows the traffic of the public gateway in near-real time. It runs on the operator workstation and listens on loopback only. It does not change the host.

## Start the dashboard

1. Make sure that the SSH alias `attackbox` connects to the host without a prompt.
2. Run this command from the repository root:

   ```bash
   go run ./cmd/attackbox-live
   ```

   The dashboard auto-detects your egress address and the host address through SSH. To set them explicitly:

   ```bash
   go run ./cmd/attackbox-live -own <your egress address>,<host address>
   ```

3. Open `http://127.0.0.1:8765/`.

Stop the dashboard with Ctrl-C.

## Read from a local archive

The `-dir` option reads from a local archive directory instead of connecting over SSH:

```bash
go run ./cmd/attackbox-live -dir ~/.local/share/attackbox-evidence
```

The directory must hold the evidence paths under their absolute host paths, for example `<dir>/var/lib/attackbox-public-capture/requests/capture-20241128.jsonl`.

## Data sources

| Source | Content | Delay |
|---|---|---|
| Public capture files | One record for each HTTP request: source address, method, full target with query string, `Host`, user-agent, route, status, probe class, headers, and bounded body. | About two seconds. |
| OTLP traces | Pre-HTTP connections with outcome and TLS SNI class. Request spans with model, canary key, MCP method, credential type, and stream flag. | About two seconds. |
| Shipper events | Host security events from Falco and audit-filter, egress blocks, and private bait traffic. | About two seconds. |

The dashboard reads the capture and evidence files with `tail` through one SSH session. It reads files only.

The source address is the TCP peer of the connection. The gateway ignores forwarded-address headers, because a client can set them to any value.

## Security views

The dashboard shows views built for the project's purpose:

| View | Fields |
|---|---|
| AI agent activity | One row per source address: chat and generation request counts, models asked, client tool names (at most 10, shown as text), system-message flag, stream flag, user-agents. |
| Exploit chains | One row per source address and chain kind: the steps reached in order, with a time for each step, and complete or partial status. Chains shown: Open WebUI (signup, tool or function create, delete), LiteLLM (key generation, later use of that key), env-file canary reuse (canary served, same key seen as credential), MCP (initialize, tools/list, tools/call). |
| Host security | Falco rule names and priority counts, egress blocks split into reply-direction noise from published ports and container-initiated connections. |
| Test environment | Counts of own or test traffic and private-bait events, kept separate from internet data. |

Chains that the data cannot support are not shown. The credential matching for LiteLLM and canary reuse chains relies on the OTLP `attackbox.credential.value` attribute and the capture body field. The canary key comes from the OTLP `attackbox.canary.key` attribute. MCP method comes from the OTLP `attackbox.mcp.method` attribute.

## Data origin

A record is `test` when its source address is loopback, the host's own address, or an operator address. Operator addresses are the admin SSH egress and any address in `-own`. The host address comes from `ssh -G attackbox | awk '/^hostname /{print $2}'`. The SSH egress is `ssh attackbox 'echo ${SSH_CLIENT%% *}'`. When `-own` is not given, the dashboard auto-detects these addresses through SSH at startup.

A record is also `test` when its user-agent starts with `attackbox-deploy-test/`. This separation is for dashboard accounting; a user-agent is not proof of source ownership.

Private bait stack records and host security events are always `test`. Every other record is `internet`.

The page shows internet data by default. Select **Test** or **Both** to see your own traffic or everything.

## Read the page

| Area | Use |
|---|---|
| Source status | Shows if each data source is connected and when it last gave data. |
| Time window and filter | Select the period. Enter text to match a source address, path, query string, user-agent, route, probe class, status, or request body. |
| Internet and test | Counts request and pre-HTTP connection events and sources for each origin. Host security and shipper-only events do not enter these totals. The page shows internet traffic only, until you select **Test** or **Both**. Rows from your own addresses carry the label `test`. |
| Listener ports | Shows traffic on each configured listener port with request count, pre-HTTP connection count, source count, and last seen time. Select a port to see only its traffic. |
| Sources to endpoints | Shows which source addresses reached which port and endpoint. Line width shows the event count. Select a source or an endpoint to see only its traffic. |
| Sources and Endpoints tables | Show the same data as text, with counts, the last time seen, and the most used user-agent. |
| Requests and connections | Shows the newest 300 events in the selection. **Prompt in body** highlights timestamps with captured user input. Select a marked time for the user prompt preview and full request. A POST, a generic body preview, or a route label alone does not earn a marker. |

Select **Pause** to stop the refresh while you read.

## Options

| Flag | Default | Purpose |
|---|---|---|
| `-listen` | `127.0.0.1:8765` | Loopback address of the dashboard. Other addresses are refused. |
| `-ssh` | `attackbox` | SSH alias of the host. |
| `-dir` | none | Read evidence from a local directory. SSH is not used. The directory must hold the evidence paths under their absolute host paths. |
| `-days` | `2` | UTC days of evidence to load, from 1 to 7. |
| `-own` | none | Addresses of your own machines, separated by commas: your egress address and the host. The page counts their traffic apart from internet traffic and shows internet traffic by default. Without this option and without SSH, your tests count as internet traffic. With SSH, the dashboard auto-detects these addresses at startup. |
| `-ports` | `80,443,1234,3000,4000,8000,8080,8188,8888,11434` | Comma-separated listener ports always listed in the ports table, from 1 to 16 ports, each 1 to 65535. |
| `-keep` | `200000` | Events kept in memory. |

## Safety

- Captured text is data. The dashboard does not execute it, open it, or send it to a tool or a model.
- The page puts captured text into the document as text only. A content security policy blocks inline scripts.
- The server accepts only `GET` requests that name the loopback address. This prevents access from a web page on a different origin.
- The dashboard keeps events in memory only. It writes no captured data to disk.
- Request bodies can contain harmful text or personal data. Do not copy them into public documents.

## Limits

- The text filter does not search headers.
- One SSH session stays open while the dashboard runs.
- The dashboard has no geographic lookup. It does not send source addresses to a lookup service.
