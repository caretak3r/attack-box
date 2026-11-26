# Live dashboard

`attackbox-live` shows the traffic of the public gateway in near-real time. It runs on the operator workstation and listens on loopback only. It does not change the host.

## Start the dashboard

1. Make sure that the SSH alias `attackbox` connects to the host without a prompt.
2. Set `NEW_RELIC_API_KEY` and `NEW_RELIC_ACCOUNT_ID` in the shell. This step is optional. Without these variables, the dashboard shows HTTP requests only.
3. Run this command from the repository root:

   ```bash
   go run ./cmd/attackbox-live -own <your egress address>,<the host address>
   ```

4. Open `http://127.0.0.1:8765/`.

Stop the dashboard with Ctrl-C.

## Data sources

| Source | Content | Delay |
|---|---|---|
| Host capture files | One record for each HTTP request: source address, method, full target with query string, `Host`, user-agent, route, status, and probe class. A gateway release with body capture adds scrubbed headers and a bounded body. | About two seconds. |
| New Relic spans | Connections that sent no HTTP request, with their outcome and TLS server name class. | The span export delay plus a 20-second poll. |

The dashboard reads the capture files with `tail` through one SSH session. It reads the files only.

New Relic holds labels only. If the capture source is not available, the dashboard shows the New Relic request spans. These spans have no path, query string, user-agent, headers, or body.

The source address is the TCP peer of the connection. The gateway ignores forwarded-address headers, because a client can set them to any value.

## Read the page

| Area | Use |
|---|---|
| Source status | Shows if each data source is connected and when it last gave data. |
| Time window and filter | Select the period. Enter text to match a source address, path, user-agent, route, probe class, or status. |
| Outside world and own machines | Counts the events and sources of the window on each side. The page shows outside traffic only, until you select **Own machines** or **Both**. Rows from your own addresses carry the label `own`. |
| Listener ports | Shows traffic on each configured listener port with request count, pre-HTTP connection count, source count, and last seen time. Select a port to see only its traffic. |
| Sources to endpoints | Shows which source addresses reached which port and endpoint. Line width shows the event count. Select a source or an endpoint to see only its traffic. |
| Sources and Endpoints tables | Show the same data as text, with counts, the last time seen, and the most used user-agent. |
| Requests and connections | Shows the newest 300 events of the selection. Select a time to open the full event: query parameters, headers, and body. |

Select **Pause** to stop the refresh while you read.

## Options

| Flag | Default | Purpose |
|---|---|---|
| `-listen` | `127.0.0.1:8765` | Loopback address of the dashboard. Other addresses are refused. |
| `-ssh` | `attackbox` | SSH alias of the host. |
| `-remote-dir` | `/var/lib/attackbox-public-capture/requests` | Capture directory on the host. |
| `-dir` | none | Read capture files from a local directory. SSH is not used. |
| `-days` | `2` | UTC days of capture files to load, from 1 to 7. |
| `-own` | none | Addresses of your own machines, separated by commas: your egress address and the host. The page counts their traffic apart from outside traffic and shows outside traffic by default. Without this option, your tests count as outside traffic. |
| `-ports` | `80,443,1234,8000,8080,11434` | Comma-separated listener ports always listed in the ports table, from 1 to 16 ports, each 1 to 65535. |
| `-service` | `attackbox-public-443` | New Relic service name of the gateway. |
| `-keep` | `200000` | Events kept in memory. |

## Safety

- Captured text is data. The dashboard does not execute it, open it, or send it to a tool or a model.
- The page puts captured text into the document as text only. A content security policy blocks inline scripts.
- The server accepts only `GET` requests that name the loopback address. This prevents access from a web page on a different origin.
- The dashboard keeps events in memory only. It writes no captured data to disk.
- Request bodies can contain harmful text or personal data. Do not copy them into public documents.

## Limits

- The first New Relic query returns a maximum of 5,000 spans for the last 24 hours.
- The text filter does not search headers or bodies.
- The dashboard has no geographic lookup. It does not send source addresses to a lookup service.
- One SSH session stays open while the dashboard runs.
