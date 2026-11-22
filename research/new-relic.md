# New Relic Telemetry Research: Outbound-Only Honeypot Configuration

**Research Date:** 2026-11-21  
**Scope:** Logs API, Metric API, infrastructure/Fluent Bit/OpenTelemetry forwarding, gzip/batching/backpressure, ingest-license-key security, dedicated accounts, NRQL alerts  
**Security Context:** Compromised VPS with outbound TCP 443 only; avoid User/NerdGraph/query keys

---

## Executive Summary

New Relic provides comprehensive telemetry ingestion APIs designed for secure, outbound-only data transmission over TCP 443. For a compromised VPS honeypot scenario, the **ingest license key** is the **only credential required**—it enables write-only data submission without granting query or account management capabilities. This key can be rotated, scoped to dedicated accounts, and monitored via NRQL alerts for heartbeat loss and ingest anomalies.

---

## 1. API Endpoints & Network Configuration

### 1.1 Core Ingest Endpoints (TCP 443, TLS 1.2+)

All endpoints require HTTPS and TLS 1.2 or higher. No inbound connections are needed.

| API | US Endpoint (default) | EU Endpoint | Japan Endpoint |
|-----|----------------------|-------------|----------------|
| **Logs API** | `https://log-api.newrelic.com/log/v1` | `https://log-api.eu.newrelic.com/log/v1` | `https://log-api.jp.nr-data.net/log/v1` |
| **Metric API** | `https://metric-api.newrelic.com/metric/v1` | `https://metric-api.eu.newrelic.com/metric/v1` | `https://metric-api.jp.nr-data.net/metric/v1` |
| **Event API** | `https://insights-collector.newrelic.com` | `https://insights-collector.eu01.nr-data.net` | `https://insights-collector.jp.nr-data.net` |
| **Trace API** | `https://trace-api.newrelic.com` | `https://trace-api.eu.newrelic.com` | `https://trace-api.jp.nr-data.net` |
| **OpenTelemetry (OTLP)** | `https://otlp.nr-data.net` (ports: 443, 4317, 4318) | `https://otlp.eu01.nr-data.net` | `https://otlp.jp.nr-data.net` |
| **Infrastructure Agent** | `https://infra-api.newrelic.com` | `https://infra-api.eu.newrelic.com` | `https://infra-api.jp.nr-data.net` |

**Documentation:**
- Network endpoints: https://docs.newrelic.com/docs/new-relic-solutions/get-started/networks
- Log API: https://docs.newrelic.com/docs/logs/log-api/introduction-log-api
- Metric API: https://docs.newrelic.com/docs/data-apis/ingest-apis/metric-api/report-metrics-metric-api
- OTLP endpoint: https://docs.newrelic.com/docs/opentelemetry/best-practices/opentelemetry-otlp

### 1.2 IP Address Allowlisting (Optional)

If firewall egress rules require destination IPs:

**US Data Center (Dualstack):**
- IPv4: `162.247.240.0/22`, `152.38.128.0/21`
- IPv6: `2602:816:5000::/40`, `2620:16:4000::/48`

**EU Data Center (Dualstack):**
- IPv4: `185.221.84.0/22`, `212.32.0.0/21`
- IPv6: `2a0d:8000::/29`

**Japan Data Center (Native):**
- IPv4: `64.251.192.0/20`
- IPv6: `2401:7c60::/32`

**Reference:** https://docs.newrelic.com/docs/new-relic-solutions/get-started/networks/#dualstack-ip-blocks

---

## 2. Authentication: Ingest License Keys Only

### 2.1 Key Types and Security Scope

| Key Type | Scope | Capability | Risk if Compromised | Use on Honeypot VPS? |
|----------|-------|------------|---------------------|----------------------|
| **Ingest License Key** | Write-only data ingestion | Send logs, metrics, traces, events | Attacker can send garbage data to your account | ✅ **YES** (safe for untrusted hosts) |
| **User Key** | Per-user, full access | Query data via NerdGraph, modify account settings | Full account compromise | ❌ **NEVER** |
| **Browser Key** | Write-only browser data | Send browser monitoring data | Limited to browser telemetry spam | ✅ (if needed) |
| **Insights Query Key** (deprecated) | Read-only queries | Query data via Insights API | Data exfiltration | ❌ **NEVER** |

**Key Finding:** Only the **ingest license key** (40-character hex) should be deployed to compromised infrastructure. It cannot query data, list accounts, or modify configurations.

**Documentation:** https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys

### 2.2 License Key Rotation and Scoping

**Creating Rotatable Keys:**
1. Navigate to **[one.newrelic.com/api-keys](https://one.newrelic.com/)**
2. Click **Create a key** → Select **Ingest - License**
3. Name it descriptively (e.g., `honeypot-prod-2026-11`)
4. The original account license key **cannot be deleted**, but user-created keys can be rotated

**Best Practices:**
- Create **separate keys per environment/host** for granular revocation
- Rotate keys on a schedule (e.g., quarterly)
- Use key name prefixes: `honeypot-<env>-<date>`
- Monitor key usage via **Last used** column (User Keys only; not supported for License Keys)
- Assign **owning teams** to ingest keys for accountability

**Key Deactivation (without deletion):**
- Temporarily disable a key via UI: **... menu → Deactivate key**
- Reactivate later if needed; useful for incident containment

**Reference:** https://docs.newrelic.com/docs/apis/nerdgraph/examples/use-nerdgraph-manage-license-keys-user-keys

### 2.3 HTTP Authentication Methods

**Option 1: Header (recommended):**
```bash
curl -X POST https://log-api.newrelic.com/log/v1 \
  -H "Content-Type: application/json" \
  -H "Api-Key: REDACTED" \
  --data '[{"message":"test"}]'
```

**Option 2: Query Parameter (for systems without custom headers):**
```bash
curl -X POST "https://log-api.newrelic.com/log/v1?Api-Key=REDACTED" \
  -H "Content-Type: application/json" \
  --data '[{"message":"test"}]'
```

---

## 3. Compression, Batching, and Backpressure

### 3.1 Payload Limits and Compression

| API | Max Payload Size | Compression | Recommended Batch Size |
|-----|------------------|-------------|----------------------|
| **Logs API** | 1 MB (10^6 bytes) | gzip (optional, recommended) | <1 MB compressed |
| **Metric API** | 1 MB (10^6 bytes) | gzip (optional) | <1 MB compressed |
| **Event API** | 1 MB (10^6 bytes) | gzip (highly recommended) | <1 MB compressed |
| **OTLP** | 1 MB (10^6 bytes) | gzip (required by spec) | <1 MB compressed |

**Compression Headers:**
```bash
# For gzip-compressed payloads
Content-Type: application/json
Content-Encoding: gzip
```

**Reference:**
- Logs API limits: https://docs.newrelic.com/docs/logs/log-api/introduction-log-api/#limits
- Metric API limits: https://docs.newrelic.com/docs/data-apis/ingest-apis/metric-api/metric-api-limits-restricted-attributes
- OTLP batching: https://docs.newrelic.com/docs/opentelemetry/best-practices/opentelemetry-otlp/#payload-batching

### 3.2 Rate Limits and Backpressure Handling

**Rate Limits (per account):**
- **HTTP Requests:** 300,000 requests/minute (Logs API)
- **Uncompressed Bytes:** 10 GB/minute (Logs API)

**429 Response Handling:**
When rate limits are exceeded, the API returns `HTTP 429` with a `Retry-After` header (seconds to wait).

**Example Retry Logic (Python):**
```python
import time
import requests

def send_with_backoff(url, headers, payload, max_retries=3):
    for attempt in range(max_retries):
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code == 202:
            return response  # Success
        
        elif response.status_code == 429:
            retry_after = int(response.headers.get('Retry-After', 60))
            print(f"Rate limited. Retrying after {retry_after}s...")
            time.sleep(retry_after)
        
        else:
            response.raise_for_status()
    
    raise Exception("Max retries exceeded")
```

**Go SDK Example:**
The Go Telemetry SDK automatically handles retries and batching:
```go
h, _ := telemetry.NewHarvester(telemetry.ConfigAPIKey(os.Getenv("NEW_RELIC_LICENSE_KEY")))
h.RecordMetric(telemetry.Gauge{Name: "cpu.usage", Value: 0.75})
h.HarvestNow(context.Background())  // Auto-batches and retries 429s
```

**Reference:**
- API overload protection: https://docs.newrelic.com/docs/apis/rest-api-v2/basic-functions/api-overload-protection-handling-429-errors

### 3.3 Asynchronous Response Validation

All ingest APIs are **asynchronous**:
- `HTTP 202` = Accepted (not guaranteed success)
- Validation errors appear in `NrIntegrationError` events (queryable via NRQL)

**Check for Integration Errors:**
```sql
FROM NrIntegrationError 
SELECT * 
WHERE newRelicFeature = 'Logs' 
SINCE 1 hour ago
```

**Reference:** https://docs.newrelic.com/docs/data-apis/manage-data/nrintegrationerror

---

## 4. Forwarding Technologies

### 4.1 Fluent Bit Plugin (Recommended for Logs)

**Official Plugin:** `newrelic-fluent-bit-output`  
**Repository:** https://github.com/newrelic/newrelic-fluent-bit-output

**Example Configuration (`fluent-bit.conf`):**
```ini
[SERVICE]
    Flush        5
    Daemon       Off
    Log_Level    info
    Plugins_File plugins.conf

[INPUT]
    Name   tail
    Path   /var/log/honeypot/*.log
    Tag    honeypot

[OUTPUT]
    Name       newrelic
    Match      *
    licenseKey REDACTED
    endpoint   https://log-api.newrelic.com/log/v1

[FILTER]
    Name   modify
    Match  *
    Add    hostname honeypot-01
    Add    environment prod
```

**Retry Configuration (Built-in):**
```ini
[OUTPUT]
    Name         newrelic
    Match        *
    licenseKey   REDACTED
    Retry_Limit  False  # Infinite retries (use with caution)
```

**Docker Deployment:**
```bash
docker run -d \
  -v /var/log:/var/log:ro \
  -v /path/to/fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf \
  -e LICENSE_KEY=REDACTED \
  newrelic/newrelic-fluentbit-output:latest
```

**Documentation:** https://docs.newrelic.com/docs/logs/forward-logs/fluent-bit-plugin-log-forwarding

### 4.2 OpenTelemetry Collector (Recommended for Metrics + Traces)

**Configuration Example (`otel-collector.yaml`):**
```yaml
receivers:
  hostmetrics:
    collection_interval: 30s
    scrapers:
      cpu:
      memory:
      disk:
      network:

processors:
  batch:
    timeout: 10s
    send_batch_size: 1000
  
  memory_limiter:
    check_interval: 1s
    limit_mib: 512

exporters:
  otlphttp:
    endpoint: https://otlp.nr-data.net
    headers:
      api-key: REDACTED
    compression: gzip

service:
  pipelines:
    metrics:
      receivers: [hostmetrics]
      processors: [memory_limiter, batch]
      exporters: [otlphttp]
```

**Running the Collector:**
```bash
# Binary
otelcol-contrib --config otel-collector.yaml

# Docker
docker run -d \
  -v $(pwd)/otel-collector.yaml:/etc/otel-collector.yaml \
  otel/opentelemetry-collector-contrib:latest \
  --config /etc/otel-collector.yaml
```

**Documentation:**
- OpenTelemetry Collector setup: https://docs.newrelic.com/docs/opentelemetry/get-started/collector-processing/opentelemetry-collector-processing-intro
- OTLP endpoint: https://docs.newrelic.com/docs/opentelemetry/best-practices/opentelemetry-otlp

### 4.3 Infrastructure Agent (Lightweight Host Metrics)

**Installation (Ubuntu):**
```bash
curl -Ls https://download.newrelic.com/infrastructure_agent/gpg/newrelic-infra.gpg | sudo apt-key add -
printf "deb https://download.newrelic.com/infrastructure_agent/linux/apt focal main" | sudo tee /etc/apt/sources.list.d/newrelic-infra.list
sudo apt-get update && sudo apt-get install newrelic-infra -y
```

**Configuration (`/etc/newrelic-infra.yml`):**
```yaml
license_key: REDACTED
display_name: honeypot-01
custom_attributes:
  environment: prod
  role: honeypot
```

**Service Management:**
```bash
sudo systemctl start newrelic-infra
sudo systemctl enable newrelic-infra
```

**Documentation:**
- Installation: https://docs.newrelic.com/docs/infrastructure/infrastructure-agent/linux-installation/package-manager-install
- Configuration: https://docs.newrelic.com/docs/infrastructure/infrastructure-agent/configuration/infrastructure-agent-configuration-settings

### 4.4 Direct API Integration (Python SDK)

**Installation:**
```bash
pip install newrelic-telemetry-sdk
```

**Example Code:**
```python
import os
import time
from newrelic_telemetry_sdk import GaugeMetric, CountMetric, MetricClient, LogClient, Log

# Metric Client
metric_client = MetricClient(os.environ["NEW_RELIC_LICENSE_KEY"])

# Send metrics
cpu_gauge = GaugeMetric("honeypot.cpu.usage", 45.2, {"host": "honeypot-01"})
attack_count = CountMetric("honeypot.attacks", 15, interval_ms=60000)
response = metric_client.send_batch([cpu_gauge, attack_count])
response.raise_for_status()

# Log Client
log_client = LogClient(os.environ["NEW_RELIC_LICENSE_KEY"])
log = Log("SSH brute force attempt", attributes={"srcIP": "1.2.3.4", "port": 22})
response = log_client.send(log)
response.raise_for_status()
```

**Repository:** https://github.com/newrelic/newrelic-telemetry-sdk-python

### 4.5 Direct API Integration (Go SDK)

**Installation:**
```bash
go get github.com/newrelic/newrelic-telemetry-sdk-go
```

**Example Code:**
```go
package main

import (
    "context"
    "os"
    "time"
    "github.com/newrelic/newrelic-telemetry-sdk-go/telemetry"
)

func main() {
    h, _ := telemetry.NewHarvester(telemetry.ConfigAPIKey(os.Getenv("NEW_RELIC_LICENSE_KEY")))
    
    // Record gauge metric
    h.RecordMetric(telemetry.Gauge{
        Name:      "honeypot.cpu.usage",
        Value:     0.75,
        Timestamp: time.Now(),
        Attributes: map[string]interface{}{"host": "honeypot-01"},
    })
    
    // Auto-batches and sends every 5 seconds (default)
    h.HarvestNow(context.Background())
}
```

**Repository:** https://github.com/newrelic/newrelic-telemetry-sdk-go

---

## 5. Dedicated Accounts and Organization Structure

### 5.1 Account Isolation Strategy

For honeypot security, create a **dedicated account** within your New Relic organization:

**Benefits:**
- Separate ingest keys (revoke honeypot keys without affecting production)
- Isolated billing/quota tracking
- RBAC boundary: restrict user access to honeypot data
- Easier forensic analysis (no cross-contamination with prod telemetry)

**Setup Steps:**
1. Navigate to **[one.newrelic.com](https://one.newrelic.com) → Administration → Accounts**
2. Click **Create account**
3. Name: `Honeypot Production`
4. Create ingest license keys specific to this account

**Multi-Tenancy (Enterprise Only):**
For managing multiple customers/business units, use **multi-tenancy** to create separate organizations:
- Each tenant has isolated accounts, keys, and billing
- Useful for MSPs providing honeypot-as-a-service

**Documentation:**
- Account structure: https://docs.newrelic.com/docs/accounts/accounts-billing/account-structure/new-relic-account-structure
- Multi-tenancy: https://docs.newrelic.com/docs/accounts/accounts-billing/account-structure/multi-tenancy/intro-to-multi-tenancy

### 5.2 Access Control (Least Privilege)

For the honeypot account, grant minimal permissions:

**Recommended Role:** **Read-only user** (for analysis team)  
**Avoid:** Admin or billing roles on honeypot account

**Key Insight:** Even if the VPS is fully compromised, the ingest license key cannot be used to:
- Query existing data
- List other accounts
- Modify alert policies
- Access user credentials

---

## 6. NRQL Alerts for Heartbeat Loss and Ingest Spikes

### 6.1 Heartbeat Loss Detection (Missing Data)

**Use Case:** Detect when honeypot stops sending telemetry (potential service crash or attacker tampering).

**NRQL Alert Condition:**
```sql
FROM Log 
SELECT count(*) 
WHERE hostname = 'honeypot-01' 
FACET hostname
```

**Loss of Signal Configuration:**
1. Create NRQL alert condition (above query)
2. Set **Aggregation window:** 1 minute
3. Configure **Loss of signal threshold:**
   - **Signal is lost after:** 5 minutes
   - **Open new "loss of signal" incident** (creates alert)

**Alert Trigger:** If no logs arrive for 5+ minutes, incident opens.

**Documentation:**
- Loss of signal: https://docs.newrelic.com/whats-new/2020/10/alerting-loss-signal-detection-configurable-gap-filling-strategies
- NRQL conditions: https://docs.newrelic.com/docs/alerts/create-alert/create-alert-condition/create-nrql-alert-conditions

### 6.2 Ingest Spike Detection (Anomaly/Attack Surge)

**Use Case:** Detect sudden increase in attack traffic or attacker uploading malicious logs.

**NRQL Baseline Alert:**
```sql
FROM Metric 
SELECT rate(sum(honeypot.attacks), 1 minute) 
WHERE environment = 'prod'
```

**Threshold Configuration:**
- **Static Threshold:** Critical when > 1000 attacks/minute
- **Anomaly Detection:** Use baseline alerting (requires Pro/Enterprise)

**Anomaly Alert (Recommended):**
```sql
FROM Log 
SELECT count(*) 
WHERE hostname = 'honeypot-01'
```
- Set **Anomaly direction:** Upper only
- **Deviation:** 3 standard deviations

**Documentation:**
- Baseline alerting: https://docs.newrelic.com/docs/alerts/create-alert/fine-tune/streaming-alerts-key-terms-concepts
- Anomaly detection: https://docs.newrelic.com/docs/tutorial-optimize-telemetry/detect-anomalies

### 6.3 Integration Error Monitoring

**NRQL Query:**
```sql
FROM NrIntegrationError 
SELECT count(*) 
WHERE newRelicFeature = 'Logs' 
  AND message LIKE '%rate limit%' 
FACET accountId, message
```

**Alert Trigger:** Critical when count > 10 (indicates sustained rate limiting or malformed payloads).

---

## 7. Sample Curl Payloads

### 7.1 Logs API (Simple)

```bash
curl -X POST https://log-api.newrelic.com/log/v1 \
  -H "Content-Type: application/json" \
  -H "Api-Key: REDACTED" \
  --data '[
    {
      "timestamp": 1700000000000,
      "message": "SSH login attempt from 1.2.3.4",
      "attributes": {
        "hostname": "honeypot-01",
        "srcIP": "1.2.3.4",
        "port": 22,
        "logtype": "ssh"
      }
    }
  ]'
```

### 7.2 Logs API (Detailed with Common Block)

```bash
curl -X POST https://log-api.newrelic.com/log/v1 \
  -H "Content-Type: application/json" \
  -H "Api-Key: REDACTED" \
  --data '[
    {
      "common": {
        "attributes": {
          "hostname": "honeypot-01",
          "environment": "prod"
        }
      },
      "logs": [
        {"timestamp": 1700000000000, "message": "Event 1"},
        {"timestamp": 1700000001000, "message": "Event 2"}
      ]
    }
  ]'
```

### 7.3 Metric API (Gauge + Count)

```bash
curl -X POST https://metric-api.newrelic.com/metric/v1 \
  -H "Content-Type: application/json" \
  -H "Api-Key: REDACTED" \
  --data '[
    {
      "metrics": [
        {
          "name": "honeypot.cpu.usage",
          "type": "gauge",
          "value": 0.75,
          "timestamp": 1700000000000,
          "attributes": {"host": "honeypot-01"}
        },
        {
          "name": "honeypot.attacks",
          "type": "count",
          "value": 42,
          "interval.ms": 60000,
          "timestamp": 1700000000000,
          "attributes": {"protocol": "ssh"}
        }
      ]
    }
  ]'
```

### 7.4 Metric API (Summary)

```bash
curl -X POST https://metric-api.newrelic.com/metric/v1 \
  -H "Content-Type: application/json" \
  -H "Api-Key: REDACTED" \
  --data '[
    {
      "metrics": [
        {
          "name": "honeypot.response.duration",
          "type": "summary",
          "value": {
            "count": 100,
            "sum": 4.5,
            "min": 0.001,
            "max": 0.5
          },
          "interval.ms": 60000,
          "timestamp": 1700000000000,
          "attributes": {"endpoint": "/api/fake"}
        }
      ]
    }
  ]'
```

### 7.5 Gzip Compression Example (Bash)

```bash
echo '[{"message":"compressed log"}]' | gzip | curl -X POST \
  https://log-api.newrelic.com/log/v1 \
  -H "Content-Type: application/json" \
  -H "Content-Encoding: gzip" \
  -H "Api-Key: REDACTED" \
  --data-binary @-
```

---

## 8. Security Best Practices for Compromised VPS

### 8.1 Credential Isolation

| Credential Type | Deploy to Honeypot? | Rationale |
|----------------|---------------------|-----------|
| Ingest License Key | ✅ YES | Write-only; cannot query data or modify account |
| User Key | ❌ NEVER | Full account access (query + config) |
| Browser/Mobile Keys | ✅ (if needed) | Write-only for specific telemetry types |
| Insights Query Key | ❌ NEVER | Can exfiltrate all data |
| NerdGraph API | ❌ NEVER | Requires User Key (full access) |

### 8.2 Key Rotation Workflow

**Automated Rotation Script (Bash):**
```bash
#!/bin/bash
# Rotate honeypot license key quarterly

NEW_KEY=$(curl -X POST https://api.newrelic.com/graphql \
  -H "Api-Key: $ADMIN_USER_KEY" \
  -d '{"query":"mutation { apiAccessCreateKeys(keys: [{accountId: 123456, keyType: INGEST, name: \"honeypot-2026-q4\"}]) { createdKeys { key } }}"}' \
  | jq -r '.data.apiAccessCreateKeys.createdKeys[0].key')

# Deploy new key to honeypot
ssh honeypot-01 "echo 'license_key: $NEW_KEY' > /etc/newrelic-infra.yml && systemctl restart newrelic-infra"

# Wait 24h for traffic migration, then deactivate old key
sleep 86400
curl -X POST https://api.newrelic.com/graphql \
  -H "Api-Key: $ADMIN_USER_KEY" \
  -d '{"query":"mutation { apiAccessDeleteKeys(keys: [{id: \"OLD_KEY_ID\", keyType: INGEST}]) { deletedKeys { id } }}"}'
```

**Reference:** https://docs.newrelic.com/docs/apis/nerdgraph/examples/use-nerdgraph-manage-license-keys-user-keys

### 8.3 Monitoring for Key Abuse

**NRQL Query (detect unusual data sources):**
```sql
FROM Log 
SELECT count(*) 
WHERE NOT hostname IN ('honeypot-01', 'honeypot-02') 
FACET hostname 
SINCE 1 hour ago
```

**Alert:** Trigger if unknown hostnames appear (indicates key compromise).

### 8.4 Network Segmentation

**Firewall Rules (iptables example):**
```bash
# Allow outbound HTTPS to New Relic only
iptables -A OUTPUT -p tcp -d 162.247.240.0/22 --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp -d 152.38.128.0/21 --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j DROP  # Block all other HTTPS
```

**Docker Compose with Network Policies:**
```yaml
services:
  honeypot:
    image: my-honeypot:latest
    networks:
      - restricted
    cap_drop:
      - ALL

networks:
  restricted:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

---

## 9. Example Implementation: Go Honeypot with OpenAI Impersonation

**Scenario:** Ubuntu VPS running a fake OpenAI API endpoint, logging attack attempts to New Relic.

**Directory Structure:**
```
/opt/honeypot/
├── main.go
├── go.mod
├── config.yaml
└── Dockerfile
```

**`main.go` (Simplified):**
```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "os"
    "time"
    "github.com/newrelic/newrelic-telemetry-sdk-go/telemetry"
)

var harvester *telemetry.Harvester

func init() {
    h, err := telemetry.NewHarvester(telemetry.ConfigAPIKey(os.Getenv("NEW_RELIC_LICENSE_KEY")))
    if err != nil {
        log.Fatal(err)
    }
    harvester = h
}

func fakeOpenAIHandler(w http.ResponseWriter, r *http.Request) {
    // Log attack attempt
    harvester.RecordMetric(telemetry.Count{
        Name:      "honeypot.requests",
        Value:     1,
        Timestamp: time.Now(),
        Attributes: map[string]interface{}{
            "method":     r.Method,
            "path":       r.URL.Path,
            "source_ip":  r.RemoteAddr,
            "user_agent": r.UserAgent(),
        },
    })
    
    // Fake response
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, `{"error":"invalid_api_key"}`)
}

func main() {
    http.HandleFunc("/v1/chat/completions", fakeOpenAIHandler)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

**Deployment:**
```bash
export NEW_RELIC_LICENSE_KEY="your_key_here"
go run main.go
```

**Docker Deployment:**
```dockerfile
FROM golang:1.21-alpine
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o honeypot main.go

ENV NEW_RELIC_LICENSE_KEY=""
EXPOSE 8080
CMD ["./honeypot"]
```

```bash
docker build -t honeypot:latest .
docker run -d -p 8080:8080 -e NEW_RELIC_LICENSE_KEY=$KEY honeypot:latest
```

---

## 10. References and Further Reading

### 10.1 Official Documentation

**Core APIs:**
- Logs API: https://docs.newrelic.com/docs/logs/log-api/introduction-log-api
- Metric API: https://docs.newrelic.com/docs/data-apis/ingest-apis/metric-api/introduction-metric-api
- Event API: https://docs.newrelic.com/docs/data-apis/ingest-apis/event-api/introduction-event-api
- Trace API: https://docs.newrelic.com/docs/distributed-tracing/trace-api/introduction-trace-api

**Security & Keys:**
- API Keys: https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys
- Key Management via NerdGraph: https://docs.newrelic.com/docs/apis/nerdgraph/examples/use-nerdgraph-manage-license-keys-user-keys

**Forwarding & Integration:**
- Fluent Bit Plugin: https://docs.newrelic.com/docs/logs/forward-logs/fluent-bit-plugin-log-forwarding
- OpenTelemetry: https://docs.newrelic.com/docs/opentelemetry/get-started/collector-processing/opentelemetry-collector-processing-intro
- Infrastructure Agent: https://docs.newrelic.com/docs/infrastructure/infrastructure-agent/configuration/infrastructure-agent-configuration-settings

**Alerting:**
- NRQL Alert Conditions: https://docs.newrelic.com/docs/alerts/create-alert/create-alert-condition/create-nrql-alert-conditions
- Loss of Signal: https://docs.newrelic.com/whats-new/2020/10/alerting-loss-signal-detection-configurable-gap-filling-strategies
- Anomaly Detection: https://docs.newrelic.com/docs/tutorial-optimize-telemetry/detect-anomalies

**Network & Limits:**
- Network Endpoints: https://docs.newrelic.com/docs/new-relic-solutions/get-started/networks
- Rate Limits: https://docs.newrelic.com/docs/apis/rest-api-v2/basic-functions/api-overload-protection-handling-429-errors
- Data Limits: https://docs.newrelic.com/docs/data-apis/manage-data/view-system-limits

### 10.2 GitHub Reference Implementations

**SDKs:**
- Python SDK: https://github.com/newrelic/newrelic-telemetry-sdk-python
- Go SDK: https://github.com/newrelic/newrelic-telemetry-sdk-go
- Node.js SDK: https://github.com/newrelic/newrelic-telemetry-sdk-node

**Plugins:**
- Fluent Bit Output Plugin: https://github.com/newrelic/newrelic-fluent-bit-output
- OpenTelemetry Examples: https://github.com/newrelic/newrelic-opentelemetry-examples

**Other:**
- Helm Charts: https://github.com/newrelic/helm-charts
- Infrastructure Agent: https://github.com/newrelic/infrastructure-agent

### 10.3 Account & Organization Management

- Account Structure: https://docs.newrelic.com/docs/accounts/accounts-billing/account-structure/new-relic-account-structure
- Multi-Tenancy: https://docs.newrelic.com/docs/accounts/accounts-billing/account-structure/multi-tenancy/intro-to-multi-tenancy
- Create Accounts: https://docs.newrelic.com/docs/accounts/accounts-billing/account-structure/add-accounts

---

## 11. Summary: Outbound-Only Configuration Checklist

✅ **Use ingest license keys only** (never User/Query keys)  
✅ **Create dedicated account** for honeypot isolation  
✅ **Rotate keys quarterly** via UI or NerdGraph  
✅ **Enable gzip compression** for all API calls  
✅ **Batch logs/metrics** to stay under 1MB/payload limit  
✅ **Implement 429 retry logic** with exponential backoff  
✅ **Configure loss-of-signal alerts** (5-minute threshold)  
✅ **Monitor NrIntegrationError** for payload validation issues  
✅ **Restrict egress** to New Relic IPs (optional but recommended)  
✅ **Use Fluent Bit or OpenTelemetry Collector** for production reliability  

**Key Insight:** New Relic's ingest-only architecture is **designed for untrusted environments**. The license key cannot query data or modify settings—it's safe to deploy on compromised infrastructure as long as you monitor for abuse (e.g., attackers sending garbage data to exhaust your ingest quota).

---

**End of Report**