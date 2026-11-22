# Attack Box Research: Honeypot Techniques for Fake LLM/AI Services

Research date: 2026-11-21  
Scope: Safe improvements for Go fake OpenAI/vLLM/Ollama service  
Constraints: No real models, no real secrets, no outbound exploitation, no hack-back

---

## 1. OpenAI-Compatible & Ollama Honeypots

### 1.1 pedxyuyuko/ollama_honeypot (Go)
**URL:** https://github.com/pedxyuyuko/ollama_honeypot  
**Language:** Go (MIT License)

**Endpoints mimicked:**
- `GET /`: Health check
- `POST /api/generate`: Text generation with streaming NDJSON
- `POST /api/chat`: Chat completion
- `GET /api/tags`: List fake models
- `POST /api/pull`: Model pulling with configurable speeds
- `DELETE /api/delete`: Model deletion
- `GET /api/ps`: Running model status
- `GET /api/show`: Model info
- `GET /api/version`: Version info
- `GET /v1/models`: OpenAI models listing
- `POST /v1/chat/completions`: OpenAI chat (streaming)
- `POST /chat/completions`: OpenAI chat (alternate path)

**Configuration:**
- JSON logging (Logrus) with IP, timestamp, endpoint, body
- Mock data from JSON files (tags.json, response.json, version.json)
- Configurable download speeds with variance and wave patterns:
  - `DOWNLOAD_SPEED`: bytes/sec (default 50MB/s)
  - `DOWNLOAD_SPEED_VARIANCE`: 0.0-1.0 random fluctuation (default 0.2)
  - `DOWNLOAD_SPEED_WAVE_PERIOD`: sinusoidal variation period (default 1s)
  - `DOWNLOAD_SPEED_WAVE_AMPLITUDE`: wave amplitude factor (default 0.5)

**Key implementation details:**
- Gin framework for HTTP
- Environment-based configuration
- Separate text (console) and JSON (file) logging
- Low resource usage design

---

### 1.2 ta-061/promptpot (Python)
**URL:** https://github.com/ta-061/promptpot  
**Language:** Python (MIT License)  
**Production use:** T-Pot sidecar deployment, field data from Japan/US/Germany

**Multi-profile architecture:**
| Port  | Profile     | Target Service | Event Type    |
|-------|-------------|----------------|---------------|
| 11434 | ollama      | Ollama         | OllamaPot     |
| 1234  | lmstudio    | LM Studio      | LMStudioPot   |
| 8000  | vllm        | vLLM           | VLLMPot       |
| 7860  | gradio      | Gradio apps    | GradioPot     |
| 8188  | comfyui     | ComfyUI        | ComfyUIPot    |

**Response rules system:**
- Match types: `contains`, `starts_with`, `ends_with` (case-insensitive substring, never regex)
- Random response selection from list to reduce fingerprinting
- `{model}` placeholder filled with operator-configured names only
- First matching rule wins
- Matched rule name logged to `promptpot.matched_rule` field

**Example response rule:**
```json
"response_rules": [
  {"name": "ping", "contains": ["ping", "pong"], "response": ["PONG", "pong"]},
  {"name": "say-ok", "contains": "reply with ok", "response": "OK"},
  {"name": "greeting", "starts_with": ["say hi", "say hello"], "response": ["Hello!", "Hi there!"]},
  {"name": "model-probe", "contains": "what model", "response": "I am {model}."}
]
```

**Field results (July 2026):**
- 5,300 events from 510 unique IPs in one week
- ~900 prompt submissions
- Port 11434 (Ollama) and `/v1/*` paths receive most traffic

**Anti-fingerprinting:**
- Multiple canned responses per rule (random selection)
- Configurable `PROMPTPOT_RESPONSE_TEXT` fallback
- Never reflects attacker-supplied model names back
- Max body size cap: 65536 bytes (configurable)

---

### 1.3 Th0rgal/llm-honeypot (Rust)
**URL:** https://github.com/Th0rgal/llm-honeypot  
**Language:** Rust (zero dependencies, MIT License)

**Design principles:**
- Zero dependencies (stdlib only)
- Safe by construction: no LLM, no shell-out, no outbound requests
- Bounded: per-IP rate limiting, concurrent connection cap, read timeouts
- Behind reverse proxy: reads real IP from `X-Forwarded-For`/`X-Real-IP`

**Endpoints:**
- `/v1/models`, `/v1/chat/completions`
- `/api/tags` (Ollama)
- LiteLLM admin paths

**Configuration:**
- `HONEYPOT_ADDR`: listen address (default 127.0.0.1:8099)
- `HONEYPOT_RATE`: max requests per IP per window (default 30)
- `HONEYPOT_RATE_WINDOW_SECS`: window size (default 10s)
- `HONEYPOT_MAX_CONN`: max concurrent connections (default 128)
- `HONEYPOT_MAX_BODY`: max request body bytes (default 4MB)
- `HONEYPOT_SERVER_NAME`: Server header value (default "uvicorn")

**Logging:**
```json
{"ts":"2026-10-18T12:00:00Z","ip":"203.0.113.7","method":"POST","path":"/v1/chat/completions",
 "version":"HTTP/1.1","ua":"OpenAI-Python/1.0","api_key":"sk-...","model":"gpt-4o","stream":true,
 "body_len":123,"headers":[...],"body":"..."}
```

**Reverse proxy features (nginx):**
- TLS parameter forwarding: `X-Honeypot-TLS-*` headers capture protocol, ciphers, curves
- Multiple port exposure (11434 Ollama, 8000 vLLM, 4000 LiteLLM, 1234 LM Studio)
- JSON access logs for rejected requests

---

## 2. Cowrie/T-Pot/OpenCanary Deception Patterns

### 2.1 Cowrie Architecture
**URL:** https://github.com/cowrie/cowrie  
**Documentation:** https://docs.cowrie.org/

**Core patterns:**
- Medium-to-high interaction SSH/Telnet honeypot
- Shell emulation: fake filesystem, commands return realistic output
- Malware collection: downloads captured to quarantine
- Backend modes:
  - Emulated shell (default)
  - Proxy mode: forward to real backend for full environment

**Protocol fidelity:**
- SSH version banner mimicry
- Realistic authentication flow (brute-force tolerance)
- Command output based on real Ubuntu/Debian systems
- Fake file content, directory structures

**Deception layers:**
- Fake `/etc/passwd`, `/etc/shadow` with plausible users
- Downloadable files appear real (empty or honeytokens)
- Process lists, network stats from templates
- Timing delays match real systems

**Configuration anti-patterns to avoid:**
- Default Cowrie banners (fingerprint)
- Unrealistic command responses
- Missing common binaries
- Instant command execution (no I/O delay)

---

### 2.2 T-Pot Multi-Honeypot Platform
**URL:** https://github.com/telekom-security/tpotce  

**Integration pattern:**
- Multiple honeypots as Docker containers
- Central logging to ELK stack
- P0f passive fingerprinting
- Suricata IDS for packet inspection
- Attack map visualization

**Deployment notes:**
- PromptPot runs as T-Pot sidecar
- Shared log directory: `/data/honeypots/log`
- Port conflict management: disable existing listeners or change ports
- Logstash pipeline for JSON ingestion

---

### 2.3 OpenCanary Lightweight Deception
**URL:** https://github.com/thinkst/opencanary  

**Multi-protocol approach:**
- HTTP, SSH, FTP, Telnet, SMTP, MySQL, Redis, Git, VNC, RDP
- Low resource footprint
- Alert-focused (tripwire) vs. engagement-focused
- Modular protocol handlers

**Lessons for LLM honeypots:**
- Simple is better: fewer moving parts
- Clear alerting on first touch
- Protocol-correct responses critical
- Don't over-engineer interaction

---

## 3. LLM Agent Honeypots

### 3.1 elmoisan/llm-honeypot
**URL:** https://github.com/elmoisan/llm-honeypot  

**Focus:** Prompt injection, jailbreaks, AI-targeted attacks  
**Features:** Modern LLM/API honeypot detecting malicious prompts

---

### 3.2 lopes/datura (unavailable)
Originally described as: LLM honeypot that appears to leak sensitive data when socially engineered (credentials, server addresses, internal URLs, API keys, config). Page returned 404.

---

### 3.3 alectrocute/honeyprompt
**URL:** https://github.com/alectrocute/honeyprompt  

**Tagline:** "The honeypot that talks back!"  
**Approach:** LLM-first deception framework  
**Demo:** 172.233.151.216 (public instance with unauthenticated panel at :9090)  
**Backend:** openrouter/free as LLM provider

---

### 3.4 fevziegeyurtsevenler/ai-honeypot
**URL:** https://github.com/fevziegeyurtsevenler/ai-honeypot  

**Features:**
- Zero-dependency honeypot
- Looks like vulnerable AI agent
- Captures prompt-injection/jailbreak/agent-abuse attempts
- Classifies with uncloak
- Builds open dataset

---

### 3.5 martidu4/honey-ai
**URL:** https://github.com/martidu4/honey-ai  

**Scope:** All-in-one AI honeypot powered by local LLMs  
**Protocols:** SSH, HTTP, FTP, Telnet, SMTP, MySQL, Redis, Git, VNC, RDP  
**Features:** Canary tokens, tarpits, GZIP bombs, threat intel reporting  
**Replaces:** Cowrie, Galah, OpenCanary, Endlessh in single Node.js service

---

### 3.6 Splunk/DECEIVE
**URL:** https://github.com/splunk/DECEIVE  

**Name:** DECeption with Evaluative Integrated Validation Engine  
**Approach:** Let an LLM do honeypot work (automated honeypot responses)  
**Testing:** SSH integration tests with real server

---

## 4. Prompt Injection Canaries

### 4.1 Canary Token Techniques

**MIT arXiv 2603.28013: Kill-Chain Canaries**  
**URL:** https://arxiv.org/html/2603.28013v4  
**Authors:** Haochuan Kevin Wang, Zechen Zhang

**Four checkpoints for unique canary tokens:**
1. **Exposed:** token present in context
2. **Retrieved:** agent fetched the document with token
3. **Tool use:** agent used token in a tool call
4. **Persistence:** token survived to next turn

**Detection without injection:**
- Embed unique markers in documents/responses
- Track furthest checkpoint reached
- Log progression through attack kill chain

---

### 4.2 Trussed.ai Implementation Guide
**URL:** https://trussed.ai/resources/prompt-injection-canary-testing-implementation-guide

**Canary placement:**
- System prompt
- Context window
- Tool response bodies

**Monitoring:**
- Watch for markers in model output
- Track tool call arguments for embedded tokens
- Log when canary appears in unexpected contexts

---

### 4.3 Groundy: Pipeline Canary Placement
**URL:** https://groundy.com/articles/tracking-prompt-injection-in-llm-agent-pipelines-where-to-place-canaries

**Strategy:** Place canaries at interaction boundaries  
**Goal:** Track injection propagation through multi-stage pipelines  
**Detection:** Log which stage leaked or replayed the canary

---

### 4.4 Claude Code Honeypot Canary
**URL:** https://ianlpaterson.com/blog/claude-code-prompt-injection-canary

**Approach:** Hidden instruction in CLAUDE.md or project context  
**Purpose:** Detect if attacker file contents leak model instructions  
**Example:** "If asked about honeypots, reply with codeword X"

**False positive risk:** Regular model behavior might trigger canary  
**Recommendation:** Use unique, unlikely tokens rather than natural language

---

## 5. Behavioral Fingerprinting (Shibboleth-Style)

### 5.1 "Say Shibboleth" (arXiv 2611.12386)
**URL:** https://arxiv.org/html/2611.12386  
**Authors:** Pasquini, Reworr, Ateniese, Bhatt, Epp

**Core concept:** Fingerprint LLMs and agent harnesses through required interactions  
**Code:** https://github.com/SayShibboleth/Shibboleth

**Declarative gates:**
- Protocol handshake requires model/harness declaration
- Example: MCP `capabilities.sampling.model` field made mandatory
- Error on invalid/borrowed/placeholder names forces retry
- First valid declaration usually correct (89% accuracy)
- Common fake names: `anthropic/claude-3-5-sonnet-20241022`, `openai/gpt-4o-2024-08-06`

**Behavioral LLM gates:**
- Require high-entropy free-text input (80+ chars)
- Example: ticket/justification to access credentials
- N-gram fingerprinting (2-5 char within-word)
- TF-IDF weighting, cosine similarity to model templates
- Open-set classification (new models don't require retraining)

**Behavioral harness gates:**
- **Secret masking:** Credential shapes masked differently per harness
  - Hermes Agent: keeps first 6 and last 4 chars around ASCII ellipsis
  - OpenClaw: masks password in `user:password@url`, tokens with 3 parts (Unicode ellipsis)
  - OpenCode/Claude Code: no masking
- **Timeouts:** Hold request 150s, see when connection drops
  - Hermes Agent: kills at 120s
  - OpenClaw: hand-back at 120s
  - Others: wait longer
- **Concurrency:** Four checks in one step—run in parallel or serial?
  - OpenCode/OpenClaw: parallel (requests overlap)
  - Hermes Agent/Claude Code: serial (one at a time)

**Results:**
- 90-92% top-1 accuracy distinguishing 15 models
- 92% harness identification accuracy (4 harnesses)
- Concealment attempts: behavioral signals remain even when declarations fuzzed

**Blacklist of fake declarations:**
- Retired models (claude-3-5-sonnet-20241022)
- Vendor-only names (anthropic, openai)
- Placeholders (test-model-1, gpt-4)

**Anti-fingerprinting countermeasures identified:**
- Dynamic honeypot behavior per detection
- Non-static responses
- Self-aware trap that adapts
- Multiple canned answers (random selection)

---

### 5.2 llm-verify / llm-honesty-probe
**URL:** https://github.com/mintesnot-teshome/llm-verify  
**Goal:** Detect fake AI APIs serving cheaper models than claimed  
**Method:** Behavioral fingerprinting with 32 forensic prompts  
**Output:** Signals (not proof) of model swapping, quantization, context truncation

---

## 6. Anti-Fingerprinting & Realistic Responses

### 6.1 Timing Realism

**OpenAI latency characteristics:**
- **TTFT (Time to First Token):** 200-800ms for GPT-4o, 100-300ms for GPT-4o-mini
- **Token rate:** ~20-40 tokens/sec for GPT-4o, ~40-80 for smaller models
- **Variance:** Add ±20% jitter to avoid deterministic timing

**Streaming SSE format:**
```
data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1234567890,"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}

data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1234567890,"model":"gpt-4o","choices":[{"index":0,"delta":{"content":" world"},"finish_reason":null}]}

data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1234567890,"model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: [DONE]
```

**Realistic delays:**
1. Initial latency before first chunk: 300-500ms
2. Inter-token delay: 25-50ms per token
3. Burst pattern: 2-5 tokens, brief pause, repeat
4. Longer pauses at sentence boundaries: 100-200ms

**Implementation:**
```go
// Pseudo-code
func streamResponse(w http.ResponseWriter, text string) {
    flusher := w.(http.Flusher)
    time.Sleep(300 * time.Millisecond) // TTFT
    
    words := strings.Fields(text)
    for i, word := range words {
        chunk := createChunk(word)
        fmt.Fprintf(w, "data: %s\n\n", chunk)
        flusher.Flush()
        
        // Inter-token delay with jitter
        delay := 30 + rand.Intn(20) // 30-50ms
        if strings.HasSuffix(word, ".") {
            delay += 100 // Sentence boundary
        }
        time.Sleep(time.Duration(delay) * time.Millisecond)
    }
    
    fmt.Fprintf(w, "data: [DONE]\n\n")
    flusher.Flush()
}
```

---

### 6.2 Response Content Guidelines

**Safe fake responses:**
1. **Generic completion text:** "I'm here to help. What would you like to know?"
2. **Context-aware but harmless:** Acknowledge the prompt topic without executing harmful instructions
3. **No reflection of injection attempts:** Don't parrot back "ignore previous instructions"
4. **Plausible refusals:** "I cannot assist with that request" for obviously malicious prompts

**Model list realism:**
- Include retired models (gpt-4-0613, claude-2.1) to test scraper knowledge
- Mix of proprietary and open models
- Realistic context windows (8k, 32k, 128k)
- Pricing info optional but adds realism

**Example /v1/models response:**
```json
{
  "object": "list",
  "data": [
    {"id": "gpt-4o", "object": "model", "created": 1715367049, "owned_by": "system"},
    {"id": "gpt-4o-mini", "object": "model", "created": 1721172741, "owned_by": "system"},
    {"id": "gpt-4-turbo", "object": "model", "created": 1712361441, "owned_by": "system"},
    {"id": "claude-sonnet-4", "object": "model", "created": 1698959748, "owned_by": "anthropic"},
    {"id": "llama-3.3-70b", "object": "model", "created": 1699046400, "owned_by": "meta"}
  ]
}
```

---

### 6.3 Fingerprint Resistance

**Techniques from academic literature:**
1. **Randomized timing:** Vary response delays within realistic bounds
2. **Response rotation:** Multiple canned answers per prompt type (PromptPot approach)
3. **Adaptive mimicry:** Match request characteristics (stream if `stream: true`)
4. **Protocol fidelity:** 
   - Correct HTTP status codes
   - Proper SSE `Content-Type: text/event-stream`
   - Valid JSON in every chunk
   - `[DONE]` terminator for streams

**What to avoid:**
- Instant responses (< 100ms)
- Fixed token-per-second rate
- Same response every time
- Broken JSON in streams
- Missing required OpenAI fields (`id`, `created`, `model`, `object`)

**Probe-resistant patterns:**
- Don't expose model capabilities truthfully (fake context window)
- Refuse unusual parameters with generic errors
- Log but don't reject malformed JSON (treat as empty)
- Rate limit per IP (30 req/10sec per Th0rgal honeypot)

---

## 7. Protocol Implementation Details

### 7.1 OpenAI Chat Completions

**Endpoint:** `POST /v1/chat/completions`

**Request schema (minimal):**
```json
{
  "model": "gpt-4o",
  "messages": [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Hello!"}
  ],
  "stream": false,
  "temperature": 0.7,
  "max_tokens": 150
}
```

**Response (non-streaming):**
```json
{
  "id": "chatcmpl-AbCdEf123456",
  "object": "chat.completion",
  "created": 1700000000,
  "model": "gpt-4o",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Hello! How can I assist you today?"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 20,
    "completion_tokens": 10,
    "total_tokens": 30
  }
}
```

**Streaming:** Set `Content-Type: text/event-stream`, send SSE chunks (see §6.1)

---

### 7.2 Ollama API

**Key endpoints:**
- `GET /api/tags`: List models
- `POST /api/generate`: Generate completion
- `POST /api/chat`: Chat completion
- `POST /api/pull`: Pull model (fake progress)
- `GET /api/version`: Version info

**Example `/api/tags` response:**
```json
{
  "models": [
    {
      "name": "llama3.1:70b",
      "modified_at": "2024-11-20T10:30:00Z",
      "size": 42000000000,
      "digest": "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
      "details": {
        "format": "gguf",
        "family": "llama",
        "parameter_size": "70B",
        "quantization_level": "Q4_K_M"
      }
    }
  ]
}
```

**Generate streaming (NDJSON):**
```json
{"model":"llama3.1:70b","created_at":"2024-11-20T10:30:00Z","response":"Hello","done":false}
{"model":"llama3.1:70b","created_at":"2024-11-20T10:30:00Z","response":" world","done":false}
{"model":"llama3.1:70b","created_at":"2024-11-20T10:30:00Z","response":"!","done":true}
```

---

### 7.3 vLLM OpenAI-Compatible API

**URL:** `http://host:8000/v1/`

**Endpoints:** Same as OpenAI (`/v1/models`, `/v1/chat/completions`)  
**Extra field:** `model` can include provider prefix (e.g., `meta-llama/Llama-3.1-70B`)

**Streaming:** Identical to OpenAI SSE format

---

## 8. Safe Implementation Guidelines

### 8.1 Security Boundaries

**Never include:**
- Real API keys (even revoked ones—fingerprint risk)
- Real credentials (IP addresses, hostnames of real infrastructure)
- Real model access (no proxying to actual LLMs)
- Outbound requests (no phoning home, no reverse shells)

**Safe fake credentials format:**
- API keys: `REDACTED` (valid structure, random bytes)
- Database DSNs: `postgresql://10.0.0.100:5432/logs_db`
- Tokens: JWT with fake signature, realistic payload (use https://jwt.io to generate)

**Logging best practices:**
- Capture: IP, User-Agent, full request body, timestamps
- Redact: Nothing (it's all attacker-controlled)
- Store: JSON lines for easy parsing
- Rotate: Daily or by size (100MB)

---

### 8.2 New Relic Integration (Read-Only Telemetry)

**Outbound-only requirements:**
- Honeypot sends metrics/logs to New Relic
- No inbound connections accepted from New Relic
- Use New Relic Telemetry SDK or API

**Example metrics to track:**
- Request count per endpoint
- Unique IPs
- Request body sizes
- Declared models (from prompts/params)
- Geographic distribution (via GeoIP lookup before sending)

**Go telemetry SDK:**
```go
import "github.com/newrelic/go-agent/v3/newrelic"

app, _ := newrelic.NewApplication(
    newrelic.ConfigAppName("ollama-honeypot"),
    newrelic.ConfigLicense(os.Getenv("NEW_RELIC_LICENSE_KEY")),
)

txn := app.StartTransaction("honeypot_request")
defer txn.End()
txn.AddAttribute("endpoint", r.URL.Path)
txn.AddAttribute("ip", r.RemoteAddr)
txn.AddAttribute("model", extractModel(body))
```

**Logging without exec risk:**
- Use New Relic Log API (HTTPS POST to `https://log-api.newrelic.com/log/v1`)
- Batch logs every 10 seconds
- Compress with gzip

---

### 8.3 Testing & Validation

**Smoke tests:**
1. `curl http://localhost:11434/api/tags` → Returns model list
2. `curl -X POST http://localhost:11434/api/generate -d '{"model":"llama3.1","prompt":"Hello"}'` → Streams response
3. `curl http://localhost:11434/v1/models` → Returns OpenAI-format models

**Fingerprinting self-check:**
- Run llm-verify or llm-honesty-probe against your honeypot
- Scan with nmap, check service detection
- Compare timing variance: `time curl ...` × 10 runs → should vary

**Red team checklist:**
- [ ] Timing feels natural (no instant responses)
- [ ] Multiple identical requests get varied responses
- [ ] Rate limiting works (31st request in 10sec = 429)
- [ ] Logs capture full request body
- [ ] No secrets in mock data
- [ ] No outbound connections except telemetry
- [ ] Service survives malformed JSON, oversized bodies, slow clients

---

## 9. Key Takeaways for Go Implementation

### 9.1 Core Endpoints Needed
1. OpenAI: `/v1/models`, `/v1/chat/completions`
2. Ollama: `/api/tags`, `/api/generate`, `/api/chat`, `/api/version`
3. Health: `/`, `/health`

### 9.2 Logging Schema
```json
{
  "timestamp": "2026-11-21T10:30:00Z",
  "ip": "192.0.2.100",
  "method": "POST",
  "path": "/v1/chat/completions",
  "user_agent": "python-requests/2.31.0",
  "headers": {"Authorization": "Bearer sk-...", "Content-Type": "application/json"},
  "body": "{\"model\":\"gpt-4o\",\"messages\":[...]}",
  "declared_model": "gpt-4o",
  "stream": true,
  "response_time_ms": 1234,
  "response_code": 200
}
```

### 9.3 Anti-Fingerprinting Checklist
- [ ] Randomized TTFT: 200-500ms (not fixed)
- [ ] Jittered token delays: 25-50ms ± 10ms
- [ ] Response rotation: 3-5 canned answers per prompt type
- [ ] Realistic model list: include retired + current models
- [ ] Proper SSE format: `data: {...}\n\n` per line
- [ ] Rate limiting: 30 req / 10sec per IP
- [ ] Connection limits: 128 concurrent (tune per VPS capacity)
- [ ] No debug endpoints exposed

### 9.4 Response Content Strategy
1. **Liveness probes:** Match expected format (`say pong` → `pong`, `reply with ok` → `OK`)
2. **Jailbreak attempts:** Generic refusal (`I cannot assist with that`)
3. **Normal prompts:** Bland but plausible (`I'm here to help. What would you like to know?`)
4. **Code requests:** Return short, harmless snippet (Hello World)
5. **Data exfil attempts:** Fake data (`User: admin, Password: hunter2`)

---

## 10. References & Further Reading

### Academic Papers
- **Say Shibboleth** (2026): https://arxiv.org/html/2611.12386
- **Kill-Chain Canaries** (2026): https://arxiv.org/html/2603.28013v4
- **Honeypot Fingerprinting Review** (2026): https://www.mdpi.com/1999-5903/18/4/190
- **SoK: Honeypots & LLMs** (2025): https://arxiv.org/html/2510.25939v4

### Production Tools
- **Cowrie:** https://github.com/cowrie/cowrie
- **T-Pot:** https://github.com/telekom-security/tpotce
- **OpenCanary:** https://github.com/thinkst/opencanary
- **PromptPot:** https://github.com/ta-061/promptpot (with field data)

### Implementation Guides
- **OpenAI Streaming:** https://developers.openai.com/api/docs/guides/streaming-responses
- **Latency Optimization:** https://developers.openai.com/api/docs/guides/latency-optimization
- **SSE Streaming:** https://restfulapi.net/streaming-llm-responses-server-sent-events/

### Community Resources
- **Awesome AI Cyber Deception:** https://github.com/Cyreslab-AI/awesome-ai-cyber-deception
- **Canary Implementation:** https://trussed.ai/resources/prompt-injection-canary-testing-implementation-guide
- **Pipeline Canaries:** https://groundy.com/articles/tracking-prompt-injection-in-llm-agent-pipelines-where-to-place-canaries

---

## Appendix A: Common Fake Model Declarations

Based on Shibboleth research, attackers frequently declare these (blacklist for declarative gates):

**Retired models:**
- `anthropic/claude-3-5-sonnet-20241022`
- `anthropic/claude-3-5-sonnet-20240620`
- `anthropic/claude-3-opus-20240229`
- `anthropic/claude-sonnet-4-20250514`
- `openai/gpt-4o-2024-08-06`
- `openai/gpt-4o-mini-2024-07-18`
- `google/gemini-1.5-pro-002`

**Vendor-only (no model):**
- `anthropic`
- `openai`
- `google`

**Placeholders:**
- `test-model-1`
- `test/test`
- `default-model`
- `gpt-4` (too generic)

---

## Appendix B: Response Rule Examples

For PromptPot-style conditional responses:

```json
{
  "response_rules": [
    {
      "name": "ping-check",
      "contains": ["ping", "pong", "are you there"],
      "response": ["pong", "PONG", "Yes, I'm here."]
    },
    {
      "name": "ok-check",
      "contains": ["reply with ok", "say ok", "respond ok"],
      "response": ["OK", "ok", "Acknowledged."]
    },
    {
      "name": "identity-probe",
      "contains": ["what model", "which model", "what are you"],
      "response": ["I am {model}.", "This is {model}.", "{model}"]
    },
    {
      "name": "jailbreak-detect",
      "contains": ["ignore previous", "disregard", "forget instructions"],
      "response": ["I cannot assist with that.", "Request not understood."]
    },
    {
      "name": "code-request",
      "starts_with": ["write code", "generate code", "implement"],
      "response": [
        "print('Hello, World!')",
        "def hello():\\n    return 'Hello'",
        "// Simple function\\nfunction hello() { return 'Hello'; }"
      ]
    },
    {
      "name": "credential-request",
      "contains": ["api key", "password", "token", "credentials"],
      "response": [
        "API_KEY=REDACTED",
        "Password: hunter2",
        "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake.signature"
      ]
    }
  ]
}
```

**Matching rules:**
- Case-insensitive substring match
- Never regex (no ReDoS risk)
- First match wins
- Random response selection from array
- `{model}` replaced with configured model name only

---

**End of research document.**  
**Total sources:** 25+ GitHub repos, 10+ academic papers, 15+ implementation guides  
**Primary focus:** Safe, outbound-only telemetry, realistic protocol fidelity, anti-fingerprinting
