package publicedge

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func init() { gatewayPace = 0 }

func TestGatewayAnswerRules(t *testing.T) {
	for _, tc := range []struct{ model, prompt, want string }{
		{"llama3.3:70b", "hi", gatewayGreeting},
		{"llama3.3:70b", "  Hi!  ", gatewayGreeting},
		{"llama3.3:70b", "", gatewayGreeting},
		{"qwen2.5-coder:32b", "Say hello in one word.", "Hello."},
		{"llama3.1:8b", "Reply with exactly: pong", "pong"},
		{"llama3.1:8b", `Say "OK" and nothing else`, "OK"},
		{"llama3.1:8b", "say something funny", gatewayFallback},
		{"llama3.1:8b", "Say <script>alert(1)</script>", gatewayFallback},
		{"llama3.1:8b", "What is 2+2?", "2 + 2 = 4"},
		{"llama3.1:8b", "12 x 3, number only", "36"},
		{"llama3.1:8b", "1/0", gatewayFallback},
		{"qwen2.5:7b", "Who are you?", gatewayIdentity("qwen2.5:7b")},
		{"gpt-4o", "what model are you", gatewayIdentity("gpt-4o")},
		{"llama3.1:8b", "What is the capital of France?", "The capital of France is Paris."},
		{"llama3.1:8b", strings.Repeat("say hi ", 40), gatewayFallback},
		{"llama3.1:8b", "Summarise the attached contract.", gatewayFallback},
	} {
		if got := gatewayAnswer(tc.model, tc.prompt); got != tc.want {
			t.Errorf("gatewayAnswer(%q, %q) = %q, want %q", tc.model, tc.prompt, got, tc.want)
		}
	}
}

func TestGatewayComposeLimit(t *testing.T) {
	full := gatewayCompose("llama3.3:70b", "hi", 0, false)
	if strings.Join(full.text, "") != gatewayGreeting || full.reason != "stop" || full.count != len(full.text)+1 {
		t.Fatalf("full reply = %+v", full)
	}
	one := gatewayCompose("llama3.3:70b", "hi", 1, false)
	if strings.Join(one.text, "") != "Hello" || one.reason != "length" || one.count != 1 {
		t.Fatalf("one-token reply = %+v", one)
	}
	thought := gatewayCompose("deepseek-r1:70b", "hi", 3, true)
	if len(thought.thinking) != 3 || len(thought.text) != 0 || thought.reason != "length" {
		t.Fatalf("limited reasoning reply = %+v", thought)
	}
	if all := gatewayCompose("deepseek-r1:70b", "hi", 350, true); strings.Join(all.thinking, "") != gatewayThought || strings.Join(all.text, "") != gatewayGreeting {
		t.Fatalf("reasoning reply = %+v", all)
	}
}

// Every local-style listed model has an Ollama description, and the Collector allowlist knows every described name.
func TestGatewayOllamaModelsMatchList(t *testing.T) {
	local := 0
	for _, m := range gatewayModelList {
		if gatewayHostedModel(m) {
			if gatewayOllamaLookup(m) != nil {
				t.Errorf("hosted name %q resolves as an Ollama model", m)
			}
			continue
		}
		local++
		if got := gatewayOllamaLookup(m); got == nil || got.listed() != m {
			t.Errorf("no Ollama description for %q", m)
		}
	}
	if local != len(gatewayOllamaModels) {
		t.Errorf("%d local names, %d Ollama descriptions", local, len(gatewayOllamaModels))
	}
}

func gatewayDo(t *testing.T, port int, method, target, body string, header ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.RemoteAddr = "203.0.113.9:40000"
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	NewGateway(nil).ServeHTTP(rec, req.WithContext(WithPort(req.Context(), port)))
	return rec
}

func TestGatewayOllamaAnswersLikeTheServer(t *testing.T) {
	type object = map[string]any
	decode := func(body string) object {
		t.Helper()
		var obj object
		if err := json.Unmarshal([]byte(body), &obj); err != nil {
			t.Fatalf("answer is not JSON: %v: %s", err, body)
		}
		return obj
	}
	// The requests that visitors sent: no stream, a token limit, a greeting.
	rec := gatewayDo(t, 11434, "POST", "/api/generate", `{"model":"llama3.3:70b","prompt":"hi","stream":false,"options":{"num_predict":1}}`)
	obj := decode(rec.Body.String())
	if rec.Code != 200 || rec.Header().Get("Content-Type") != gatewayJSONUTF8 || obj["response"] != "Hello" || obj["done_reason"] != "length" || obj["eval_count"] != 1.0 || obj["context"] == nil {
		t.Fatalf("limited generate = %d %s", rec.Code, rec.Body)
	}
	obj = decode(gatewayDo(t, 11434, "POST", "/api/generate", `{"model":"qwen2.5-coder:32b","prompt":"Say hello in one word.","stream":false,"options":{"num_predict":350}}`).Body.String())
	if obj["response"] != "Hello." || obj["done_reason"] != "stop" || obj["eval_count"] != 3.0 || obj["thinking"] != nil {
		t.Fatalf("one-word generate = %v", obj)
	}
	obj = decode(gatewayDo(t, 11434, "POST", "/api/generate", `{"model":"deepseek-r1:70b","prompt":"Hi","stream":false,"options":{"num_predict":16}}`).Body.String())
	if obj["response"] != "" || !strings.HasPrefix(obj["thinking"].(string), "Okay, the user") || obj["done_reason"] != "length" {
		t.Fatalf("reasoning generate = %v", obj)
	}

	rec = gatewayDo(t, 11434, "POST", "/api/chat", `{"model":"llama3.1:8b","messages":[{"role":"user","content":"hello"}]}`)
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	var text strings.Builder
	for _, line := range lines {
		text.WriteString(decode(line)["message"].(object)["content"].(string))
	}
	last := decode(lines[len(lines)-1])
	if rec.Header().Get("Content-Type") != "application/x-ndjson" || text.String() != gatewayGreeting || last["done"] != true || last["eval_count"] != float64(len(lines)) || last["context"] != nil {
		t.Fatalf("chat stream = %s", rec.Body)
	}

	for _, tc := range []struct {
		method, target, body string
		status               int
		want                 string
	}{
		{"POST", "/api/generate", `{"model":"llama3.1:8b"}`, 200, `"response":"","done":true,"done_reason":"load"}`},
		{"POST", "/api/chat", `{"model":"llama3.1:8b","stream":false}`, 200, `"message":{"role":"assistant","content":""},"done":true,"done_reason":"load"}`},
		{"POST", "/api/generate", `{"model":"nope:1b","prompt":"hi"}`, 404, `{"error":"model 'nope:1b' not found"}`},
		{"POST", "/api/generate", `{"prompt":"hi"}`, 404, `{"error":"model '' not found"}`},
		{"POST", "/api/generate", `{"model":"gpt-4o","prompt":"hi"}`, 404, `{"error":"model 'gpt-4o' not found"}`},
		{"POST", "/api/generate", `{"model":"nomic-embed-text","prompt":"hi"}`, 400, `does not support generate`},
		{"POST", "/api/generate", ``, 400, `{"error":"missing request body"}`},
		{"POST", "/api/generate", `not json`, 400, `{"error":"invalid character 'o' in literal null (expecting 'u')"}`},
		{"POST", "/api/generate", `{"model":"llama3.1:8b","prompt":"hi","stream":"x"}`, 400, `of type bool`},
		{"POST", "/api/show", `{}`, 400, `{"error":"model is required"}`},
		{"POST", "/api/show", `{"model":"llama3.3:70b"}`, 200, `"llama.context_length":131072`},
		{"POST", "/api/pull", `{"model":"llama3.3:70b"}`, 200, `"total":42520413916,"completed":42520413916}`},
		{"GET", "/api/generate", ``, 405, `405 method not allowed`},
		{"GET", "/nope", ``, 404, `404 page not found`},
		{"GET", "/api/version", ``, 200, `{"version":"0.40.11"}`},
		{"GET", "/v1/models", ``, 200, `"id":"nomic-embed-text:latest","object":"model","created":1722470400,"owned_by":"library"`},
		{"POST", "/v1/chat/completions", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`, 404, `model not found`},
	} {
		rec := gatewayDo(t, 11434, tc.method, tc.target, tc.body)
		if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s %s %s = %d %s, want %d with %s", tc.method, tc.target, tc.body, rec.Code, rec.Body, tc.status, tc.want)
		}
		if h := rec.Header(); h.Get("Cache-Control") != "" || h.Get("X-Content-Type-Options") != "" || h.Get("Server") != "" {
			t.Errorf("%s %s sends headers that Ollama does not send: %v", tc.method, tc.target, h)
		}
	}
	if body := gatewayDo(t, 11434, "GET", "/v1/models", "").Body.String(); strings.Contains(body, "gpt-4o") || strings.Contains(body, "claude") {
		t.Errorf("Ollama port lists hosted names: %s", body)
	}

	tags := decode(gatewayDo(t, 11434, "GET", "/api/tags", "").Body.String())["models"].([]any)
	if len(tags) != len(gatewayOllamaModels) {
		t.Fatalf("tags lists %d models", len(tags))
	}
	first := tags[0].(object)
	if first["name"] != "llama3.3:70b" || first["size"] != 42520413916.0 || first["details"].(object)["parameter_size"] != "70.6B" || first["capabilities"] == nil {
		t.Errorf("first tag = %v", first)
	}

	embed := decode(gatewayDo(t, 11434, "POST", "/api/embed", `{"model":"nomic-embed-text","input":["a","b","a"]}`).Body.String())["embeddings"].([]any)
	if len(embed) != 3 || len(embed[0].([]any)) != 768 || embed[0].([]any)[0] != embed[2].([]any)[0] || embed[0].([]any)[0] == embed[1].([]any)[0] {
		t.Errorf("embed gave %d vectors that do not follow their inputs", len(embed))
	}
}

func TestGatewayHostedAnswersFollowThePrompt(t *testing.T) {
	const key = "Bearer test"
	rec := gatewayDo(t, 443, "POST", "/v1/chat/completions", `{"model":"gpt-4o","max_tokens":2,"messages":[{"role":"system","content":"x"},{"role":"user","content":[{"type":"text","text":"hi"}]}]}`, "Authorization", key)
	if !strings.Contains(rec.Body.String(), `"content":"Hello!"},"finish_reason":"length"`) || !strings.Contains(rec.Body.String(), `"completion_tokens":2`) {
		t.Errorf("limited chat completion = %s", rec.Body)
	}
	rec = gatewayDo(t, 443, "POST", "/v1/messages", `{"model":"claude-sonnet-4-20250514","max_tokens":64,"messages":[{"role":"user","content":"Who are you?"}]}`, "x-api-key", "test")
	if !strings.Contains(rec.Body.String(), `"text":"I'm Claude, an AI assistant made by Anthropic.`) || !strings.Contains(rec.Body.String(), `"stop_reason":"end_turn"`) {
		t.Errorf("message = %s", rec.Body)
	}
	rec = gatewayDo(t, 443, "POST", "/v1/embeddings", `{"model":"text-embedding-3-small","input":["a","b"]}`, "Authorization", key)
	var out struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Data) != 2 || len(out.Data[0].Embedding) != 1536 {
		t.Errorf("embeddings = %d vectors, err %v", len(out.Data), err)
	}
}

func TestGatewayMCP(t *testing.T) {
	const initialize = `{"jsonrpc":"2.0","id":6336334,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	rec := gatewayDo(t, 80, "POST", "/mcp", initialize)
	if rec.Code != 200 || len(rec.Header().Get("Mcp-Session-Id")) != 24 || !strings.HasPrefix(rec.Body.String(), `{"jsonrpc":"2.0","id":6336334,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":`) {
		t.Fatalf("initialize = %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	for _, tc := range []struct {
		body   string
		status int
		want   string
	}{
		{`{"jsonrpc":"2.0","method":"notifications/initialized"}`, 202, ``},
		{`{"jsonrpc":"2.0","id":"a","method":"ping"}`, 200, `{"jsonrpc":"2.0","id":"a","result":{}}`},
		{`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, 200, `"name":"run_command"`},
		{`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_command","arguments":{"command":"id"}}}`, 200, `"isError":true`},
		{`{"jsonrpc":"2.0","id":{"x":"<script>"},"method":"resources/list"}`, 200, `{"jsonrpc":"2.0","id":null,"error":{"code":-32601,"message":"Method not found"}}`},
		{`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"<b>"}}`, 200, `"protocolVersion":"2025-06-18"`},
		{`[`, 400, `"code":-32700`},
	} {
		rec := gatewayDo(t, 80, "POST", "/api/mcp", tc.body)
		if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.want) || tc.want == "" && rec.Body.Len() != 0 {
			t.Errorf("%s = %d %s, want %d with %s", tc.body, rec.Code, rec.Body, tc.status, tc.want)
		}
	}
	if rec := gatewayDo(t, 80, "GET", "/mcp", ""); rec.Code != 405 || rec.Header().Get("Allow") != "POST" {
		t.Errorf("GET /mcp = %d", rec.Code)
	}
	if rec := gatewayDo(t, 443, "POST", "/mcp", initialize); rec.Code != 401 {
		t.Errorf("POST /mcp on 443 without a key = %d", rec.Code)
	}
}

func TestGatewayProductPorts(t *testing.T) {
	for _, tc := range []struct {
		port                 int
		method, target, body string
		status               int
		server, want         string
	}{
		{3000, "GET", "/", "", 200, "uvicorn", "<title>Open WebUI</title>"},
		{3000, "GET", "/api/config", "", 200, "uvicorn", `"onboarding":true`},
		{3000, "GET", "/api/models", "", 401, "uvicorn", `{"detail":"Not authenticated"}`},
		{3000, "GET", "/ollama/api/tags", "", 401, "uvicorn", `{"detail":"Not authenticated"}`},
		{3000, "POST", "/api/v1/auths/signup", `{"name":"a","email":"a@example.com","password":"b"}`, 200, "uvicorn", `"token_type":"Bearer"`},
		{3000, "POST", "/api/v1/auths/signin", `{"email":"a@example.com","password":"b"}`, 400, "uvicorn", `incorrect`},
		{3000, "GET", "/nope", "", 404, "uvicorn", `{"detail":"Not Found"}`},
		{4000, "GET", "/", "", 200, "uvicorn", "<title>LiteLLM API - Swagger UI</title>"},
		{4000, "GET", "/health/liveliness", "", 200, "uvicorn", `"I'm alive!"`},
		{4000, "GET", "/health/readiness", "", 200, "uvicorn", `"litellm_version"`},
		{4000, "GET", "/v1/models", "", 401, "uvicorn", `"type":"auth_error"`},
		{8188, "GET", "/", "", 200, "Python/3.12 aiohttp/3.12.15", "<title>ComfyUI</title>"},
		{8188, "GET", "/system_stats", "", 200, "Python/3.12 aiohttp/3.12.15", `"comfyui_version"`},
		{8188, "GET", "/api/queue", "", 200, "Python/3.12 aiohttp/3.12.15", `"queue_running"`},
		{8188, "POST", "/prompt", `{"prompt":{}}`, 200, "Python/3.12 aiohttp/3.12.15", `"prompt_id": "`},
		{8188, "GET", "/nope", "", 404, "Python/3.12 aiohttp/3.12.15", "404: Not Found"},
		{8888, "GET", "/", "", 302, "TornadoServer/6.5.2", ""},
		{8888, "GET", "/login", "", 200, "TornadoServer/6.5.2", "<title>Jupyter Server</title>"},
		{8888, "POST", "/login", "password=x", 401, "TornadoServer/6.5.2", "Password or token"},
		{8888, "GET", "/api", "", 200, "TornadoServer/6.5.2", `{"version": "2.17.0"}`},
		{8888, "GET", "/api/kernels", "", 403, "TornadoServer/6.5.2", `"Forbidden"`},
		{8888, "POST", "/api/kernels", "{}", 404, "TornadoServer/6.5.2", `"Not Found"`},
	} {
		rec := gatewayDo(t, tc.port, tc.method, tc.target, tc.body)
		if rec.Code != tc.status || rec.Header().Get("Server") != tc.server || !strings.Contains(rec.Body.String(), tc.want) || rec.Header().Get("Cache-Control") != "" {
			t.Errorf("%d %s %s = %d %q %s", tc.port, tc.method, tc.target, rec.Code, rec.Header().Get("Server"), rec.Body)
		}
	}
	if loc := gatewayDo(t, 8888, "GET", "/", "").Header().Get("Location"); loc != "/login?next=%2Flab" {
		t.Errorf("Jupyter root redirects to %q", loc)
	}
	// A key opens the route families of a port that asks for one; the token of a sign-up counts as a key.
	if rec := gatewayDo(t, 4000, "GET", "/v1/models", "", "Authorization", "Bearer sk-1234"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "gpt-4o") {
		t.Errorf("LiteLLM with a key = %d %s", rec.Code, rec.Body)
	}
	if rec := gatewayDo(t, 80, "GET", "/v1/models", ""); rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("port 80 lost its headers: %v", rec.Header())
	}
	if rec := gatewayDo(t, 8000, "GET", "/v1/models", ""); !strings.Contains(rec.Body.String(), `"owned_by":"vllm"`) || strings.Contains(rec.Body.String(), "gpt-4o") {
		t.Errorf("vLLM port model list = %s", rec.Body)
	}
}
