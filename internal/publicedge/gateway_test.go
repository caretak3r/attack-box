package publicedge

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestGatewayModelsRoute(t *testing.T) {
	g := NewGateway(nil)
	req := httptest.NewRequest("GET", "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer test") // port 443 is the default port, and it answers 401 without a credential
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"local-instruct-8b"`) {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

func TestGatewayChatCompletion(t *testing.T) {
	g := NewGateway(nil)
	body := `{"model":"local-instruct-8b","messages":[{"role":"user","content":"test"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"chatcmpl-`) {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

func TestGatewayStreamingChatCompletion(t *testing.T) {
	g := NewGateway(nil)
	body := `{"model":"local-instruct-8b","messages":[{"role":"user","content":"test"}],"stream":true}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("expected text/event-stream, got %s", w.Header().Get("Content-Type"))
	}
	if !strings.Contains(w.Body.String(), "data: [DONE]") {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

func TestGatewayCompletion(t *testing.T) {
	g := NewGateway(nil)
	body := `{"model":"local-instruct-8b","prompt":"test"}`
	req := httptest.NewRequest("POST", "/v1/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"cmpl-`) {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

func TestGatewayAzureDeployment(t *testing.T) {
	g := NewGateway(nil)
	body := `{"messages":[{"role":"user","content":"test"}]}`
	req := httptest.NewRequest("POST", "/openai/deployments/local-instruct-8b/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"chatcmpl-`) {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

func TestGatewayRejectsUnknownModel(t *testing.T) {
	g := NewGateway(nil)
	body := `{"model":"unknown","messages":[{"role":"user","content":"test"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGatewayRejectsInvalidRequest(t *testing.T) {
	g := NewGateway(nil)
	body := `{"model":"local-instruct-8b"}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestGatewayDoesNotRedirectUntrustedTargets(t *testing.T) {
	w := httptest.NewRecorder()
	NewGateway(nil).ServeHTTP(w, httptest.NewRequest("GET", "/v1//models?note=synthetic-marker", nil))
	if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), "synthetic-marker") {
		t.Fatal("noncanonical target was redirected or reflected")
	}
}

func TestGatewayRejectsLargeBody(t *testing.T) {
	g := NewGateway(nil)
	body := strings.Repeat("x", 65*1024)
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
}

func TestGatewayBusyWhenSlotsFull(t *testing.T) {
	g := NewGateway(nil)
	for i := 0; i < 16; i++ {
		g.slots <- struct{}{}
	}
	req := httptest.NewRequest("GET", "/v1/models", nil)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") != "1" {
		t.Fatalf("expected Retry-After: 1, got %s", w.Header().Get("Retry-After"))
	}
}

func TestGatewayWriterFlush(t *testing.T) {
	w := &gatewayWriter{ResponseWriter: httptest.NewRecorder()}
	w.Flush()
	if w.status != http.StatusOK {
		t.Fatalf("expected status 200 after flush, got %d", w.status)
	}
}

func TestGatewayReadObjectRejectsInvalid(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	_, status := gatewayReadObject(req)
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", status)
	}
}

func TestGatewayReadObjectRejectsOversized(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/completions", strings.NewReader(`{"prompt":"`+strings.Repeat("x", gatewayBodyLimit)+`"}`))
	req.ContentLength = -1
	req.Header.Set("Authorization", "Bearer test")
	w := httptest.NewRecorder()
	NewGateway(nil).ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for an oversized chunked body, got %d", w.Code)
	}
}

func TestClientAddress(t *testing.T) {
	tests := []struct {
		name   string
		remote string
		want   string
	}{
		{"public IPv4", "203.0.113.42:12345", "203.0.113.42"},
		{"IPv6", "[2001:db8::1]:8080", ""},
		{"loopback", "127.0.0.1:443", ""},
		{"private 10", "10.1.2.3:443", ""},
		{"private 192.168", "192.168.1.1:443", ""},
		{"private 172.16-31", "172.20.0.1:443", ""},
		{"link-local", "169.254.1.1:443", ""},
		{"shared 100.64/10", "100.65.0.1:443", ""},
		{"multicast", "224.0.0.1:443", ""},
		{"first octet zero", "0.1.2.3:443", ""},
		{"mapped IPv4", "[::ffff:203.0.113.5]:443", "203.0.113.5"},
		{"scoped mapped", "[::ffff:203.0.113.5%eth0]:443", ""},
		{"invalid port", "203.0.113.1:http", ""},
		{"no port", "203.0.113.1", ""},
		{"invalid", "not-an-ip", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClientAddress(tt.remote)
			if got != tt.want {
				t.Errorf("ClientAddress(%q) = %q, want %q", tt.remote, got, tt.want)
			}
		})
	}
}

func TestGatewayContentType(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"application/json", "application/json", "application/json"},
		{"json with charset", "application/json; charset=utf-8", "application/json"},
		{"json mixed case", "Application/JSON", "application/json"},
		{"text/plain", "text/plain", "text/plain"},
		{"octet-stream", "application/octet-stream", "application/octet-stream"},
		{"form-urlencoded", "application/x-www-form-urlencoded", "application/x-www-form-urlencoded"},
		{"multipart", "multipart/form-data", "multipart/form-data"},
		{"multipart with boundary", "multipart/form-data; boundary=----", "multipart/form-data"},
		{"other type", "application/xml", "other"},
		{"empty", "", "none"},
		{"whitespace", "  ", "none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := gatewayContentType(tt.header)
			if got != tt.want {
				t.Errorf("gatewayContentType(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestGatewayRequestEvidence(t *testing.T) {
	const peer = "203.0.113.42:12345"
	const completion = `{"model":"local-instruct-8b","prompt":"fixture-private","stream":false}`
	const defaults = `{"prompt":"fixture-private"}`
	for _, tc := range []struct {
		name, method, path, route, remote, body string
		unknownLength                           bool
		status                                  int
		want                                    []attribute.KeyValue
	}{
		{"mapped HEAD", "HEAD", "/v1/models?q=fixture-private&b=2", "/v1/models", "[::ffff:203.0.113.42]:443", "", false, 200,
			[]attribute.KeyValue{attribute.String("client.address", "203.0.113.42"), attribute.Int64("http.request.body.size", 0), attribute.Int("attackbox.request.query_params", 2)}},
		{"chunked completion", "POST", "/v1/completions", "/v1/completions", peer, completion, true, 200,
			[]attribute.KeyValue{attribute.String("client.address", "203.0.113.42"), attribute.Int64("http.request.body.size", int64(len(completion))), attribute.String("gen_ai.request.model", gatewayModel), attribute.Bool("attackbox.request.stream", false), attribute.Int("attackbox.request.query_params", 0)}},
		{"implicit model and stream", "POST", "/v1/completions", "/v1/completions", "172.19.0.1:12345", defaults, false, 200,
			[]attribute.KeyValue{attribute.Int64("http.request.body.size", int64(len(defaults))), attribute.Int("attackbox.request.query_params", 0)}},
		{"unread chunked body", "GET", "/fixture-private", "/unmatched", "127.0.0.1:443", "fixture-private", true, 404,
			[]attribute.KeyValue{attribute.Int("attackbox.request.query_params", 0), attribute.String("attackbox.probe.class", "other")}},
		{"family variant", "POST", "/proxy/v1/api/completions?filter=fixture-private", "/proxy/v1/api/completions", peer, completion, false, 200,
			[]attribute.KeyValue{attribute.String("client.address", "203.0.113.42"), attribute.Int64("http.request.body.size", int64(len(completion))), attribute.String("gen_ai.request.model", gatewayModel), attribute.Bool("attackbox.request.stream", false), attribute.Int("attackbox.request.query_params", 1)}},
		{"query credential", "GET", "/v1/models?key=AIzaFixture", "/v1/models", peer, "", false, 200,
			[]attribute.KeyValue{attribute.String("client.address", "203.0.113.42"), attribute.Int64("http.request.body.size", 0), attribute.Int("attackbox.request.query_params", 1),
				attribute.String("attackbox.credential.source", "query"), attribute.String("attackbox.credential.type", "google"), attribute.String("attackbox.credential.value", "AIzaFixture")}},
	} {
		// The local capture must never change what a span exports.
		for _, captured := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s capture=%v", tc.name, captured), func(t *testing.T) {
				rec := tracetest.NewSpanRecorder()
				tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
				defer tp.Shutdown(t.Context())
				r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
				r.RemoteAddr = tc.remote
				if tc.unknownLength {
					r.ContentLength = -1
				}
				r.Header.Set("Content-Type", "Application/JSON; secret=fixture-private")
				r.Header.Set("X-Forwarded-For", "198.51.100.1")
				r.Header.Set("X-Real-IP", "198.51.100.2")
				g := NewGateway(tp.Tracer("test"))
				if captured {
					c, err := OpenCapture(t.TempDir())
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					g.Capture = c
				}
				// Port 80: port 443 needs a credential, and a credential adds attributes to each case.
				g.ServeHTTP(httptest.NewRecorder(), r.WithContext(WithPort(r.Context(), 80)))
				spans := rec.Ended()
				if len(spans) != 1 || spans[0].Name() != "public.request" {
					t.Fatal("missing public.request span")
				}
				want := attribute.NewSet(append([]attribute.KeyValue{
					attribute.Int("server.port", 80), attribute.String("attackbox.persona", "cloud-gateway"),
					attribute.String("http.route", tc.route), attribute.String("http.request.method", tc.method),
					attribute.Int("http.response.status_code", tc.status), attribute.String("attackbox.request.content_type", gatewayJSON),
				}, tc.want...)...)
				got := attribute.NewSet(spans[0].Attributes()...)
				if !want.Equals(&got) {
					t.Errorf("request attributes = %v, want %v", got.ToSlice(), want.ToSlice())
				}
			})
		}
	}
}

func TestGatewayRouteFamilies(t *testing.T) {
	const chat = `{"model":"local-instruct-8b","messages":[{"role":"user","content":"x"}]}`
	for _, tc := range []struct {
		method, path, body, route string
		status                    int
		contentType, contains     string
	}{
		{"POST", "/v1/api/completions", `{"prompt":"x"}`, "/v1/api/completions", 200, gatewayJSON, `"text_completion"`},
		{"POST", "/chat/completions", chat, "/chat/completions", 200, gatewayJSON, `"chat.completion"`},
		{"POST", "/openai/v1/chat/completions", chat, "/openai/v1/chat/completions", 200, gatewayJSON, `"chat.completion"`},
		{"POST", "/v1/engines/local-instruct-8b/completions", `{"prompt":"x"}`, "/v1/engines/{model}/completions", 200, gatewayJSON, `"text_completion"`},
		{"POST", "/openai/deployments/gpt-5-preview/chat/completions", chat, "/openai/deployments/{deployment}/chat/completions", 404, gatewayJSON, "model not found"},
		{"POST", "/openai/deployments/gpt-4o/chat/completions", `{"messages":[{"role":"user","content":"x"}]}`, "/openai/deployments/{deployment}/chat/completions", 200, gatewayJSON, `"model":"gpt-4o"`},
		{"POST", "/v1/chat/completions", `{"model":"claude-3-5-sonnet-20241022","stream":true,"messages":[{"role":"user","content":"x"}]}`, "/v1/chat/completions", 200, "text/event-stream", `"model":"claude-3-5-sonnet-20241022"`},
		{"GET", "/api/v1/models", "", "/api/v1/models", 200, gatewayJSON, `"local-instruct-8b"`},
		{"POST", "/v1/models", "", "/v1/models", 405, "text/plain; charset=utf-8", "Method Not Allowed"},
		{"POST", "/v1/embeddings", `{"input":"x"}`, "/v1/embeddings", 200, gatewayJSON, `"embedding"`},
		{"POST", "/v1/messages", `{"model":"local-instruct-8b","max_tokens":8,"messages":[{"role":"user","content":"x"}]}`, "/v1/messages", 200, gatewayJSON, `"type":"message"`},
		{"POST", "/v1/messages", `{"model":"local-instruct-8b","max_tokens":8,"stream":true,"messages":[{"role":"user","content":"x"}]}`, "/v1/messages", 200, "text/event-stream", "event: message_stop"},
		{"POST", "/v1/messages", `{"model":"claude-3","max_tokens":8,"messages":[{"role":"user","content":"x"}]}`, "/v1/messages", 404, gatewayJSON, "not_found_error"},
		{"POST", "/v1/messages", `{"model":"local-instruct-8b","messages":[{"role":"user","content":"x"}]}`, "/v1/messages", 400, gatewayJSON, "invalid_request_error"},
		{"GET", "/api/tags", "", "/api/tags", 200, gatewayJSONUTF8, `"local-instruct-8b:latest"`},
		{"GET", "/api/tags", "", "/api/tags", 200, gatewayJSONUTF8, `"name":"deepseek-r1:8b"`},
		{"POST", "/api/chat", `{"model":"qwen2.5:7b","stream":false,"messages":[{"role":"user","content":"x"}]}`, "/api/chat", 200, gatewayJSONUTF8, `"model":"qwen2.5:7b"`},
		{"POST", "/api/chat", `{"model":"local-instruct-8b","messages":[{"role":"user","content":"x"}]}`, "/api/chat", 200, "application/x-ndjson", `"done":true`},
		{"POST", "/ollama/api/generate", `{"model":"local-instruct-8b:latest","prompt":"x","stream":false}`, "/ollama/api/generate", 200, gatewayJSONUTF8, `"response":"I'm here to help!`},
		{"POST", "/api/generate", `{"model":"llama3","prompt":"x"}`, "/api/generate", 404, gatewayJSONUTF8, "model 'llama3' not found"},
		{"GET", "/api/tags", "", "/api/tags", 200, gatewayJSONUTF8, `"name":"llama3.3:70b","model":"llama3.3:70b","modified_at":"2026-`},
		{"GET", "/api/tags", "", "/api/tags", 200, gatewayJSONUTF8, `"parameter_size":"8.0B","quantization_level":"Q4_K_M","context_length":131072`},
		{"POST", "/api/show", `{"model":"llama3.3:70b"}`, "/api/show", 200, gatewayJSONUTF8, `"parameter_size":"70.6B"`},
		{"POST", "/api/show", `{"name":"llama3"}`, "/api/show", 404, gatewayJSONUTF8, "model 'llama3' not found"},
		{"POST", "/api/show", `{"stream":false}`, "/api/show", 400, gatewayJSONUTF8, "model is required"},
		{"POST", "/api/pull", `{"model":"llama3.1:8b"}`, "/api/pull", 200, "application/x-ndjson", `{"status":"writing manifest"}` + "\n" + `{"status":"success"}` + "\n"},
		{"POST", "/api/pull", `{"name":"other/model:1b"}`, "/api/pull", 200, "application/x-ndjson", `{"status":"pulling manifest"}` + "\n" + `{"error":"pull model manifest: file does not exist"}` + "\n"},
		{"POST", "/api/pull", `{"model":"other/model:1b","stream":false}`, "/api/pull", 404, gatewayJSONUTF8, "file does not exist"},
		{"POST", "/api/create", `{"model":"mine","from":"llama3.1:8b","stream":false}`, "/api/create", 200, gatewayJSONUTF8, `{"status":"success"}`},
		{"DELETE", "/api/delete", `{"model":"mistral:7b"}`, "/api/delete", 200, "", ""},
		{"POST", "/api/delete", `{"model":"mistral:7b"}`, "/api/delete", 405, "text/plain; charset=utf-8", "Method Not Allowed"},
		{"POST", "/api/embed", `{"model":"nomic-embed-text","input":"x"}`, "/api/embed", 200, gatewayJSONUTF8, `"model":"nomic-embed-text:latest","embeddings":[[`},
		{"POST", "/ollama/api/embeddings", `{"model":"nomic-embed-text","prompt":"x"}`, "/ollama/api/embeddings", 200, gatewayJSONUTF8, `{"embedding":[`},
		{"POST", "/xyz/completions", `{"prompt":"x"}`, "/unmatched", 404, "text/plain; charset=utf-8", "404 page not found"},
		{"POST", "/v1/v1/v1/v1/v1/completions", `{"prompt":"x"}`, "/unmatched", 404, "text/plain; charset=utf-8", "404 page not found"},
		{"GET", "/9f1c2e7a", "", "/unmatched", 404, "text/plain; charset=utf-8", "404 page not found"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := tracetest.NewSpanRecorder()
			tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
			defer tp.Shutdown(t.Context())
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			// Port 80: port 443 needs a credential.
			NewGateway(tp.Tracer("test")).ServeHTTP(w, r.WithContext(WithPort(r.Context(), 80)))
			if w.Code != tc.status || w.Header().Get("Content-Type") != tc.contentType || !strings.Contains(w.Body.String(), tc.contains) {
				t.Fatalf("got %d %q %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
			}
			if strings.HasPrefix(tc.contentType, gatewayJSON) && !json.Valid(w.Body.Bytes()) {
				t.Fatalf("answer is not JSON: %s", w.Body.String())
			}
			var route string
			for _, a := range rec.Ended()[0].Attributes() {
				if a.Key == "http.route" {
					route = a.Value.AsString()
				}
			}
			if route != tc.route {
				t.Fatalf("route = %q, want %q", route, tc.route)
			}
		})
	}
}

func TestGatewayPortPersonas(t *testing.T) {
	for _, tc := range []struct {
		port                      int
		method, path, route       string
		status                    int
		contentType, body, server string
	}{
		{11434, "GET", "/", "/", 200, "text/plain; charset=utf-8", "Ollama is running", ""},
		{11434, "GET", "/api/version", "/api/version", 200, gatewayJSONUTF8, `{"version":"0.40.11"}`, ""},
		{11434, "POST", "/", "/unmatched", 404, "text/plain", "404 page not found", ""},
		{443, "GET", "/", "/unmatched", 404, "text/plain; charset=utf-8", "404 page not found\n", ""},
		{443, "GET", "/api/version", "/unmatched", 404, "text/plain; charset=utf-8", "404 page not found\n", ""},
		{80, "GET", "/health", "/unmatched", 404, "text/plain; charset=utf-8", "404 page not found\n", ""},
		{1234, "GET", "/", "/unmatched", 200, gatewayJSONUTF8, `{"error":"Unexpected endpoint or method. (GET /)"}`, ""},
		{1234, "POST", `/a"b`, "/unmatched", 200, gatewayJSONUTF8, `{"error":"Unexpected endpoint or method. (POST /a\"b)"}`, ""},
		{8000, "GET", "/health", "/health", 200, "", "", "uvicorn"},
		{8000, "GET", "/version", "/version", 200, gatewayJSON, `{"version":"0.10.2"}`, "uvicorn"},
		{8000, "GET", "/nope", "/unmatched", 404, gatewayJSON, `{"detail":"Not Found"}`, "uvicorn"},
		{8080, "GET", "/health", "/health", 200, gatewayJSONUTF8, `{"status":"ok"}`, "llama.cpp"},
		{8080, "POST", "/health", "/unmatched", 404, gatewayJSONUTF8, `{"error":{"code":404,"message":"File Not Found","type":"not_found_error"}}`, "llama.cpp"},
		{443, "GET", "/v1/models", "/v1/models", 401, gatewayJSON, gatewayNoKey, ""},
		{443, "POST", "/v1/models", "/v1/models", 401, gatewayJSON, gatewayNoKey, ""},
	} {
		t.Run(fmt.Sprintf("%d %s %s", tc.port, tc.method, tc.path), func(t *testing.T) {
			rec := tracetest.NewSpanRecorder()
			tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
			defer tp.Shutdown(t.Context())
			r := httptest.NewRequest(tc.method, "/", nil)
			r.URL.Path = tc.path
			w := httptest.NewRecorder()
			NewGateway(tp.Tracer("test")).ServeHTTP(w, r.WithContext(WithPort(r.Context(), tc.port)))
			if w.Code != tc.status || w.Header().Get("Content-Type") != tc.contentType || w.Body.String() != tc.body || w.Header().Get("Server") != tc.server {
				t.Fatalf("got %d %q server %q %s", w.Code, w.Header().Get("Content-Type"), w.Header().Get("Server"), w.Body.String())
			}
			for _, a := range rec.Ended()[0].Attributes() {
				if a.Key == "http.route" && a.Value.AsString() != tc.route {
					t.Fatalf("route = %q, want %q", a.Value.AsString(), tc.route)
				}
			}
		})
	}

	// A local model server lists the local-style names only, and a generic family keeps working on a persona port.
	for path, want := range map[string][2]string{"/api/v0/models": {`"id":"local-instruct-8b"`, "gpt-4o"}, "/v1/models": {`"owned_by":"organization_owner"`, "gpt-4o"}} {
		r := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		NewGateway(nil).ServeHTTP(w, r.WithContext(WithPort(r.Context(), 1234)))
		if w.Code != 200 || !strings.Contains(w.Body.String(), want[0]) || strings.Contains(w.Body.String(), want[1]) {
			t.Errorf("port 1234 %s: %d %s", path, w.Code, w.Body.String())
		}
	}

	// Port 443 accepts any credential, and the other ports do not ask for one.
	for _, tc := range []struct {
		port         int
		path, header string
	}{{443, "/v1/models", "Authorization"}, {443, "/v1/models", "X-Api-Key"}, {443, "/v1/models?key=any", ""}, {80, "/v1/models", ""}, {11434, "/api/tags", ""}} {
		r := httptest.NewRequest("GET", tc.path, nil)
		if tc.header != "" {
			r.Header.Set(tc.header, "any")
		}
		w := httptest.NewRecorder()
		NewGateway(nil).ServeHTTP(w, r.WithContext(WithPort(r.Context(), tc.port)))
		if w.Code != 200 {
			t.Errorf("port %d %s %s: %d", tc.port, tc.path, tc.header, w.Code)
		}
	}

	r := httptest.NewRequest("GET", "/api/ps", nil)
	w := httptest.NewRecorder()
	NewGateway(nil).ServeHTTP(w, r.WithContext(WithPort(r.Context(), 11434)))
	var ps struct {
		Models []struct {
			Name      string
			SizeVRAM  int64     `json:"size_vram"`
			ExpiresAt time.Time `json:"expires_at"`
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &ps); err != nil || len(ps.Models) != 1 || ps.Models[0].Name != "llama3.3:70b" || ps.Models[0].SizeVRAM < 40<<30 || !ps.Models[0].ExpiresAt.After(time.Now()) {
		t.Errorf("/api/ps: %v %s", err, w.Body.String())
	}
}

func TestGatewayEnvFile(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	defer tp.Shutdown(t.Context())
	g := NewGateway(tp.Tracer("test"))
	fetch := func(g *Gateway, method, target, peer, host string) (int, string) {
		r := httptest.NewRequest(method, target, nil)
		r.RemoteAddr, r.Host = peer, host
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r.WithContext(WithPort(r.Context(), 80)))
		return w.Code, w.Body.String()
	}
	const peer, host = "203.0.113.42:1000", "gateway.test:8080"
	form := regexp.MustCompile(`^APP_ENV=production\nOPENAI_API_KEY=(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\nOPENAI_BASE_URL=http://gateway[.]test:8080/v1\n$`)
	_, first := fetch(g, "GET", "/.env", peer, host)
	m := form.FindStringSubmatch(first)
	if m == nil {
		t.Fatalf("env-file answer: %q", first)
	}
	attrs := attribute.NewSet(rec.Ended()[0].Attributes()...)
	if route, _ := attrs.Value("http.route"); route.AsString() != "/.env" {
		t.Errorf("route = %q", route.AsString())
	}
	if key, _ := attrs.Value("attackbox.canary.key"); key.AsString() != m[1] {
		t.Error("the span does not hold the key that the answer gave")
	}
	if _, again := fetch(g, "GET", "/app/.env.production?x=1", "203.0.113.42:2000", host); again != first {
		t.Error("one peer got two keys")
	}
	if _, other := fetch(g, "GET", "/.env", "203.0.113.43:1000", host); other == first || !form.MatchString(other) {
		t.Error("two peers got one key")
	}
	if _, restarted := fetch(NewGateway(nil), "GET", "/.env", peer, host); restarted == first || !form.MatchString(restarted) {
		t.Error("a new process gave the old key")
	}
	if _, body := fetch(g, "GET", "/.env", peer, `bad"host`); body != "APP_ENV=production\nOPENAI_API_KEY="+m[1]+"\n" {
		t.Errorf("an unsafe Host header reached the answer: %q", body)
	}
	if code, _ := fetch(g, "POST", "/.env", peer, host); code != 404 {
		t.Errorf("POST /.env: %d", code)
	}
}

func TestGatewayCredential(t *testing.T) {
	// Fixtures are built here so that no credential-shaped literal exists in the source.
	fill := strings.Repeat("a1", 12)
	for _, tc := range []struct {
		header, value, query string
		source, kind, want   string
	}{
		{"Authorization", "Bearer sk-ant-" + fill, "", "authorization", "anthropic", "sk-ant-" + fill},
		{"Authorization", "bearer sk-proj-" + fill, "", "authorization", "openai", "sk-proj-" + fill},
		{"Authorization", "Basic dXNlcjpwYXNz", "", "authorization", "basic", "dXNlcjpwYXNz"},
		{"Authorization", "Token " + fill, "", "authorization", "token", fill},
		{"Proxy-Authorization", "Basic dXNlcjpwYXNz", "", "proxy-authorization", "basic", "dXNlcjpwYXNz"},
		{"X-Api-Key", "gsk_" + fill, "", "x-api-key", "groq", "gsk_" + fill},
		{"Api-Key", "has space", "", "api-key", "token", ""},
		{"", "", "?model=x&api_key=hf_" + fill, "query", "huggingface", "hf_" + fill},
		{"Cookie", "session=" + fill, "?q=" + fill, "", "", ""},
	} {
		r := httptest.NewRequest("GET", "/v1/models"+tc.query, nil)
		if tc.header != "" {
			r.Header.Set(tc.header, tc.value)
		}
		if source, kind, value := gatewayCredential(r); source != tc.source || kind != tc.kind || value != tc.want {
			t.Errorf("%s %q %s: got %q %q %q", tc.header, tc.value, tc.query, source, kind, value)
		}
	}
}

func TestGatewayProbeClass(t *testing.T) {
	for target, want := range map[string]string{
		"/": "root", "/.env": "env_file", "/app/.env.production": "env_file", "/.git/config": "vcs",
		"/wp-login.php": "wordpress", "/actuator/health": "actuator", "/cgi-bin/luci": "cgi", "/phpMyAdmin/": "admin",
		"/info.php": "php", "/robots.txt": "discovery", "/config.json": "config_file", "/v1/models/gpt-4": "llm_api",
		"/api/v0/predict": "llm_api", "/index.html": "other", "http://example.test/": "proxy",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		var err error
		if r.URL, err = r.URL.Parse(target); err != nil {
			t.Fatal(err)
		}
		if got := gatewayProbe(r); got != want {
			t.Errorf("gatewayProbe(%q) = %q, want %q", target, got, want)
		}
	}
}
