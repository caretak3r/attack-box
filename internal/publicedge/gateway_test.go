package publicedge

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestGatewayModelsRoute(t *testing.T) {
	g := NewGateway(nil)
	req := httptest.NewRequest("GET", "/v1/models", nil)
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
				g.ServeHTTP(httptest.NewRecorder(), r)
				spans := rec.Ended()
				if len(spans) != 1 || spans[0].Name() != "public.request" {
					t.Fatal("missing public.request span")
				}
				want := attribute.NewSet(append([]attribute.KeyValue{
					attribute.Int("server.port", 443), attribute.String("attackbox.persona", "cloud-gateway"),
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
		{"GET", "/api/tags", "", "/api/tags", 200, gatewayJSON, `"local-instruct-8b:latest"`},
		{"GET", "/api/tags", "", "/api/tags", 200, gatewayJSON, `"name":"deepseek-r1:8b"`},
		{"POST", "/api/chat", `{"model":"qwen2.5:7b","stream":false,"messages":[{"role":"user","content":"x"}]}`, "/api/chat", 200, gatewayJSON, `"model":"qwen2.5:7b"`},
		{"POST", "/api/chat", `{"model":"local-instruct-8b","messages":[{"role":"user","content":"x"}]}`, "/api/chat", 200, "application/x-ndjson", `"done":true`},
		{"POST", "/ollama/api/generate", `{"model":"local-instruct-8b:latest","prompt":"x","stream":false}`, "/ollama/api/generate", 200, gatewayJSON, `"response":"Ready."`},
		{"POST", "/api/generate", `{"model":"llama3","prompt":"x"}`, "/api/generate", 404, gatewayJSON, "model not found"},
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
			NewGateway(tp.Tracer("test")).ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get("Content-Type") != tc.contentType || !strings.Contains(w.Body.String(), tc.contains) {
				t.Fatalf("got %d %q %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
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
