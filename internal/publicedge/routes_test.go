package publicedge

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// collectorPattern returns the allowlist that deploy/public-otel/config.yaml applies to one span attribute.
func collectorPattern(t *testing.T, attr string) *regexp.Regexp {
	t.Helper()
	config, err := os.ReadFile("../../deploy/public-otel/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`not IsMatch\(span\.attributes\["` + regexp.QuoteMeta(attr) + `"\], "([^"]+)"\)`).FindSubmatch(config)
	if m == nil {
		t.Fatalf("no allowlist for %s", attr)
	}
	return regexp.MustCompile(string(m[1]))
}

// The collector drops a span whose route label or fake key is not in its allowlist.
func TestGatewayPatternRoutes(t *testing.T) {
	routes, keys, models := collectorPattern(t, "http.route"), collectorPattern(t, "attackbox.canary.key"), collectorPattern(t, "gen_ai.request.model")
	for port, p := range gatewayPersonas {
		for _, paths := range []map[string]http.HandlerFunc{p.paths, p.posts} {
			for path := range paths {
				if !routes.MatchString(path) {
					t.Errorf("port %d path %s is not in the collector allowlist", port, path)
				}
			}
		}
	}

	dir := t.TempDir()
	capture, err := OpenCapture(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Close()
	tool := `{"id":"sys_diag_709","name":"Diag \"x\"","content":"class Tools:\n    pass","meta":{"description":"d"}}`
	for _, tc := range []struct {
		port                        int
		method, target, body, route string
		status                      int
		want                        string
	}{
		{3000, "GET", "/api/v1/tools/", "", "/api/v1/tools/", 200, `[]`},
		{3000, "POST", "/api/v1/tools/create", tool, "/api/v1/tools/create", 200, `{"id":"sys_diag_709","user_id":"`},
		{3000, "POST", "/api/v1/tools/create", tool, "/api/v1/tools/create", 200, `"name":"Diag \"x\"","meta":{"description":null,"manifest":{}},"access_control":null,`},
		{3000, "POST", "/api/v1/functions/create", `{"id":"f1","name":"n","content":"class Filter:\n    pass"}`, "/api/v1/functions/create", 200, `"type":"filter","is_active":false`},
		{3000, "POST", "/api/v1/tools/create", `{"id":"a-b","name":"n","content":""}`, "/api/v1/tools/create", 400, `Only alphanumeric characters`},
		{3000, "POST", "/api/v1/tools/create", `{`, "/api/v1/tools/create", 422, `json_invalid`},
		{3000, "DELETE", "/api/v1/tools/id/sys_diag_709/delete", "", "/api/v1/tools/id/{id}/delete", 200, `true`},
		{3000, "DELETE", "/api/v1/functions/id/f1/delete", "", "/api/v1/functions/id/{id}/delete", 200, `true`},
		// Open WebUI serves a stored pipe function as a model named by its id; the span does not name it.
		{3000, "POST", "/api/chat/completions", `{"model":"sys_pipe_1","messages":[{"role":"user","content":"x"}]}`, "/api/chat/completions", 200, `"model":"sys_pipe_1"`},
		{3000, "POST", "/api/chat/completions", `{"model":"no-such-model","messages":[{"role":"user","content":"x"}]}`, "/api/chat/completions", 404, `model not found`},
		{3000, "GET", "/api/v1/tools/create", "", "/unmatched", 404, `{"detail":"Not Found"}`},
		{4000, "GET", "/model/info", "", "/model/info", 200, `{"model_name":"claude-sonnet-4-20250514","litellm_params":{"model":"anthropic/claude-sonnet-4-20250514"}`},
		{4000, "GET", "/v1/model/info", "", "/v1/model/info", 200, `"model":"ollama/llama3.3:70b"`},
		{4000, "GET", "/key/list", "", "/key/list", 200, `"total_count":0`},
		{4000, "POST", "/key/generate", `{}`, "/key/generate", 200, `{"key":"sk-`},
		{4000, "POST", "/config/update", `{"general_settings":{}}`, "/config/update", 200, `Config updated successfully`},
		{4000, "POST", "/guardrails/test_custom_code", `{"custom_code":"x"}`, "/guardrails/test_custom_code", 200, `"success":false`},
		// One trailing slash is a valid target; other unclean targets are not.
		{8000, "POST", "/mcp/", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, "/mcp", 200, `"result":{}`},
		{3000, "GET", "/nope/", "", "/unmatched", 404, `{"detail":"Not Found"}`},
		{3000, "GET", "//nope", "", "/unmatched", 400, "invalid request target"},
		{3000, "GET", "/a/../nope", "", "/unmatched", 400, "invalid request target"},
	} {
		t.Run(fmt.Sprintf("%d %s %s %d", tc.port, tc.method, tc.target, tc.status), func(t *testing.T) {
			spans := tracetest.NewSpanRecorder()
			tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
			defer tp.Shutdown(t.Context())
			g := NewGateway(tp.Tracer("test"))
			g.Capture = capture // the public service always has a capture, and it reads the body before the handler
			do := func(header ...string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(tc.method, "/", strings.NewReader(tc.body))
				r.URL.Path, r.RequestURI = tc.target, tc.target
				for i := 0; i+1 < len(header); i += 2 {
					r.Header.Set(header[i], header[i+1])
				}
				w := httptest.NewRecorder()
				g.ServeHTTP(w, r.WithContext(WithPort(r.Context(), tc.port)))
				return w
			}
			w := do("Authorization", "Bearer test")
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.want) || !json200(w) {
				t.Fatalf("got %d %s", w.Code, w.Body)
			}
			var route, key string
			for _, a := range spans.Ended()[0].Attributes() {
				switch a.Key {
				case "http.route":
					route = a.Value.AsString()
				case "attackbox.canary.key":
					key = a.Value.AsString()
				case "gen_ai.request.model":
					if !models.MatchString(a.Value.AsString()) {
						t.Errorf("model %q not in the collector allowlist", a.Value.AsString())
					}
				}
			}
			if route != tc.route || !routes.MatchString(route) {
				t.Errorf("route = %q, want %q in the collector allowlist", route, tc.route)
			}
			if (tc.route == "/key/generate") != keys.MatchString(key) || key != "" && !strings.Contains(w.Body.String(), `"key":"`+key+`"`) {
				t.Errorf("fake key %q does not match the answer or the collector allowlist", key)
			}
			// A product route answers its own 401 until the client sends a credential.
			if tc.route != "/unmatched" && tc.route != "/mcp" {
				if w := do(); w.Code != 401 || !strings.Contains(w.Body.String(), map[int]string{3000: "Not authenticated", 4000: "auth_error"}[tc.port]) {
					t.Errorf("without a credential: %d %s", w.Code, w.Body)
				}
			}
		})
	}
}

func TestGatewayModelAllowlist(t *testing.T) {
	modelPattern := collectorPattern(t, "gen_ai.request.model")
	for _, m := range gatewayModelList {
		if !modelPattern.MatchString(m) {
			t.Errorf("model %q not in collector allowlist", m)
		}
	}
}

func TestGatewayHostedVsLocal(t *testing.T) {
	for _, m := range gatewayModelList {
		isHosted := gatewayHostedModel(m)
		hasColon := strings.Contains(m, ":")
		isLocalStyle := m == "local-instruct-8b" || m == "nomic-embed-text" || hasColon
		if isLocalStyle && isHosted {
			t.Errorf("model %q is local-style but gatewayHostedModel returned true", m)
		}
		if !isLocalStyle && !isHosted {
			t.Errorf("model %q is hosted but gatewayHostedModel returned false", m)
		}
	}
}

// json200 reports whether a 200 answer with a JSON content type holds valid JSON.
func json200(w *httptest.ResponseRecorder) bool {
	return w.Code != 200 || w.Header().Get("Content-Type") != gatewayJSON || json.Valid(w.Body.Bytes())
}
