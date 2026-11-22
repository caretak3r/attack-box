package server

import (
	"strings"
	"testing"
)

func TestVLLMSurface(t *testing.T) {
	r := newRig(t, PersonaVLLM)

	rec := r.do("GET", "/health", "")
	if rec.Code != 200 || rec.Body.Len() != 0 {
		t.Fatalf("health = %d %q", rec.Code, rec.Body)
	}
	if rec.Header().Get("Server") != "uvicorn" || rec.Header().Get("X-Request-Id") != "" {
		t.Fatalf("headers = %v", rec.Header())
	}
	if rec = r.do("GET", "/version", ""); decode(t, rec)["version"] != "0.11.0" {
		t.Fatalf("version = %s", rec.Body)
	}

	rec = r.do("GET", "/v1/models", "")
	m := list(t, decode(t, rec), "data")[0].(map[string]any)
	if m["owned_by"] != "vllm" || m["root"] != "qwen3:8b" || m["parent"] != nil || m["max_model_len"] != float64(40960) {
		t.Fatalf("model = %v", m)
	}
	if perm := list(t, m, "permission"); len(perm) != 1 {
		t.Fatalf("permission = %v", perm)
	}

	rec = r.do("GET", "/metrics", "")
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") ||
		!strings.Contains(rec.Body.String(), `vllm:num_requests_running{engine="0",model_name="qwen3:8b"} 0.0`) {
		t.Fatalf("metrics = %d %s", rec.Code, rec.Body)
	}
	rec = r.do("GET", "/docs", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "/openapi.json") {
		t.Fatalf("docs = %d", rec.Code)
	}
	rec = r.do("GET", "/openapi.json", "")
	paths := sub(t, decode(t, rec), "paths")
	post := sub(t, paths["/v1/chat/completions"].(map[string]any), "post")
	if post["summary"] != "Create Chat Completion" {
		t.Fatalf("openapi = %v", post)
	}
	if _, ok := paths["/metrics"]; ok {
		t.Fatal("hidden route is in the schema")
	}
	get := sub(t, paths["/v1/models/{model}"].(map[string]any), "get")
	if len(list(t, get, "parameters")) != 1 {
		t.Fatalf("path parameters = %v", get)
	}
}

func TestVLLMChatEnvelope(t *testing.T) {
	r := newRig(t, PersonaVLLM)
	// vLLM falls back to the served model when none is named.
	rec := r.do("POST", "/v1/chat/completions", `{"messages":[{"role":"user","content":"hi"}]}`)
	m := decode(t, rec)
	if rec.Code != 200 || m["model"] != "qwen3:8b" {
		t.Fatalf("chat = %d %v", rec.Code, m)
	}
	id := m["id"].(string)
	if !strings.HasPrefix(id, "chatcmpl-") || len(id) != len("chatcmpl-")+32 {
		t.Fatalf("id = %q", id)
	}
	if _, ok := m["system_fingerprint"]; ok {
		t.Fatal("vllm sends no system_fingerprint")
	}
	if v, ok := m["prompt_logprobs"]; !ok || v != nil {
		t.Fatalf("prompt_logprobs = %v", v)
	}
	ch := list(t, m, "choices")[0].(map[string]any)
	msg := sub(t, ch, "message")
	if v, ok := ch["stop_reason"]; !ok || v != nil {
		t.Fatalf("stop_reason = %v", v)
	}
	if _, ok := msg["tool_calls"]; !ok {
		t.Fatalf("message = %v", msg)
	}
}

func TestVLLMErrors(t *testing.T) {
	r := newRig(t, PersonaVLLM)
	rec := r.do("POST", "/v1/chat/completions", `{"model":"nope"}`)
	m := decode(t, rec)
	if rec.Code != 404 || m["object"] != "error" || m["type"] != "NotFoundError" ||
		m["code"] != float64(404) || m["message"] != "The model `nope` does not exist." {
		t.Fatalf("unknown model = %d %v", rec.Code, m)
	}
	rec = r.do("POST", "/v1/chat/completions", `[`)
	if m = decode(t, rec); rec.Code != 400 || m["type"] != "BadRequestError" {
		t.Fatalf("bad JSON = %d %v", rec.Code, m)
	}
	rec = r.do("GET", "/nothing", "")
	if rec.Code != 404 || decode(t, rec)["detail"] != "Not Found" {
		t.Fatalf("404 = %d %s", rec.Code, rec.Body)
	}
	rec = r.do("DELETE", "/health", "")
	if rec.Code != 405 || decode(t, rec)["detail"] != "Method Not Allowed" || rec.Header().Get("Allow") != "GET" {
		t.Fatalf("405 = %d %s %v", rec.Code, rec.Body, rec.Header())
	}
}

func TestVLLMInvocations(t *testing.T) {
	r := newRig(t, PersonaVLLM)
	rec := r.do("POST", "/invocations", `{"messages":[{"role":"user","content":"hi"}]}`)
	if decode(t, rec)["object"] != "chat.completion" {
		t.Fatalf("messages body = %s", rec.Body)
	}
	rec = r.do("POST", "/invocations", `{"prompt":"hi"}`)
	if decode(t, rec)["object"] != "text_completion" {
		t.Fatalf("prompt body = %s", rec.Body)
	}
	rec = r.do("POST", "/v1/responses/resp_x/cancel", "")
	if decode(t, rec)["status"] != "cancelled" {
		t.Fatalf("cancel = %s", rec.Body)
	}
}
