package server

import (
	"strings"
	"testing"
)

func TestOllamaBasics(t *testing.T) {
	r := newRig(t, PersonaOllama)
	rec := r.do("GET", "/", "")
	if rec.Code != 200 || rec.Body.String() != "Ollama is running" {
		t.Fatalf("root = %d %q", rec.Code, rec.Body)
	}
	if rec = r.do("HEAD", "/", ""); rec.Code != 200 {
		t.Fatalf("HEAD / = %d", rec.Code)
	}
	if rec = r.do("GET", "/api/version", ""); decode(t, rec)["version"] != "0.12.6" {
		t.Fatalf("version = %s", rec.Body)
	}
	rec = r.do("GET", "/api/tags", "")
	models := list(t, decode(t, rec), "models")
	first := models[0].(map[string]any)
	d := sub(t, first, "details")
	if len(models) != 3 || first["name"] != "qwen3:8b" || d["format"] != "gguf" || d["family"] != "qwen3" ||
		!strings.HasSuffix(first["modified_at"].(string), "Z") || len(first["digest"].(string)) != 64 {
		t.Fatalf("tags = %v", first)
	}
	if rec = r.do("GET", "/api/ps", ""); len(list(t, decode(t, rec), "models")) != 0 {
		t.Fatalf("ps = %s", rec.Body)
	}
	rec = r.do("POST", "/api/show", `{"model":"qwen3:8b"}`)
	m := decode(t, rec)
	if rec.Code != 200 || sub(t, m, "model_info")["general.architecture"] != "qwen3" {
		t.Fatalf("show = %d %v", rec.Code, m)
	}
	rec = r.do("POST", "/api/show", `{"model":"nope"}`)
	if rec.Code != 404 || decode(t, rec)["error"] != "model 'nope' not found" {
		t.Fatalf("show unknown = %d %s", rec.Code, rec.Body)
	}
}

func TestOllamaChatStream(t *testing.T) {
	r := newRig(t, PersonaOllama)
	rec := r.do("POST", "/api/chat", chatBody)
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("content type %q", ct)
	}
	frames := ndjsonLines(t, rec.Body.String())
	var text strings.Builder
	for _, f := range frames[:len(frames)-1] {
		if f["done"] != false {
			t.Fatalf("early done: %v", f)
		}
		text.WriteString(sub(t, f, "message")["content"].(string))
	}
	last := frames[len(frames)-1]
	if last["done"] != true || last["done_reason"] != "stop" || last["eval_count"].(float64) <= 0 ||
		last["total_duration"].(float64) <= 0 || last["prompt_eval_count"] != float64(2) {
		t.Fatalf("final frame = %v", last)
	}
	if text.String() != r.sink.lastTranscript(t).Body {
		t.Fatalf("streamed %q", text.String())
	}
}

func TestOllamaNonStreaming(t *testing.T) {
	r := newRig(t, PersonaOllama)
	rec := r.do("POST", "/api/chat", `{"model":"qwen3:8b","stream":false,"messages":[{"role":"user","content":"hi"}]}`)
	m := decode(t, rec)
	msg := sub(t, m, "message")
	if m["done"] != true || msg["role"] != "assistant" || msg["content"] != r.sink.lastTranscript(t).Body {
		t.Fatalf("chat = %v", m)
	}
	rec = r.do("POST", "/api/generate", `{"model":"qwen3:8b","stream":false,"prompt":"hi"}`)
	m = decode(t, rec)
	if m["done"] != true || m["response"] != r.sink.lastTranscript(t).Body {
		t.Fatalf("generate = %v", m)
	}
	rec = r.do("POST", "/api/generate", `{"model":"qwen3:8b","prompt":"hi"}`)
	frames := ndjsonLines(t, rec.Body.String())
	if len(frames) < 2 || frames[0]["response"] == nil {
		t.Fatalf("generate stream = %s", rec.Body)
	}
}

func TestOllamaLoadRequests(t *testing.T) {
	r := newRig(t, PersonaOllama)
	rec := r.do("POST", "/api/generate", `{"model":"qwen3:8b"}`)
	m := decode(t, rec)
	if m["done"] != true || m["done_reason"] != "load" || m["response"] != "" {
		t.Fatalf("generate load = %v", m)
	}
	rec = r.do("POST", "/api/chat", `{"model":"qwen3:8b","messages":[]}`)
	m = decode(t, rec)
	if m["done_reason"] != "load" || sub(t, m, "message")["content"] != "" {
		t.Fatalf("chat load = %v", m)
	}
	if len(r.sink.stream("transcript")) != 0 {
		t.Fatal("a load request reached the responder")
	}
}

func TestOllamaErrors(t *testing.T) {
	r := newRig(t, PersonaOllama)
	rec := r.do("POST", "/api/chat", `{"model":"nope","messages":[{"role":"user","content":"x"}]}`)
	if rec.Code != 404 || decode(t, rec)["error"] != `model 'nope' not found` {
		t.Fatalf("unknown = %d %s", rec.Code, rec.Body)
	}
	rec = r.do("POST", "/api/chat", `{}`)
	if rec.Code != 400 || decode(t, rec)["error"] != "model is required" {
		t.Fatalf("missing = %d %s", rec.Code, rec.Body)
	}
	rec = r.do("POST", "/api/chat", `nonsense`)
	if rec.Code != 400 || decode(t, rec)["error"] == nil {
		t.Fatalf("bad json = %d %s", rec.Code, rec.Body)
	}
	// gin answers a wrong method like an unknown route.
	for _, p := range []string{"/api/chat", "/api/nothing"} {
		rec = r.do("GET", p, "")
		if rec.Code != 404 || rec.Body.String() != "404 page not found" {
			t.Fatalf("GET %s = %d %q", p, rec.Code, rec.Body)
		}
	}
	rec = r.do("GET", "/v1/responses/resp_abc", "")
	if rec.Code != 404 {
		t.Fatalf("stored response = %d", rec.Code)
	}
}

func TestOllamaOpenAISubset(t *testing.T) {
	r := newRig(t, PersonaOllama)
	rec := r.do("GET", "/v1/models", "")
	if m := list(t, decode(t, rec), "data")[0].(map[string]any); m["owned_by"] != "library" {
		t.Fatalf("model = %v", m)
	}
	rec = r.do("POST", "/v1/chat/completions", chatBody)
	m := decode(t, rec)
	if rec.Code != 200 || m["object"] != "chat.completion" || m["system_fingerprint"] != "fp_ollama" {
		t.Fatalf("chat = %d %v", rec.Code, m)
	}
	rec = r.do("POST", "/v1/chat/completions", `{"model":"nope","messages":[]}`)
	e := sub(t, decode(t, rec), "error")
	if rec.Code != 404 || e["type"] != "not_found_error" || e["message"] != "model 'nope' not found" {
		t.Fatalf("unknown = %d %v", rec.Code, e)
	}
	if rec = r.do("GET", "/v1/nothing", ""); rec.Code != 404 || rec.Body.String() != "404 page not found" {
		t.Fatalf("404 = %d %q", rec.Code, rec.Body)
	}
}

func TestOllamaManagement(t *testing.T) {
	r := newRig(t, PersonaOllama)
	rec := r.do("POST", "/api/pull", `{"model":"qwen3:8b"}`)
	frames := ndjsonLines(t, rec.Body.String())
	if len(frames) != 2 || frames[1]["status"] != "success" {
		t.Fatalf("pull = %s", rec.Body)
	}
	rec = r.do("POST", "/api/pull", `{"model":"other:1b"}`)
	frames = ndjsonLines(t, rec.Body.String())
	if frames[len(frames)-1]["error"] == nil {
		t.Fatalf("pull unknown = %s", rec.Body)
	}
	rec = r.do("POST", "/api/pull", `{"model":"other:1b","stream":false}`)
	if rec.Code != 500 || decode(t, rec)["error"] == nil {
		t.Fatalf("pull unknown, no stream = %d %s", rec.Code, rec.Body)
	}
	rec = r.do("POST", "/api/push", `{"model":"qwen3:8b","stream":false}`)
	if rec.Code != 200 {
		t.Fatalf("push = %d", rec.Code)
	}
	rec = r.do("POST", "/api/create", `{"model":"mine","from":"qwen3:8b"}`)
	if rec.Code != 200 || ndjsonLines(t, rec.Body.String())[0]["status"] != "success" {
		t.Fatalf("create = %d %s", rec.Code, rec.Body)
	}
	// Nothing is stored: the created model does not exist afterwards.
	rec = r.do("POST", "/api/show", `{"model":"mine"}`)
	if rec.Code != 404 {
		t.Fatalf("created model is visible: %d", rec.Code)
	}
	if rec = r.do("POST", "/api/copy", `{"source":"qwen3:8b","destination":"x"}`); rec.Code != 200 {
		t.Fatalf("copy = %d", rec.Code)
	}
	if rec = r.do("POST", "/api/copy", `{"source":"nope","destination":"x"}`); rec.Code != 404 {
		t.Fatalf("copy unknown = %d", rec.Code)
	}
	if rec = r.do("POST", "/api/copy", `{"source":"qwen3:8b"}`); rec.Code != 400 {
		t.Fatalf("copy incomplete = %d", rec.Code)
	}
	for _, method := range []string{"DELETE", "POST"} {
		if rec = r.do(method, "/api/delete", `{"model":"qwen3:8b"}`); rec.Code != 200 {
			t.Fatalf("%s delete = %d", method, rec.Code)
		}
	}
	if rec = r.do("DELETE", "/api/delete", `{"model":"nope"}`); rec.Code != 404 {
		t.Fatalf("delete unknown = %d", rec.Code)
	}
	if rec = r.do("GET", "/api/tags", ""); len(list(t, decode(t, rec), "models")) != 3 {
		t.Fatal("delete removed a model")
	}
}
