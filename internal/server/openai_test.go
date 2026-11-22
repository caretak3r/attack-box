package server

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"attackbox/internal/responder"
	"attackbox/internal/telemetry"
)

func TestOpenAIModels(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	rec := r.do("GET", "/v1/models", "")
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	m := decode(t, rec)
	if m["object"] != "list" {
		t.Fatalf("object = %v", m["object"])
	}
	data := list(t, m, "data")
	if len(data) != 3 {
		t.Fatalf("got %d models", len(data))
	}
	first := data[0].(map[string]any)
	if first["id"] != "qwen3:8b" || first["object"] != "model" || first["owned_by"] != "system" {
		t.Fatalf("model = %v", first)
	}
	if _, ok := first["root"]; ok {
		t.Fatal("openai model carries a vllm-only field")
	}

	rec = r.do("GET", "/v1/models/gpt-oss:20b", "")
	if rec.Code != 200 || decode(t, rec)["id"] != "gpt-oss:20b" {
		t.Fatalf("get model: %d %s", rec.Code, rec.Body)
	}
	rec = r.do("GET", "/v1/models/nope", "")
	e := sub(t, decode(t, rec), "error")
	if rec.Code != 404 || e["code"] != "model_not_found" || e["param"] != "model" ||
		e["message"] != "The model 'nope' does not exist" || e["type"] != "invalid_request_error" {
		t.Fatalf("unknown model: %d %v", rec.Code, e)
	}
}

func TestOpenAIChatEnvelope(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	rec := r.do("POST", "/v1/chat/completions", chatBody)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status %d ct %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("X-Request-Id") == "" {
		t.Fatal("no X-Request-Id")
	}
	m := decode(t, rec)
	if !strings.HasPrefix(m["id"].(string), "chatcmpl-") || len(m["id"].(string)) != len("chatcmpl-")+29 {
		t.Fatalf("id = %v", m["id"])
	}
	if m["object"] != "chat.completion" || m["model"] != "qwen3:8b" || m["created"] != float64(fixedNow.Unix()) {
		t.Fatalf("envelope = %v", m)
	}
	if !strings.HasPrefix(m["system_fingerprint"].(string), "fp_") {
		t.Fatalf("fingerprint = %v", m["system_fingerprint"])
	}
	ch := list(t, m, "choices")[0].(map[string]any)
	msg := sub(t, ch, "message")
	if ch["finish_reason"] != "stop" || msg["role"] != "assistant" || msg["refusal"] != nil {
		t.Fatalf("choice = %v", ch)
	}
	if msg["content"] != r.sink.lastTranscript(t).Body {
		t.Fatal("content differs from the logged transcript")
	}
	u := sub(t, m, "usage")
	if u["total_tokens"] != u["prompt_tokens"].(float64)+u["completion_tokens"].(float64) || u["prompt_tokens"] != float64(2) {
		t.Fatalf("usage = %v", u)
	}
}

func TestOpenAIJSONMode(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	rec := r.do("POST", "/v1/chat/completions",
		`{"model":"qwen3:8b","response_format":{"type":"json_object"},"messages":[{"role":"user","content":"hi"}]}`)
	msg := sub(t, list(t, decode(t, rec), "choices")[0].(map[string]any), "message")
	var wrapped map[string]string
	if err := json.Unmarshal([]byte(msg["content"].(string)), &wrapped); err != nil {
		t.Fatalf("content is not JSON: %v", err)
	}
	if wrapped["status"] != "pending" || wrapped["message"] != r.sink.lastTranscript(t).Body {
		t.Fatalf("wrapped = %v", wrapped)
	}
}

func TestOpenAIModelErrors(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	rec := r.do("POST", "/v1/chat/completions", `{"messages":[]}`)
	e := sub(t, decode(t, rec), "error")
	if rec.Code != 400 || e["message"] != "you must provide a model parameter" {
		t.Fatalf("missing model: %d %v", rec.Code, e)
	}
	rec = r.do("POST", "/v1/chat/completions", `{"model":"nope‮\u0007","messages":[]}`)
	e = sub(t, decode(t, rec), "error")
	if rec.Code != 404 || e["code"] != "model_not_found" ||
		e["message"] != "The model `nope` does not exist or you do not have access to it." {
		t.Fatalf("unknown model: %d %v", rec.Code, e)
	}
}

func TestOpenAIChatStream(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	rec := r.do("POST", "/v1/chat/completions",
		`{"model":"qwen3:8b","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hello there"}]}`)
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream; charset=utf-8" {
		t.Fatalf("content type %q", ct)
	}
	blocks, _ := parseSSE(rec.Body.String())
	if blocks[len(blocks)-1].data != "[DONE]" {
		t.Fatalf("stream does not end with [DONE]: %q", blocks[len(blocks)-1].data)
	}
	var text strings.Builder
	var sawRole, sawStop, sawUsage bool
	for _, b := range blocks[:len(blocks)-1] {
		var c map[string]any
		if err := json.Unmarshal([]byte(b.data), &c); err != nil {
			t.Fatalf("bad frame %q: %v", b.data, err)
		}
		if c["object"] != "chat.completion.chunk" {
			t.Fatalf("object = %v", c["object"])
		}
		if u, ok := c["usage"].(map[string]any); ok {
			sawUsage = u["total_tokens"].(float64) > 0 && len(list(t, c, "choices")) == 0
			continue
		}
		ch := list(t, c, "choices")[0].(map[string]any)
		d := sub(t, ch, "delta")
		if d["role"] == "assistant" {
			sawRole = true
		}
		if s, ok := d["content"].(string); ok {
			text.WriteString(s)
		}
		if ch["finish_reason"] == "stop" {
			sawStop = true
		}
	}
	if !sawRole || !sawStop || !sawUsage {
		t.Fatalf("role=%v stop=%v usage=%v", sawRole, sawStop, sawUsage)
	}
	if text.String() != r.sink.lastTranscript(t).Body {
		t.Fatalf("streamed text %q differs from the transcript", text.String())
	}
}

func TestOpenAICompletions(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	for _, body := range []string{
		`{"model":"qwen3:8b","prompt":"say hi"}`,
		`{"model":"qwen3:8b","prompt":["say hi","again"]}`,
	} {
		rec := r.do("POST", "/v1/completions", body)
		m := decode(t, rec)
		ch := list(t, m, "choices")[0].(map[string]any)
		if rec.Code != 200 || m["object"] != "text_completion" || ch["text"] == "" || ch["finish_reason"] != "stop" {
			t.Fatalf("completion = %d %v", rec.Code, m)
		}
	}
	rec := r.do("POST", "/v1/completions", `{"model":"qwen3:8b","prompt":"x","stream":true}`)
	blocks, _ := parseSSE(rec.Body.String())
	if len(blocks) < 3 || blocks[len(blocks)-1].data != "[DONE]" {
		t.Fatalf("stream = %q", rec.Body)
	}
}

func TestOpenAIResponses(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	rec := r.do("POST", "/v1/responses", `{"model":"qwen3:8b","input":"hello there"}`)
	m := decode(t, rec)
	if rec.Code != 200 || m["object"] != "response" || m["status"] != "completed" || !strings.HasPrefix(m["id"].(string), "resp_") {
		t.Fatalf("response = %d %v", rec.Code, m)
	}
	item := list(t, m, "output")[0].(map[string]any)
	part := list(t, item, "content")[0].(map[string]any)
	if item["type"] != "message" || part["type"] != "output_text" || part["text"] != r.sink.lastTranscript(t).Body {
		t.Fatalf("output = %v", item)
	}

	rec = r.do("POST", "/v1/responses", `{"model":"qwen3:8b","input":"hello","stream":true}`)
	blocks, _ := parseSSE(rec.Body.String())
	var names []string
	var text strings.Builder
	for i, b := range blocks {
		if !strings.HasPrefix(b.data, `{"type":"`+b.event+`"`) {
			t.Fatalf("frame %d: type is not first or does not match %q: %s", i, b.event, b.data)
		}
		var f map[string]any
		_ = json.Unmarshal([]byte(b.data), &f)
		if f["sequence_number"] != float64(i) {
			t.Fatalf("frame %d: sequence_number = %v", i, f["sequence_number"])
		}
		if b.event == "response.output_text.delta" {
			text.WriteString(f["delta"].(string))
		}
		if len(names) == 0 || names[len(names)-1] != b.event {
			names = append(names, b.event)
		}
	}
	want := []string{
		"response.created", "response.in_progress", "response.output_item.added", "response.content_part.added",
		"response.output_text.delta", "response.output_text.done", "response.content_part.done",
		"response.output_item.done", "response.completed",
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v", names)
	}
	if text.String() != r.sink.lastTranscript(t).Body {
		t.Fatalf("streamed text %q", text.String())
	}
}

func TestOpenAIStoredResponses(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	rec := r.do("GET", "/v1/responses/resp_abc123", "")
	m := decode(t, rec)
	if rec.Code != 200 || m["id"] != "resp_abc123" || m["status"] != "completed" {
		t.Fatalf("get = %d %v", rec.Code, m)
	}
	rec = r.do("POST", "/v1/responses/resp_abc123/cancel", "")
	if m := decode(t, rec); rec.Code != 200 || m["status"] != "cancelled" {
		t.Fatalf("cancel = %d %v", rec.Code, m)
	}
	rec = r.do("GET", "/v1/responses/not-an-id", "")
	e := sub(t, decode(t, rec), "error")
	if rec.Code != 404 || e["code"] != "response_not_found" {
		t.Fatalf("bad id = %d %v", rec.Code, e)
	}
}

func TestOpenAIRoutingErrors(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	rec := r.do("GET", "/v1/unknown/thing", "")
	e := sub(t, decode(t, rec), "error")
	if rec.Code != 404 || e["message"] != "Invalid URL (GET /v1/unknown/thing)" {
		t.Fatalf("404 = %d %v", rec.Code, e)
	}
	rec = r.do("DELETE", "/v1/models", "")
	if rec.Code != 405 || rec.Header().Get("Allow") != "GET" {
		t.Fatalf("405 = %d allow=%q", rec.Code, rec.Header().Get("Allow"))
	}
	if rec = r.do("GET", "/health", ""); rec.Code != 200 || decode(t, rec)["status"] != "ok" {
		t.Fatalf("health = %d %s", rec.Code, rec.Body)
	}
	if rec = r.do("GET", "/version", ""); decode(t, rec)["version"] != "1.0.0" {
		t.Fatalf("version = %s", rec.Body)
	}
	for _, p := range []string{"/metrics", "/docs", "/openapi.json", "/invocations", "/api/tags"} {
		if rec = r.do("GET", p, ""); rec.Code != 404 {
			t.Fatalf("%s = %d, want 404 on the openai persona", p, rec.Code)
		}
	}
}

func TestRetryGate(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	r.pin("retry")
	r.warm()
	rec := r.do("POST", "/v1/chat/completions", chatBody)
	e := sub(t, decode(t, rec), "error")
	if rec.Code != 429 || rec.Header().Get("Retry-After") != "1" ||
		e["message"] != "Rate limit reached for requests. Please try again in 1s." || e["type"] != "requests" {
		t.Fatalf("retry gate = %d %v %v", rec.Code, rec.Header(), e)
	}
	edge := r.sink.lastEdge(t)
	if edge.Result != "rate_limited" || edge.ProbeID != "retry" || edge.Status != 429 {
		t.Fatalf("edge = %+v", edge)
	}
	// The client honours Retry-After: the next request gets the payout path.
	if rec = r.do("POST", "/v1/chat/completions", chatBody); rec.Code != 200 {
		t.Fatalf("after retry: %d", rec.Code)
	}
}

func TestHoldSilentCompletes(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	r.pin("timeout-silent")
	r.warm()
	rec := r.do("POST", "/v1/chat/completions", chatBody)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if w := r.clk.recorded(); len(w) != 1 || w[0] != 100*time.Millisecond {
		t.Fatalf("waits = %v", w)
	}
	edge := r.sink.lastEdge(t)
	if edge.Attrs["hold_result"] != "completed" || edge.ProbeID != "timeout-silent" {
		t.Fatalf("edge attrs = %v", edge.Attrs)
	}
}

func TestHoldIsCappedByMaxStreamDuration(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.MaxStreamDuration = 40 * time.Millisecond })
	r.pin("timeout-silent")
	r.warm()
	r.do("POST", "/v1/chat/completions", chatBody)
	if w := r.clk.recorded(); len(w) != 1 || w[0] != 40*time.Millisecond {
		t.Fatalf("waits = %v", w)
	}
}

func TestHoldClientDisconnect(t *testing.T) {
	for _, stream := range []bool{false, true} {
		r := newRig(t, PersonaOpenAI)
		r.pin("timeout-silent")
		r.warm()
		r.clk.setGate(make(chan time.Time)) // never released
		body := chatBody
		if stream {
			body = strings.Replace(chatBody, `"model"`, `"stream":true,"model"`, 1)
		}
		req, cancel := withCancel(request("POST", "/v1/chat/completions", body))
		done := make(chan struct{})
		go func() { r.serve(req); close(done) }()
		r.clk.waitEntered(t, 1)
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("handler ignored the closed connection")
		}
		edge := r.sink.lastEdge(t)
		if edge.Attrs["hold_result"] != "client_closed" {
			t.Fatalf("stream=%v attrs = %v", stream, edge.Attrs)
		}
		if !stream && (edge.Status != 499 || edge.Result != "client_closed") {
			t.Fatalf("status = %d result = %q", edge.Status, edge.Result)
		}
	}
}

func TestIdleHoldSendsKeepalives(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.IdleInterval = 30 * time.Millisecond })
	r.pin("timeout-idle")
	r.warm()
	rec := r.do("POST", "/v1/chat/completions", strings.Replace(chatBody, `"model"`, `"stream":true,"model"`, 1))
	want := []time.Duration{30 * time.Millisecond, 30 * time.Millisecond, 30 * time.Millisecond, 10 * time.Millisecond}
	got := r.clk.recorded()
	if len(got) != len(want) {
		t.Fatalf("waits = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("waits = %v, want %v", got, want)
		}
	}
	blocks, keep := parseSSE(rec.Body.String())
	if keep != 3 {
		t.Fatalf("keepalives = %d", keep)
	}
	if blocks[len(blocks)-1].data != "[DONE]" {
		t.Fatal("stream did not end normally")
	}
}

func TestSilentStreamHasNoKeepalives(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.IdleInterval = 30 * time.Millisecond })
	r.pin("timeout-silent")
	r.warm()
	rec := r.do("POST", "/v1/chat/completions", strings.Replace(chatBody, `"model"`, `"stream":true,"model"`, 1))
	if _, keep := parseSSE(rec.Body.String()); keep != 0 {
		t.Fatalf("keepalives = %d", keep)
	}
	if w := r.clk.recorded(); len(w) != 1 {
		t.Fatalf("waits = %v", w)
	}
}

func TestEdgeStatus(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	rec := r.do("GET", "/v1/edge/B/status", "")
	m := decode(t, rec)
	if rec.Code != 200 || m["status"] != "ok" || m["label"] != "B" {
		t.Fatalf("status = %d %v", rec.Code, m)
	}
	if w := r.clk.recorded(); len(w) != 1 || w[0] != 200*time.Millisecond {
		t.Fatalf("waits = %v", w)
	}
	for _, label := range []string{"E", "a", "AA", "0"} {
		if rec = r.do("GET", "/v1/edge/"+label+"/status", ""); rec.Code != 404 {
			t.Fatalf("label %q = %d", label, rec.Code)
		}
	}
	if len(r.clk.recorded()) != 1 {
		t.Fatal("a rejected label held the request")
	}
}

func TestEdgeStatusOverlap(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	gate := make(chan time.Time)
	r.clk.setGate(gate)
	done := make(chan int, 4)
	for _, label := range []string{"A", "B", "C", "D"} {
		go func() { done <- r.do("GET", "/v1/edge/"+label+"/status", "").Code }()
	}
	r.clk.waitEntered(t, 4)
	close(gate)
	for i := 0; i < 4; i++ {
		if code := <-done; code != 200 {
			t.Fatalf("status %d", code)
		}
	}
	peak := 0
	for _, e := range r.sink.stream(telemetry.StreamEdge) {
		obs, _ := e.Attrs["observations"].([]responder.Observation)
		for _, o := range obs {
			if o.ProbeID != "concurrency" {
				t.Fatalf("probe %q", o.ProbeID)
			}
			p, err := strconv.Atoi(o.Result["peak"])
			if err != nil {
				t.Fatal(err)
			}
			peak = max(peak, p)
		}
	}
	if peak != 4 {
		t.Fatalf("peak overlap = %d, want 4", peak)
	}
}
