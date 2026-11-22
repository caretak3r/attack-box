package server

import (
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// The response goes to the log as its own edge event with the same request id,
// byte for byte when it fits under MaxLogBody.
func TestResponseCaptured(t *testing.T) {
	for _, stream := range []bool{false, true} {
		r := newRig(t, PersonaOpenAI)
		body := chatBody
		if stream {
			body = `{"model":"qwen3:8b","stream":true,"messages":[{"role":"user","content":"hello there"}]}`
		}
		rec := r.do("POST", "/v1/chat/completions", body)
		req, resp := r.sink.lastEdge(t), r.sink.lastResponse(t)
		if resp.RequestID != req.RequestID || resp.SessionID != req.SessionID || resp.Status != rec.Code {
			t.Fatalf("stream=%v: response event ids/status %+v vs %+v", stream, resp, req)
		}
		if resp.Body != rec.Body.String() {
			t.Fatalf("stream=%v: logged response differs:\n%q\n%q", stream, resp.Body, rec.Body.String())
		}
		if resp.Attrs["response_bytes"] != int64(rec.Body.Len()) || resp.Attrs["body_truncated"] != nil ||
			resp.Attrs["route"] != "/v1/chat/completions" || req.Attrs["direction"] != "request" {
			t.Fatalf("stream=%v: attrs %v / %v", stream, resp.Attrs, req.Attrs)
		}
		ct, _ := resp.Attrs["content_type"].(string)
		if stream != strings.HasPrefix(ct, "text/event-stream") || (stream && !strings.HasSuffix(resp.Body, "data: [DONE]\n\n")) {
			t.Fatalf("stream=%v: content type %q, body tail %q", stream, ct, resp.Body[max(0, len(resp.Body)-20):])
		}
	}
}

// Echoed attacker text in a response is scrubbed like the request body.
func TestResponseCaptureRedacts(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	key := "sk-" + strings.Repeat("A", 40)
	rec := r.do("POST", "/v1/chat/completions", `{"model":"`+key+`","messages":[{"role":"user","content":"hi"}]}`)
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), key) {
		t.Fatalf("precondition: %d %s", rec.Code, rec.Body)
	}
	got := r.sink.lastResponse(t).Body
	if strings.Contains(got, "sk-AAAA") || !strings.Contains(got, "[redacted:hmac256:") || !strings.Contains(got, "model_not_found") {
		t.Fatalf("response log = %q", got)
	}
}

// A long response keeps only a bounded head in memory and in the log, and the
// total size still shows the real length.
func TestResponseCaptureBounded(t *testing.T) {
	const limit = 100
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.MaxLogBody = limit })
	rec := r.do("POST", "/v1/embeddings", `{"model":"qwen3:8b","input":["`+strings.Repeat("word ", 50)+`"]}`)
	if rec.Code != 200 || rec.Body.Len() <= r.srv.logRawLimit() {
		t.Fatalf("precondition: %d, %d bytes", rec.Code, rec.Body.Len())
	}
	resp := r.sink.lastResponse(t)
	if len(resp.Body) > limit || !utf8.ValidString(resp.Body) || resp.Attrs["body_truncated"] != true ||
		resp.Attrs["response_bytes"] != int64(rec.Body.Len()) || !strings.HasPrefix(rec.Body.String(), resp.Body[:20]) {
		t.Fatalf("response event: %d bytes, attrs %v", len(resp.Body), resp.Attrs)
	}

	w := &recorder{ResponseWriter: httptest.NewRecorder(), keep: 10}
	for i := 0; i < 5; i++ {
		_, _ = w.Write([]byte("0123456"))
	}
	if string(w.head) != "0123456012" || w.n != 35 {
		t.Fatalf("recorder head %q n %d", w.head, w.n)
	}
}

// A request cut for the log carries a keyed fingerprint of the whole body, so
// repeats of one oversized payload stay linkable.
func TestRequestCutFingerprint(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.MaxLogBody = 200 })
	body := `{"model":"qwen3:8b","messages":[{"role":"user","content":"` + strings.Repeat("z", 9000) + `"}]}`
	r.do("POST", "/v1/chat/completions", body)
	edge := r.sink.lastEdge(t)
	if edge.Attrs["body_truncated"] != true || edge.Attrs["body_fingerprint"] != r.srv.cfg.Redactor.Fingerprint(body) {
		t.Fatalf("attrs %v", edge.Attrs)
	}
	r.do("POST", "/v1/chat/completions", chatBody)
	if _, ok := r.sink.lastEdge(t).Attrs["body_fingerprint"]; ok {
		t.Fatal("an uncut body carries body_fingerprint")
	}
}

// A request that gets no response bytes logs no response event.
func TestNoResponseEventWithoutBytes(t *testing.T) {
	r := newRig(t, PersonaVLLM)
	if rec := r.do("GET", "/health", ""); rec.Code != 200 || rec.Body.Len() != 0 {
		t.Fatalf("precondition: %d %q", rec.Code, rec.Body)
	}
	if n := len(r.sink.edges("response")); n != 0 {
		t.Fatalf("%d response events for an empty response", n)
	}
	if len(r.sink.edges("request")) != 1 {
		t.Fatal("no request event")
	}
}
