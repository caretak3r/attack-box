package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

// A request cut for the log carries a keyed fingerprint of every byte read, so
// repeats of one oversized payload stay linkable. An uncut body carries one too,
// and the old body_fingerprint name is gone.
func TestRequestCutFingerprint(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.MaxLogBody = 200 })
	body := `{"model":"qwen3:8b","messages":[{"role":"user","content":"` + strings.Repeat("z", 9000) + `"}]}`
	r.do("POST", "/v1/chat/completions", body)
	edge := r.sink.lastEdge(t)
	if edge.Attrs["body_truncated"] != true || edge.Attrs["input_fp"] != r.srv.cfg.Redactor.Fingerprint(body) ||
		edge.Attrs["input_fp_scope"] != "full" {
		t.Fatalf("attrs %v", edge.Attrs)
	}
	r.do("POST", "/v1/chat/completions", chatBody)
	edge = r.sink.lastEdge(t)
	if _, ok := edge.Attrs["body_fingerprint"]; ok {
		t.Fatal("an uncut body carries body_fingerprint")
	}
	if edge.Attrs["input_fp"] != r.srv.cfg.Redactor.Fingerprint(chatBody) || edge.Attrs["input_fp_scope"] != "full" {
		t.Fatalf("attrs %v", edge.Attrs)
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

// failingBody hands out data and the error in its first Read, then the error
// again: the bytes-plus-error shape of a dropped connection.
type failingBody struct {
	data string
	err  error
	done bool
}

func (b *failingBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, b.err
	}
	b.done = true
	return copy(p, b.data), b.err
}

func (*failingBody) Close() error { return nil }

// failingRequest is a chat request whose body read fails; its length is unknown.
func failingRequest(data string, err error) *http.Request {
	req := request("POST", "/v1/chat/completions", "")
	req.Body, req.ContentLength = &failingBody{data: data, err: err}, -1
	return req
}

// capture_state comes from the read and the preview alone, parse_state from the
// handler's decode alone, and neither changes the response.
func TestCaptureAndParseState(t *testing.T) {
	big := `{"model":"qwen3:8b","messages":[{"role":"user","content":"` + strings.Repeat("x", 400) + `"}]}`
	valid := `{"model":"qwen3:8b","messages":[{"role":"user","content":"hi"}]}`
	limit := func(c *Config) { c.MaxBodyBytes = 64 }
	cases := []struct {
		name     string
		mut      func(*Config)
		req      *http.Request
		status   int
		capture  string
		parse    string
		read     string // the bytes the server read
		declared any    // nil: no declared_bytes
		scope    string // "": no input_fp
	}{
		{"no body", nil, request("GET", "/v1/models", ""), 200, "none", "not_attempted", "", nil, ""},
		{"empty body on a parsing route", nil, request("POST", "/v1/chat/completions", ""), 400, "none", "failed", "", nil, ""},
		{"missing messages", nil, request("POST", "/v1/chat/completions", "{}"), 400, "complete", "ok", "{}", int64(2), "full"},
		{"null is not an object", nil, request("POST", "/v1/chat/completions", "null"), 400, "complete", "failed", "null", int64(4), "full"},
		{"invalid embedding JSON", nil, request("POST", "/v1/embeddings", "{"), 400, "complete", "failed", "{", int64(1), "full"},
		{"complete", nil, request("POST", "/v1/chat/completions", chatBody), 200, "complete", "ok", chatBody, int64(len(chatBody)), "full"},
		{"log prefix", func(c *Config) { c.MaxLogBody = 64 }, request("POST", "/v1/chat/completions", big), 200, "log_prefix", "ok", big, int64(len(big)), "full"},
		{"body limit", limit, request("POST", "/v1/chat/completions", big), 413, "body_limit_exceeded", "not_attempted", big[:64], int64(len(big)), "prefix"},
		{"unknown route over the limit", limit, request("POST", "/nope", big), 404, "body_limit_exceeded", "not_attempted", big[:64], int64(len(big)), "prefix"},
		{"wrong method", nil, request("GET", "/v1/chat/completions", "{}"), 405, "complete", "not_attempted", "{}", int64(2), "full"},
		{"route without a body parser", nil, request("GET", "/v1/models", "x"), 200, "complete", "not_attempted", "x", int64(1), "full"},
		{"read error, decode ok", nil, failingRequest(valid, io.ErrUnexpectedEOF), 200, "read_error", "ok", valid, nil, "prefix"},
		{"read error, decode failed", nil, failingRequest("{", io.ErrUnexpectedEOF), 400, "read_error", "failed", "{", nil, "prefix"},
		{"client abort", nil, failingRequest(`{"model":`, context.Canceled), 400, "read_error", "failed", `{"model":`, nil, "prefix"},
		{"read error, no bytes", nil, failingRequest("", io.ErrUnexpectedEOF), 400, "read_error", "failed", "", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mut []func(*Config)
			if tc.mut != nil {
				mut = append(mut, tc.mut)
			}
			r := newRig(t, PersonaOpenAI, mut...)
			rec := r.serve(tc.req)
			edge := r.sink.lastEdge(t)
			a := edge.Attrs
			if rec.Code != tc.status || edge.Status != tc.status {
				t.Fatalf("status %d / %d, want %d", rec.Code, edge.Status, tc.status)
			}
			if a["capture_state"] != tc.capture || a["parse_state"] != tc.parse || a["observed_bytes"] != len(tc.read) {
				t.Fatalf("attrs %v", a)
			}
			if got, ok := a["declared_bytes"]; ok != (tc.declared != nil) || (ok && got != tc.declared) {
				t.Fatalf("declared_bytes = %v (%v), want %v", got, ok, tc.declared)
			}
			if tc.scope == "" {
				if _, ok := a["input_fp"]; ok || a["input_fp_scope"] != nil {
					t.Fatalf("input_fp without bytes: %v", a)
				}
			} else if a["input_fp"] != r.srv.cfg.Redactor.Fingerprint(tc.read) || a["input_fp_scope"] != tc.scope {
				t.Fatalf("input_fp %v scope %v", a["input_fp"], a["input_fp_scope"])
			}
			if (a["body_limit_exceeded"] == true) != (tc.capture == "body_limit_exceeded") ||
				(a["body_truncated"] == true) != (tc.capture == "log_prefix") {
				t.Fatalf("limit flags %v", a)
			}
			if a["captured_bytes"] != len(edge.Body) {
				t.Fatalf("captured_bytes %v, body %d bytes", a["captured_bytes"], len(edge.Body))
			}
			for _, old := range []string{"body_bytes", "body_fingerprint"} {
				if _, ok := a[old]; ok {
					t.Fatalf("final request still carries %s", old)
				}
			}
		})
	}
}

// A request answered before its body is read says so, even when it claims one.
func TestCaptureRateLimitedNotRead(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.MaxPerSource = 1 })
	gate := make(chan time.Time)
	r.clk.setGate(gate)
	done := make(chan int, 1)
	go func() { done <- r.do("GET", "/v1/edge/A/status", "").Code }()
	r.clk.waitEntered(t, 1)
	rec := r.do("POST", "/v1/chat/completions", chatBody)
	edge := r.sink.lastEdge(t) // before the held request finishes
	close(gate)
	<-done
	a := edge.Attrs
	if rec.Code != 429 || a["capture_state"] != "not_read" || a["parse_state"] != "not_attempted" ||
		a["observed_bytes"] != 0 || a["captured_bytes"] != 0 || a["declared_bytes"] != int64(len(chatBody)) {
		t.Fatalf("status %d attrs %v", rec.Code, a)
	}
	if _, ok := a["input_fp"]; ok {
		t.Fatal("an unread body has an input_fp")
	}
}

// declared_bytes is the client's claim: absent without a Content-Length, zero
// only when the client sent zero, never filled in for a chunked body.
func TestCaptureDeclaredBytes(t *testing.T) {
	explicitZero := request("POST", "/v1/chat/completions", "")
	explicitZero.Header.Set("Content-Length", "0")
	newChunked := func() *http.Request {
		req := request("POST", "/v1/chat/completions", chatBody)
		req.ContentLength, req.TransferEncoding = -1, []string{"chunked"}
		return req
	}
	chunked := newChunked()
	cases := []struct {
		name string
		req  *http.Request
		want any
	}{
		{"length", request("POST", "/v1/chat/completions", chatBody), int64(len(chatBody))},
		{"explicit zero", explicitZero, int64(0)},
		{"chunked", chunked, nil},
		{"no header, no body", request("GET", "/v1/models", ""), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, PersonaOpenAI)
			r.serve(tc.req)
			got, ok := r.sink.lastEdge(t).Attrs["declared_bytes"]
			if ok != (tc.want != nil) || (ok && got != tc.want) {
				t.Fatalf("declared_bytes = %v (%v), want %v", got, ok, tc.want)
			}
		})
	}
	// A chunked body still reports what the server read.
	r := newRig(t, PersonaOpenAI)
	r.serve(newChunked())
	if got := r.sink.lastEdge(t).Attrs["observed_bytes"]; got != len(chatBody) {
		t.Fatalf("chunked observed_bytes = %v", got)
	}
}

// A prefix fingerprint links bodies that share their first MaxBodyBytes and
// says it is a prefix; a full one keys the whole body.
func TestInputFingerprintFullVsPrefix(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.MaxBodyBytes = 64 })
	red := r.srv.cfg.Redactor
	head := strings.Repeat("a", 64)
	r.do("POST", "/nope", head+"1111")
	a := r.sink.lastEdge(t).Attrs
	r.do("POST", "/nope", head+"2222")
	b := r.sink.lastEdge(t).Attrs
	if a["input_fp"] != red.Fingerprint(head) || b["input_fp"] != a["input_fp"] ||
		a["input_fp_scope"] != "prefix" || b["input_fp_scope"] != "prefix" {
		t.Fatalf("prefix fingerprints %v / %v", a, b)
	}
	r.do("POST", "/nope", "short")
	c := r.sink.lastEdge(t).Attrs
	if c["input_fp"] != red.Fingerprint("short") || c["input_fp"] == a["input_fp"] || c["input_fp_scope"] != "full" {
		t.Fatalf("full fingerprint %v", c)
	}
}

// Request metadata that borrows the new attribute names changes no attribute
// the server sets.
func TestCaptureIgnoresForgedMetadata(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	body := `{"model":"qwen3:8b","messages":[{"role":"user","content":"hi"}],"capture_state":"none",` +
		`"parse_state":"failed","input_fp":"forged","declared_bytes":1,"observed_bytes":1,"redactions":9}`
	r.serve(request("POST", "/v1/chat/completions?capture_state=none&input_fp=forged&declared_bytes=1", body,
		"X-Capture-State", "none", "X-Input-Fp", "forged", "Content-Length", "1"))
	a := r.sink.lastEdge(t).Attrs
	if a["capture_state"] != "complete" || a["parse_state"] != "ok" || a["observed_bytes"] != len(body) ||
		a["declared_bytes"] != int64(len(body)) || a["input_fp"] != r.srv.cfg.Redactor.Fingerprint(body) ||
		a["input_fp_scope"] != "full" || a["redactions"] != 0 {
		t.Fatalf("attrs %v", a)
	}
}

// Invalid UTF-8 becomes U+FFFD before redaction, the flag says so, and the
// limit applies to the text that ships.
func TestCaptureInvalidUTF8(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	r.do("POST", "/v1/chat/completions", chatBody)
	if got := r.sink.lastEdge(t).Attrs["body_utf8_replaced"]; got != false {
		t.Fatalf("valid body: body_utf8_replaced = %v", got)
	}
	body := "{\"model\":\"qwen3:8b\",\"note\":\"a\xffb\xc3\"}"
	r.do("POST", "/v1/chat/completions", body)
	edge := r.sink.lastEdge(t)
	a := edge.Attrs
	if a["body_utf8_replaced"] != true || !utf8.ValidString(edge.Body) || !strings.Contains(edge.Body, "�") ||
		a["captured_bytes"] != len(edge.Body) || a["observed_bytes"] != len(body) || a["capture_state"] != "complete" ||
		a["input_fp"] != r.srv.cfg.Redactor.Fingerprint(body) {
		t.Fatalf("attrs %v body %q", a, edge.Body)
	}

	// Each invalid byte grows to three, so the replaced text outgrows the limit.
	const limit = 64
	r = newRig(t, PersonaOpenAI, func(c *Config) { c.MaxLogBody = limit })
	r.do("POST", "/nope", strings.Repeat("\xffa", 100))
	edge = r.sink.lastEdge(t)
	a = edge.Attrs
	if a["body_utf8_replaced"] != true || a["capture_state"] != "log_prefix" || a["body_truncated"] != true ||
		len(edge.Body) > limit || !utf8.ValidString(edge.Body) || a["captured_bytes"] != len(edge.Body) {
		t.Fatalf("attrs %v body %d bytes", a, len(edge.Body))
	}
}

// Cutting the scan window inside a valid rune is not malformed input.
func TestPreviewCutRuneNotMalformed(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.MaxLogBody = 100 })
	for _, unit := range []string{"世", "é", "\U0001F600"} {
		for extra := 0; extra < 4; extra++ {
			b := strings.Repeat(unit, 1+(100+logRedactMargin+extra*len(unit))/len(unit))
			p := r.srv.preview([]byte(b), int64(len(b)))
			if !p.cut || p.replaced || len(p.text) > 100 || !utf8.ValidString(p.text) {
				t.Fatalf("unit %q extra %d: cut=%v replaced=%v len=%d", unit, extra, p.cut, p.replaced, len(p.text))
			}
		}
	}
}

// redactions counts what the scrubber replaced. Marker text that the client
// sent is not a replacement. A body that grows past the limit after redaction
// keeps a prefix and says so.
func TestCaptureRedactions(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	r.do("POST", "/v1/chat/completions", `{"model":"qwen3:8b","messages":[],"password":"hunter2hunter2hunter2hunter2hunter2"}`)
	edge := r.sink.lastEdge(t)
	if n, _ := edge.Attrs["redactions"].(int); n < 1 || strings.Contains(edge.Body, "hunter2") || edge.Attrs["captured_bytes"] != len(edge.Body) {
		t.Fatalf("attrs %v body %q", edge.Attrs, edge.Body)
	}

	const marker = "[redacted:hmac256:0123456789abcdef]"
	r.do("POST", "/v1/chat/completions", `{"model":"qwen3:8b","note":"[redacted] `+marker+`"}`)
	edge = r.sink.lastEdge(t)
	if edge.Attrs["redactions"] != 0 || !strings.Contains(edge.Body, marker) {
		t.Fatalf("forged marker: attrs %v body %q", edge.Attrs, edge.Body)
	}

	item := `{"password":"hunter2hunter2hunter2"}`
	body := `{"model":"qwen3:8b","extra":[` + strings.Repeat(item+",", 11) + item + `]}`
	r = newRig(t, PersonaOpenAI, func(c *Config) { c.MaxLogBody = len(body) + 8 })
	if text, n := r.srv.cfg.Redactor.TextCount(body); n == 0 || len(text) <= r.srv.cfg.MaxLogBody {
		t.Fatalf("precondition: %d redactions, %d bytes for a limit of %d", n, len(text), r.srv.cfg.MaxLogBody)
	}
	r.do("POST", "/v1/chat/completions", body)
	edge = r.sink.lastEdge(t)
	a := edge.Attrs
	if n, _ := a["redactions"].(int); n < 1 || a["capture_state"] != "log_prefix" || a["body_truncated"] != true ||
		len(edge.Body) > r.srv.cfg.MaxLogBody || a["captured_bytes"] != len(edge.Body) || a["input_fp_scope"] != "full" {
		t.Fatalf("expansion: attrs %v body %d bytes", a, len(edge.Body))
	}
}

// The response event reports its own capture state and keeps response_bytes;
// the request-only attributes stay off it.
func TestResponseCaptureState(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	rec := r.do("POST", "/v1/chat/completions", chatBody)
	resp := r.sink.lastResponse(t)
	a := resp.Attrs
	if a["capture_state"] != "complete" || a["captured_bytes"] != len(resp.Body) || a["body_utf8_replaced"] != false ||
		a["redactions"] != 0 || a["response_bytes"] != int64(rec.Body.Len()) {
		t.Fatalf("complete response attrs %v", a)
	}
	for _, k := range []string{"parse_state", "declared_bytes", "observed_bytes", "input_fp", "input_fp_scope", "body_bytes"} {
		if _, ok := a[k]; ok {
			t.Fatalf("response carries %s", k)
		}
	}

	r = newRig(t, PersonaOpenAI, func(c *Config) { c.MaxLogBody = 100 })
	rec = r.do("POST", "/v1/embeddings", `{"model":"qwen3:8b","input":["`+strings.Repeat("word ", 50)+`"]}`)
	resp = r.sink.lastResponse(t)
	a = resp.Attrs
	if a["capture_state"] != "log_prefix" || a["body_truncated"] != true || a["captured_bytes"] != len(resp.Body) ||
		len(resp.Body) > 100 || a["response_bytes"] != int64(rec.Body.Len()) {
		t.Fatalf("prefix response attrs %v", a)
	}

	r = newRig(t, PersonaOpenAI)
	r.do("POST", "/v1/chat/completions", `{"model":"sk-`+strings.Repeat("A", 40)+`","messages":[{"role":"user","content":"hi"}]}`)
	if n, _ := r.sink.lastResponse(t).Attrs["redactions"].(int); n < 1 {
		t.Fatalf("echoed key not counted: %v", r.sink.lastResponse(t).Attrs)
	}
}
