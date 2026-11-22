package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"attackbox/internal/responder"
	"attackbox/internal/telemetry"
)

func TestNewValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("no error without a Responder")
	}
	store := responder.NewStore(responder.StoreConfig{})
	rsp := responder.New(responder.Config{}, store)
	if _, err := New(Config{Responder: rsp, Persona: "bogus"}); err == nil {
		t.Fatal("no error for an unknown persona")
	}
	s, err := New(Config{Responder: rsp})
	if err != nil {
		t.Fatal(err)
	}
	c := s.cfg
	if s.persona != PersonaOpenAI || c.Version != "1.0.0" || len(c.Models) != 3 || c.MaxBodyBytes != 1<<20 ||
		c.MaxMessages != 1024 || c.MaxTools != 128 || c.MaxConcurrent != 256 || c.MaxPerSource != 8 ||
		c.MaxStreamDuration != 180*time.Second || c.HoldSilent != 150*time.Second ||
		c.IdleInterval != 45*time.Second || len(c.SessionKey) == 0 || len(c.EmbedSeed) == 0 ||
		c.Redactor == nil || c.Sink == nil || c.Now == nil || c.After == nil {
		t.Fatalf("defaults = %+v", c)
	}
	// With no Sink and a real clock the server still answers.
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, request("GET", "/v1/models", ""))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestBodyLimit(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.MaxBodyBytes = 64 })
	big := `{"model":"qwen3:8b","messages":[{"role":"user","content":"` + strings.Repeat("x", 400) + `"}]}`
	rec := r.do("POST", "/v1/chat/completions", big)
	e := sub(t, decode(t, rec), "error")
	if rec.Code != 413 || e["message"] != "Request body too large" {
		t.Fatalf("status %d %v", rec.Code, e)
	}
	edge := r.sink.lastEdge(t)
	if edge.Attrs["body_limit_exceeded"] != true || len(edge.Body) > 64 || edge.Result != "too_large" {
		t.Fatalf("edge = %v (%d body bytes)", edge.Attrs, len(edge.Body))
	}
	if len(r.sink.stream(telemetry.StreamTranscript)) != 0 {
		t.Fatal("an oversized body reached the responder")
	}
}

func TestLogBodyIsCapped(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.MaxLogBody = 50 })
	r.do("POST", "/v1/chat/completions", `{"model":"qwen3:8b","messages":[{"role":"user","content":"`+strings.Repeat("\u00e9", 100)+`"}]}`)
	edge := r.sink.lastEdge(t)
	if len(edge.Body) > 50 || edge.Attrs["body_truncated"] != true {
		t.Fatalf("body %d bytes, attrs %v", len(edge.Body), edge.Attrs)
	}
}

// The body is cut before scrubbing; a credential split by the cut must still
// be redacted.
func TestLogBodyCutCredential(t *testing.T) {
	const secret = "hunter2hunter2hunter2hunter2hunter2"
	head := `{"model":"qwen3:8b","password":"`
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.MaxLogBody = len(head) + 10 })
	r.do("POST", "/v1/chat/completions", head+secret+`","messages":[]}`)
	edge := r.sink.lastEdge(t)
	if strings.Contains(edge.Body, "hunter2") || edge.Attrs["body_truncated"] != true {
		t.Fatalf("body %q, attrs %v", edge.Body, edge.Attrs)
	}
}

func TestMalformedBodies(t *testing.T) {
	for _, persona := range []string{PersonaOpenAI, PersonaVLLM, PersonaOllama} {
		r := newRig(t, persona)
		path := "/v1/chat/completions"
		if persona == PersonaOllama {
			path = "/api/chat"
		}
		for _, body := range []string{"{", "[]", "null", `"x"`, "42", ""} {
			rec := r.do("POST", path, body)
			if rec.Code != 400 {
				t.Errorf("%s %q = %d", persona, body, rec.Code)
			}
		}
		// Wrong field types read as absent, never crash.
		for _, body := range []string{
			`{"model":7,"messages":"x"}`,
			`{"model":"qwen3:8b","messages":[1,"a",null,{"role":5,"content":{}}],"tools":"x","stream":"yes"}`,
		} {
			if rec := r.do("POST", path, body); rec.Code >= 500 {
				t.Errorf("%s %q = %d", persona, body, rec.Code)
			}
		}
	}
}

func TestArrayLimits(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.MaxMessages = 2; c.MaxTools = 1 })
	msg := `{"role":"user","content":"x"}`
	rec := r.do("POST", "/v1/chat/completions", `{"model":"qwen3:8b","messages":[`+strings.Join([]string{msg, msg, msg}, ",")+`]}`)
	e := sub(t, decode(t, rec), "error")
	if rec.Code != 400 || e["param"] != "messages" || e["code"] != "array_above_max_length" ||
		!strings.Contains(e["message"].(string), "maximum length 2, but got an array with length 3") {
		t.Fatalf("messages = %d %v", rec.Code, e)
	}
	rec = r.do("POST", "/v1/chat/completions", `{"model":"qwen3:8b","messages":[`+msg+`],"tools":[{},{}]}`)
	if e = sub(t, decode(t, rec), "error"); rec.Code != 400 || e["param"] != "tools" {
		t.Fatalf("tools = %d %v", rec.Code, e)
	}
	rec = r.do("POST", "/v1/completions", `{"model":"qwen3:8b","prompt":["a","b","c"]}`)
	if rec.Code != 400 {
		t.Fatalf("prompts = %d", rec.Code)
	}
	rec = r.do("POST", "/v1/responses", `{"model":"qwen3:8b","input":["a","b","c"]}`)
	if rec.Code != 400 {
		t.Fatalf("input = %d", rec.Code)
	}
	// At the limit is fine.
	rec = r.do("POST", "/v1/chat/completions", `{"model":"qwen3:8b","messages":[`+msg+`,`+msg+`],"tools":[{}]}`)
	if rec.Code != 200 {
		t.Fatalf("at the limit = %d", rec.Code)
	}
	if edge := r.sink.lastEdge(t); edge.Attrs["tool_count"] != 1 {
		t.Fatalf("tool_count = %v", edge.Attrs["tool_count"])
	}
}

func TestPerSourceLimit(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.MaxPerSource = 1 })
	gate := make(chan time.Time)
	r.clk.setGate(gate)
	done := make(chan int, 1)
	go func() { done <- r.do("GET", "/v1/edge/A/status", "").Code }()
	r.clk.waitEntered(t, 1)

	rec := r.do("GET", "/health", "")
	e := sub(t, decode(t, rec), "error")
	if rec.Code != 429 || rec.Header().Get("Retry-After") != "1" || e["code"] != "rate_limit_exceeded" {
		t.Fatalf("same source = %d %v", rec.Code, e)
	}
	if edge := r.sink.lastEdge(t); edge.Result != "rate_limited" {
		t.Fatalf("result = %q", edge.Result)
	}
	if rec = r.serve(fromAddr("198.51.100.7:4000", "GET", "/health")); rec.Code != 200 {
		t.Fatalf("other source = %d", rec.Code)
	}
	close(gate)
	if code := <-done; code != 200 {
		t.Fatalf("held request = %d", code)
	}
	if rec = r.do("GET", "/health", ""); rec.Code != 200 {
		t.Fatalf("slot not released: %d", rec.Code)
	}
}

func TestGlobalLimit(t *testing.T) {
	r := newRig(t, PersonaOllama, func(c *Config) { c.MaxConcurrent = 1 })
	gate := make(chan time.Time)
	r.clk.setGate(gate)
	done := make(chan int, 1)
	go func() { done <- r.do("GET", "/v1/edge/A/status", "").Code }()
	r.clk.waitEntered(t, 1)
	rec := r.serve(fromAddr("198.51.100.7:4000", "GET", "/api/version"))
	if rec.Code != 429 || !strings.Contains(decode(t, rec)["error"].(string), "server busy") {
		t.Fatalf("over the global limit = %d %s", rec.Code, rec.Body)
	}
	close(gate)
	<-done
}

func fromAddr(addr, method, path string, hdr ...string) *http.Request {
	req := request(method, path, "", hdr...)
	req.RemoteAddr = addr
	return req
}

func TestForwardedFor(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.TrustedProxies = trusted })
	cases := []struct {
		name, peer, xff, want string
	}{
		{"untrusted peer ignored", "192.0.2.10:1", "1.2.3.4", "192.0.2.10"},
		{"trusted peer, one hop", "10.0.0.5:1", "203.0.113.9", "203.0.113.9"},
		{"spoofed left entry ignored", "10.0.0.5:1", "1.2.3.4, 203.0.113.9", "203.0.113.9"},
		{"trusted hops skipped", "10.0.0.5:1", "203.0.113.9, 10.0.0.7", "203.0.113.9"},
		{"no header", "10.0.0.5:1", "", "10.0.0.5"},
		{"garbage entry", "10.0.0.5:1", "nonsense", "10.0.0.5"},
		{"all trusted", "10.0.0.5:1", "10.1.1.1", "10.0.0.5"},
		{"v4-mapped peer", "[::ffff:10.0.0.5]:1", "203.0.113.9", "203.0.113.9"},
	}
	for _, tc := range cases {
		var hdr []string
		if tc.xff != "" {
			hdr = []string{"X-Forwarded-For", tc.xff}
		}
		r.serve(fromAddr(tc.peer, "GET", "/health", hdr...))
		if got := r.sink.lastEdge(t).SrcIP; got != tc.want {
			t.Errorf("%s: src = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestSessionKeyVariance(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	key := func(s *Server, src, ua string, hdr ...string) string {
		h := http.Header{}
		for i := 0; i+1 < len(hdr); i += 2 {
			h.Set(hdr[i], hdr[i+1])
		}
		return s.sessionKey(src, ua, h)
	}
	base := key(r.srv, "192.0.2.1", "ua/1", "Authorization", "Bearer abc")
	if base != key(r.srv, "192.0.2.1", "ua/1", "Authorization", "Bearer abc") {
		t.Fatal("key is not stable")
	}
	variants := map[string]string{
		"source":     key(r.srv, "192.0.2.2", "ua/1", "Authorization", "Bearer abc"),
		"user agent": key(r.srv, "192.0.2.1", "ua/2", "Authorization", "Bearer abc"),
		"credential": key(r.srv, "192.0.2.1", "ua/1", "Authorization", "Bearer abd"),
		"no cred":    key(r.srv, "192.0.2.1", "ua/1"),
		"api key":    key(r.srv, "192.0.2.1", "ua/1", "X-Api-Key", "Bearer abc"),
	}
	seen := map[string]string{base: "base"}
	for name, k := range variants {
		if prev, dup := seen[k]; dup && !(name == "api key" && prev == "base") {
			t.Errorf("%s collides with %s", name, prev)
		}
		seen[k] = name
	}
	// Authorization wins over X-Api-Key when both are present: the API key is
	// ignored, whatever its value, and an empty Authorization falls back to it.
	both := key(r.srv, "192.0.2.1", "ua/1", "Authorization", "Bearer abc", "X-Api-Key", "other")
	if both != base {
		t.Fatal("X-Api-Key changed the key while Authorization was present")
	}
	if both == key(r.srv, "192.0.2.1", "ua/1", "X-Api-Key", "other") {
		t.Fatal("X-Api-Key took priority over Authorization")
	}
	if key(r.srv, "192.0.2.1", "ua/1", "Authorization", "", "X-Api-Key", "other") != key(r.srv, "192.0.2.1", "ua/1", "X-Api-Key", "other") {
		t.Fatal("empty Authorization did not fall back to X-Api-Key")
	}
	// The fields are NUL-separated, so shifting a byte between them changes the key.
	if key(r.srv, "a", "bc") == key(r.srv, "ab", "c") {
		t.Fatal("fields are not delimited")
	}
	other := newRig(t, PersonaOpenAI, func(c *Config) { c.SessionKey = []byte("different") })
	if key(other.srv, "192.0.2.1", "ua/1", "Authorization", "Bearer abc") == base {
		t.Fatal("the key does not depend on SessionKey")
	}
	// Same inputs share a responder session; any difference splits it.
	r.do("POST", "/v1/chat/completions", chatBody)
	r.do("POST", "/v1/chat/completions", chatBody)
	r.do("POST", "/v1/chat/completions", chatBody, "User-Agent", "someone-else/2")
	ev := r.sink.stream(telemetry.StreamTranscript)
	if ev[0].SessionID != ev[1].SessionID || ev[0].SessionID == ev[2].SessionID {
		t.Fatalf("sessions = %q %q %q", ev[0].SessionID, ev[1].SessionID, ev[2].SessionID)
	}
}

func TestCredentialRedaction(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	secrets := []string{
		"sk-headersecretvalue123456", "sk-xapikeysecretvalue12345", "cookiesecretvalue99",
		"sk-bodysecretvalue1234567890", "bodybearertoken1234", "hunter2hunter2", "sk-pathsecretvalue12345678",
	}
	req := request("POST", "/v1/chat/completions?api_key=hunter2hunter2&x=1",
		`{"model":"qwen3:8b","messages":[{"role":"user","content":"use sk-bodysecretvalue1234567890 and Bearer bodybearertoken1234"}]}`,
		"Authorization", "Bearer "+secrets[0], "X-Api-Key", secrets[1], "Cookie", "sid="+secrets[2])
	r.serve(req)
	r.do("GET", "/v1/models/"+secrets[6], "")
	blob, _ := json.Marshal(r.sink.events)
	for _, s := range secrets {
		if strings.Contains(string(blob), s) {
			t.Errorf("secret %q reached the log", s)
		}
	}
	for _, s := range []string{"hmac256:", "credential_fingerprints"} {
		if !strings.Contains(string(blob), s) {
			t.Errorf("no %q in the log", s)
		}
	}
}

func TestMetricLabelHygiene(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	for _, p := range []string{
		"/v1/models/12345", "/v1/unknown/987654", "/v1/models/sk-abcdefghijklmnopqrstuvwxyz", "/x/192.0.2.10/y",
	} {
		r.do("GET", p, "")
	}
	r.do("POST", "/v1/chat/completions", chatBody)
	r.do("DELETE", "/v1/models", "")
	allowed := map[string]bool{"persona": true, "endpoint": true, "status_class": true, "probe_id": true, "task": true}
	if len(r.sink.counts) == 0 {
		t.Fatal("no counters")
	}
	endpoints := map[string]bool{}
	for _, c := range r.sink.counts {
		if c.name != "attackbox.requests" && c.name != "attackbox.probes" {
			t.Fatalf("unexpected metric %q", c.name)
		}
		for k, v := range c.attrs {
			if !allowed[k] {
				t.Errorf("label %q is not bounded", k)
			}
			for _, bad := range []string{"192.0.2", "12345", "987654", "abcdefghij", "sk-"} {
				if strings.Contains(v, bad) {
					t.Errorf("label %s=%q carries request data", k, v)
				}
			}
		}
		if e, ok := c.attrs["endpoint"]; ok {
			endpoints[e] = true
		}
	}
	for _, want := range []string{"/v1/models/{model}", "/unmatched", "/v1/chat/completions", "/v1/models"} {
		if !endpoints[want] {
			t.Errorf("no endpoint label %q in %v", want, endpoints)
		}
	}
	probes := 0
	for _, c := range r.sink.counts {
		if c.name == "attackbox.probes" {
			probes++
			if c.attrs["probe_id"] == "" || c.attrs["task"] == "" || c.attrs["persona"] != PersonaOpenAI {
				t.Errorf("probe counter = %v", c.attrs)
			}
		}
	}
	if probes != 1 {
		t.Errorf("probe counter fired %d times", probes)
	}
}

func TestEventShape(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	r.do("POST", "/v1/chat/completions?a=1", chatBody, "Authorization", "Bearer sk-live-aaaaaaaaaaaaaaaa")
	edge, tr := r.sink.lastEdge(t), r.sink.lastTranscript(t)
	if edge.SessionID == "" || edge.SessionID != tr.SessionID || edge.RequestID != tr.RequestID || edge.RequestID == "" {
		t.Fatalf("ids: %+v / %+v", edge, tr)
	}
	if edge.SrcIP != "192.0.2.10" || edge.UserAgent != testUA || edge.Persona != PersonaOpenAI ||
		edge.Action != "POST" || edge.Resource != "/v1/chat/completions" || edge.Result != "ok" || edge.Status != 200 {
		t.Fatalf("edge = %+v", edge)
	}
	if edge.Body != chatBody || edge.Attrs["query"] != "a=1" || edge.Attrs["route"] != "/v1/chat/completions" ||
		edge.Attrs["task"] == nil || edge.Attrs["stream"] != false {
		t.Fatalf("edge attrs = %v", edge.Attrs)
	}
	if tr.ProbeID != edge.ProbeID || tr.ProbeID == "" || len(tr.TaskLabels) == 0 && tr.Body == "" {
		t.Fatalf("transcript = %+v", tr)
	}
	if edge.Timestamp != fixedNow {
		t.Fatalf("timestamp = %v", edge.Timestamp)
	}
	// Non-inference traffic has no transcript.
	n := len(r.sink.stream(telemetry.StreamTranscript))
	r.do("GET", "/v1/models", "")
	if len(r.sink.stream(telemetry.StreamTranscript)) != n {
		t.Fatal("a model listing wrote a transcript")
	}
}

func TestConcurrentClients(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	const clients = 50
	var wg sync.WaitGroup
	fail := make(chan string, clients*2)
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr := fmt.Sprintf("192.0.2.%d:4000", i+1)
			for j := 0; j < 2; j++ {
				body := chatBody
				if j == 1 {
					body = strings.Replace(chatBody, `"model"`, `"stream":true,"model"`, 1)
				}
				req := request("POST", "/v1/chat/completions", body)
				req.RemoteAddr = addr
				if rec := r.serve(req); rec.Code != 200 {
					fail <- fmt.Sprintf("client %d request %d: %d", i, j, rec.Code)
				}
			}
		}()
	}
	wg.Wait()
	close(fail)
	for f := range fail {
		t.Error(f)
	}
	if n := len(r.sink.stream(telemetry.StreamEdge)); n != clients*2 {
		t.Errorf("edge events = %d", n)
	}
	if n := len(r.sink.stream(telemetry.StreamTranscript)); n != clients*2 {
		t.Errorf("transcript events = %d", n)
	}
	sessions := map[string]bool{}
	for _, e := range r.sink.stream(telemetry.StreamTranscript) {
		sessions[e.SessionID] = true
	}
	if len(sessions) != clients {
		t.Errorf("sessions = %d, want %d", len(sessions), clients)
	}
}

// TestNoSelfDescription walks every endpoint of every persona, with every
// responder gate, and checks that no response says what the service is.
func TestNoSelfDescription(t *testing.T) {
	forbidden := []string{"attackbox", "attack-box", "honeypot", "decoy", "canary", "canaries"}
	common := [][3]string{
		{"GET", "/v1/models", ""}, {"GET", "/v1/models/qwen3:8b", ""}, {"GET", "/v1/models/nope", ""},
		{"POST", "/v1/chat/completions", chatBody},
		{"POST", "/v1/chat/completions", strings.Replace(chatBody, `"model"`, `"stream":true,"model"`, 1)},
		{"POST", "/v1/completions", `{"model":"qwen3:8b","prompt":"hi"}`},
		{"POST", "/v1/responses", `{"model":"qwen3:8b","input":"hi"}`},
		{"POST", "/v1/responses", `{"model":"qwen3:8b","input":"hi","stream":true}`},
		{"GET", "/v1/responses/resp_abc", ""}, {"POST", "/v1/responses/resp_abc/cancel", ""},
		{"POST", "/v1/embeddings", `{"model":"qwen3:8b","input":"hi"}`},
		{"GET", "/v1/edge/A/status", ""}, {"GET", "/v1/edge/Z/status", ""},
		{"GET", "/health", ""}, {"GET", "/version", ""}, {"GET", "/metrics", ""}, {"GET", "/docs", ""}, {"GET", "/openapi.json", ""},
		{"POST", "/invocations", `{"prompt":"hi"}`},
		{"GET", "/", ""}, {"GET", "/api/version", ""}, {"GET", "/api/tags", ""}, {"GET", "/api/ps", ""},
		{"POST", "/api/show", `{"model":"qwen3:8b"}`}, {"POST", "/api/chat", chatBody},
		{"POST", "/api/generate", `{"model":"qwen3:8b","prompt":"hi"}`},
		{"POST", "/api/embed", `{"model":"qwen3:8b","input":"hi"}`},
		{"POST", "/api/pull", `{"model":"other"}`}, {"POST", "/api/push", `{"model":"other"}`},
		{"POST", "/api/create", `{"model":"x"}`}, {"POST", "/api/copy", `{"source":"nope","destination":"y"}`},
		{"DELETE", "/api/delete", `{"model":"nope"}`},
		{"GET", "/nowhere", ""}, {"PUT", "/v1/models", ""}, {"POST", "/v1/chat/completions", "{"},
		{"POST", "/v1/chat/completions", `{"model":"attackbox honeypot decoy canary"}`},
	}
	for _, persona := range []string{PersonaOpenAI, PersonaVLLM, PersonaOllama} {
		for _, behavior := range responder.Behaviors {
			r := newRig(t, persona, func(c *Config) { c.IdleInterval = 10 * time.Millisecond })
			r.pin(behavior)
			for round := 0; round < 3; round++ {
				for _, rq := range common {
					rec := r.do(rq[0], rq[1], rq[2])
					dump := strings.ToLower(rec.Body.String())
					for k, v := range rec.Header() {
						dump += "\n" + strings.ToLower(k+": "+strings.Join(v, ","))
					}
					for _, w := range forbidden {
						if strings.Contains(dump, w) && !strings.Contains(rq[2], w) {
							t.Fatalf("%s/%s: %s %s leaks %q:\n%.300s", persona, behavior, rq[0], rq[1], w, rec.Body)
						}
					}
				}
			}
		}
	}
}
