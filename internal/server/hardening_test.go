package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestLogBodyRedactsBeforeCut(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.MaxLogBody = 64 })
	// The key starts before the cap and ends after it. Cutting first would leave
	// a 14-character stub that no redactor pattern matches.
	secret := "sk-" + strings.Repeat("A", 40)
	body := strings.Repeat("x", 49) + " " + secret + strings.Repeat("y", 100)
	got, cut := r.srv.logBody([]byte(body))
	if !cut || len(got) > 64 {
		t.Fatalf("cut=%v len=%d", cut, len(got))
	}
	if strings.Contains(got, "sk-AAAA") {
		t.Fatalf("key stub survived: %q", got)
	}
}

func TestLogBodyRuneSafe(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.MaxLogBody = 100 })
	for _, unit := range []string{"世", "é", "x", "\U0001F600"} {
		for extra := 0; extra < 4; extra++ {
			b := strings.Repeat(unit, 1+(100+logRedactMargin+extra*len(unit))/len(unit))
			got, cut := r.srv.logBody([]byte(b))
			if !cut || len(got) > 100 || !utf8.ValidString(got) {
				t.Fatalf("unit %q extra %d: cut=%v len=%d valid=%v", unit, extra, cut, len(got), utf8.ValidString(got))
			}
		}
	}
	if got, cut := r.srv.logBody([]byte("short")); cut || got != "short" {
		t.Fatalf("short body = %q, %v", got, cut)
	}
	if got, cut := r.srv.logBody(nil); cut || got != "" {
		t.Fatalf("empty body = %q, %v", got, cut)
	}
}

func TestPanicBecomesPersona500(t *testing.T) {
	cases := map[string]func(*testing.T, map[string]any){
		PersonaOpenAI: func(t *testing.T, m map[string]any) {
			if e := sub(t, m, "error"); e["type"] != "server_error" {
				t.Errorf("openai error = %v", e)
			}
		},
		PersonaVLLM: func(t *testing.T, m map[string]any) {
			if m["type"] != "InternalServerError" || m["code"] != float64(500) {
				t.Errorf("vllm error = %v", m)
			}
		},
		PersonaOllama: func(t *testing.T, m map[string]any) {
			if m["error"] != "Internal Server Error" {
				t.Errorf("ollama error = %v", m)
			}
		},
	}
	for persona, check := range cases {
		r := newRig(t, persona)
		r.srv.routes = append(r.srv.routes,
			newRoute("GET", "/boom", "", func(*call) { panic("boom\x07 " + strings.Repeat("z", 500)) }),
			newRoute("GET", "/late", "", func(c *call) { c.plain(200, "text/plain", "partial"); panic("late") }),
		)
		rec := r.do("GET", "/boom", "")
		if rec.Code != 500 {
			t.Fatalf("%s: status %d", persona, rec.Code)
		}
		check(t, decode(t, rec))
		edge := r.sink.lastEdge(t)
		if edge.Status != 500 || edge.Result != "error" || edge.Attrs["panic"] != true {
			t.Fatalf("%s: edge = %d %s %v", persona, edge.Status, edge.Result, edge.Attrs)
		}
		if v := attr[string](t, edge, "panic_value"); len(v) > 256 || strings.ContainsRune(v, 7) {
			t.Fatalf("%s: panic_value %q", persona, v)
		}
		// A panic after the reply began keeps that reply and is still tagged.
		rec = r.do("GET", "/late", "")
		if rec.Code != 200 || rec.Body.String() != "partial" {
			t.Fatalf("%s: late = %d %q", persona, rec.Code, rec.Body)
		}
		if edge = r.sink.lastEdge(t); edge.Status != 200 || edge.Attrs["panic"] != true {
			t.Fatalf("%s: late edge = %d %v", persona, edge.Status, edge.Attrs)
		}
	}
}

func TestAbortHandlerPropagates(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	r.srv.routes = append(r.srv.routes, newRoute("GET", "/abort", "", func(*call) { panic(http.ErrAbortHandler) }))
	defer func() {
		if v := recover(); v != http.ErrAbortHandler {
			t.Fatalf("recovered %v, want ErrAbortHandler", v)
		}
	}()
	r.do("GET", "/abort", "")
}

// deadlineWriter records the deadlines the server sets through
// http.ResponseController.
type deadlineWriter struct {
	*httptest.ResponseRecorder
	write []time.Time
}

func (d *deadlineWriter) SetWriteDeadline(t time.Time) error {
	d.write = append(d.write, t)
	return nil
}

func TestWriteDeadlineOnEveryRequest(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	for _, path := range []string{"/v1/models", "/v1/nothing"} {
		w := &deadlineWriter{ResponseRecorder: httptest.NewRecorder()}
		before := time.Now()
		r.h.ServeHTTP(w, request("GET", path, ""))
		after := time.Now()
		if len(w.write) == 0 {
			t.Fatalf("%s: no write deadline", path)
		}
		slack := r.srv.cfg.MaxStreamDuration + 15*time.Second
		for _, d := range w.write {
			if d.Before(before.Add(slack)) || d.After(after.Add(slack)) {
				t.Errorf("%s: deadline %v outside [%v, %v]", path, d, before.Add(slack), after.Add(slack))
			}
		}
	}
}

// A real http.Server with a ReadTimeout shorter than the hold. The hold must
// run to the end, for a bodiless request and for one that carried a body.
func TestReadTimeoutDoesNotCutHold(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) {
		c.After = time.After
		c.StatusHold = 2200 * time.Millisecond
		c.HoldSilent = 2200 * time.Millisecond
	})
	ts := httptest.NewUnstartedServer(r.h)
	ts.Config.ReadTimeout = time.Second
	ts.Start()
	defer ts.Close()

	// The client dials from loopback; pin that session to the silent hold.
	sess, _ := r.store.Get(r.srv.sessionKey("127.0.0.1", testUA, http.Header{}))
	sess.Behavior = "timeout-silent"

	do := func(method, path, body string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("User-Agent", testUA)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	// finish runs after the reply; wait for the n-th edge event.
	holdResult := func(n int) any {
		t.Helper()
		for i := 0; i < 100 && len(r.sink.stream("edge")) < n; i++ {
			time.Sleep(20 * time.Millisecond)
		}
		ev := r.sink.stream("edge")
		if len(ev) < n {
			t.Fatalf("want %d edge events, have %d", n, len(ev))
		}
		return ev[n-1].Attrs["hold_result"]
	}

	if code, b := do("GET", "/v1/edge/A/status", ""); code != 200 || !strings.Contains(b, `"status":"ok"`) {
		t.Fatalf("status hold: %d %q", code, b)
	}
	if hr := holdResult(1); hr != "completed" {
		t.Fatalf("status hold_result = %v", hr)
	}
	for i := 0; i < 2; i++ { // the first two requests are registration, with no hold
		do("POST", "/v1/chat/completions", chatBody)
	}
	if code, b := do("POST", "/v1/chat/completions", chatBody); code != 200 {
		t.Fatalf("chat hold: %d %q", code, b)
	}
	if hr := holdResult(4); hr != "completed" {
		t.Fatalf("chat hold_result = %v", hr)
	}
}

func TestBufferedBodiesCarryContentLength(t *testing.T) {
	emb := `{"model":"qwen3:8b","input":["alpha","beta gamma"]}`
	cases := []struct {
		persona, method, path, body string
	}{
		{PersonaOpenAI, "GET", "/v1/models", ""},
		{PersonaOpenAI, "GET", "/v1/nothing", ""},
		{PersonaOpenAI, "POST", "/v1/embeddings", emb},
		{PersonaOpenAI, "POST", "/v1/embeddings", `{"model":"qwen3:8b","input":["a"],"encoding_format":"base64"}`},
		{PersonaVLLM, "GET", "/metrics", ""},
		{PersonaVLLM, "GET", "/docs", ""},
		{PersonaVLLM, "GET", "/openapi.json", ""},
		{PersonaVLLM, "GET", "/nothing", ""},
		{PersonaVLLM, "POST", "/v1/embeddings", emb},
		{PersonaOllama, "GET", "/api/tags", ""},
		{PersonaOllama, "GET", "/nothing", ""},
		{PersonaOllama, "POST", "/v1/embeddings", emb},
		{PersonaOllama, "POST", "/api/embed", emb},
		{PersonaOllama, "POST", "/api/embeddings", `{"model":"qwen3:8b","prompt":"hi"}`},
	}
	for _, tc := range cases {
		r := newRig(t, tc.persona)
		rec := r.do(tc.method, tc.path, tc.body)
		if rec.Code != 200 && rec.Code != 404 {
			t.Errorf("%s %s = %d", tc.persona, tc.path, rec.Code)
			continue
		}
		if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(rec.Body.Len()) {
			t.Errorf("%s %s: Content-Length %q, body %d bytes", tc.persona, tc.path, got, rec.Body.Len())
		}
	}
}

func TestRequestIDHeader(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	rec := r.do("GET", "/v1/models", "")
	id := rec.Header().Get("X-Request-Id")
	if !regexp.MustCompile(`^req_[0-9a-f]{32}$`).MatchString(id) {
		t.Fatalf("X-Request-Id = %q", id)
	}
	if edge := r.sink.lastEdge(t); !strings.HasPrefix(id, "req_"+edge.RequestID) {
		t.Fatalf("header %q does not match logged id %q", id, edge.RequestID)
	}
	if rec = newRig(t, PersonaVLLM).do("GET", "/v1/models", ""); rec.Header().Get("X-Request-Id") != "" {
		t.Fatal("vllm persona sent X-Request-Id")
	}
}

func TestOllamaContentType(t *testing.T) {
	const want = "application/json; charset=utf-8"
	r := newRig(t, PersonaOllama)
	for _, tc := range [][3]string{
		{"POST", "/v1/chat/completions", chatBody},
		{"GET", "/v1/models", ""},
		{"POST", "/v1/chat/completions", `{"model":"nope","messages":[]}`},
		{"GET", "/api/tags", ""},
	} {
		if got := r.do(tc[0], tc[1], tc[2]).Header().Get("Content-Type"); got != want {
			t.Errorf("%s %s: Content-Type %q", tc[0], tc[1], got)
		}
	}
	if got := newRig(t, PersonaOpenAI).do("GET", "/v1/models", "").Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("openai Content-Type %q", got)
	}
}

func TestMissingMessages(t *testing.T) {
	for _, body := range []string{`{"model":"qwen3:8b"}`, `{"model":"qwen3:8b","messages":null}`} {
		rec := newRig(t, PersonaOpenAI).do("POST", "/v1/chat/completions", body)
		e := sub(t, decode(t, rec), "error")
		if rec.Code != 400 || e["param"] != "messages" || e["code"] != "missing_required_parameter" ||
			e["message"] != "Missing required parameter: 'messages'." {
			t.Errorf("openai %s = %d %v", body, rec.Code, e)
		}
		rec = newRig(t, PersonaVLLM).do("POST", "/v1/chat/completions", body)
		m := decode(t, rec)
		if rec.Code != 400 || m["type"] != "BadRequestError" || m["object"] != "error" ||
			!strings.Contains(m["message"].(string), "'loc': ('body', 'messages'), 'msg': 'Field required'") {
			t.Errorf("vllm %s = %d %v", body, rec.Code, m)
		}
		rec = newRig(t, PersonaOllama).do("POST", "/v1/chat/completions", body)
		e = sub(t, decode(t, rec), "error")
		if rec.Code != 400 || e["message"] != "[] is too short - 'messages'" || e["type"] != "invalid_request_error" {
			t.Errorf("ollama v1 %s = %d %v", body, rec.Code, e)
		}
	}
	// Ollama's native chat without messages is a model load, not an error.
	if rec := newRig(t, PersonaOllama).do("POST", "/api/chat", `{"model":"qwen3:8b"}`); rec.Code != 200 {
		t.Errorf("native load = %d %s", rec.Code, rec.Body)
	}
	// An empty array is present, so it is not the missing-field case.
	if rec := newRig(t, PersonaOpenAI).do("POST", "/v1/chat/completions", `{"model":"qwen3:8b","messages":[]}`); rec.Code != 200 {
		t.Errorf("empty messages = %d", rec.Code)
	}
}

func TestBadEmbeddingInput(t *testing.T) {
	const wrong = `{"model":"qwen3:8b","input":7}`
	const missing = `{"model":"qwen3:8b"}`

	r := newRig(t, PersonaOpenAI)
	rec := r.do("POST", "/v1/embeddings", wrong)
	e := sub(t, decode(t, rec), "error")
	if rec.Code != 400 || e["param"] != "input" || e["code"] != "invalid_type" ||
		!strings.Contains(e["message"].(string), "but got an integer instead") {
		t.Errorf("openai wrong = %d %v", rec.Code, e)
	}
	rec = r.do("POST", "/v1/embeddings", missing)
	if e = sub(t, decode(t, rec), "error"); rec.Code != 400 || e["message"] != "Missing required parameter: 'input'." {
		t.Errorf("openai missing = %d %v", rec.Code, e)
	}

	rec = newRig(t, PersonaVLLM).do("POST", "/v1/embeddings", wrong)
	if m := decode(t, rec); rec.Code != 400 || m["type"] != "BadRequestError" ||
		!strings.Contains(m["message"].(string), "'loc': ('body', 'input')") || !strings.Contains(m["message"].(string), "'input': 7") {
		t.Errorf("vllm wrong = %d %v", rec.Code, m)
	}

	r = newRig(t, PersonaOllama)
	rec = r.do("POST", "/api/embed", wrong)
	if m := decode(t, rec); rec.Code != 400 || m["error"] != "invalid input type" {
		t.Errorf("ollama wrong = %d %v", rec.Code, m)
	}
	rec = r.do("POST", "/api/embed", missing)
	if m := decode(t, rec); rec.Code != 400 || m["error"] != "input is required" {
		t.Errorf("ollama missing = %d %v", rec.Code, m)
	}
}

func TestEmbeddingFloatCap(t *testing.T) {
	inputs := func(n int) string { return `"input":` + manyStrings(n) }
	// llama3.1:8b is 2048 wide: 128 inputs is exactly the cap, 129 is over.
	if got := maxEmbedFloats / 2048; got != 128 {
		t.Fatalf("test assumes a cap of 128 inputs at 2048 dims, have %d", got)
	}
	for _, persona := range []string{PersonaOpenAI, PersonaVLLM, PersonaOllama} {
		r := newRig(t, persona)
		over := `{"model":"llama3.1:8b",` + inputs(129) + `}`
		rec := r.do("POST", "/v1/embeddings", over)
		if rec.Code != 400 {
			t.Errorf("%s: over the cap = %d", persona, rec.Code)
		}
		if persona == PersonaOpenAI {
			e := sub(t, decode(t, rec), "error")
			if e["param"] != "input" || !strings.Contains(e["message"].(string), "too many embeddings requested") {
				t.Errorf("openai cap error = %v", e)
			}
		}
	}
	r := newRig(t, PersonaOpenAI)
	rec := r.do("POST", "/v1/embeddings", `{"model":"llama3.1:8b",`+inputs(128)+`}`)
	if rec.Code != 200 || rec.Header().Get("Content-Length") != strconv.Itoa(rec.Body.Len()) {
		t.Errorf("at the cap = %d, Content-Length %q, %d bytes", rec.Code, rec.Header().Get("Content-Length"), rec.Body.Len())
	}
	// A client-chosen width counts too.
	rec = r.do("POST", "/v1/embeddings", `{"model":"qwen3:8b","dimensions":4096,`+inputs(65)+`}`)
	if rec.Code != 400 {
		t.Errorf("dimensions over the cap = %d", rec.Code)
	}
	rec = newRig(t, PersonaOllama).do("POST", "/api/embed", `{"model":"llama3.1:8b",`+inputs(129)+`}`)
	if m := decode(t, rec); rec.Code != 400 || m["error"] == nil {
		t.Errorf("ollama over the cap = %d %v", rec.Code, m)
	}
}

func TestFailParseDialects(t *testing.T) {
	decErr := func(body string) string {
		var m map[string]json.RawMessage
		return json.NewDecoder(bytes.NewReader([]byte(body))).Decode(&m).Error()
	}
	for _, body := range []string{"{", "nonsense", `{"model":}`} {
		want := decErr(body)
		r := newRig(t, PersonaOllama)
		rec := r.do("POST", "/api/chat", body)
		if m := decode(t, rec); rec.Code != 400 || m["error"] != want {
			t.Errorf("native %q = %d %v, want %q", body, rec.Code, m, want)
		}
		rec = r.do("POST", "/v1/chat/completions", body)
		if e := sub(t, decode(t, rec), "error"); rec.Code != 400 || e["message"] != want {
			t.Errorf("v1 %q = %d %v, want %q", body, rec.Code, e, want)
		}
	}
	rec := newRig(t, PersonaOllama).do("POST", "/api/chat", "")
	if m := decode(t, rec); rec.Code != 400 || m["error"] != "missing request body" {
		t.Errorf("empty body = %d %v", rec.Code, m)
	}

	// The array caps read as plain complaints outside the OpenAI persona.
	two := `{"model":"qwen3:8b","messages":[{"role":"user","content":"a"},{"role":"user","content":"b"}]}`
	for persona, path := range map[string]string{PersonaOllama: "/api/chat", PersonaVLLM: "/v1/chat/completions"} {
		r := newRig(t, persona, func(c *Config) { c.MaxMessages = 1 })
		rec := r.do("POST", path, two)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "too many items in 'messages'") {
			t.Errorf("%s cap = %d %s", persona, rec.Code, rec.Body)
		}
	}
}

func TestPyRepr(t *testing.T) {
	got := pyRepr(json.RawMessage(`{"b":[1,2.5,true,null],"a":"it's"}`))
	if want := `{'a': 'it\'s', 'b': [1, 2.5, True, None]}`; got != want {
		t.Errorf("pyRepr = %s, want %s", got, want)
	}
	if got := pyRepr(json.RawMessage(`"` + strings.Repeat("x", 1000) + `"`)); utf8.RuneCountInString(got) > 256 {
		t.Errorf("pyRepr not capped: %d runes", utf8.RuneCountInString(got))
	}
	for raw, want := range map[string]string{
		`7`: "an integer", `7.5`: "a number", `true`: "a boolean", `{}`: "an object", `[1]`: "an array", `"s"`: "a string", `null`: "null",
	} {
		if got := jsonTypeName(json.RawMessage(raw)); got != want {
			t.Errorf("jsonTypeName(%s) = %q, want %q", raw, got, want)
		}
	}
}
