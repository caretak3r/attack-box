package server

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestWordChunksJoin(t *testing.T) {
	for _, s := range []string{"", "one", "  lead and trail  ", "a b c d e f g h i", "tabs\tand\nnewlines  here now ok", "éè 世界 x y z w v"} {
		for _, per := range []int{1, 3, 4, 100} {
			chunks := wordChunks(s, per)
			if got := strings.Join(chunks, ""); got != s {
				t.Errorf("per=%d: %q rejoined as %q", per, s, got)
			}
			for _, c := range chunks {
				if c == "" {
					t.Errorf("per=%d: empty chunk in %q", per, s)
				}
			}
		}
	}
	if n := len(wordChunks("a b c d e f g h", 4)); n != 2 {
		t.Errorf("8 words / 4 = %d chunks", n)
	}
}

func TestCleanEcho(t *testing.T) {
	if got := cleanEcho("a\x00b‮c​d\ne\x1b[31m", 64); got != "abcde[31m" {
		t.Errorf("controls kept: %q", got)
	}
	if got := cleanEcho(strings.Repeat("é", 50), 10); utf8.RuneCountInString(got) != 10 {
		t.Errorf("cap: %d runes", utf8.RuneCountInString(got))
	}
	if got := cleanEcho("bad\xffbyte", 64); got != "badbyte" || !utf8.ValidString(got) {
		t.Errorf("invalid utf8: %q", got)
	}
}

func TestTruncation(t *testing.T) {
	s := "aé世\U0001F600z"
	for n := 0; n <= len(s)+2; n++ {
		got := truncBytes(s, n)
		if len(got) > n || !utf8.ValidString(got) || !strings.HasPrefix(s, got) {
			t.Errorf("truncBytes(%d) = %q", n, got)
		}
	}
	if got := truncRunes(s, 3); got != "aé世" {
		t.Errorf("truncRunes = %q", got)
	}
	if truncRunes(s, 99) != s || truncRunes("abc", 3) != "abc" {
		t.Error("truncRunes cut a short string")
	}
}

func TestModelMeta(t *testing.T) {
	known := metaFor("qwen3:8b")
	if known.family != "qwen3" || known.params != "8.2B" {
		t.Fatalf("known = %+v", known)
	}
	a, b := metaFor("Mystery-Model:7b"), metaFor("Mystery-Model:7b")
	if a != b || a.family != "mysterymodel" || a.size < 2_000_000_000 {
		t.Fatalf("derived = %+v", a)
	}
	if metaFor("!!!").family != "llama" {
		t.Fatal("empty family not defaulted")
	}
	if embedDimsFor("qwen3:8b") != 1024 || embedDimsFor("gpt-oss:20b") != 768 || embedDimsFor("llama3.1:8b") != 2048 {
		t.Fatal("known embedding dims wrong")
	}
	if embedDimsFor("other") != defaultEmbedDims {
		t.Fatal("default embedding dims wrong")
	}
	if len(modelDigest("x")) != 64 || modelDigest("x") == modelDigest("y") || modelCreated("x") == modelCreated("y") {
		t.Fatal("model identity is not per-name")
	}
}

func TestIDShapes(t *testing.T) {
	cases := []struct {
		persona, prefix string
		n               int
	}{
		{PersonaOpenAI, "chatcmpl-", 29}, {PersonaOpenAI, "resp_", 48}, {PersonaOpenAI, "msg_", 48},
		{PersonaVLLM, "chatcmpl-", 32}, {PersonaVLLM, "resp_", 32},
	}
	for _, tc := range cases {
		s := newRig(t, tc.persona).srv
		a, b := s.newID(tc.prefix), s.newID(tc.prefix)
		if !strings.HasPrefix(a, tc.prefix) || len(a)-len(tc.prefix) != tc.n || a == b {
			t.Errorf("%s %s: %q %q", tc.persona, tc.prefix, a, b)
		}
	}
	if fp := newRig(t, PersonaOllama).srv.fingerprint("qwen3:8b"); fp != "fp_ollama" {
		t.Errorf("ollama fingerprint %q", fp)
	}
	o := newRig(t, PersonaOpenAI).srv
	if o.fingerprint("qwen3:8b") != o.fingerprint("qwen3:8b") || o.fingerprint("qwen3:8b") == o.fingerprint("llama3.1:8b") {
		t.Error("fingerprint not stable per model")
	}
}

func raw(s string) json.RawMessage { return json.RawMessage(s) }

func TestContentText(t *testing.T) {
	cases := map[string]string{
		`"plain"`: "plain",
		`[{"type":"text","text":"a"},{"type":"image_url","image_url":{}},{"type":"input_text","text":"b"},"c"]`: "a\nb\nc",
		`[{"type":"output_text","text":"z"}]`: "z",
		`7`:                                   "",
		`null`:                                "",
		`{"type":"text","text":"x"}`:          "",
	}
	for in, want := range cases {
		if got := contentText(raw(in)); got != want {
			t.Errorf("contentText(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestToolForced(t *testing.T) {
	cases := map[string]bool{
		`"required"`: true, `"auto"`: false, `"none"`: false, `null`: false, `5`: false,
		`{"type":"function","function":{"name":"f"}}`: true,
		`{"type":"function","function":{}}`:           false,
		`{"type":"function","name":"f"}`:              true,
		`{}`:                                          false,
	}
	for in, want := range cases {
		if got := toolForced(raw(in)); got != want {
			t.Errorf("toolForced(%s) = %v", in, got)
		}
	}
}

func TestJSONRequested(t *testing.T) {
	obj := func(s string) map[string]json.RawMessage {
		m := map[string]json.RawMessage{}
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	cases := []struct {
		k    kind
		body string
		want bool
	}{
		{kindChat, `{"response_format":{"type":"json_object"}}`, true},
		{kindChat, `{"response_format":{"type":"json_schema"}}`, true},
		{kindChat, `{"response_format":{"type":"text"}}`, false},
		{kindCompletion, `{"response_format":{"type":"json_object"}}`, true},
		{kindResponses, `{"text":{"format":{"type":"json_schema"}}}`, true},
		{kindResponses, `{"text":{"format":{"type":"text"}}}`, false},
		{kindOllamaChat, `{"format":"json"}`, true},
		{kindOllamaGenerate, `{"format":{"type":"object"}}`, true},
		{kindOllamaChat, `{"format":""}`, false},
		{kindOllamaChat, `{}`, false},
		{kindInvocations, `{"response_format":{"type":"json_object"}}`, false},
	}
	for _, tc := range cases {
		if got := jsonRequested(tc.k, obj(tc.body)); got != tc.want {
			t.Errorf("kind %d %s = %v", tc.k, tc.body, got)
		}
	}
}

func TestParseInference(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	parse := func(k kind, body string) (*inferReq, error) {
		return r.srv.parseInference(&call{s: r.srv, body: []byte(body)}, k)
	}

	p, err := parse(kindChat, `{"model":"m","user":"u1","metadata":{"a":1},"tool_choice":"required","tools":[{}],
		"stream":true,"stream_options":{"include_usage":true},"parallel_tool_calls":false,
		"messages":[{"role":"system","content":"sys"},{"role":"user","content":[{"type":"text","text":"hi"}]},
		{"role":"assistant","content":"skip me"},{"role":"tool","content":"tool out"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if p.req.Text != "sys\nhi" || p.req.Untrusted != "tool out" || !p.req.HasTools || !p.req.ToolForce ||
		p.req.User != "u1" || p.req.Metadata["a"] == nil || !p.stream || !p.includeUsage ||
		p.parallel == nil || *p.parallel || p.tools != 1 || p.promptWords != 4 {
		t.Fatalf("chat = %+v", p)
	}

	p, err = parse(kindResponses, `{"instructions":"be brief","input":[
		{"type":"message","role":"user","content":[{"type":"input_text","text":"q"}]},
		{"type":"function_call_output","call_id":"c","output":"result data"},
		{"type":"input_text","text":"more"},"plain"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if p.req.Text != "be brief\nq\nmore\nplain" || p.req.Untrusted != "result data" {
		t.Fatalf("responses = %q / %q", p.req.Text, p.req.Untrusted)
	}

	p, _ = parse(kindCompletion, `{"prompt":["a","b"]}`)
	if p.req.Text != "a\nb" || p.stream {
		t.Fatalf("completion = %+v", p)
	}
	p, _ = parse(kindInvocations, `{"messages":[{"role":"user","content":"x"}]}`)
	if p.kind != kindChat {
		t.Fatalf("invocations with messages = %d", p.kind)
	}
	p, _ = parse(kindInvocations, `{"prompt":"x"}`)
	if p.kind != kindCompletion {
		t.Fatalf("invocations with prompt = %d", p.kind)
	}

	p, _ = parse(kindOllamaChat, `{"model":"m"}`)
	if !p.load || !p.stream {
		t.Fatalf("ollama chat load = %+v", p)
	}
	p, _ = parse(kindOllamaGenerate, `{"model":"m","system":"s","prompt":"p","stream":false}`)
	if p.load || p.stream || p.req.Text != "s\np" {
		t.Fatalf("ollama generate = %+v", p)
	}
	p, _ = parse(kindOllamaGenerate, `{"model":"m"}`)
	if !p.load {
		t.Fatal("empty generate is not a load")
	}

	if _, err = parse(kindChat, `[1]`); err == nil {
		t.Fatal("array body accepted")
	}
	if _, err = parse(kindResponses, `{"input":`+manyStrings(300)+`}`); err == nil {
		t.Fatal("responses input over the cap accepted")
	}
	if _, err = parse(kindChat, `{"functions":`+manyObjects(65)+`}`); err == nil {
		t.Fatal("functions over the cap accepted")
	} else if le, ok := err.(*limitError); !ok || le.param != "functions" || le.Error() == "" {
		t.Fatalf("limit error = %#v", err)
	}
}

func manyStrings(n int) string {
	return "[" + strings.TrimSuffix(strings.Repeat(`"x",`, n), ",") + "]"
}

func manyObjects(n int) string {
	return "[" + strings.TrimSuffix(strings.Repeat(`{},`, n), ",") + "]"
}

func TestEmbedInputs(t *testing.T) {
	s := newRig(t, PersonaOpenAI).srv
	cases := []struct {
		in   string
		want []string
	}{
		{`"a"`, []string{"a"}}, {`""`, []string{""}}, {`["a","","b"]`, []string{"a", "", "b"}},
		{`[[1,2],[3]]`, []string{"[1,2]", "[3]"}}, {`[1,2,3]`, []string{"1", "2", "3"}}, {`7`, []string{"7"}},
	}
	for _, tc := range cases {
		got, err := s.embedInputs(raw(tc.in))
		if err != nil || strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%s = %q, %v", tc.in, got, err)
		}
	}
	if got, _ := s.embedInputs(nil); got != nil {
		t.Errorf("absent input = %q", got)
	}
	if _, err := s.embedInputs(raw(manyStrings(maxEmbedInputs + 1))); err == nil {
		t.Error("input over the cap accepted")
	}
}

func TestErrorTypes(t *testing.T) {
	for status, want := range map[int]string{429: "requests", 500: "server_error", 503: "server_error", 400: "invalid_request_error"} {
		if got := openAIType(status); got != want {
			t.Errorf("openAIType(%d) = %q", status, got)
		}
	}
	for status, want := range map[int]string{
		400: "BadRequestError", 404: "NotFoundError", 405: "MethodNotAllowed", 413: "RequestEntityTooLarge",
		429: "TooManyRequests", 500: "InternalServerError",
	} {
		if got := vllmType(status); got != want {
			t.Errorf("vllmType(%d) = %q", status, got)
		}
	}
}
