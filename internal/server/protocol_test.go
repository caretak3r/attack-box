package server

import (
	"encoding/json"
	"strings"
	"testing"
)

// Contract tests for the client-visible shapes in research/protocol-review.md.

// sseJSON decodes the JSON data frames of a stream, skipping [DONE].
func sseJSON(t *testing.T, body string) []map[string]any {
	t.Helper()
	blocks, _ := parseSSE(body)
	var out []map[string]any
	for _, b := range blocks {
		if b.data == "[DONE]" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(b.data), &m); err != nil {
			t.Fatalf("frame %q: %v", b.data, err)
		}
		out = append(out, m)
	}
	return out
}

func TestStreamUsageNull(t *testing.T) {
	for _, path := range []string{"/v1/chat/completions", "/v1/completions"} {
		body := `{"model":"qwen3:8b","stream":true,"stream_options":{"include_usage":true},` +
			`"messages":[{"role":"user","content":"hi"}],"prompt":"hi"}`
		for _, persona := range []string{PersonaOpenAI, PersonaVLLM, PersonaOllama} {
			rec := newRig(t, persona).do("POST", path, body)
			frames := sseJSON(t, rec.Body.String())
			if len(frames) < 2 || !strings.HasSuffix(rec.Body.String(), "data: [DONE]\n\n") {
				t.Fatalf("%s %s stream = %q", persona, path, rec.Body)
			}
			last := frames[len(frames)-1]
			if _, ok := last["usage"].(map[string]any); !ok || len(list(t, last, "choices")) != 0 {
				t.Fatalf("%s %s usage chunk = %v", persona, path, last)
			}
			for _, f := range frames[:len(frames)-1] {
				v, has := f["usage"]
				switch {
				case persona == PersonaOpenAI && (!has || v != nil):
					t.Fatalf("%s %s chunk lacks usage:null: %v", persona, path, f)
				case persona != PersonaOpenAI && has:
					t.Fatalf("%s %s chunk has usage: %v", persona, path, f)
				}
			}
		}
		// Without include_usage no chunk carries the key.
		rec := newRig(t, PersonaOpenAI).do("POST", path, strings.Replace(body, "true}", "false}", 1))
		for _, f := range sseJSON(t, rec.Body.String()) {
			if _, has := f["usage"]; has {
				t.Fatalf("%s usage without include_usage: %v", path, f)
			}
		}
	}
}

func TestCompletionPromptArrayChoices(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	m := decode(t, r.do("POST", "/v1/completions", `{"model":"qwen3:8b","prompt":["say hi","again"]}`))
	choices := list(t, m, "choices")
	if len(choices) != 2 {
		t.Fatalf("choices = %v", choices)
	}
	for i, c := range choices {
		ch := c.(map[string]any)
		if ch["index"] != float64(i) || ch["text"] == "" || ch["finish_reason"] != "stop" {
			t.Fatalf("choice %d = %v", i, ch)
		}
	}
	u := sub(t, m, "usage")
	if u["total_tokens"] != u["prompt_tokens"].(float64)+u["completion_tokens"].(float64) {
		t.Fatalf("usage = %v", u)
	}

	// One token-array prompt is one prompt; an array of token arrays is several.
	for body, want := range map[string]int{
		`{"model":"qwen3:8b","prompt":[1,2,3]}`:         1,
		`{"model":"qwen3:8b","prompt":[[1,2],[3],[4]]}`: 3,
	} {
		if got := len(list(t, decode(t, newRig(t, PersonaVLLM).do("POST", "/v1/completions", body)), "choices")); got != want {
			t.Fatalf("%s: %d choices, want %d", body, got, want)
		}
	}

	rec := newRig(t, PersonaOpenAI).do("POST", "/v1/completions", `{"model":"qwen3:8b","prompt":["a","b"],"stream":true}`)
	seen := map[float64]int{}
	finished := map[float64]bool{}
	for _, f := range sseJSON(t, rec.Body.String()) {
		chs := list(t, f, "choices")
		if len(chs) != 1 {
			t.Fatalf("stream chunk with %d choices: %v", len(chs), f)
		}
		ch := chs[0].(map[string]any)
		idx := ch["index"].(float64)
		seen[idx]++
		if ch["finish_reason"] == "stop" {
			finished[idx] = true
		}
	}
	if len(seen) != 2 || !finished[0] || !finished[1] || seen[0] != seen[1] {
		t.Fatalf("stream choice indexes = %v finished %v", seen, finished)
	}
}

// checkResponse asserts the required Response fields.
func checkResponse(t *testing.T, o map[string]any, wantStatus string) {
	t.Helper()
	if o["object"] != "response" || o["status"] != wantStatus {
		t.Fatalf("response = %v", o)
	}
	if v, ok := o["access_programs"]; !ok || v != nil {
		t.Fatalf("access_programs = %v (present %v)", v, ok)
	}
	if _, ok := o["metadata"].(map[string]any); !ok {
		t.Fatalf("metadata = %v", o["metadata"])
	}
	for _, it := range list(t, o, "output") {
		item := it.(map[string]any)
		if s := item["status"]; s != "completed" && s != "in_progress" && s != "incomplete" {
			t.Fatalf("output item status %v", s)
		}
		for _, p := range list(t, item, "content") {
			if lp, ok := p.(map[string]any)["logprobs"].([]any); !ok || len(lp) != 0 {
				t.Fatalf("output_text logprobs = %v", p)
			}
		}
	}
	if o["usage"] != nil {
		d := sub(t, sub(t, o, "usage"), "input_tokens_details")
		if d["cached_tokens"] != float64(0) || d["cache_write_tokens"] != float64(0) {
			t.Fatalf("input_tokens_details = %v", d)
		}
	}
}

func TestResponsesContract(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	m := decode(t, r.do("POST", "/v1/responses", `{"model":"qwen3:8b","input":"hi","metadata":{"run":"7"}}`))
	checkResponse(t, m, "completed")
	if sub(t, m, "metadata")["run"] != "7" {
		t.Fatalf("metadata not echoed: %v", m["metadata"])
	}
	// Metadata outside the documented limits is not echoed.
	long := strings.Repeat("x", 513)
	m = decode(t, newRig(t, PersonaOpenAI).do("POST", "/v1/responses", `{"model":"qwen3:8b","input":"hi","metadata":{"k":"`+long+`"}}`))
	if len(sub(t, m, "metadata")) != 0 {
		t.Fatalf("oversized metadata echoed: %v", m["metadata"])
	}

	rec := newRig(t, PersonaOpenAI).do("POST", "/v1/responses", `{"model":"qwen3:8b","input":"hi","stream":true}`)
	blocks, _ := parseSSE(rec.Body.String())
	for _, b := range blocks {
		var ev map[string]any
		if err := json.Unmarshal([]byte(b.data), &ev); err != nil {
			t.Fatalf("event %q: %v", b.data, err)
		}
		if resp, ok := ev["response"].(map[string]any); ok {
			checkResponse(t, resp, resp["status"].(string))
		}
		switch b.event {
		case "response.output_text.delta", "response.output_text.done":
			if lp, ok := ev["logprobs"].([]any); !ok || len(lp) != 0 {
				t.Fatalf("%s logprobs = %v", b.event, ev)
			}
		case "response.content_part.added", "response.content_part.done":
			if lp, ok := sub(t, ev, "part")["logprobs"].([]any); !ok || len(lp) != 0 {
				t.Fatalf("%s part logprobs = %v", b.event, ev)
			}
		}
	}

	checkResponse(t, decode(t, r.do("GET", "/v1/responses/resp_abc", "")), "completed")
	m = decode(t, r.do("POST", "/v1/responses/resp_abc/cancel", ""))
	checkResponse(t, m, "cancelled")
	if st := list(t, m, "output")[0].(map[string]any)["status"]; st != "incomplete" {
		t.Fatalf("cancelled item status = %v", st)
	}
}

func TestEmbeddingTokenInputs(t *testing.T) {
	for body, want := range map[string]int{
		`{"model":"qwen3:8b","input":[1,2,3]}`:         1,
		`{"model":"qwen3:8b","input":[[1,2,3]]}`:       1,
		`{"model":"qwen3:8b","input":[[1,2,3],[4,5]]}`: 2,
	} {
		m := decode(t, newRig(t, PersonaOpenAI).do("POST", "/v1/embeddings", body))
		data := list(t, m, "data")
		if len(data) != want {
			t.Fatalf("%s: %d embeddings, want %d", body, len(data), want)
		}
		for i, d := range data {
			if d.(map[string]any)["index"] != float64(i) {
				t.Fatalf("%s: index %v", body, d)
			}
		}
		u := sub(t, m, "usage")
		tokens := float64(3)
		if want == 2 {
			tokens = 5
		}
		if u["prompt_tokens"] != tokens || u["total_tokens"] != tokens {
			t.Fatalf("%s usage = %v", body, u)
		}
	}
}

func TestOllamaUnload(t *testing.T) {
	r := newRig(t, PersonaOllama)
	for _, ka := range []string{`0`, `"0"`, `"0s"`, `"0m"`} {
		m := decode(t, r.do("POST", "/api/generate", `{"model":"qwen3:8b","keep_alive":`+ka+`}`))
		if m["done"] != true || m["done_reason"] != "unload" || m["response"] != "" {
			t.Fatalf("generate keep_alive %s = %v", ka, m)
		}
		m = decode(t, r.do("POST", "/api/chat", `{"model":"qwen3:8b","messages":[],"keep_alive":`+ka+`}`))
		if m["done_reason"] != "unload" || sub(t, m, "message")["content"] != "" {
			t.Fatalf("chat keep_alive %s = %v", ka, m)
		}
	}
	for _, ka := range []string{`300`, `"5m"`, `-1`, `"x"`} {
		m := decode(t, r.do("POST", "/api/generate", `{"model":"qwen3:8b","keep_alive":`+ka+`}`))
		if m["done_reason"] != "load" {
			t.Fatalf("keep_alive %s = %v", ka, m)
		}
	}
}

func TestOllamaCreateCopyBodies(t *testing.T) {
	r := newRig(t, PersonaOllama)
	rec := r.do("POST", "/api/create", `{"model":"mine","from":"qwen3:8b","stream":false}`)
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") ||
		decode(t, rec)["status"] != "success" {
		t.Fatalf("create stream:false = %d %q %s", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}
	rec = r.do("POST", "/api/create", `{"model":"mine","from":"qwen3:8b"}`)
	if rec.Header().Get("Content-Type") != ollamaContentType {
		t.Fatalf("create default content type = %q", rec.Header().Get("Content-Type"))
	}
	rec = r.do("POST", "/api/copy", `{"source":"qwen3:8b","destination":"x"}`)
	if rec.Code != 200 || decode(t, rec)["status"] != "success" {
		t.Fatalf("copy = %d %s", rec.Code, rec.Body)
	}
}
