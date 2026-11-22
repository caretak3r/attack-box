package server

import (
	"encoding/base64"
	"encoding/binary"
	"math"
	"strings"
	"testing"
)

func floats(t *testing.T, v any) []float64 {
	t.Helper()
	raw, ok := v.([]any)
	if !ok {
		t.Fatalf("not an array: %T", v)
	}
	out := make([]float64, len(raw))
	for i, x := range raw {
		out[i] = x.(float64)
	}
	return out
}

func embedOne(t *testing.T, r *rig, body string) []float64 {
	t.Helper()
	rec := r.do("POST", "/v1/embeddings", body)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	d := list(t, decode(t, rec), "data")[0].(map[string]any)
	return floats(t, d["embedding"])
}

func TestEmbeddingShapeAndNorm(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	rec := r.do("POST", "/v1/embeddings", `{"model":"qwen3:8b","input":["alpha","beta gamma"]}`)
	m := decode(t, rec)
	if m["object"] != "list" || m["model"] != "qwen3:8b" {
		t.Fatalf("envelope = %v", m)
	}
	data := list(t, m, "data")
	if len(data) != 2 {
		t.Fatalf("got %d vectors", len(data))
	}
	for i, d := range data {
		e := d.(map[string]any)
		if e["object"] != "embedding" || e["index"] != float64(i) {
			t.Fatalf("item = %v", e["index"])
		}
		v := floats(t, e["embedding"])
		if len(v) != 1024 {
			t.Fatalf("dims = %d", len(v))
		}
		var sum float64
		for _, x := range v {
			sum += x * x
		}
		if math.Abs(sum-1) > 1e-4 {
			t.Fatalf("norm^2 = %f", sum)
		}
	}
	if u := sub(t, m, "usage"); u["prompt_tokens"] != float64(3) || u["total_tokens"] != float64(3) {
		t.Fatalf("usage = %v", u)
	}
	if r.sink.lastEdge(t).Attrs["model"] != "qwen3:8b" {
		t.Fatal("model not logged")
	}
}

func TestEmbeddingDeterminism(t *testing.T) {
	body := `{"model":"qwen3:8b","input":"same text"}`
	a := embedOne(t, newRig(t, PersonaOpenAI), body)
	// A restart with the same seed gives the same vector, on any persona.
	b := embedOne(t, newRig(t, PersonaVLLM), body)
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("component %d differs across servers", i)
		}
	}
	if c := embedOne(t, newRig(t, PersonaOpenAI), `{"model":"qwen3:8b","input":"other text"}`); c[0] == a[0] && c[1] == a[1] {
		t.Fatal("different inputs gave the same vector")
	}
	if c := embedOne(t, newRig(t, PersonaOpenAI), `{"model":"gpt-oss:20b","input":"same text"}`); len(c) == len(a) {
		t.Fatal("model dimensions are not per model")
	}
	other := newRig(t, PersonaOpenAI, func(c *Config) { c.EmbedSeed = []byte("another seed") })
	if c := embedOne(t, other, body); c[0] == a[0] && c[1] == a[1] {
		t.Fatal("the seed does not change the vector")
	}
}

func TestEmbeddingOptions(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	plain := embedOne(t, r, `{"model":"qwen3:8b","input":"x"}`)
	rec := r.do("POST", "/v1/embeddings", `{"model":"qwen3:8b","input":"x","encoding_format":"base64"}`)
	enc := list(t, decode(t, rec), "data")[0].(map[string]any)["embedding"].(string)
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(raw) != 4*len(plain) {
		t.Fatalf("base64: %v, %d bytes", err, len(raw))
	}
	for i, want := range plain {
		got := math.Float32frombits(binary.LittleEndian.Uint32(raw[4*i:]))
		if math.Abs(float64(got)-want) > 1e-6 {
			t.Fatalf("component %d: %v vs %v", i, got, want)
		}
	}
	if v := embedOne(t, r, `{"model":"qwen3:8b","input":"x","dimensions":16}`); len(v) != 16 {
		t.Fatalf("dimensions = %d", len(v))
	}
	if v := embedOne(t, r, `{"model":"qwen3:8b","input":[[1,2,3]]}`); len(v) != 1024 {
		t.Fatalf("token array = %d", len(v))
	}
}

func TestEmbeddingErrors(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	cases := []struct{ name, body, param string }{
		{"no input", `{"model":"qwen3:8b"}`, "input"},
		{"empty string", `{"model":"qwen3:8b","input":""}`, "input"},
		{"empty array", `{"model":"qwen3:8b","input":[]}`, "input"},
		{"bad dims", `{"model":"qwen3:8b","input":"x","dimensions":0}`, "dimensions"},
		{"huge dims", `{"model":"qwen3:8b","input":"x","dimensions":99999}`, "dimensions"},
		{"too many", `{"model":"qwen3:8b","input":[` + strings.Repeat(`"a",`, 256) + `"a"]}`, "input"},
	}
	for _, tc := range cases {
		rec := r.do("POST", "/v1/embeddings", tc.body)
		e := sub(t, decode(t, rec), "error")
		if rec.Code != 400 || e["param"] != tc.param {
			t.Errorf("%s: %d %v", tc.name, rec.Code, e)
		}
	}
	if rec := r.do("POST", "/v1/embeddings", `{"model":"nope","input":"x"}`); rec.Code != 404 {
		t.Errorf("unknown model = %d", rec.Code)
	}
}

func TestOllamaEmbeddings(t *testing.T) {
	r := newRig(t, PersonaOllama)
	rec := r.do("POST", "/api/embed", `{"model":"qwen3:8b","input":["a","b"]}`)
	m := decode(t, rec)
	vs := list(t, m, "embeddings")
	if rec.Code != 200 || len(vs) != 2 || len(floats(t, vs[0])) != 1024 || m["prompt_eval_count"] != float64(2) || m["total_duration"] == nil {
		t.Fatalf("embed = %d %.200s", rec.Code, rec.Body)
	}
	rec = r.do("POST", "/api/embeddings", `{"model":"qwen3:8b","prompt":"a"}`)
	if v := floats(t, decode(t, rec)["embedding"]); len(v) != 1024 || v[0] != floats(t, vs[0])[0] {
		t.Fatalf("legacy embedding differs from /api/embed")
	}
	rec = r.do("POST", "/v1/embeddings", `{"model":"qwen3:8b","input":"a"}`)
	if v := list(t, decode(t, rec), "data")[0].(map[string]any); floats(t, v["embedding"])[0] != floats(t, vs[0])[0] {
		t.Fatal("OpenAI-style embedding differs from /api/embed")
	}
}
