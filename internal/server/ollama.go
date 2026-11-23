package server

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"
)

const ollamaContentType = "application/x-ndjson"

func (s *Server) ollamaRoutes() []route {
	return []route{
		newRoute("GET", "/", "", s.ollamaRoot),
		newRoute("HEAD", "/", "", s.ollamaRoot),
		newRoute("GET", "/api/version", "", s.version),
		newRoute("GET", "/api/tags", "", s.ollamaTags),
		newRoute("GET", "/api/ps", "", s.ollamaPS),
		newRoute("POST", "/api/show", "", s.ollamaShow),
		newRoute("POST", "/api/generate", "", func(c *call) { s.serveInference(c, kindOllamaGenerate) }),
		newRoute("POST", "/api/chat", "", func(c *call) { s.serveInference(c, kindOllamaChat) }),
		newRoute("POST", "/api/embed", "", s.ollamaEmbed),
		newRoute("POST", "/api/embeddings", "", s.ollamaEmbeddings),
		newRoute("POST", "/api/pull", "", func(c *call) { s.ollamaTransfer(c, "pulling manifest", "pull model manifest: file does not exist") }),
		newRoute("POST", "/api/push", "", func(c *call) {
			s.ollamaTransfer(c, "retrieving manifest", "you are not authorized to push to this namespace, create the model under a namespace you own")
		}),
		newRoute("POST", "/api/create", "", s.ollamaCreate),
		newRoute("POST", "/api/copy", "", s.ollamaCopy),
		newRoute("DELETE", "/api/delete", "", s.ollamaDelete),
		newRoute("POST", "/api/delete", "", s.ollamaDelete),
	}
}

// durations are the fake timings of a response, in nanoseconds. They derive
// from the sizes alone, so the same request always reports the same numbers.
type durations struct{ total, load, promptEval, eval int64 }

func (s *Server) durations(model string, prompt, out int) durations {
	h := nameHash(model)
	load := 4_000_000 + int64(binary.BigEndian.Uint32(h[12:16]))%40_000_000
	d := durations{load: load, promptEval: int64(prompt) * 2_000_000, eval: int64(out) * 25_000_000}
	d.total = load + d.promptEval + d.eval
	return d
}

type ollamaFormat struct {
	s      *Server
	kind   kind
	model  string
	prompt int
}

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ollamaFrame is one NDJSON object of /api/chat or /api/generate. Field order
// follows the real server.
type ollamaFrame struct {
	Model              string         `json:"model"`
	CreatedAt          string         `json:"created_at"`
	Response           *string        `json:"response,omitempty"`
	Message            *ollamaMessage `json:"message,omitempty"`
	Done               bool           `json:"done"`
	DoneReason         string         `json:"done_reason,omitempty"`
	TotalDuration      *int64         `json:"total_duration,omitempty"`
	LoadDuration       *int64         `json:"load_duration,omitempty"`
	PromptEvalCount    *int           `json:"prompt_eval_count,omitempty"`
	PromptEvalDuration *int64         `json:"prompt_eval_duration,omitempty"`
	EvalCount          *int           `json:"eval_count,omitempty"`
	EvalDuration       *int64         `json:"eval_duration,omitempty"`
}

func (f *ollamaFormat) frame(text string, done bool) ollamaFrame {
	fr := ollamaFrame{
		Model:     f.model,
		CreatedAt: f.s.cfg.Now().UTC().Format(time.RFC3339Nano),
		Done:      done,
	}
	if f.kind == kindOllamaChat {
		fr.Message = &ollamaMessage{Role: "assistant", Content: text}
	} else {
		fr.Response = &text
	}
	return fr
}

// final is the closing frame with the timings of a reply of text.
func (f *ollamaFormat) final(text string) ollamaFrame {
	fr := f.frame("", true)
	n := wordCount(text)
	d := f.s.durations(f.model, f.prompt, n)
	fr.DoneReason = "stop"
	fr.TotalDuration, fr.LoadDuration = &d.total, &d.load
	fr.PromptEvalCount, fr.PromptEvalDuration = &f.prompt, &d.promptEval
	fr.EvalCount, fr.EvalDuration = &n, &d.eval
	return fr
}

func (f *ollamaFormat) contentType() string { return ollamaContentType }
func (f *ollamaFormat) start() [][]byte     { return nil }
func (f *ollamaFormat) delta(text string) []byte {
	return ndjson(f.frame(text, false))
}

// idle sends an empty delta, which every Ollama client already tolerates.
func (f *ollamaFormat) idle() []byte { return f.delta("") }

func (f *ollamaFormat) finish(text string) [][]byte { return [][]byte{ndjson(f.final(text))} }

func (f *ollamaFormat) full(text string) any {
	fr := f.final(text)
	if f.kind == kindOllamaChat {
		fr.Message.Content = text
	} else {
		fr.Response = &text
	}
	return fr
}

// serveLoad answers a request that only asks to load the model.
func (s *Server) serveLoad(c *call, f *ollamaFormat, unload bool) {
	fr := f.frame("", true)
	fr.DoneReason = "load"
	if unload {
		fr.DoneReason = "unload"
	}
	c.json(fr)
}

func (s *Server) ollamaRoot(c *call) {
	c.plain(http.StatusOK, "text/plain; charset=utf-8", "Ollama is running")
}

type ollamaDetails struct {
	ParentModel       string   `json:"parent_model"`
	Format            string   `json:"format"`
	Family            string   `json:"family"`
	Families          []string `json:"families"`
	ParameterSize     string   `json:"parameter_size"`
	QuantizationLevel string   `json:"quantization_level"`
}

func detailsFor(name string) ollamaDetails {
	m := metaFor(name)
	return ollamaDetails{Format: "gguf", Family: m.family, Families: []string{m.family}, ParameterSize: m.params, QuantizationLevel: m.quant}
}

type ollamaTag struct {
	Name       string        `json:"name"`
	Model      string        `json:"model"`
	ModifiedAt string        `json:"modified_at"`
	Size       int64         `json:"size"`
	Digest     string        `json:"digest"`
	Details    ollamaDetails `json:"details"`
}

func (s *Server) ollamaTags(c *call) {
	tags := make([]ollamaTag, 0, len(s.cfg.Models))
	for _, name := range s.cfg.Models {
		tags = append(tags, ollamaTag{
			Name: name, Model: name, ModifiedAt: modelModified(name), Size: metaFor(name).size,
			Digest: modelDigest(name), Details: detailsFor(name),
		})
	}
	c.json(map[string]any{"models": tags})
}

func (s *Server) ollamaPS(c *call) { c.json(map[string]any{"models": []any{}}) }

// ollamaBody reads a JSON object body for the management endpoints.
func (c *call) ollamaBody() (map[string]json.RawMessage, bool) {
	raw, err := c.decodeBody()
	if err != nil {
		c.failParse(err)
		return nil, false
	}
	return raw, true
}

// namedModel returns the model name of a management request: "model", or the
// older "name".
func namedModel(b map[string]json.RawMessage) string {
	if m := str(b["model"]); m != "" {
		return m
	}
	return str(b["name"])
}

func (c *call) modelMissing(name string) {
	c.fail(http.StatusNotFound, fmt.Sprintf("model '%s' not found", cleanEcho(name, 128)), "", "")
}

func (s *Server) has(name string) bool { return slices.Contains(s.cfg.Models, name) }

func (s *Server) ollamaShow(c *call) {
	b, ok := c.ollamaBody()
	if !ok {
		return
	}
	name := namedModel(b)
	if name == "" {
		c.fail(http.StatusBadRequest, "model is required", "", "")
		return
	}
	if !s.has(name) {
		c.modelMissing(name)
		return
	}
	m := metaFor(name)
	c.model = name
	c.json(map[string]any{
		"license":    "Apache License\nVersion 2.0, January 2004",
		"modelfile":  fmt.Sprintf("# Modelfile generated by \"ollama show\"\nFROM %s\nTEMPLATE {{ .Prompt }}", name),
		"parameters": "stop \"<|im_start|>\"\nstop \"<|im_end|>\"",
		"template":   "{{ .Prompt }}",
		"details":    detailsFor(name),
		"model_info": map[string]any{
			"general.architecture":         m.family,
			"general.parameter_count":      m.size * 3 / 2,
			"general.file_type":            15,
			m.family + ".context_length":   m.ctx,
			m.family + ".embedding_length": embedDimsFor(name),
			"tokenizer.ggml.model":         "gpt2",
		},
		"capabilities": []string{"completion", "tools"},
		"modified_at":  modelModified(name),
	})
}

// ollamaTransfer answers pull and push. Nothing is fetched or sent: a name that
// the server lists "succeeds", any other name fails like a missing manifest.
func (s *Server) ollamaTransfer(c *call, step, failure string) {
	b, ok := c.ollamaBody()
	if !ok {
		return
	}
	name := namedModel(b)
	if name == "" {
		c.fail(http.StatusBadRequest, "model is required", "", "")
		return
	}
	known := s.has(name)
	if stream, ok := boolOf(b["stream"]); ok && !stream {
		if known {
			c.json(map[string]string{"status": "success"})
		} else {
			c.fail(http.StatusInternalServerError, failure, "", "")
		}
		return
	}
	c.w.Header().Set("Content-Type", ollamaContentType)
	c.w.WriteHeader(http.StatusOK)
	_, _ = c.w.Write(ndjson(map[string]string{"status": step}))
	if known {
		_, _ = c.w.Write(ndjson(map[string]string{"status": "success"}))
		return
	}
	_, _ = c.w.Write(ndjson(map[string]string{"error": failure}))
}

// ollamaCreate accepts and forgets: no model is stored.
func (s *Server) ollamaCreate(c *call) {
	b, ok := c.ollamaBody()
	if !ok {
		return
	}
	if namedModel(b) == "" {
		c.fail(http.StatusBadRequest, "model is required", "", "")
		return
	}
	if stream, ok := boolOf(b["stream"]); ok && !stream {
		c.json(map[string]string{"status": "success"})
		return
	}
	c.w.Header().Set("Content-Type", ollamaContentType)
	c.w.WriteHeader(http.StatusOK)
	_, _ = c.w.Write(ndjson(map[string]string{"status": "success"}))
}

func (s *Server) ollamaCopy(c *call) {
	b, ok := c.ollamaBody()
	if !ok {
		return
	}
	src, dst := str(b["source"]), str(b["destination"])
	if src == "" || dst == "" {
		c.fail(http.StatusBadRequest, "source and destination are required", "", "")
		return
	}
	if !s.has(src) {
		c.modelMissing(src)
		return
	}
	c.json(map[string]string{"status": "success"})
}

func (s *Server) ollamaDelete(c *call) {
	b, ok := c.ollamaBody()
	if !ok {
		return
	}
	name := namedModel(b)
	if name == "" {
		c.fail(http.StatusBadRequest, "model is required", "", "")
		return
	}
	if !s.has(name) {
		c.modelMissing(name)
		return
	}
	c.empty(http.StatusOK)
}
