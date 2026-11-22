package server

import (
	"bytes"
	"encoding/json"
	"strings"

	"attackbox/internal/responder"
)

// kind selects the request dialect and response envelope.
type kind int

const (
	kindChat kind = iota
	kindCompletion
	kindResponses
	kindInvocations // resolved to chat or completion from the body
	kindOllamaChat
	kindOllamaGenerate
)

// jsonError reports a body that is not a JSON object. err is the decoder's own
// error; it is nil for a literal null, which decodes without one.
type jsonError struct{ err error }

func (e *jsonError) Error() string { return "invalid JSON body" }
func (e *jsonError) Unwrap() error { return e.err }

// limitError reports an array over its cap.
type limitError struct {
	param string
	max   int
	got   int
}

func (e *limitError) Error() string { return "array too long: " + e.param }

// fieldError reports a required field that is absent or has the wrong type.
// value is the offending value of a wrong-typed field.
type fieldError struct {
	param   string
	missing bool
	value   json.RawMessage
}

func (e *fieldError) Error() string {
	if e.missing {
		return "missing field: " + e.param
	}
	return "invalid field: " + e.param
}

// inferReq is one normalized inference request. It holds no request text
// beyond what the responder needs.
type inferReq struct {
	kind         kind
	model        string
	stream       bool
	includeUsage bool
	jsonMode     bool
	tools        int
	parallel     *bool
	req          responder.Request
	promptWords  int
	load         bool // Ollama model-load request: no prompt at all
	noMessages   bool // chat request without a messages array
}

// The decoders below are lenient: a field of the wrong type reads as absent.

func decodeObject(b []byte) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&m); err != nil {
		return nil, &jsonError{err}
	}
	if m == nil {
		return nil, &jsonError{}
	}
	return m, nil
}

func str(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

func boolOf(raw json.RawMessage) (bool, bool) {
	var b bool
	if json.Unmarshal(raw, &b) != nil {
		return false, false
	}
	return b, true
}

func arrayOf(raw json.RawMessage) ([]json.RawMessage, bool) {
	var a []json.RawMessage
	if json.Unmarshal(raw, &a) != nil {
		return nil, false
	}
	return a, true
}

func objectOf(raw json.RawMessage) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// contentText reads message content: a string, or an array of text parts.
func contentText(raw json.RawMessage) string {
	if s := str(raw); s != "" {
		return s
	}
	parts, ok := arrayOf(raw)
	if !ok {
		return ""
	}
	var out []string
	for _, p := range parts {
		if s := str(p); s != "" {
			out = append(out, s)
			continue
		}
		o := objectOf(p)
		switch str(o["type"]) {
		case "text", "input_text", "output_text":
			out = append(out, str(o["text"]))
		}
	}
	return strings.Join(out, "\n")
}

// parseInference normalizes an inference body for the responder.
func (s *Server) parseInference(c *call, k kind) (*inferReq, error) {
	raw, err := decodeObject(c.body)
	if err != nil {
		return nil, err
	}
	if k == kindInvocations {
		k = kindCompletion
		if _, ok := raw["messages"]; ok {
			k = kindChat
		}
	}
	p := &inferReq{kind: k, model: str(raw["model"])}
	ollama := k == kindOllamaChat || k == kindOllamaGenerate
	p.stream = ollama // Ollama streams unless told not to
	if b, ok := boolOf(raw["stream"]); ok {
		p.stream = b
	}
	if o := objectOf(raw["stream_options"]); o != nil {
		p.includeUsage, _ = boolOf(o["include_usage"])
	}
	if b, ok := boolOf(raw["parallel_tool_calls"]); ok {
		p.parallel = &b
	}
	for _, key := range []string{"tools", "functions"} {
		if a, ok := arrayOf(raw[key]); ok {
			if len(a) > s.cfg.MaxTools {
				return nil, &limitError{key, s.cfg.MaxTools, len(a)}
			}
			p.tools += len(a)
		}
	}
	p.req.HasTools = p.tools > 0
	p.req.ToolForce = toolForced(raw["tool_choice"])
	p.req.User = str(raw["user"])
	var md map[string]any
	if json.Unmarshal(raw["metadata"], &md) == nil && md != nil {
		p.req.Metadata = md
	}
	p.jsonMode = jsonRequested(k, raw)

	var text, untrusted []string
	switch k {
	case kindChat, kindOllamaChat:
		msgs, _ := arrayOf(raw["messages"])
		if m, ok := raw["messages"]; k == kindChat && (!ok || string(m) == "null") {
			p.noMessages = true
		}
		if len(msgs) > s.cfg.MaxMessages {
			return nil, &limitError{"messages", s.cfg.MaxMessages, len(msgs)}
		}
		p.load = k == kindOllamaChat && len(msgs) == 0
		for _, m := range msgs {
			o := objectOf(m)
			switch str(o["role"]) {
			case "system", "developer", "user":
				text = append(text, contentText(o["content"]))
			case "tool", "function":
				untrusted = append(untrusted, contentText(o["content"]))
			}
		}
	case kindCompletion:
		prompts, ok := arrayOf(raw["prompt"])
		if !ok {
			prompts = []json.RawMessage{raw["prompt"]}
		}
		if len(prompts) > s.cfg.MaxMessages {
			return nil, &limitError{"prompt", s.cfg.MaxMessages, len(prompts)}
		}
		for _, pr := range prompts {
			text = append(text, str(pr))
		}
	case kindOllamaGenerate:
		pr := str(raw["prompt"])
		p.load = pr == ""
		text = append(text, str(raw["system"]), pr)
	case kindResponses:
		text = append(text, str(raw["instructions"]))
		if in := str(raw["input"]); in != "" {
			text = append(text, in)
			break
		}
		items, _ := arrayOf(raw["input"])
		if len(items) > s.cfg.MaxMessages {
			return nil, &limitError{"input", s.cfg.MaxMessages, len(items)}
		}
		for _, it := range items {
			if sv := str(it); sv != "" {
				text = append(text, sv)
				continue
			}
			o := objectOf(it)
			typ, role := str(o["type"]), str(o["role"])
			switch {
			case strings.HasSuffix(typ, "_call_output"):
				untrusted = append(untrusted, contentText(o["output"]))
			case role == "system" || role == "developer" || role == "user":
				text = append(text, contentText(o["content"]))
			case role == "tool":
				untrusted = append(untrusted, contentText(o["content"]))
			case typ == "input_text":
				text = append(text, str(o["text"]))
			}
		}
	}
	p.req.Text = strings.Join(text, "\n")
	p.req.Untrusted = strings.Join(untrusted, "\n")
	p.promptWords = wordCount(p.req.Text) + wordCount(p.req.Untrusted)
	return p, nil
}

// toolForced reports a tool_choice that requires a call or names a function.
func toolForced(raw json.RawMessage) bool {
	if s := str(raw); s != "" {
		return s == "required"
	}
	o := objectOf(raw)
	if o == nil {
		return false
	}
	if f := objectOf(o["function"]); f != nil && str(f["name"]) != "" {
		return true
	}
	return str(o["name"]) != ""
}

// jsonRequested reports a structured-output request.
func jsonRequested(k kind, raw map[string]json.RawMessage) bool {
	structured := func(o map[string]json.RawMessage) bool {
		t := str(o["type"])
		return t == "json_object" || t == "json_schema"
	}
	switch k {
	case kindChat, kindCompletion:
		return structured(objectOf(raw["response_format"]))
	case kindResponses:
		return structured(objectOf(objectOf(raw["text"])["format"]))
	case kindOllamaChat, kindOllamaGenerate:
		f, ok := raw["format"]
		return ok && (str(f) == "json" || objectOf(f) != nil)
	}
	return false
}

// embedInputs reads an embeddings input: a string, an array of strings or an
// array of token arrays. Non-string items are hashed as their JSON text. An
// absent or null input reads as none; any other type is a fieldError.
func (s *Server) embedInputs(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	if sv := str(raw); sv != "" || bytes.Equal(bytes.TrimSpace(raw), []byte(`""`)) {
		return []string{sv}, nil
	}
	items, ok := arrayOf(raw)
	if !ok {
		return nil, &fieldError{param: "input", value: raw}
	}
	if len(items) > maxEmbedInputs {
		return nil, &limitError{"input", maxEmbedInputs, len(items)}
	}
	out := make([]string, len(items))
	for i, it := range items {
		if sv := str(it); sv != "" || bytes.Equal(bytes.TrimSpace(it), []byte(`""`)) {
			out[i] = sv
		} else {
			out[i] = string(it)
		}
	}
	return out, nil
}
