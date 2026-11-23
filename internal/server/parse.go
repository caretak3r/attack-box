package server

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

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
	prompts      int  // legacy completion prompts; one choice each
	load         bool // Ollama model-load request: no prompt at all
	unload       bool // a load request with keep_alive 0 unloads instead
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

// decodeBody is the one top-level object decode of the request body. It also
// records the outcome for the log; later validation of the fields does not
// undo a successful decode.
func (c *call) decodeBody() (map[string]json.RawMessage, error) {
	raw, err := decodeObject(c.body)
	c.parse = parseOK
	if err != nil {
		c.parse = parseFailed
	}
	return raw, err
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
	raw, err := c.decodeBody()
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
	if c.r != nil {
		for _, h := range []string{"Authorization", "X-Api-Key"} {
			if v := c.r.Header.Get(h); v != "" {
				if p.req.Headers == nil {
					p.req.Headers = map[string]string{}
				}
				p.req.Headers[strings.ToLower(h)] = v
			}
		}
	}
	var md map[string]any
	if json.Unmarshal(raw["metadata"], &md) == nil && md != nil {
		p.req.Metadata = md
	}
	p.jsonMode = jsonRequested(k, raw)

	var text, untrusted []string
	// msg records a history turn for reply attribution. Roles are the
	// client's claim; "assistant" turns are never operator material.
	msg := func(role, t string) {
		p.req.Messages = append(p.req.Messages, responder.Message{Role: role, Text: t})
	}
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
			role := str(o["role"])
			switch role {
			case "system", "developer", "user":
				t := contentText(o["content"])
				text = append(text, t)
				msg(role, t)
			case "tool", "function":
				t := contentText(o["content"])
				untrusted = append(untrusted, t)
				msg("tool", t)
			case "assistant":
				msg(role, contentText(o["content"]))
			}
		}
	case kindCompletion:
		prompts, ok := arrayOf(raw["prompt"])
		if !ok || (len(prompts) > 0 && isNumber(prompts[0])) {
			// A string, or one prompt given as a token array.
			prompts = []json.RawMessage{raw["prompt"]}
		}
		p.prompts = len(prompts)
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
		msg("system", text[0])
		if in := str(raw["input"]); in != "" {
			text = append(text, in)
			msg("user", in)
			break
		}
		items, _ := arrayOf(raw["input"])
		if len(items) > s.cfg.MaxMessages {
			return nil, &limitError{"input", s.cfg.MaxMessages, len(items)}
		}
		for _, it := range items {
			if sv := str(it); sv != "" {
				text = append(text, sv)
				msg("user", sv)
				continue
			}
			o := objectOf(it)
			typ, role := str(o["type"]), str(o["role"])
			switch {
			case strings.HasSuffix(typ, "_call_output"):
				t := contentText(o["output"])
				untrusted = append(untrusted, t)
				msg("tool", t)
			case role == "system" || role == "developer" || role == "user":
				t := contentText(o["content"])
				text = append(text, t)
				msg(role, t)
			case role == "tool":
				t := contentText(o["content"])
				untrusted = append(untrusted, t)
				msg("tool", t)
			case role == "assistant":
				msg(role, contentText(o["content"]))
			case typ == "input_text":
				t := str(o["text"])
				text = append(text, t)
				msg("user", t)
			}
		}
	}
	p.unload = p.load && keepAliveZero(raw["keep_alive"])
	p.req.Text = strings.Join(text, "\n")
	for i := len(text) - 1; i >= 0; i-- {
		if strings.TrimSpace(text[i]) != "" {
			p.req.Latest = text[i]
			break
		}
	}
	p.req.Untrusted = strings.Join(untrusted, "\n")
	p.promptWords = wordCount(p.req.Text) + wordCount(p.req.Untrusted)
	return p, nil
}

// isNumber reports a JSON number token.
func isNumber(raw json.RawMessage) bool {
	b := bytes.TrimSpace(raw)
	return len(b) > 0 && (b[0] == '-' || (b[0] >= '0' && b[0] <= '9'))
}

// keepAliveZero reports an Ollama keep_alive of zero: the number 0 (seconds)
// or a zero duration string such as "0" or "0s".
func keepAliveZero(raw json.RawMessage) bool {
	var n float64
	if json.Unmarshal(raw, &n) == nil {
		return n == 0
	}
	sv := str(raw)
	if sv == "0" {
		return true
	}
	d, err := time.ParseDuration(sv)
	return err == nil && d == 0
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

// embedInput is one embeddings input. tokens is the token count of an input
// given as token IDs; text inputs leave it 0 and are counted by words.
type embedInput struct {
	text   string
	tokens int
}

// embedInputs reads an embeddings input: a string, an array of strings, one
// token array, or an array of token arrays. Token arrays are hashed as their
// JSON text.
func (s *Server) embedInputs(raw json.RawMessage) ([]embedInput, error) {
	if len(raw) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil, nil
	}
	isEmpty := func(r json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(r), []byte(`""`)) }
	if sv := str(raw); sv != "" || isEmpty(raw) {
		return []embedInput{{text: sv}}, nil
	}
	items, ok := arrayOf(raw)
	if !ok {
		return nil, &fieldError{param: "input", value: raw}
	}
	if len(items) > 0 && isNumber(items[0]) {
		return []embedInput{{text: string(raw), tokens: len(items)}}, nil
	}
	if len(items) > maxEmbedInputs {
		return nil, &limitError{"input", maxEmbedInputs, len(items)}
	}
	out := make([]embedInput, len(items))
	for i, it := range items {
		switch inner, isArr := arrayOf(it); {
		case isArr:
			out[i] = embedInput{text: string(it), tokens: max(1, len(inner))}
		default:
			out[i] = embedInput{text: str(it)}
			if out[i].text == "" && !isEmpty(it) {
				out[i].text = string(it)
			}
		}
	}
	return out, nil
}
