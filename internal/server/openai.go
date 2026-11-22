package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

func (s *Server) usageFor(prompt int, text string) *usage {
	n := wordCount(text)
	return &usage{PromptTokens: prompt, CompletionTokens: n, TotalTokens: prompt + n}
}

// usageNull reports whether stream chunks other than the final usage chunk
// carry "usage":null. OpenAI does this when include_usage is set; vLLM and
// Ollama leave the key out.
func (s *Server) usageNull(requested bool) bool {
	return requested && s.persona == PersonaOpenAI
}

// --- chat completions ---

type chatFormat struct {
	s       *Server
	model   string
	id      string
	created int64
	prompt  int
	usage   bool
}

type chatMessage struct {
	Role             string          `json:"role"`
	Content          string          `json:"content"`
	Refusal          json.RawMessage `json:"refusal,omitempty"`
	Annotations      json.RawMessage `json:"annotations,omitempty"`
	ToolCalls        json.RawMessage `json:"tool_calls,omitempty"`
	ReasoningContent json.RawMessage `json:"reasoning_content,omitempty"`
}

type chatChoice struct {
	Index        int             `json:"index"`
	Message      chatMessage     `json:"message"`
	Logprobs     json.RawMessage `json:"logprobs"`
	FinishReason string          `json:"finish_reason"`
	StopReason   json.RawMessage `json:"stop_reason,omitempty"`
}

type chatCompletion struct {
	ID                string          `json:"id"`
	Object            string          `json:"object"`
	Created           int64           `json:"created"`
	Model             string          `json:"model"`
	Choices           []chatChoice    `json:"choices"`
	Usage             *usage          `json:"usage"`
	SystemFingerprint string          `json:"system_fingerprint,omitempty"`
	PromptLogprobs    json.RawMessage `json:"prompt_logprobs,omitempty"`
}

type chatDelta struct {
	Role    string  `json:"role,omitempty"`
	Content *string `json:"content,omitempty"`
}

type chunkChoice struct {
	Index        int             `json:"index"`
	Delta        chatDelta       `json:"delta"`
	Logprobs     json.RawMessage `json:"logprobs"`
	FinishReason *string         `json:"finish_reason"`
}

type chatChunk struct {
	ID                string        `json:"id"`
	Object            string        `json:"object"`
	Created           int64         `json:"created"`
	Model             string        `json:"model"`
	SystemFingerprint string        `json:"system_fingerprint,omitempty"`
	Choices           []chunkChoice `json:"choices"`
	Usage             any           `json:"usage,omitempty"`
}

func (f *chatFormat) contentType() string { return sseContentType }
func (f *chatFormat) idle() []byte        { return sseKeepAlive }

func (f *chatFormat) chunk(d chatDelta, finish *string) chatChunk {
	fp := ""
	if f.s.persona != PersonaVLLM {
		fp = f.s.fingerprint(f.model)
	}
	c := chatChunk{
		ID: f.id, Object: "chat.completion.chunk", Created: f.created, Model: f.model, SystemFingerprint: fp,
		Choices: []chunkChoice{{Delta: d, Logprobs: jsonNull, FinishReason: finish}},
	}
	if f.s.usageNull(f.usage) {
		c.Usage = jsonNull
	}
	return c
}

func (f *chatFormat) start() [][]byte {
	empty := ""
	return [][]byte{sseData(f.chunk(chatDelta{Role: "assistant", Content: &empty}, nil))}
}

func (f *chatFormat) delta(text string) []byte {
	return sseData(f.chunk(chatDelta{Content: &text}, nil))
}

func (f *chatFormat) finish(text string) [][]byte {
	stop := "stop"
	out := [][]byte{sseData(f.chunk(chatDelta{}, &stop))}
	if f.usage {
		u := f.chunk(chatDelta{}, nil)
		u.Choices = []chunkChoice{}
		u.Usage = f.s.usageFor(f.prompt, text)
		out = append(out, sseData(u))
	}
	return append(out, sseDone)
}

func (f *chatFormat) full(text string) any {
	msg := chatMessage{Role: "assistant", Content: text}
	out := chatCompletion{
		ID: f.id, Object: "chat.completion", Created: f.created, Model: f.model,
		Usage: f.s.usageFor(f.prompt, text),
	}
	choice := chatChoice{FinishReason: "stop", Logprobs: jsonNull}
	if f.s.persona == PersonaVLLM {
		msg.ToolCalls = json.RawMessage("[]")
		msg.ReasoningContent = jsonNull
		choice.StopReason = jsonNull
		out.PromptLogprobs = jsonNull
	} else {
		msg.Refusal = jsonNull
		msg.Annotations = json.RawMessage("[]")
		out.SystemFingerprint = f.s.fingerprint(f.model)
	}
	choice.Message = msg
	out.Choices = []chatChoice{choice}
	return out
}

// --- legacy completions ---

type completionFormat struct {
	s       *Server
	model   string
	id      string
	created int64
	prompt  int
	usage   bool
	choices int // one choice per prompt
}

type completionChoice struct {
	Text         string          `json:"text"`
	Index        int             `json:"index"`
	Logprobs     json.RawMessage `json:"logprobs"`
	FinishReason *string         `json:"finish_reason"`
	StopReason   json.RawMessage `json:"stop_reason,omitempty"`
}

type completionBody struct {
	ID                string             `json:"id"`
	Object            string             `json:"object"`
	Created           int64              `json:"created"`
	Model             string             `json:"model"`
	Choices           []completionChoice `json:"choices"`
	SystemFingerprint string             `json:"system_fingerprint,omitempty"`
	Usage             any                `json:"usage,omitempty"`
}

func (f *completionFormat) contentType() string { return sseContentType }
func (f *completionFormat) idle() []byte        { return sseKeepAlive }
func (f *completionFormat) start() [][]byte     { return nil }

// body builds one envelope. index < 0 puts every choice in it (the
// non-streaming body); otherwise it carries only that choice, as a stream
// chunk does.
func (f *completionFormat) body(text string, finish *string, index int) completionBody {
	b := completionBody{ID: f.id, Object: "text_completion", Created: f.created, Model: f.model}
	if f.s.persona != PersonaVLLM {
		b.SystemFingerprint = f.s.fingerprint(f.model)
	}
	if f.s.usageNull(f.usage) {
		b.Usage = jsonNull
	}
	lo, hi := index, index+1
	if index < 0 {
		lo, hi = 0, max(1, f.choices)
	}
	b.Choices = make([]completionChoice, 0, hi-lo)
	for i := lo; i < hi; i++ {
		choice := completionChoice{Text: text, Index: i, Logprobs: jsonNull, FinishReason: finish}
		if f.s.persona == PersonaVLLM {
			choice.StopReason = jsonNull
		}
		b.Choices = append(b.Choices, choice)
	}
	return b
}

// perChoice frames one SSE chunk per choice index.
func (f *completionFormat) perChoice(text string, finish *string) []byte {
	var out []byte
	for i := range max(1, f.choices) {
		out = append(out, sseData(f.body(text, finish, i))...)
	}
	return out
}

// usage counts every choice's completion tokens.
func (f *completionFormat) usageOf(text string) *usage {
	u := f.s.usageFor(f.prompt, text)
	u.CompletionTokens *= max(1, f.choices)
	u.TotalTokens = u.PromptTokens + u.CompletionTokens
	return u
}

func (f *completionFormat) delta(text string) []byte { return f.perChoice(text, nil) }

func (f *completionFormat) finish(text string) [][]byte {
	stop := "stop"
	out := [][]byte{f.perChoice("", &stop)}
	if f.usage {
		u := f.body("", nil, 0)
		u.Choices = []completionChoice{}
		u.Usage = f.usageOf(text)
		out = append(out, sseData(u))
	}
	return append(out, sseDone)
}

func (f *completionFormat) full(text string) any {
	stop := "stop"
	b := f.body(text, &stop, -1)
	b.Usage = f.usageOf(text)
	return b
}

// --- responses ---

type responsesFormat struct {
	s       *Server
	model   string
	id      string
	msgID   string
	created int64
	prompt  int
	seq     int
	status  string         // status of full(); "completed" unless cancelled
	meta    map[string]any // request metadata, echoed back
}

type outputText struct {
	Type        string `json:"type"`
	Text        string `json:"text"`
	Annotations []any  `json:"annotations"`
	Logprobs    []any  `json:"logprobs"`
}

func newOutputText(text string) outputText {
	return outputText{Type: "output_text", Text: text, Annotations: []any{}, Logprobs: []any{}}
}

type outputItem struct {
	ID      string       `json:"id"`
	Type    string       `json:"type"`
	Status  string       `json:"status"`
	Role    string       `json:"role"`
	Content []outputText `json:"content"`
}

type respUsage struct {
	InputTokens         int            `json:"input_tokens"`
	InputTokensDetails  map[string]int `json:"input_tokens_details"`
	OutputTokens        int            `json:"output_tokens"`
	OutputTokensDetails map[string]int `json:"output_tokens_details"`
	TotalTokens         int            `json:"total_tokens"`
}

type responseObject struct {
	ID                 string         `json:"id"`
	Object             string         `json:"object"`
	CreatedAt          int64          `json:"created_at"`
	Status             string         `json:"status"`
	AccessPrograms     any            `json:"access_programs"`
	Error              any            `json:"error"`
	IncompleteDetails  any            `json:"incomplete_details"`
	Instructions       any            `json:"instructions"`
	MaxOutputTokens    any            `json:"max_output_tokens"`
	Metadata           map[string]any `json:"metadata"`
	Model              string         `json:"model"`
	Output             []outputItem   `json:"output"`
	ParallelToolCalls  bool           `json:"parallel_tool_calls"`
	PreviousResponseID any            `json:"previous_response_id"`
	Store              bool           `json:"store"`
	Temperature        float64        `json:"temperature"`
	ToolChoice         string         `json:"tool_choice"`
	Tools              []any          `json:"tools"`
	TopP               float64        `json:"top_p"`
	Usage              *respUsage     `json:"usage"`
}

// responseMetadata returns the metadata a Response echoes: the request's
// string pairs when they fit the documented limits (16 pairs, 64-character
// keys, 512-character values), otherwise an empty object.
func responseMetadata(md map[string]any) map[string]any {
	out := map[string]any{}
	if len(md) > 16 {
		return out
	}
	for k, v := range md {
		sv, ok := v.(string)
		if !ok || len(k) > 64 || len(sv) > 512 {
			return map[string]any{}
		}
		out[k] = sv
	}
	return out
}

func (f *responsesFormat) contentType() string { return sseContentType }
func (f *responsesFormat) idle() []byte        { return sseKeepAlive }

func (f *responsesFormat) item(status, text string) outputItem {
	content := []outputText{}
	if text != "" || status == "completed" {
		content = append(content, newOutputText(text))
	}
	return outputItem{ID: f.msgID, Type: "message", Status: status, Role: "assistant", Content: content}
}

func (f *responsesFormat) object(status, text string, withOutput bool) responseObject {
	o := responseObject{
		ID: f.id, Object: "response", CreatedAt: f.created, Status: status, Model: f.model,
		Metadata: responseMetadata(f.meta), Output: []outputItem{}, ParallelToolCalls: true, Store: true,
		Temperature: 1, ToolChoice: "auto", Tools: []any{}, TopP: 1,
	}
	if withOutput {
		o.Output = []outputItem{f.item("completed", text)}
		n := wordCount(text)
		o.Usage = &respUsage{
			InputTokens: f.prompt, InputTokensDetails: map[string]int{"cached_tokens": 0, "cache_write_tokens": 0},
			OutputTokens: n, OutputTokensDetails: map[string]int{"reasoning_tokens": 0},
			TotalTokens: f.prompt + n,
		}
	}
	return o
}

func (f *responsesFormat) event(name string, fields map[string]any) []byte {
	f.seq++
	fields["type"] = name
	fields["sequence_number"] = f.seq - 1
	return sseEvent(name, orderedEvent(fields))
}

// orderedEvent marshals an event with type first, as the real stream does.
type orderedEvent map[string]any

func (e orderedEvent) MarshalJSON() ([]byte, error) {
	rest := make(map[string]any, len(e))
	for k, v := range e {
		if k != "type" {
			rest[k] = v
		}
	}
	tail, err := json.Marshal(rest)
	if err != nil {
		return nil, err
	}
	t, _ := json.Marshal(e["type"])
	if len(tail) == 2 {
		return []byte(`{"type":` + string(t) + `}`), nil
	}
	return []byte(`{"type":` + string(t) + `,` + string(tail[1:])), nil
}

func (f *responsesFormat) start() [][]byte {
	return [][]byte{
		f.event("response.created", map[string]any{"response": f.object("in_progress", "", false)}),
		f.event("response.in_progress", map[string]any{"response": f.object("in_progress", "", false)}),
		f.event("response.output_item.added", map[string]any{"output_index": 0, "item": f.item("in_progress", "")}),
		f.event("response.content_part.added", map[string]any{
			"item_id": f.msgID, "output_index": 0, "content_index": 0,
			"part": newOutputText(""),
		}),
	}
}

func (f *responsesFormat) delta(text string) []byte {
	return f.event("response.output_text.delta", map[string]any{
		"item_id": f.msgID, "output_index": 0, "content_index": 0, "delta": text, "logprobs": []any{},
	})
}

func (f *responsesFormat) finish(text string) [][]byte {
	return [][]byte{
		f.event("response.output_text.done", map[string]any{
			"item_id": f.msgID, "output_index": 0, "content_index": 0, "text": text, "logprobs": []any{},
		}),
		f.event("response.content_part.done", map[string]any{
			"item_id": f.msgID, "output_index": 0, "content_index": 0,
			"part": newOutputText(text),
		}),
		f.event("response.output_item.done", map[string]any{"output_index": 0, "item": f.item("completed", text)}),
		f.event("response.completed", map[string]any{"response": f.object("completed", text, true)}),
	}
}

func (f *responsesFormat) full(text string) any {
	status := f.status
	if status == "" {
		status = "completed"
	}
	o := f.object(status, text, true)
	if status != "completed" {
		// A cancelled Response is "cancelled"; its interrupted message is
		// "incomplete", the only terminal non-completed item status.
		o.Output = []outputItem{f.item("incomplete", text)}
	}
	return o
}

// --- shared inference flow ---

// newFormat builds the envelope writer for a parsed request.
func (s *Server) newFormat(c *call, p *inferReq, model string) format {
	created := s.cfg.Now().Unix()
	switch p.kind {
	case kindCompletion:
		return &completionFormat{s: s, model: model, id: s.newID("cmpl-"), created: created, prompt: p.promptWords, usage: p.includeUsage, choices: p.prompts}
	case kindResponses:
		return &responsesFormat{s: s, model: model, id: s.newID("resp_"), msgID: s.newID("msg_"), created: created, prompt: p.promptWords, meta: p.req.Metadata}
	case kindOllamaChat, kindOllamaGenerate:
		return &ollamaFormat{s: s, kind: p.kind, model: model, prompt: p.promptWords}
	}
	return &chatFormat{s: s, model: model, id: s.newID("chatcmpl-"), created: created, prompt: p.promptWords, usage: p.includeUsage}
}

// failParse maps a parse error to the persona's 400.
func (c *call) failParse(err error) {
	var (
		le *limitError
		fe *fieldError
		je *jsonError
	)
	switch {
	case errors.As(err, &le):
		c.failLimit(le)
	case errors.As(err, &fe):
		c.failField(fe)
	case errors.As(err, &je):
		c.failJSON(je)
	default:
		c.fail(http.StatusBadRequest, "bad request", "", "")
	}
}

func (c *call) failLimit(le *limitError) {
	switch c.style {
	case styleOllama, styleOllamaV1, styleVLLM:
		// None of these servers caps array lengths, so the cap reads as a plain
		// size complaint in the dialect of the persona.
		c.fail(http.StatusBadRequest, fmt.Sprintf("too many items in '%s': at most %d allowed", le.param, le.max), "", "")
	default:
		c.fail(http.StatusBadRequest, fmt.Sprintf(
			"Invalid '%s': array too long. Expected an array with maximum length %d, but got an array with length %d instead.",
			le.param, le.max, le.got), le.param, "array_above_max_length")
	}
}

// failField answers a required field that is absent or of the wrong type.
func (c *call) failField(fe *fieldError) {
	p := fe.param
	switch c.style {
	case styleVLLM:
		typ, msg, in := "missing", "Field required", pyRepr(c.body)
		if !fe.missing {
			typ, msg, in = "string_type", "Input should be a valid string", pyRepr(fe.value)
		}
		c.fail(http.StatusBadRequest, fmt.Sprintf(
			"[{'type': '%s', 'loc': ('body', '%s'), 'msg': '%s', 'input': %s}]", typ, p, msg, in), "", "")
	case styleOllama:
		if fe.missing {
			c.fail(http.StatusBadRequest, p+" is required", "", "")
			return
		}
		c.fail(http.StatusBadRequest, "invalid "+p+" type", "", "")
	case styleOllamaV1:
		if fe.missing {
			c.fail(http.StatusBadRequest, fmt.Sprintf("[] is too short - '%s'", p), "", "")
			return
		}
		c.fail(http.StatusBadRequest, "invalid "+p+" type", "", "")
	default:
		if fe.missing {
			c.fail(http.StatusBadRequest, fmt.Sprintf("Missing required parameter: '%s'.", p), p, "missing_required_parameter")
			return
		}
		c.fail(http.StatusBadRequest, fmt.Sprintf(
			"Invalid type for '%s': expected one of a string or array of strings or tokens, but got %s instead.",
			p, jsonTypeName(fe.value)), p, "invalid_type")
	}
}

// failJSON answers a body that does not parse as a JSON object.
func (c *call) failJSON(je *jsonError) {
	switch c.style {
	case styleOllama, styleOllamaV1:
		// gin binds with encoding/json and passes its error text through.
		msg := "invalid request body"
		switch {
		case len(c.body) == 0:
			msg = "missing request body"
		case je.err != nil:
			msg = je.err.Error()
		}
		c.fail(http.StatusBadRequest, msg, "", "")
	case styleVLLM:
		c.fail(http.StatusBadRequest, "JSON decode error: the request body is not a valid JSON object", "", "")
	default:
		c.fail(http.StatusBadRequest, "We could not parse the JSON body of your request. (HINT: This likely means you aren't using your HTTP library correctly. The OpenAI API expects a JSON payload, but what was sent was not valid JSON. If you have trouble figuring out how to fix this, please contact us through our help center at help.openai.com.)", "", "")
	}
}

// jsonTypeName names the JSON type of raw the way OpenAI errors do.
func jsonTypeName(raw json.RawMessage) string {
	t := bytes.TrimSpace(raw)
	switch {
	case len(t) == 0 || string(t) == "null":
		return "null"
	case t[0] == '{':
		return "an object"
	case t[0] == '[':
		return "an array"
	case t[0] == '"':
		return "a string"
	case string(t) == "true" || string(t) == "false":
		return "a boolean"
	case bytes.ContainsAny(t, ".eE"):
		return "a number"
	}
	return "an integer"
}

// pyRepr renders a JSON value as Python would print the decoded object, capped
// so that an error never echoes a large client value.
func pyRepr(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return "None"
	}
	var b strings.Builder
	pyWrite(&b, v, 0)
	return truncRunes(cleanEcho(b.String(), 256), 256)
}

func pyWrite(b *strings.Builder, v any, depth int) {
	if b.Len() > 512 || depth > 4 {
		return
	}
	switch t := v.(type) {
	case nil:
		b.WriteString("None")
	case bool:
		if t {
			b.WriteString("True")
		} else {
			b.WriteString("False")
		}
	case float64:
		b.WriteString(strconv.FormatFloat(t, 'g', -1, 64))
	case string:
		b.WriteString("'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(t) + "'")
	case []any:
		b.WriteByte('[')
		for i, it := range t {
			if i > 0 {
				b.WriteString(", ")
			}
			pyWrite(b, it, depth+1)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteString(", ")
			}
			pyWrite(b, k, depth+1)
			b.WriteString(": ")
			pyWrite(b, t[k], depth+1)
		}
		b.WriteByte('}')
	}
}

// checkModel resolves the requested model. Only configured names are ever
// echoed back; an unknown name appears, cleaned and capped, in the 404 only.
func (c *call) checkModel(name string) (string, bool) {
	s := c.s
	if name == "" {
		switch {
		case s.persona == PersonaVLLM:
			return s.cfg.Models[0], true
		case c.style == styleOllama:
			c.fail(http.StatusBadRequest, "model is required", "", "")
		default:
			c.fail(http.StatusBadRequest, "you must provide a model parameter", "", "")
		}
		return "", false
	}
	for _, m := range s.cfg.Models {
		if m == name {
			return m, true
		}
	}
	c.modelNotFound(name, false)
	return "", false
}

func (c *call) modelNotFound(name string, lookup bool) {
	name = cleanEcho(name, 128)
	switch c.style {
	case styleVLLM:
		c.fail(http.StatusNotFound, fmt.Sprintf("The model `%s` does not exist.", name), "", "")
	case styleOllama, styleOllamaV1:
		c.modelMissing(name)
	default:
		if lookup {
			c.fail(http.StatusNotFound, fmt.Sprintf("The model '%s' does not exist", name), "model", "model_not_found")
			return
		}
		c.fail(http.StatusNotFound, fmt.Sprintf("The model `%s` does not exist or you do not have access to it.", name), "", "model_not_found")
	}
}

// serveInference is the common path of every inference endpoint.
func (s *Server) serveInference(c *call, k kind) {
	p, err := s.parseInference(c, k)
	if err != nil {
		c.failParse(err)
		return
	}
	if p.noMessages {
		c.failParse(&fieldError{param: "messages", missing: true})
		return
	}
	model, ok := c.checkModel(p.model)
	if !ok {
		return
	}
	c.model, c.streaming, c.tools, c.parallel = model, p.stream, p.tools, p.parallel
	f := s.newFormat(c, p, model)

	if p.load {
		s.serveLoad(c, f.(*ollamaFormat), p.unload)
		return
	}
	d := s.cfg.Responder.Decide(c.key, p.req)
	c.dec = &d
	c.probeText = d.Probe.Text
	if d.Probe.Status >= http.StatusBadRequest {
		if d.Probe.RetryAfter > 0 {
			c.w.Header().Set("Retry-After", fmt.Sprint(d.Probe.RetryAfter))
		}
		c.fail(d.Probe.Status, d.Probe.Text, "", "rate_limit_exceeded")
		return
	}
	text := d.Probe.Text
	if p.jsonMode {
		text = string(marshal(map[string]string{"status": "pending", "message": text}))
		text = strings.TrimSuffix(text, "\n")
	}
	if p.stream {
		c.stream(f, text, d.Probe.Hold)
		return
	}
	if !c.holdFor(d.Probe.Hold, nil) {
		return
	}
	c.json(f.full(text))
}

func (s *Server) chat(c *call)        { s.serveInference(c, kindChat) }
func (s *Server) completions(c *call) { s.serveInference(c, kindCompletion) }
func (s *Server) responses(c *call)   { s.serveInference(c, kindResponses) }
func (s *Server) invocations(c *call) { s.serveInference(c, kindInvocations) }

// --- models, health, version ---

type modelPermission struct {
	ID                 string  `json:"id"`
	Object             string  `json:"object"`
	Created            int64   `json:"created"`
	AllowCreateEngine  bool    `json:"allow_create_engine"`
	AllowSampling      bool    `json:"allow_sampling"`
	AllowLogprobs      bool    `json:"allow_logprobs"`
	AllowSearchIndices bool    `json:"allow_search_indices"`
	AllowView          bool    `json:"allow_view"`
	AllowFineTuning    bool    `json:"allow_fine_tuning"`
	Organization       string  `json:"organization"`
	Group              *string `json:"group"`
	IsBlocking         bool    `json:"is_blocking"`
}

type modelObject struct {
	ID          string            `json:"id"`
	Object      string            `json:"object"`
	Created     int64             `json:"created"`
	OwnedBy     string            `json:"owned_by"`
	Root        string            `json:"root,omitempty"`
	Parent      json.RawMessage   `json:"parent,omitempty"`
	MaxModelLen int               `json:"max_model_len,omitempty"`
	Permission  []modelPermission `json:"permission,omitempty"`
}

func (s *Server) modelObject(name string) modelObject {
	m := modelObject{ID: name, Object: "model", Created: modelCreated(name), OwnedBy: "system"}
	switch s.persona {
	case PersonaVLLM:
		m.OwnedBy = "vllm"
		m.Root = name
		m.Parent = jsonNull
		m.MaxModelLen = metaFor(name).ctx
		m.Permission = []modelPermission{{
			ID: "modelperm-" + modelDigest(name)[:32], Object: "model_permission", Created: modelCreated(name),
			AllowSampling: true, AllowLogprobs: true, AllowView: true, Organization: "*",
		}}
	case PersonaOllama:
		m.OwnedBy = "library"
	}
	return m
}

func (s *Server) listModels(c *call) {
	data := make([]modelObject, 0, len(s.cfg.Models))
	for _, name := range s.cfg.Models {
		data = append(data, s.modelObject(name))
	}
	c.json(struct {
		Object string        `json:"object"`
		Data   []modelObject `json:"data"`
	}{"list", data})
}

func (s *Server) getModel(c *call) {
	name := c.params["model"]
	for _, m := range s.cfg.Models {
		if m == name {
			c.json(s.modelObject(m))
			return
		}
	}
	c.modelNotFound(name, true)
}

func (s *Server) health(c *call) {
	if s.persona == PersonaVLLM {
		c.empty(http.StatusOK)
		return
	}
	c.json(map[string]string{"status": "ok"})
}

func (s *Server) version(c *call) { c.json(map[string]string{"version": s.cfg.Version}) }

// --- stored responses ---

var respIDRe = regexp.MustCompile(`^resp_[A-Za-z0-9_-]{1,64}$`)

func (s *Server) responseNotFound(c *call, id string) {
	c.fail(http.StatusNotFound, fmt.Sprintf("Response with id '%s' not found.", cleanEcho(id, 128)), "response_id", "response_not_found")
}

// storedResponse is the fake record behind GET and cancel.
func (s *Server) storedResponse(c *call, status string) (any, bool) {
	id := c.params["response_id"]
	if !respIDRe.MatchString(id) {
		s.responseNotFound(c, id)
		return nil, false
	}
	f := &responsesFormat{
		s: s, model: s.cfg.Models[0], id: id, msgID: "msg_" + strings.TrimPrefix(id, "resp_"),
		created: s.cfg.Now().Unix(), status: status,
	}
	return f.full("This response has no stored output."), true
}

func (s *Server) getResponse(c *call) {
	if s.persona == PersonaOllama {
		c.fail(http.StatusNotFound, "retrieving a stored response is not supported", "", "")
		return
	}
	if v, ok := s.storedResponse(c, ""); ok {
		c.json(v)
	}
}

func (s *Server) cancelResponse(c *call) {
	if v, ok := s.storedResponse(c, "cancelled"); ok {
		c.json(v)
	}
}

// --- concurrency gate ---

func (s *Server) edgeStatus(c *call) {
	label := c.params["label"]
	obs, done, ok := s.cfg.Responder.StatusHit(c.key, label)
	if !ok {
		s.notFound(c)
		return
	}
	defer done()
	c.obs = append(c.obs, obs)
	sess, _ := s.cfg.Responder.Store().Get(c.key)
	c.sessionID = sess.ID
	if !c.wait(s.cfg.StatusHold, 0, nil) {
		return
	}
	c.json(struct {
		Status string `json:"status"`
		Label  string `json:"label"`
	}{"ok", label})
}
