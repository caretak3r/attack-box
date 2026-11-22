package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
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
	Usage             *usage        `json:"usage,omitempty"`
}

func (f *chatFormat) contentType() string { return sseContentType }
func (f *chatFormat) idle() []byte        { return sseKeepAlive }

func (f *chatFormat) chunk(d chatDelta, finish *string) chatChunk {
	fp := ""
	if f.s.persona != PersonaVLLM {
		fp = f.s.fingerprint(f.model)
	}
	return chatChunk{
		ID: f.id, Object: "chat.completion.chunk", Created: f.created, Model: f.model, SystemFingerprint: fp,
		Choices: []chunkChoice{{Delta: d, Logprobs: jsonNull, FinishReason: finish}},
	}
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
	Usage             *usage             `json:"usage,omitempty"`
}

func (f *completionFormat) contentType() string { return sseContentType }
func (f *completionFormat) idle() []byte        { return sseKeepAlive }
func (f *completionFormat) start() [][]byte     { return nil }

func (f *completionFormat) body(text string, finish *string) completionBody {
	choice := completionChoice{Text: text, Logprobs: jsonNull, FinishReason: finish}
	b := completionBody{ID: f.id, Object: "text_completion", Created: f.created, Model: f.model}
	if f.s.persona == PersonaVLLM {
		choice.StopReason = jsonNull
	} else {
		b.SystemFingerprint = f.s.fingerprint(f.model)
	}
	b.Choices = []completionChoice{choice}
	return b
}

func (f *completionFormat) delta(text string) []byte { return sseData(f.body(text, nil)) }

func (f *completionFormat) finish(text string) [][]byte {
	stop := "stop"
	out := [][]byte{sseData(f.body("", &stop))}
	if f.usage {
		u := f.body("", nil)
		u.Choices = []completionChoice{}
		u.Usage = f.s.usageFor(f.prompt, text)
		out = append(out, sseData(u))
	}
	return append(out, sseDone)
}

func (f *completionFormat) full(text string) any {
	stop := "stop"
	b := f.body(text, &stop)
	b.Usage = f.s.usageFor(f.prompt, text)
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
	status  string // status of full(); "completed" unless cancelled
}

type outputText struct {
	Type        string `json:"type"`
	Text        string `json:"text"`
	Annotations []any  `json:"annotations"`
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
	ID                 string       `json:"id"`
	Object             string       `json:"object"`
	CreatedAt          int64        `json:"created_at"`
	Status             string       `json:"status"`
	Error              any          `json:"error"`
	IncompleteDetails  any          `json:"incomplete_details"`
	Instructions       any          `json:"instructions"`
	MaxOutputTokens    any          `json:"max_output_tokens"`
	Model              string       `json:"model"`
	Output             []outputItem `json:"output"`
	ParallelToolCalls  bool         `json:"parallel_tool_calls"`
	PreviousResponseID any          `json:"previous_response_id"`
	Store              bool         `json:"store"`
	Temperature        float64      `json:"temperature"`
	ToolChoice         string       `json:"tool_choice"`
	Tools              []any        `json:"tools"`
	TopP               float64      `json:"top_p"`
	Usage              *respUsage   `json:"usage"`
}

func (f *responsesFormat) contentType() string { return sseContentType }
func (f *responsesFormat) idle() []byte        { return sseKeepAlive }

func (f *responsesFormat) item(status, text string) outputItem {
	content := []outputText{}
	if text != "" || status == "completed" {
		content = append(content, outputText{Type: "output_text", Text: text, Annotations: []any{}})
	}
	return outputItem{ID: f.msgID, Type: "message", Status: status, Role: "assistant", Content: content}
}

func (f *responsesFormat) object(status, text string, withOutput bool) responseObject {
	o := responseObject{
		ID: f.id, Object: "response", CreatedAt: f.created, Status: status, Model: f.model,
		Output: []outputItem{}, ParallelToolCalls: true, Store: true, Temperature: 1, ToolChoice: "auto",
		Tools: []any{}, TopP: 1,
	}
	if withOutput {
		o.Output = []outputItem{f.item("completed", text)}
		n := wordCount(text)
		o.Usage = &respUsage{
			InputTokens: f.prompt, InputTokensDetails: map[string]int{"cached_tokens": 0},
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
			"part": outputText{Type: "output_text", Annotations: []any{}},
		}),
	}
}

func (f *responsesFormat) delta(text string) []byte {
	return f.event("response.output_text.delta", map[string]any{
		"item_id": f.msgID, "output_index": 0, "content_index": 0, "delta": text,
	})
}

func (f *responsesFormat) finish(text string) [][]byte {
	return [][]byte{
		f.event("response.output_text.done", map[string]any{
			"item_id": f.msgID, "output_index": 0, "content_index": 0, "text": text,
		}),
		f.event("response.content_part.done", map[string]any{
			"item_id": f.msgID, "output_index": 0, "content_index": 0,
			"part": outputText{Type: "output_text", Text: text, Annotations: []any{}},
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
		o.Output = []outputItem{f.item(status, text)}
	}
	return o
}

// --- shared inference flow ---

// newFormat builds the envelope writer for a parsed request.
func (s *Server) newFormat(c *call, p *inferReq, model string) format {
	created := s.cfg.Now().Unix()
	switch p.kind {
	case kindCompletion:
		return &completionFormat{s: s, model: model, id: s.newID("cmpl-"), created: created, prompt: p.promptWords, usage: p.includeUsage}
	case kindResponses:
		return &responsesFormat{s: s, model: model, id: s.newID("resp_"), msgID: s.newID("msg_"), created: created, prompt: p.promptWords}
	case kindOllamaChat, kindOllamaGenerate:
		return &ollamaFormat{s: s, kind: p.kind, model: model, prompt: p.promptWords}
	}
	return &chatFormat{s: s, model: model, id: s.newID("chatcmpl-"), created: created, prompt: p.promptWords, usage: p.includeUsage}
}

// failParse maps a parse error to the persona's 400.
func (c *call) failParse(err error) {
	var le *limitError
	if asLimit(err, &le) {
		c.fail(http.StatusBadRequest, fmt.Sprintf(
			"Invalid '%s': array too long. Expected an array with maximum length %d, but got an array with length %d instead.",
			le.param, le.max, le.got), le.param, "array_above_max_length")
		return
	}
	switch c.style {
	case styleOllama:
		msg := "invalid character looking for beginning of value"
		if len(c.body) == 0 {
			msg = "missing request body"
		}
		c.fail(http.StatusBadRequest, msg, "", "")
	case styleVLLM:
		c.fail(http.StatusBadRequest, "JSON decode error: the request body is not a valid JSON object", "", "")
	default:
		c.fail(http.StatusBadRequest, "We could not parse the JSON body of your request. (HINT: This likely means you aren't using your HTTP library correctly. The OpenAI API expects a JSON payload, but what was sent was not valid JSON. If you have trouble figuring out how to fix this, please contact us through our help center at help.openai.com.)", "", "")
	}
}

func asLimit(err error, target **limitError) bool {
	le, ok := err.(*limitError)
	if ok {
		*target = le
	}
	return ok
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
		c.fail(http.StatusNotFound, fmt.Sprintf("model %q not found, try pulling it first", name), "", "")
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
	model, ok := c.checkModel(p.model)
	if !ok {
		return
	}
	c.model, c.streaming, c.tools, c.parallel = model, p.stream, p.tools, p.parallel
	f := s.newFormat(c, p, model)

	if p.load {
		s.serveLoad(c, f.(*ollamaFormat))
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
