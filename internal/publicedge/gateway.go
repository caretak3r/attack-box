package publicedge

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"path"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

const gatewayModel = "local-instruct-8b"

// gatewayModelList is the fixed set of names the gateway claims to serve; it must match the
// gen_ai.request.model allowlist in deploy/public-otel/config.yaml. Ollama-style names also list in /api/tags.
var gatewayModelList = []string{gatewayModel, "gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "o3-mini", "gpt-3.5-turbo",
	"claude-3-5-sonnet-20241022", "claude-3-7-sonnet-20250219", "claude-sonnet-4-20250514", "claude-3-5-haiku-20241022",
	"llama3.1:8b", "qwen2.5:7b", "deepseek-r1:8b", "mistral:7b", "text-embedding-3-small", "text-embedding-3-large", "nomic-embed-text"}

// gatewayModelName returns the listed model for a requested name; Ollama clients may add ":latest".
func gatewayModelName(s string) (string, bool) {
	s = strings.TrimSuffix(s, ":latest")
	for _, m := range gatewayModelList {
		if s == m {
			return m, true
		}
	}
	return "", false
}

// gatewayRequestModel resolves the deployment path and the body model; either one must be listed. No model means the default.
func gatewayRequestModel(r *http.Request, obj map[string]json.RawMessage) (string, bool) {
	model := gatewayModel
	if d := r.PathValue("deployment"); d != "" {
		m, ok := gatewayModelName(d)
		if !ok {
			return "", false
		}
		model = m
	}
	if raw := obj["model"]; raw != nil {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return "", false
		}
		m, ok := gatewayModelName(s)
		if !ok {
			return "", false
		}
		model = m
	}
	return model, true
}

const gatewayJSON = "application/json"
const gatewayBodyLimit = 64 << 10

type portKey struct{}

// WithPort records the public port a connection arrived on.
func WithPort(ctx context.Context, port int) context.Context {
	return context.WithValue(ctx, portKey{}, port)
}

// requestPort defaults to 443 when no listener set a port.
func requestPort(r *http.Request) int {
	if port, ok := r.Context().Value(portKey{}).(int); ok {
		return port
	}
	return 443
}

type Gateway struct {
	tracer trace.Tracer
	slots  chan struct{}
	// Capture, when set, keeps raw request lines on local disk; they are never exported.
	Capture *Capture
}

type gatewayFamily struct {
	suffix, method string
	handle         http.HandlerFunc
}

// Families match by path suffix, longest first, so a scanner's first request to a plausible variant succeeds.
var gatewayFamilies = [...]gatewayFamily{
	{"api/generate", http.MethodPost, gatewayOllama(false)},
	{"api/chat", http.MethodPost, gatewayOllama(true)},
	{"api/tags", http.MethodGet, gatewayOllamaTags},
	{"chat/completions", http.MethodPost, gatewayCompletion(true)},
	{"completions", http.MethodPost, gatewayCompletion(false)},
	{"embeddings", http.MethodPost, gatewayEmbeddings},
	{"messages", http.MethodPost, gatewayMessages},
	{"models", http.MethodGet, gatewayModels},
}

// gatewayPrefixes must match the http.route allowlist in deploy/public-otel/config.yaml.
var gatewayPrefixes = map[string]bool{"v1": true, "v2": true, "v3": true, "api": true, "openai": true, "azure": true, "llm": true, "ai": true,
	"proxy": true, "gateway": true, "inference": true, "litellm": true, "ollama": true, "anthropic": true}

const gatewayMaxPrefix = 4

func NewGateway(tracer trace.Tracer) *Gateway {
	if tracer == nil {
		tracer = noop.NewTracerProvider().Tracer("attackbox.gateway")
	}
	return &Gateway{tracer: tracer, slots: make(chan struct{}, 16)}
}

// gatewayResolve maps a clean path to a family and a route label built only from allowlisted tokens.
func gatewayResolve(p string) (f *gatewayFamily, route, deployment string) {
families:
	for i := range gatewayFamilies {
		f = &gatewayFamilies[i]
		rest, ok := strings.CutSuffix(p, "/"+f.suffix)
		if !ok {
			continue
		}
		segs := strings.Split(rest, "/")[1:]
		var label strings.Builder
		deployment = ""
		n := 0
		for j := 0; j < len(segs); j, n = j+1, n+1 {
			switch s := segs[j]; {
			case gatewayPrefixes[s]:
				label.WriteString("/" + s)
			case s == "deployments" && deployment == "" && j+1 < len(segs) && gatewayName(segs[j+1]):
				deployment, j = segs[j+1], j+1
				label.WriteString("/deployments/{deployment}")
			case s == "engines" && deployment == "" && j+1 < len(segs) && gatewayName(segs[j+1]):
				deployment, j = segs[j+1], j+1
				label.WriteString("/engines/{model}")
			default:
				continue families
			}
		}
		if n <= gatewayMaxPrefix {
			return f, label.String() + "/" + f.suffix, deployment
		}
	}
	return nil, "", ""
}

func gatewayName(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i > 0 && (c == '.' || c == '_' || c == '-')) {
			return false
		}
	}
	return true
}

func (g *Gateway) ServeHTTP(base http.ResponseWriter, req *http.Request) {
	ctx, span := g.tracer.Start(baggage.ContextWithoutBaggage(req.Context()), "public.request", trace.WithNewRoot(), trace.WithSpanKind(trace.SpanKindServer))
	r := req.WithContext(ctx)
	w := &gatewayWriter{ResponseWriter: base}
	route := "/unmatched"
	var counted *gatewayBodyCounter
	var bodyRec *captureBodyRecorder
	defer func() {
		panicked := recover() != nil
		partial := panicked && w.status != 0
		if panicked && !partial {
			gatewayReply(w, http.StatusInternalServerError, "text/plain; charset=utf-8", "internal error\n")
		}
		status := w.status
		if status == 0 {
			status = http.StatusOK
		}
		probe := ""
		if route == "/unmatched" {
			probe = gatewayProbe(r)
		}
		if span.IsRecording() {
			attrs := make([]attribute.KeyValue, 0, 13)
			attrs = append(attrs, attribute.Int("server.port", requestPort(r)), attribute.String("attackbox.persona", "cloud-gateway"),
				attribute.String("http.route", route), attribute.String("http.request.method", gatewayPublicMethod(r.Method)),
				attribute.Int("http.response.status_code", status), attribute.String("attackbox.request.content_type", gatewayContentType(r.Header.Get("Content-Type"))),
				attribute.Int("attackbox.request.query_params", gatewayQueryParams(r.URL.RawQuery)))
			if probe != "" {
				attrs = append(attrs, attribute.String("attackbox.probe.class", probe))
			}
			if addr := ClientAddress(r.RemoteAddr); addr != "" {
				attrs = append(attrs, attribute.String("client.address", addr))
			}
			if source, kind, value := gatewayCredential(r); source != "" {
				attrs = append(attrs, attribute.String("attackbox.credential.source", source), attribute.String("attackbox.credential.type", kind))
				if value != "" {
					attrs = append(attrs, attribute.String("attackbox.credential.value", value))
				}
			}
			if r.ContentLength >= 0 {
				attrs = append(attrs, attribute.Int64("http.request.body.size", r.ContentLength))
			} else if counted != nil && counted.eof {
				attrs = append(attrs, attribute.Int64("http.request.body.size", counted.bytes))
			}
			span.SetAttributes(attrs...)
			if panicked || status >= 500 {
				span.SetStatus(codes.Error, "")
			}
		}
		span.End()
		g.Capture.Record(r, route, status, probe, bodyRec)
		if partial {
			panic(http.ErrAbortHandler)
		}
	}()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodConnect || r.URL.IsAbs() || r.URL.Path == "" || r.URL.Path[0] != '/' || path.Clean(r.URL.Path) != r.URL.Path {
		gatewayReply(w, http.StatusBadRequest, "text/plain; charset=utf-8", "invalid request target\n")
		return
	}
	f, label, deployment := gatewayResolve(r.URL.Path)
	if f != nil {
		route = label
	}
	if r.ContentLength > gatewayBodyLimit {
		gatewayReply(w, http.StatusRequestEntityTooLarge, "text/plain; charset=utf-8", "request too large\n")
		return
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		w.Header().Set("Retry-After", "1")
		gatewayReply(w, http.StatusTooManyRequests, "text/plain; charset=utf-8", "busy\n")
		return
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(base, r.Body, gatewayBodyLimit)
		if r.ContentLength < 0 && span.IsRecording() {
			counted = &gatewayBodyCounter{ReadCloser: r.Body}
			r.Body = counted
		}
		if g.Capture != nil {
			bodyRec = newCaptureBodyRecorder(r.Body)
			r.Body = bodyRec
		}
	}
	// With a capture, read a body that no handler reads, so that the local record holds it.
	// The span keeps its meaning: it reports a chunked body size only when a handler read the body.
	drain := func() {
		if bodyRec != nil {
			counted = nil
			_ = http.NewResponseController(base).SetReadDeadline(time.Now().Add(2 * time.Second))
			_, _ = io.Copy(io.Discard, bodyRec)
		}
	}

	if f == nil {
		drain()
		gatewayReply(w, http.StatusNotFound, "text/plain; charset=utf-8", "404 page not found\n")
		return
	}
	if r.Method != f.method && (f.method != http.MethodGet || r.Method != http.MethodHead) {
		allow := f.method
		if allow == http.MethodGet {
			allow = "GET, HEAD"
		}
		w.Header().Set("Allow", allow)
		drain()
		gatewayReply(w, http.StatusMethodNotAllowed, "text/plain; charset=utf-8", "Method Not Allowed\n")
		return
	}
	if deployment != "" {
		r.SetPathValue("deployment", deployment)
	}
	if f.method == http.MethodGet {
		drain()
	}
	f.handle(w, r)
}

type gatewayBodyCounter struct {
	io.ReadCloser
	bytes int64
	eof   bool
}

func (b *gatewayBodyCounter) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.bytes += int64(n)
	if err == io.EOF {
		b.eof = true
	}
	return n, err
}

type gatewayWriter struct {
	http.ResponseWriter
	status int
}

func (w *gatewayWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *gatewayWriter) WriteHeader(code int) {
	if code >= 200 {
		if w.status != 0 {
			return
		}
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *gatewayWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *gatewayWriter) WriteString(s string) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return io.WriteString(w.ResponseWriter, s)
}

func (w *gatewayWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func gatewayPublicMethod(method string) string {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
		return method
	default:
		return "_OTHER"
	}
}

// ClientAddress returns the canonical public IPv4 of a TCP peer, or "" for local, private, shared or non-IPv4 peers.
func ClientAddress(remoteAddr string) string {
	peer, err := netip.ParseAddrPort(remoteAddr)
	if err != nil || peer.Port() == 0 || peer.Addr().Zone() != "" {
		return ""
	}
	ip := peer.Addr().Unmap()
	if !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return ""
	}
	octets := ip.As4()
	if octets[0] == 0 || octets[0] >= 224 || (octets[0] == 100 && octets[1] >= 64 && octets[1] < 128) {
		return ""
	}
	return ip.String()
}

func gatewayContentType(ct string) string {
	ct = strings.TrimSpace(ct)
	if ct == "" {
		return "none"
	}
	media, _, _ := strings.Cut(ct, ";")
	media = strings.TrimSpace(media)
	for _, allowed := range [...]string{gatewayJSON, "text/plain", "application/octet-stream", "application/x-www-form-urlencoded", "multipart/form-data"} {
		if len(media) == len(allowed) && strings.EqualFold(media, allowed) {
			return allowed
		}
	}
	return "other"
}

func gatewayReply(w http.ResponseWriter, status int, contentType, body string) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func gatewayReadObject(r *http.Request) (map[string]json.RawMessage, int) {
	if r.Body == nil {
		return nil, http.StatusBadRequest
	}
	d := json.NewDecoder(r.Body)
	var obj map[string]json.RawMessage
	err := d.Decode(&obj)
	if err == nil && obj != nil {
		_, err = d.Token()
		if err == io.EOF {
			return obj, 0
		}
	}
	var limit *http.MaxBytesError
	if errors.As(err, &limit) {
		return nil, http.StatusRequestEntityTooLarge
	}
	return nil, http.StatusBadRequest
}

func gatewayModels(w http.ResponseWriter, _ *http.Request) {
	var b strings.Builder
	b.WriteString(`{"object":"list","data":[`)
	for i, m := range gatewayModelList {
		owner := "local"
		switch {
		case strings.HasPrefix(m, "gpt-"), strings.HasPrefix(m, "o3-"), strings.HasPrefix(m, "text-embedding-"):
			owner = "openai"
		case strings.HasPrefix(m, "claude-"):
			owner = "anthropic"
		}
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":"%s","object":"model","created":1722470400,"owned_by":"%s"}`, m, owner)
	}
	b.WriteString(`]}`)
	gatewayReply(w, 200, gatewayJSON, b.String())
}

func gatewayCompletion(chat bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		obj, status := gatewayReadObject(r)
		if status != 0 {
			gatewayReply(w, status, gatewayJSON, gatewayInvalid)
			return
		}
		model, ok := gatewayRequestModel(r, obj)
		if !ok {
			gatewayReply(w, 404, gatewayJSON, gatewayNoModel)
			return
		}
		stream, ok := gatewayStream(obj["stream"])
		if !ok || chat && !gatewayArray(obj["messages"]) || !chat && !gatewayText(obj["prompt"]) && !gatewayArray(obj["prompt"]) {
			gatewayReply(w, 400, gatewayJSON, gatewayInvalid)
			return
		}
		gatewayTrace(r, obj, model, stream)
		id, ok := gatewayID(w)
		if !ok {
			return
		}
		now := time.Now().Unix()
		kind, prefix, content := "text_completion", "cmpl", `"text":"Ready."`
		if chat {
			kind, prefix, content = "chat.completion", "chatcmpl", `"message":{"role":"assistant","content":"Ready."}`
		}
		if !stream {
			w.Header().Set("Content-Type", gatewayJSON)
			_, _ = fmt.Fprintf(w, `{"id":"%s-%x","object":"%s","created":%d,"model":"%s","choices":[{"index":0,%s,"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`, prefix, id, kind, now, model, content)
			return
		}
		end := `"text":""`
		if chat {
			kind, content, end = "chat.completion.chunk", `"delta":{"role":"assistant","content":"Ready."}`, `"delta":{}`
		}
		w.Header().Set("Content-Type", "text/event-stream")
		const frame = `data: {"id":"%s-%x","object":"%s","created":%d,"model":"%s","choices":[{"index":0,%s,"finish_reason":%s}]}` + "\n\n"
		if _, err := fmt.Fprintf(w, frame, prefix, id, kind, now, model, content, "null"); err != nil {
			return
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			return
		}
		_, _ = fmt.Fprintf(w, frame, prefix, id, kind, now, model, end, `"stop"`)
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}
}

const gatewayInvalid = `{"error":{"message":"invalid request","type":"invalid_request_error"}}`
const gatewayNoModel = `{"error":{"message":"model not found","type":"not_found_error"}}`

// gatewayTrace records only server-chosen values: the listed model when the client named one, and the parsed stream flag.
func gatewayTrace(r *http.Request, obj map[string]json.RawMessage, model string, stream bool) {
	if span := trace.SpanFromContext(r.Context()); span.IsRecording() {
		if obj["model"] != nil || r.PathValue("deployment") != "" {
			span.SetAttributes(attribute.String("gen_ai.request.model", model))
		}
		if obj["stream"] != nil {
			span.SetAttributes(attribute.Bool("attackbox.request.stream", stream))
		}
	}
}

func gatewayID(w http.ResponseWriter) ([12]byte, bool) {
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		gatewayReply(w, 503, gatewayJSON, `{"error":{"message":"service unavailable","type":"server_error"}}`)
		return id, false
	}
	return id, true
}

func gatewayFlush(w http.ResponseWriter, frames ...string) bool {
	for _, frame := range frames {
		if _, err := io.WriteString(w, frame); err != nil {
			return false
		}
	}
	return http.NewResponseController(w).Flush() == nil
}

func gatewayEmbeddings(w http.ResponseWriter, r *http.Request) {
	obj, status := gatewayReadObject(r)
	if status != 0 {
		gatewayReply(w, status, gatewayJSON, gatewayInvalid)
		return
	}
	model, ok := gatewayRequestModel(r, obj)
	if !ok {
		gatewayReply(w, 404, gatewayJSON, gatewayNoModel)
		return
	}
	if !gatewayText(obj["input"]) && !gatewayArray(obj["input"]) {
		gatewayReply(w, 400, gatewayJSON, gatewayInvalid)
		return
	}
	gatewayTrace(r, obj, model, false)
	gatewayReply(w, 200, gatewayJSON, `{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.0123,-0.0456,0.0789,-0.0012,0.0345,-0.0678,0.0901,-0.0234]}],"model":"`+model+`","usage":{"prompt_tokens":1,"total_tokens":1}}`)
}

func gatewayMessages(w http.ResponseWriter, r *http.Request) {
	const invalid = `{"type":"error","error":{"type":"invalid_request_error","message":"invalid request"}}`
	obj, status := gatewayReadObject(r)
	if status != 0 {
		gatewayReply(w, status, gatewayJSON, invalid)
		return
	}
	stream, ok := gatewayStream(obj["stream"])
	var maxTokens int
	if !ok || obj["model"] == nil || !gatewayArray(obj["messages"]) || json.Unmarshal(obj["max_tokens"], &maxTokens) != nil || maxTokens < 1 {
		gatewayReply(w, 400, gatewayJSON, invalid)
		return
	}
	model, found := gatewayRequestModel(r, obj)
	if !found {
		gatewayReply(w, 404, gatewayJSON, `{"type":"error","error":{"type":"not_found_error","message":"model not found"}}`)
		return
	}
	gatewayTrace(r, obj, model, stream)
	id, ok := gatewayID(w)
	if !ok {
		return
	}
	const usage = `"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`
	if !stream {
		w.Header().Set("Content-Type", gatewayJSON)
		_, _ = fmt.Fprintf(w, `{"id":"msg_%x","type":"message","role":"assistant","model":"%s","content":[{"type":"text","text":"Ready."}],"stop_reason":"end_turn",`+usage, id, model)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	start := fmt.Sprintf("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_%x\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"%s\",\"content\":[],\"stop_reason\":null,"+usage+"}\n\n", id, model)
	if !gatewayFlush(w, start, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Ready.\"}}\n\n") {
		return
	}
	gatewayFlush(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":1}}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
}

// gatewayOllamaTag gives a model the tag form Ollama reports.
func gatewayOllamaTag(m string) string {
	if strings.Contains(m, ":") {
		return m
	}
	return m + ":latest"
}

// gatewayOllamaTags lists the local-style models only; hosted API names are not Ollama tags.
func gatewayOllamaTags(w http.ResponseWriter, _ *http.Request) {
	var b strings.Builder
	b.WriteString(`{"models":[`)
	n := 0
	for _, m := range gatewayModelList {
		if strings.HasPrefix(m, "gpt-") || strings.HasPrefix(m, "o3-") || strings.HasPrefix(m, "claude-") || strings.HasPrefix(m, "text-embedding-") {
			continue
		}
		if n > 0 {
			b.WriteByte(',')
		}
		n++
		tag := gatewayOllamaTag(m)
		fmt.Fprintf(&b, `{"name":"%s","model":"%s","modified_at":"2024-08-01T00:00:00Z","size":%d,"digest":"%x","details":{"parent_model":"","format":"gguf","family":"llama","families":["llama"],"parameter_size":"8.0B","quantization_level":"Q4_K_M"}}`,
			tag, tag, 4920734272-int64(n)*73400320, sha256.Sum256([]byte(tag)))
	}
	b.WriteString(`]}`)
	gatewayReply(w, 200, gatewayJSON, b.String())
}

// gatewayOllama follows Ollama's defaults: streaming NDJSON unless the client sets "stream": false.
func gatewayOllama(chat bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		obj, status := gatewayReadObject(r)
		if status != 0 {
			gatewayReply(w, status, gatewayJSON, `{"error":"invalid request"}`)
			return
		}
		stream, ok := gatewayStream(obj["stream"])
		if obj["stream"] == nil {
			stream = true
		}
		if !ok || obj["model"] == nil || chat && !gatewayArray(obj["messages"]) || !chat && !gatewayText(obj["prompt"]) {
			gatewayReply(w, 400, gatewayJSON, `{"error":"invalid request"}`)
			return
		}
		model, found := gatewayRequestModel(r, obj)
		if !found {
			gatewayReply(w, 404, gatewayJSON, `{"error":"model not found"}`)
			return
		}
		gatewayTrace(r, obj, model, stream)
		created := time.Now().UTC().Format(time.RFC3339Nano)
		content := func(text string) string {
			if chat {
				return `"message":{"role":"assistant","content":"` + text + `"}`
			}
			return `"response":"` + text + `"`
		}
		const done = `,"done_reason":"stop","done":true,"total_duration":182400000,"load_duration":10600000,"prompt_eval_count":1,"prompt_eval_duration":21300000,"eval_count":1,"eval_duration":148900000}`
		head := `{"model":"` + gatewayOllamaTag(model) + `","created_at":"` + created + `",`
		if !stream {
			gatewayReply(w, 200, gatewayJSON, head+content("Ready.")+done)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		if gatewayFlush(w, head+content("Ready.")+`,"done":false}`+"\n") {
			gatewayFlush(w, head+content("")+done+"\n")
		}
	}
}

// gatewayQueryParams counts query pairs without reading their names or values.
func gatewayQueryParams(raw string) int {
	if raw == "" {
		return 0
	}
	return min(strings.Count(raw, "&")+1, 64)
}

// gatewayProbe sorts unmatched requests into fixed classes; the class set must match deploy/public-otel/config.yaml.
func gatewayProbe(r *http.Request) string {
	if r.Method == http.MethodConnect || r.URL.IsAbs() {
		return "proxy"
	}
	p := strings.ToLower(r.URL.Path)
	has := func(parts ...string) bool {
		for _, part := range parts {
			if strings.Contains(p, part) {
				return true
			}
		}
		return false
	}
	ends := func(parts ...string) bool {
		for _, part := range parts {
			if strings.HasSuffix(p, part) {
				return true
			}
		}
		return false
	}
	switch {
	case p == "/":
		return "root"
	case has("/.env") || ends(".env"):
		return "env_file"
	case has("/.git", "/.svn", "/.hg"):
		return "vcs"
	case has("/wp-", "xmlrpc.php", "/wordpress"):
		return "wordpress"
	case has("/actuator"):
		return "actuator"
	case has("/cgi-bin"):
		return "cgi"
	case has("phpmyadmin", "/admin", "/login", "/console", "/manager"):
		return "admin"
	case ends(".php"):
		return "php"
	case has("/.well-known", "/robots.txt", "/sitemap.xml", "/favicon.ico", "/security.txt"):
		return "discovery"
	case ends(".json", ".yml", ".yaml", ".ini", ".conf", ".config", ".xml", ".properties", ".toml", ".bak", ".sql"):
		return "config_file"
	case has("/v1", "/v2", "/api", "openai", "ollama", "anthropic", "llm", "gpt", "model", "completion", "embedding", "generate", "chat", "inference", "predict"):
		return "llm_api"
	default:
		return "other"
	}
}

func gatewayArray(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) > 2 && raw[0] == '[' && len(bytes.TrimSpace(raw[1:len(raw)-1])) != 0
}

func gatewayText(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) > 2 && raw[0] == '"'
}

func gatewayStream(raw json.RawMessage) (bool, bool) {
	if raw == nil {
		return false, true
	}
	switch string(bytes.TrimSpace(raw)) {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

// gatewayCredential returns the first credential a client sent: where it came from, a fixed type, and the value as sent.
// The operator chose to export full values. A value that is not 1-512 printable ASCII bytes keeps its type but not its value.
func gatewayCredential(r *http.Request) (source, kind, value string) {
	for _, h := range [...]string{"Authorization", "Proxy-Authorization", "X-Api-Key", "Api-Key", "X-Goog-Api-Key"} {
		v := r.Header.Get(h)
		if v == "" {
			continue
		}
		source, kind = strings.ToLower(h), ""
		if scheme, rest, ok := strings.Cut(v, " "); ok && strings.HasSuffix(h, "Authorization") {
			v = strings.TrimSpace(rest)
			if strings.EqualFold(scheme, "basic") {
				kind = "basic"
			}
		}
		if kind == "" {
			kind = gatewayCredentialKind(v)
		}
		return source, kind, gatewayCredentialValue(v)
	}
	q := r.URL.Query()
	for _, name := range [...]string{"key", "api_key", "apikey", "api-key", "access_token", "token"} {
		if v := q.Get(name); v != "" {
			return "query", gatewayCredentialKind(v), gatewayCredentialValue(v)
		}
	}
	return "", "", ""
}

// gatewayCredentialPrefixes is checked in order; the type set must match deploy/public-otel/config.yaml.
var gatewayCredentialPrefixes = [...][2]string{
	{"sk-ant-", "anthropic"}, {"sk-", "openai"}, {"AIza", "google"}, {"AKIA", "aws"}, {"ASIA", "aws"}, {"hf_", "huggingface"},
	{"gsk_", "groq"}, {"xai-", "xai"}, {"r8_", "replicate"}, {"eyJ", "jwt"}, {"github_pat_", "github"}, {"ghp_", "github"},
	{"gho_", "github"}, {"ghu_", "github"}, {"ghs_", "github"},
}

func gatewayCredentialKind(v string) string {
	for _, p := range gatewayCredentialPrefixes {
		if strings.HasPrefix(v, p[0]) {
			return p[1]
		}
	}
	return "token"
}

func gatewayCredentialValue(v string) string {
	if len(v) == 0 || len(v) > 512 {
		return ""
	}
	for i := range len(v) {
		if v[i] < '!' || v[i] > '~' {
			return ""
		}
	}
	return v
}
