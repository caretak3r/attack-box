package publicedge

import (
	"bytes"
	"crypto/rand"
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
const gatewayJSON = "application/json"
const gatewayBodyLimit = 64 << 10

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
			attrs := make([]attribute.KeyValue, 0, 10)
			attrs = append(attrs, attribute.Int("server.port", 443), attribute.String("attackbox.persona", "cloud-gateway"),
				attribute.String("http.route", route), attribute.String("http.request.method", gatewayPublicMethod(r.Method)),
				attribute.Int("http.response.status_code", status), attribute.String("attackbox.request.content_type", gatewayContentType(r.Header.Get("Content-Type"))),
				attribute.Int("attackbox.request.query_params", gatewayQueryParams(r.URL.RawQuery)))
			if probe != "" {
				attrs = append(attrs, attribute.String("attackbox.probe.class", probe))
			}
			if addr := ClientAddress(r.RemoteAddr); addr != "" {
				attrs = append(attrs, attribute.String("client.address", addr))
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
		g.Capture.Record(r, route, status, probe)
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
	}

	if f == nil {
		gatewayReply(w, http.StatusNotFound, "text/plain; charset=utf-8", "404 page not found\n")
		return
	}
	if r.Method != f.method && (f.method != http.MethodGet || r.Method != http.MethodHead) {
		allow := f.method
		if allow == http.MethodGet {
			allow = "GET, HEAD"
		}
		w.Header().Set("Allow", allow)
		gatewayReply(w, http.StatusMethodNotAllowed, "text/plain; charset=utf-8", "Method Not Allowed\n")
		return
	}
	if deployment != "" {
		r.SetPathValue("deployment", deployment)
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
	gatewayReply(w, 200, gatewayJSON, `{"object":"list","data":[{"id":"`+gatewayModel+`","object":"model","created":1722470400,"owned_by":"local"}]}`)
}

func gatewayCompletion(chat bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		obj, status := gatewayReadObject(r)
		if status != 0 {
			gatewayReply(w, status, gatewayJSON, gatewayInvalid)
			return
		}
		if d := r.PathValue("deployment"); d != "" && d != gatewayModel || obj["model"] != nil && !gatewayModelMatches(obj["model"]) {
			gatewayReply(w, 404, gatewayJSON, gatewayNoModel)
			return
		}
		stream, ok := gatewayStream(obj["stream"])
		if !ok || chat && !gatewayArray(obj["messages"]) || !chat && !gatewayText(obj["prompt"]) && !gatewayArray(obj["prompt"]) {
			gatewayReply(w, 400, gatewayJSON, gatewayInvalid)
			return
		}
		gatewayTrace(r, obj, stream)
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
			_, _ = fmt.Fprintf(w, `{"id":"%s-%x","object":"%s","created":%d,"model":"`+gatewayModel+`","choices":[{"index":0,%s,"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`, prefix, id, kind, now, content)
			return
		}
		end := `"text":""`
		if chat {
			kind, content, end = "chat.completion.chunk", `"delta":{"role":"assistant","content":"Ready."}`, `"delta":{}`
		}
		w.Header().Set("Content-Type", "text/event-stream")
		const frame = `data: {"id":"%s-%x","object":"%s","created":%d,"model":"` + gatewayModel + `","choices":[{"index":0,%s,"finish_reason":%s}]}` + "\n\n"
		if _, err := fmt.Fprintf(w, frame, prefix, id, kind, now, content, "null"); err != nil {
			return
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			return
		}
		_, _ = fmt.Fprintf(w, frame, prefix, id, kind, now, end, `"stop"`)
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}
}

const gatewayInvalid = `{"error":{"message":"invalid request","type":"invalid_request_error"}}`
const gatewayNoModel = `{"error":{"message":"model not found","type":"not_found_error"}}`

// gatewayTrace records only server-chosen values: the model constant and the parsed stream flag.
func gatewayTrace(r *http.Request, obj map[string]json.RawMessage, stream bool) {
	if span := trace.SpanFromContext(r.Context()); span.IsRecording() {
		if obj["model"] != nil {
			span.SetAttributes(attribute.String("gen_ai.request.model", gatewayModel))
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
	if d := r.PathValue("deployment"); d != "" && d != gatewayModel || obj["model"] != nil && !gatewayModelMatches(obj["model"]) {
		gatewayReply(w, 404, gatewayJSON, gatewayNoModel)
		return
	}
	if !gatewayText(obj["input"]) && !gatewayArray(obj["input"]) {
		gatewayReply(w, 400, gatewayJSON, gatewayInvalid)
		return
	}
	gatewayTrace(r, obj, false)
	gatewayReply(w, 200, gatewayJSON, `{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.0123,-0.0456,0.0789,-0.0012,0.0345,-0.0678,0.0901,-0.0234]}],"model":"`+gatewayModel+`","usage":{"prompt_tokens":1,"total_tokens":1}}`)
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
	if !gatewayModelMatches(obj["model"]) {
		gatewayReply(w, 404, gatewayJSON, `{"type":"error","error":{"type":"not_found_error","message":"model not found"}}`)
		return
	}
	gatewayTrace(r, obj, stream)
	id, ok := gatewayID(w)
	if !ok {
		return
	}
	const usage = `"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`
	if !stream {
		w.Header().Set("Content-Type", gatewayJSON)
		_, _ = fmt.Fprintf(w, `{"id":"msg_%x","type":"message","role":"assistant","model":"`+gatewayModel+`","content":[{"type":"text","text":"Ready."}],"stop_reason":"end_turn",`+usage, id)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	start := fmt.Sprintf("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_%x\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\""+gatewayModel+"\",\"content\":[],\"stop_reason\":null,"+usage+"}\n\n", id)
	if !gatewayFlush(w, start, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Ready.\"}}\n\n") {
		return
	}
	gatewayFlush(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":1}}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
}

const gatewayOllamaName = gatewayModel + ":latest"

func gatewayOllamaTags(w http.ResponseWriter, _ *http.Request) {
	gatewayReply(w, 200, gatewayJSON, `{"models":[{"name":"`+gatewayOllamaName+`","model":"`+gatewayOllamaName+`","modified_at":"2024-08-01T00:00:00Z","size":4920734272,"digest":"5f8a3c2e9b1d4a6f7c0e8b2d1a9f3e6c4b7d0a2e5f8c1b4d7a0e3f6c9b2d5a8e","details":{"parent_model":"","format":"gguf","family":"llama","families":["llama"],"parameter_size":"8.0B","quantization_level":"Q4_K_M"}}]}`)
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
		var model string
		if json.Unmarshal(obj["model"], &model) != nil || model != gatewayModel && model != gatewayOllamaName {
			gatewayReply(w, 404, gatewayJSON, `{"error":"model not found"}`)
			return
		}
		gatewayTrace(r, obj, stream)
		created := time.Now().UTC().Format(time.RFC3339Nano)
		content := func(text string) string {
			if chat {
				return `"message":{"role":"assistant","content":"` + text + `"}`
			}
			return `"response":"` + text + `"`
		}
		const done = `,"done_reason":"stop","done":true,"total_duration":182400000,"load_duration":10600000,"prompt_eval_count":1,"prompt_eval_duration":21300000,"eval_count":1,"eval_duration":148900000}`
		head := `{"model":"` + gatewayOllamaName + `","created_at":"` + created + `",`
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

func gatewayModelMatches(raw json.RawMessage) bool {
	var s string
	return json.Unmarshal(raw, &s) == nil && s == gatewayModel
}
