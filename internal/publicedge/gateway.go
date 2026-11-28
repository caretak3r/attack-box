package publicedge

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
var gatewayModelList = []string{gatewayModel,
	// OpenAI
	"gpt-5.6-sol", "gpt-5.5-pro", "gpt-5.5", "gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "o3-mini", "gpt-3.5-turbo",
	// Anthropic
	"claude-fable-5-2", "claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5",
	"claude-3-5-sonnet-20241022", "claude-3-7-sonnet-20250219", "claude-sonnet-4-20250514", "claude-3-5-haiku-20241022",
	// Google Gemini
	"gemini-4-argon", "gemini-3.8-flash", "gemini-3.1-flash-lite",
	// xAI
	"grok-4.7",
	// DeepSeek hosted
	"deepseek-chat", "deepseek-reasoner", "deepseek-flash", "deepseek-v4-pro",
	// Moonshot Kimi
	"kimi-k3.1-pro", "kimi-k3",
	// Mistral
	"mistral-large-4", "mistral-small-4",
	// opencode
	"big-pickle", "mimo-v2.6-flash-free", "deepseek-v4.1-flash-free", "claude-fable-5",
	// Qwen hosted
	"qwen3-max",
	// Ollama tags
	"llama3.1:8b", "qwen2.5:7b", "deepseek-r1:8b", "deepseek-r1:70b", "mistral:7b", "llama3.3:70b", "qwen2.5-coder:32b",
	"llama4:16x17b", "llama4:128x17b", "gemma3:1b", "gemma3:4b", "gemma3:12b", "gemma3:27b", "phi4:14b", "qwen3:8b", "qwen3:32b",
	"qwen3-coder:30b", "qwen3-coder:480b", "deepseek-v3:671b", "gpt-oss:20b", "gpt-oss:120b",
	// Embedding models
	"text-embedding-3-small", "text-embedding-3-large", "nomic-embed-text"}

// gatewayModelName returns the listed model for a requested name; Ollama clients may add ":latest".
// A local model server does not serve hosted API names.
func gatewayModelName(s string, local bool) (string, bool) {
	s = strings.TrimSuffix(s, ":latest")
	for _, m := range gatewayModelList {
		if s == m {
			return m, !local || !gatewayHostedModel(m)
		}
	}
	return "", false
}

// gatewayRequestModel resolves the deployment path and the body model; either one must be listed. No model means the default.
func gatewayRequestModel(r *http.Request, obj map[string]json.RawMessage) (string, bool) {
	local := requestPersona(r).local
	model := gatewayModel
	if d := r.PathValue("deployment"); d != "" {
		m, ok := gatewayModelName(d, local)
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
		m, ok := gatewayModelName(s, local)
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

// gatewayHostPersonas maps the first label of a Host header on port 443 to the port whose product it names.
var gatewayHostPersonas = map[string]int{"ollama": 11434, "openwebui": 3000, "litellm": 4000}

// requestPersona answers port 443 like a reverse proxy in front of a product when the Host name starts with that product.
func requestPersona(r *http.Request) gatewayPersona {
	port := requestPort(r)
	if port == 443 {
		label, _, _ := strings.Cut(strings.ToLower(r.Host), ".")
		if p, ok := gatewayHostPersonas[label]; ok {
			port = p
		}
	}
	return gatewayPersonas[port]
}

type Gateway struct {
	tracer trace.Tracer
	slots  chan struct{}
	// Capture, when set, keeps raw request lines on local disk; they are never exported.
	Capture *Capture
	// canary seeds the fake key of an env-file answer; a new process gives each peer a new key.
	canary [32]byte
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
	{"api/show", http.MethodPost, gatewayOllamaManage(true, gatewayOllamaShow)},
	{"api/pull", http.MethodPost, gatewayOllamaManage(false, gatewayOllamaPull)},
	{"api/create", http.MethodPost, gatewayOllamaManage(false, gatewayOllamaCreate)},
	{"api/delete", http.MethodDelete, gatewayOllamaManage(true, gatewayOllamaDelete)},
	{"api/embed", http.MethodPost, gatewayOllamaManage(true, gatewayOllamaEmbed(false))},
	{"api/embeddings", http.MethodPost, gatewayOllamaManage(true, gatewayOllamaEmbed(true))},
	{"chat/completions", http.MethodPost, gatewayCompletion(true)},
	{"completions", http.MethodPost, gatewayCompletion(false)},
	{"embeddings", http.MethodPost, gatewayEmbeddings},
	{"messages", http.MethodPost, gatewayMessages},
	{"models", http.MethodGet, gatewayModels},
	{"mcp", http.MethodPost, gatewayMCP},
}

// gatewayPrefixes must match the http.route allowlist in deploy/public-otel/config.yaml.
var gatewayPrefixes = map[string]bool{"v1": true, "v2": true, "v3": true, "api": true, "openai": true, "azure": true, "llm": true, "ai": true,
	"proxy": true, "gateway": true, "inference": true, "litellm": true, "ollama": true, "anthropic": true}

const gatewayMaxPrefix = 4

func NewGateway(tracer trace.Tracer) *Gateway {
	if tracer == nil {
		tracer = noop.NewTracerProvider().Tracer("attackbox.gateway")
	}
	g := &Gateway{tracer: tracer, slots: make(chan struct{}, 16)}
	_, _ = rand.Read(g.canary[:]) // never fails
	return g
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

	persona := requestPersona(r)
	if persona.paths == nil { // a product port sends only the headers of its product
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}
	if persona.server != "" {
		w.Header().Set("Server", persona.server)
	}
	// One trailing slash is a valid target: FastAPI products route paths such as /api/v1/tools/.
	clean := r.URL.Path
	if len(clean) > 1 {
		clean = strings.TrimSuffix(clean, "/")
	}
	if r.Method == http.MethodConnect || r.URL.IsAbs() || clean == "" || clean[0] != '/' || path.Clean(clean) != clean {
		gatewayReply(w, http.StatusBadRequest, "text/plain; charset=utf-8", "invalid request target\n")
		return
	}
	f, label, deployment := gatewayResolve(clean)
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
			bodyRec = g.Capture.bodyRecorder(r.Body)
			r.Body = bodyRec
		}
	}
	// With a capture, read a body that no handler reads, so that the local record holds it.
	// A persona handler that parses the body then reads the recorded bytes.
	// The span keeps its meaning: it reports a chunked body size only when a handler read the body.
	drain := func() {
		if bodyRec != nil {
			counted = nil
			_ = http.NewResponseController(base).SetReadDeadline(time.Now().Add(2 * time.Second))
			_, _ = io.Copy(io.Discard, bodyRec)
			r.Body = io.NopCloser(bytes.NewReader(bodyRec.buf.Bytes()))
		}
	}

	if f == nil {
		drain()
		get := r.Method == http.MethodGet || r.Method == http.MethodHead
		if h := persona.paths[r.URL.Path]; h != nil && get {
			route = r.URL.Path
			h(w, r)
		} else if h := persona.posts[r.URL.Path]; h != nil && r.Method == http.MethodPost {
			route = r.URL.Path
			h(w, r)
		} else if h, label := persona.route(r); h != nil {
			route = label
			if source, _, _ := gatewayCredential(r); persona.needKey && source == "" {
				persona.noKey(w, r)
			} else {
				h(w, r)
			}
		} else if get && gatewayProbe(r) == "env_file" {
			route = "/.env"
			g.envFile(w, r)
		} else if persona.notFound != nil {
			persona.notFound(w, r)
		} else {
			gatewayReply(w, http.StatusNotFound, "text/plain; charset=utf-8", "404 page not found\n")
		}
		return
	}
	if persona.needKey {
		if source, _, _ := gatewayCredential(r); source == "" {
			drain()
			if persona.noKey != nil {
				persona.noKey(w, r)
			} else {
				gatewayReply(w, http.StatusUnauthorized, gatewayJSON, gatewayNoKey)
			}
			return
		}
	}
	if r.Method != f.method && (f.method != http.MethodGet || r.Method != http.MethodHead) {
		allow := f.method
		if allow == http.MethodGet {
			allow = "GET, HEAD"
		}
		w.Header().Set("Allow", allow)
		drain()
		if persona.notAllowed != nil {
			persona.notAllowed(w, r)
		} else {
			gatewayReply(w, http.StatusMethodNotAllowed, "text/plain; charset=utf-8", "Method Not Allowed\n")
		}
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

func gatewayModels(w http.ResponseWriter, r *http.Request) {
	persona := requestPersona(r)
	var entries []string
	for _, m := range gatewayModelList {
		owner := "local"
		switch {
		case persona.local && gatewayHostedModel(m):
			continue
		case persona.owner != "":
			owner = persona.owner
		case strings.HasPrefix(m, "gpt-"), strings.HasPrefix(m, "o3-"), strings.HasPrefix(m, "text-embedding-"):
			owner = "openai"
		case strings.HasPrefix(m, "claude-"):
			owner = "anthropic"
		}
		if owner == "library" {
			m = gatewayOllamaTag(m) // Ollama lists full tags
		}
		entries = append(entries, fmt.Sprintf(`{"id":"%s","object":"model","created":1722470400,"owned_by":"%s"}`, m, owner))
	}
	gatewayReply(w, 200, gatewayJSON, `{"object":"list","data":[`+strings.Join(entries, ",")+`]}`)
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
		limit := gatewayLimit(obj, "max_completion_tokens", "max_tokens")
		var a gatewayAnswerText
		if chat {
			a = gatewayChatAnswer(r, model, obj["messages"], limit, false)
		} else {
			a = gatewayCompose(model, gatewayContentText(obj["prompt"]), limit, false)
		}
		text := gatewayQ(strings.Join(a.text, ""))
		gatewaySleep(r.Context(), time.Duration(a.count)*12*time.Millisecond)
		now := time.Now().Unix()
		kind, prefix, content := "text_completion", "cmpl", `"text":`+text
		if chat {
			kind, prefix, content = "chat.completion", "chatcmpl", `"message":{"role":"assistant","content":`+text+`}`
		}
		if !stream {
			w.Header().Set("Content-Type", gatewayJSON)
			_, _ = fmt.Fprintf(w, `{"id":"%s-%x","object":"%s","created":%d,"model":"%s","choices":[{"index":0,%s,"finish_reason":"%s"}],"usage":{"prompt_tokens":%d,"completion_tokens":%d,"total_tokens":%d}}`,
				prefix, id, kind, now, model, content, a.reason, a.promptTokens, a.count, a.promptTokens+a.count)
			return
		}
		end := `"text":""`
		if chat {
			kind, content, end = "chat.completion.chunk", `"delta":{"role":"assistant","content":`+text+`}`, `"delta":{}`
		}
		w.Header().Set("Content-Type", "text/event-stream")
		const frame = `data: {"id":"%s-%x","object":"%s","created":%d,"model":"%s","choices":[{"index":0,%s,"finish_reason":%s}]}` + "\n\n"
		if _, err := fmt.Fprintf(w, frame, prefix, id, kind, now, model, content, "null"); err != nil {
			return
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			return
		}
		_, _ = fmt.Fprintf(w, frame, prefix, id, kind, now, model, end, `"`+a.reason+`"`)
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}
}

const gatewayInvalid = `{"error":{"message":"invalid request","type":"invalid_request_error"}}`
const gatewayNoModel = `{"error":{"message":"model not found","type":"not_found_error"}}`
const gatewayNoKey = `{"error":{"message":"No API key provided. Send it in the Authorization header as a Bearer token.","type":"authentication_error"}}`

// envFile answers an env-file probe with a fake key and the base URL the client used. The key is not valid anywhere.
// It depends on the peer and is recorded on the span, so a later request that presents it shows who fetched it.
func (g *Gateway) envFile(w http.ResponseWriter, r *http.Request) {
	sum := sha256.Sum256(append(g.canary[:], ClientAddress(r.RemoteAddr)...))
	s := strings.NewReplacer("-", "A", "_", "B").Replace(base64.RawURLEncoding.EncodeToString(sum[:]))
	key := "sk-" + s[:20] + "T3BlbkFJ" + s[20:40]
	trace.SpanFromContext(r.Context()).SetAttributes(attribute.String("attackbox.canary.key", key))
	body := "APP_ENV=production\nOPENAI_API_KEY=" + key + "\n"
	if gatewayHost(r.Host) {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		body += "OPENAI_BASE_URL=" + scheme + "://" + r.Host + "/v1\n"
	}
	gatewayReply(w, 200, "text/plain; charset=utf-8", body)
}

// gatewayHost accepts a Host header that is safe to repeat in an answer: a name or an IPv4 address, with or without a port.
func gatewayHost(h string) bool {
	if h == "" || len(h) > 255 {
		return false
	}
	for _, c := range []byte(h) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == ':') {
			return false
		}
	}
	return true
}

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
	size := 768
	switch model {
	case "text-embedding-3-small":
		size = 1536
	case "text-embedding-3-large":
		size = 3072
	}
	inputs := gatewayInputs(obj["input"])
	data := make([]string, len(inputs))
	for i, in := range inputs {
		data[i] = fmt.Sprintf(`{"object":"embedding","index":%d,"embedding":%s}`, i, gatewayVector(size, in))
	}
	gatewayReply(w, 200, gatewayJSON, fmt.Sprintf(`{"object":"list","data":[%s],"model":"%s","usage":{"prompt_tokens":%[3]d,"total_tokens":%[3]d}}`, strings.Join(data, ","), model, 2*len(inputs)))
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
	a := gatewayChatAnswer(r, model, obj["messages"], maxTokens, false)
	text, reason := gatewayQ(strings.Join(a.text, "")), "end_turn"
	if a.reason == "length" {
		reason = "max_tokens"
	}
	gatewaySleep(r.Context(), time.Duration(a.count)*12*time.Millisecond)
	usage := fmt.Sprintf(`"stop_sequence":null,"usage":{"input_tokens":%d,"output_tokens":%d}}`, a.promptTokens, a.count)
	if !stream {
		gatewayReply(w, 200, gatewayJSON, fmt.Sprintf(`{"id":"msg_%x","type":"message","role":"assistant","model":"%s","content":[{"type":"text","text":%s}],"stop_reason":"%s",`, id, model, text, reason)+usage)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	start := fmt.Sprintf("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_%x\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"%s\",\"content\":[],\"stop_reason\":null,", id, model) + usage + "}\n\n"
	if !gatewayFlush(w, start, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":"+text+"}}\n\n") {
		return
	}
	gatewayFlush(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
		fmt.Sprintf("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"%s\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":%d}}\n\n", reason, a.count),
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
}

// gatewayHostedModel reports a hosted API name, which a local model server does not list.
func gatewayHostedModel(m string) bool {
	if strings.Contains(m, ":") {
		return false
	}
	return strings.HasPrefix(m, "gpt-") || strings.HasPrefix(m, "o3-") || strings.HasPrefix(m, "claude-") ||
		strings.HasPrefix(m, "text-embedding-") || strings.HasPrefix(m, "gemini-") || strings.HasPrefix(m, "grok-") ||
		strings.HasPrefix(m, "deepseek-") || strings.HasPrefix(m, "kimi-") || strings.HasPrefix(m, "mistral-") ||
		strings.HasPrefix(m, "big-pickle") || strings.HasPrefix(m, "mimo-") || strings.HasPrefix(m, "qwen3-max")
}

// gatewayLMStudioModels answers LM Studio's native model list with the local-style models.
func gatewayLMStudioModels(w http.ResponseWriter, _ *http.Request) {
	var b strings.Builder
	b.WriteString(`{"object":"list","data":[`)
	n := 0
	for _, m := range gatewayModelList {
		if gatewayHostedModel(m) {
			continue
		}
		if n > 0 {
			b.WriteByte(',')
		}
		n++
		fmt.Fprintf(&b, `{"id":"%s","object":"model","type":"llm","publisher":"lmstudio-community","arch":"llama","compatibility_type":"gguf","quantization":"Q4_K_M","state":"not-loaded","max_context_length":8192}`, m)
	}
	b.WriteString(`]}`)
	gatewayReply(w, 200, gatewayJSONUTF8, b.String())
}

// gatewayLMStudioNotFound answers as LM Studio does: status 200 and the request line in the error text.
func gatewayLMStudioNotFound(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Path
	if len(target) > 256 {
		target = target[:256]
	}
	body, _ := json.Marshal(map[string]string{"error": "Unexpected endpoint or method. (" + gatewayPublicMethod(r.Method) + " " + target + ")"})
	gatewayReply(w, 200, gatewayJSONUTF8, string(body))
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
