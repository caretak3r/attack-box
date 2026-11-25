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
	mux    *http.ServeMux
	routes map[string]string
	tracer trace.Tracer
	slots  chan struct{}
}

func NewGateway(tracer trace.Tracer) *Gateway {
	if tracer == nil {
		tracer = noop.NewTracerProvider().Tracer("attackbox.gateway")
	}
	g := &Gateway{mux: http.NewServeMux(), routes: make(map[string]string), tracer: tracer, slots: make(chan struct{}, 16)}
	add := func(method, route string, h http.HandlerFunc) {
		pattern := method + " " + route
		g.mux.HandleFunc(pattern, h)
		g.routes[pattern] = route
	}
	add("POST", "/openai/deployments/{deployment}/chat/completions", gatewayCompletion(true))
	add("GET", "/v1/models", gatewayModels)
	add("POST", "/v1/chat/completions", gatewayCompletion(true))
	add("POST", "/v1/completions", gatewayCompletion(false))
	return g
}

func (g *Gateway) ServeHTTP(base http.ResponseWriter, req *http.Request) {
	ctx, span := g.tracer.Start(baggage.ContextWithoutBaggage(req.Context()), "public.request", trace.WithNewRoot(), trace.WithSpanKind(trace.SpanKindServer))
	r := req.WithContext(ctx)
	r.Pattern = ""
	w := &gatewayWriter{ResponseWriter: base}
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
		if span.IsRecording() {
			route := g.routes[r.Pattern]
			if route == "" {
				route = "/unmatched"
			}
			attrs := make([]attribute.KeyValue, 0, 8)
			attrs = append(attrs, attribute.Int("server.port", 443), attribute.String("attackbox.persona", "cloud-gateway"),
				attribute.String("http.route", route), attribute.String("http.request.method", gatewayPublicMethod(r.Method)),
				attribute.Int("http.response.status_code", status), attribute.String("attackbox.request.content_type", gatewayContentType(r.Header.Get("Content-Type"))))
			if addr := gatewayClientAddress(r.RemoteAddr); addr != "" {
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

	g.mux.ServeHTTP(w, r)
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

func gatewayClientAddress(remoteAddr string) string {
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
			gatewayReply(w, status, gatewayJSON, `{"error":{"message":"invalid request","type":"invalid_request_error"}}`)
			return
		}
		if d := r.PathValue("deployment"); d != "" && d != gatewayModel || obj["model"] != nil && !gatewayModelMatches(obj["model"]) {
			gatewayReply(w, 404, gatewayJSON, `{"error":{"message":"model not found","type":"not_found_error"}}`)
			return
		}
		stream, ok := gatewayStream(obj["stream"])
		if !ok || chat && !gatewayArray(obj["messages"]) || !chat && !gatewayText(obj["prompt"]) && !gatewayArray(obj["prompt"]) {
			gatewayReply(w, 400, gatewayJSON, `{"error":{"message":"invalid request","type":"invalid_request_error"}}`)
			return
		}
		if span := trace.SpanFromContext(r.Context()); span.IsRecording() {
			if obj["model"] != nil {
				span.SetAttributes(attribute.String("gen_ai.request.model", gatewayModel))
			}
			if obj["stream"] != nil {
				span.SetAttributes(attribute.Bool("attackbox.request.stream", stream))
			}
		}
		var id [12]byte
		if _, err := rand.Read(id[:]); err != nil {
			gatewayReply(w, 503, gatewayJSON, `{"error":{"message":"service unavailable","type":"server_error"}}`)
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
