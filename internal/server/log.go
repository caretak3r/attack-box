package server

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"attackbox/internal/responder"
	"attackbox/internal/telemetry"
)

const (
	maxResourceLen = 256
	maxQueryLen    = 512
	maxUALen       = 512
	maxModelLog    = 128
)

// finish writes the edge and transcript events and the request counters.
func (s *Server) finish(c *call) {
	status := c.w.status
	if status == 0 {
		status = 499 // the client left before any response bytes
	}
	red := s.cfg.Redactor
	now := s.cfg.Now()
	headers, creds := red.Headers(c.r.Header)

	attrs := map[string]any{
		"route":                   c.endpoint,
		"headers":                 headers,
		"credential_fingerprints": creds,
		"body_bytes":              len(c.body),
		"response_bytes":          c.w.n,
		"latency_ms":              now.Sub(c.start).Milliseconds(),
		"host":                    truncRunes(red.Text(c.r.Host), 256),
		"proto":                   c.r.Proto,
	}
	if q := s.redactQuery(c.r.URL.RawQuery); q != "" {
		attrs["query"] = q
	}
	if c.tooLarge {
		attrs["body_limit_exceeded"] = true
	}
	if c.panicked {
		attrs["panic"] = true
		attrs["panic_value"] = c.panicInfo
	}
	if c.model != "" {
		attrs["model"] = truncRunes(cleanEcho(c.model, maxModelLog), maxModelLog)
		attrs["stream"] = c.streaming
		attrs["tool_count"] = c.tools
		if c.parallel != nil {
			attrs["parallel_tool_calls"] = *c.parallel
		}
	}
	if c.holdResult != "" {
		attrs["hold_result"] = c.holdResult
		attrs["hold_ms"] = c.holdMS
	}
	if c.streamCut != "" {
		attrs["stream_result"] = c.streamCut
	}
	obs := c.obs
	var labels []string
	task, probeID, sessionID := "", "", c.sessionID
	if d := c.dec; d != nil {
		sessionID = d.SessionID
		task, probeID, labels = d.Class.Task, d.Probe.ID, d.Class.Labels
		attrs["task"] = task
		if len(d.Declarations) > 0 {
			attrs["declarations"] = d.Declarations
		}
		obs = append(append([]responder.Observation(nil), d.Observations...), obs...)
	}
	if len(obs) > 0 {
		attrs["observations"] = obs
	}

	body, cut := s.logBody(c.body)
	if cut {
		attrs["body_truncated"] = true
	}
	resource := truncRunes(red.Text(c.r.URL.Path), maxResourceLen)
	ua := truncRunes(red.Text(c.ua), maxUALen)
	result := resultFor(status)
	if c.holdResult == holdServerShutdown || c.streamCut == holdServerShutdown {
		result = holdServerShutdown
	}

	s.cfg.Sink.Emit(telemetry.Event{
		Timestamp: now,
		Stream:    telemetry.StreamEdge,
		SessionID: sessionID,
		RequestID: c.id,
		SrcIP:     c.src,
		UserAgent: ua,
		Persona:   s.persona,
		Action:    truncRunes(cleanEcho(c.r.Method, 16), 16),
		Resource:  resource,
		Result:    result,
		Status:    status,
		ProbeID:   probeID,
		Attrs:     attrs,
		Body:      body,
	})
	if c.dec != nil {
		s.cfg.Sink.Emit(telemetry.Event{
			Timestamp:  now,
			Stream:     telemetry.StreamTranscript,
			SessionID:  sessionID,
			RequestID:  c.id,
			SrcIP:      c.src,
			UserAgent:  ua,
			Persona:    s.persona,
			Action:     truncRunes(cleanEcho(c.r.Method, 16), 16),
			Resource:   resource,
			Status:     status,
			ProbeID:    probeID,
			TaskLabels: labels,
			Body:       c.probeText,
		})
		s.cfg.Sink.Count("attackbox.probes", 1, telemetry.SafeLabels(map[string]string{
			"persona": s.persona, "probe_id": probeID, "task": task,
		}))
	}
	s.cfg.Sink.Count("attackbox.requests", 1, telemetry.SafeLabels(map[string]string{
		"persona": s.persona, "endpoint": c.endpoint, "status_class": strconv.Itoa(status/100) + "xx",
	}))
}

// logRedactMargin is how far past MaxLogBody the redactor still looks. Redaction
// can shrink the text, so the cut before it keeps a little more than the cap.
const logRedactMargin = 4 << 10

// logBody returns the redacted request body for the log, at most MaxLogBody
// bytes, and whether it was cut. The raw body is cut first so the redactor never
// scans a megabyte for a log line that keeps a fraction of it.
func (s *Server) logBody(b []byte) (string, bool) {
	limit := s.cfg.MaxLogBody
	keep := limit + logRedactMargin
	cut := len(b) > keep
	var raw string
	if cut {
		// A few spare bytes let truncBytes back off to a rune start.
		raw = truncBytes(string(b[:min(len(b), keep+utf8.UTFMax)]), keep)
	} else {
		raw = string(b)
	}
	body := s.cfg.Redactor.Text(raw)
	if len(body) > limit {
		body, cut = truncBytes(body, limit), true
	}
	return body, cut
}

func resultFor(status int) string {
	switch {
	case status >= 500:
		return "error"
	case status == http.StatusTooManyRequests:
		return "rate_limited"
	case status == http.StatusRequestEntityTooLarge:
		return "too_large"
	case status == http.StatusNotFound:
		return "not_found"
	case status == http.StatusMethodNotAllowed:
		return "method_not_allowed"
	case status == 499:
		return "client_closed"
	case status >= 400:
		return "bad_request"
	}
	return "ok"
}

var sensitiveQuery = []string{"key", "token", "secret", "password", "passwd", "auth", "session", "sig", "credential"}

// redactQuery masks the value of credential-looking parameters and scrubs the
// rest with the body redactor.
func (s *Server) redactQuery(raw string) string {
	if raw == "" {
		return ""
	}
	vals, err := url.ParseQuery(raw)
	if err != nil && len(vals) == 0 {
		return truncRunes(s.cfg.Redactor.Text(raw), maxQueryLen)
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		lk := strings.ToLower(k)
		sensitive := false
		for _, f := range sensitiveQuery {
			sensitive = sensitive || strings.Contains(lk, f)
		}
		for _, v := range vals[k] {
			if sensitive {
				v = "[redacted:" + s.cfg.Redactor.Fingerprint(v) + "]"
			} else {
				v = s.cfg.Redactor.Text(v)
			}
			parts = append(parts, s.cfg.Redactor.Text(k)+"="+v)
		}
	}
	return truncRunes(strings.Join(parts, "&"), maxQueryLen)
}
