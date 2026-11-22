package server

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

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

	body := red.Text(string(c.body))
	if len(body) > s.cfg.MaxLogBody {
		body = truncBytes(body, s.cfg.MaxLogBody)
		attrs["body_truncated"] = true
	}
	resource := truncRunes(red.Text(c.r.URL.Path), maxResourceLen)
	ua := truncRunes(red.Text(c.ua), maxUALen)

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
		Result:    resultFor(status),
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
