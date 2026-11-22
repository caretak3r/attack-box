package server

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
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
	var labels []string
	task, probeID, sessionID := "", "", c.sessionID
	if d := c.dec; d != nil {
		sessionID = d.SessionID
		task, probeID, labels = d.Class.Task, d.Probe.ID, d.Class.Labels
		attrs["task"] = task
	}

	attrs["direction"] = "request"
	body, cut := s.logBody(c.body, int64(len(c.body)))
	if cut {
		attrs["body_truncated"] = true
		// The keyed fingerprint of the whole body links repeats of one
		// oversized payload without logging the part past the cap.
		attrs["body_fingerprint"] = red.Fingerprint(string(c.body))
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
	if c.w.n > 0 {
		s.emitResponse(c, now, sessionID, ua, resource, result, status, probeID)
	}
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
	if c.dec != nil || len(c.obs) > 0 {
		s.emitProbe(c, now, sessionID, ua, resource, result, status)
	}
	route := telemetry.SafeLabels(map[string]string{"persona": s.persona, "endpoint": c.endpoint})
	s.cfg.Sink.Count("attackbox.requests", 1, telemetry.SafeLabels(map[string]string{
		"persona": s.persona, "endpoint": c.endpoint, "status_class": strconv.Itoa(status/100) + "xx",
	}))
	s.cfg.Sink.Count("attackbox.request_bytes", float64(len(c.body)), route)
	s.cfg.Sink.Count("attackbox.response_bytes", float64(c.w.n), route)
	if c.disconnected(status) {
		s.cfg.Sink.Gauge("attackbox.stream_disconnect_seconds", now.Sub(c.start).Seconds(), route)
	}
}

// disconnected reports whether the client left before the response ended.
func (c *call) disconnected(status int) bool {
	return status == 499 || c.holdResult == "client_closed" || c.streamCut == "client_closed"
}

// emitProbe writes the probe stream record: the gate issued, the session's
// behavioral gate and nonce, declarations, follow-up and concurrency
// observations, and hold, retry and disconnect timing. It also feeds the
// session and probe metrics, which carry only bounded labels.
func (s *Server) emitProbe(c *call, now time.Time, sessionID, ua, resource, result string, status int) {
	persona := telemetry.SafeLabels(map[string]string{"persona": s.persona})
	attrs := map[string]any{"route": c.endpoint}
	action, probeID := "status_hit", ""
	obs := c.obs
	if d := c.dec; d != nil {
		action, probeID = "decision", d.Probe.ID
		attrs["ticket"] = d.Ticket
		attrs["nonce"] = d.Nonce
		attrs["behavior"] = d.Behavior
		attrs["new_session"] = d.NewSession
		attrs["session_age_ms"] = d.SessionAge.Milliseconds()
		if d.Probe.Hold != "" {
			attrs["hold"] = d.Probe.Hold
		}
		if d.Probe.Status != 0 {
			attrs["probe_status"] = d.Probe.Status
			attrs["retry_after"] = d.Probe.RetryAfter
		}
		if len(d.Declarations) > 0 {
			attrs["declarations"] = d.Declarations
		}
		obs = append(append([]responder.Observation(nil), d.Observations...), obs...)
		if d.NewSession {
			s.cfg.Sink.Count("attackbox.sessions", 1, persona)
		}
		s.cfg.Sink.Gauge("attackbox.session_duration_seconds", d.SessionAge.Seconds(), persona)
	}
	for _, o := range obs {
		switch {
		case c.dec != nil && o.ProbeID == c.dec.Followup:
			attrs["followup"] = o.ProbeID
			s.cfg.Sink.Count("attackbox.probe_followups", 1, telemetry.SafeLabels(map[string]string{
				"persona": s.persona, "probe_id": o.ProbeID,
			}))
			if o.ProbeID == "retry" {
				s.cfg.Sink.Gauge("attackbox.retry_delay_seconds", float64(o.DelayMS)/1000, persona)
			}
		case o.ProbeID == "concurrency" && o.Result["active"] != "":
			if n, err := strconv.Atoi(o.Result["active"]); err == nil {
				s.cfg.Sink.Gauge("attackbox.concurrent_status_requests", float64(n), persona)
			}
		}
	}
	if len(obs) > 0 {
		attrs["observations"] = obs
	}
	if c.holdResult != "" {
		attrs["hold_result"] = c.holdResult
		attrs["hold_ms"] = c.holdMS
	}
	if c.streamCut != "" {
		attrs["stream_result"] = c.streamCut
	}
	if c.disconnected(status) {
		attrs["disconnect_ms"] = now.Sub(c.start).Milliseconds()
	}
	s.cfg.Sink.Emit(telemetry.Event{
		Timestamp: now,
		Stream:    telemetry.StreamProbe,
		SessionID: sessionID,
		RequestID: c.id,
		SrcIP:     c.src,
		UserAgent: ua,
		Persona:   s.persona,
		Action:    action,
		Resource:  resource,
		Result:    result,
		Status:    status,
		ProbeID:   probeID,
		Attrs:     attrs,
	})
}

// logRedactMargin is how far past MaxLogBody the redactor still looks. Redaction
// can shrink the text, so the cut before it keeps a little more than the cap.
const logRedactMargin = 4 << 10

// emitResponse writes the response body as its own edge event, so request and
// response each get the full MaxLogBody budget and their own chunk sequence.
func (s *Server) emitResponse(c *call, now time.Time, sessionID, ua, resource, result string, status int, probeID string) {
	body, cut := s.logBody(c.w.head, c.w.n)
	attrs := map[string]any{
		"route":          c.endpoint,
		"direction":      "response",
		"response_bytes": c.w.n,
	}
	if ct := c.w.Header().Get("Content-Type"); ct != "" {
		attrs["content_type"] = truncRunes(ct, 128)
	}
	if cut {
		attrs["body_truncated"] = true
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
}

// logRawLimit is how many raw body bytes a log event needs: MaxLogBody plus
// the redaction margin and a few spare bytes so the cut can back off to a
// rune start.
func (s *Server) logRawLimit() int {
	return s.cfg.MaxLogBody + logRedactMargin + utf8.UTFMax
}

// logBody returns the redacted body for the log, at most MaxLogBody bytes, and
// whether it was cut. b holds the first bytes of a body of total bytes; at
// least logRawLimit of them when the body is that long. The raw body is cut
// first so the redactor never scans a megabyte for a log line that keeps a
// fraction of it.
func (s *Server) logBody(b []byte, total int64) (string, bool) {
	limit := s.cfg.MaxLogBody
	keep := limit + logRedactMargin
	cut := total > int64(keep)
	var raw string
	if cut {
		raw = truncBytes(string(b[:min(len(b), s.logRawLimit())]), keep)
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
