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
	"attackbox/internal/secret"
	"attackbox/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	maxResourceLen = 256
	maxQueryLen    = 512
	maxUALen       = 512
	maxModelLog    = 128
)

// finish writes the edge and transcript events and the request counters.
func (s *Server) finish(c *call) {
	c.endEvidence()
	status := c.w.status
	if status == 0 {
		status = 499 // the client left before any response bytes
	}
	span := trace.SpanFromContext(c.r.Context())
	span.SetAttributes(attribute.String("http.route", c.endpoint), attribute.Int("http.response.status_code", status))
	if status >= 500 || c.panicked {
		span.SetStatus(codes.Error, "handler_error")
	}
	red := s.cfg.Redactor
	now := s.cfg.Now()
	headers, creds := red.Headers(c.r.Header)

	attrs := map[string]any{
		"route":                   c.endpoint,
		"headers":                 headers,
		"credential_fingerprints": creds,
		"observed_bytes":          len(c.body),
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
	if n, ok := c.declaredBytes(); ok {
		attrs["declared_bytes"] = n
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
	pv := s.preview(c.body, int64(len(c.body)))
	attrs["capture_state"] = c.captureState(pv.cut)
	attrs["parse_state"] = c.parse.name()
	attrs["captured_bytes"] = len(pv.text)
	attrs["body_utf8_replaced"] = pv.replaced
	attrs["redactions"] = pv.redactions
	if pv.cut {
		attrs["body_truncated"] = true
	}
	if len(c.body) > 0 {
		// The keyed fingerprint of every byte read links repeats of one
		// payload without logging the part past the cap.
		attrs["input_fp"] = red.FingerprintBytes(c.body)
		attrs["input_fp_scope"] = "full"
		if c.read == readLimit || c.read == readError {
			attrs["input_fp_scope"] = "prefix"
		}
	}
	resource := truncRunes(red.Text(c.r.URL.Path), maxResourceLen)
	ua := truncRunes(red.Text(c.ua), maxUALen)
	result := resultFor(status)
	if c.holdResult == holdServerShutdown || c.streamCut == holdServerShutdown {
		result = holdServerShutdown
	}

	c.emit(telemetry.Event{
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
		Body:      pv.text,
	})
	if c.w.n > 0 {
		s.emitResponse(c, now, sessionID, ua, resource, result, status, probeID)
	}
	if c.dec != nil {
		c.emit(telemetry.Event{
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
		if d.Issuance != nil {
			// What the server wrote, not what the client read.
			attrs["issuance"] = d.Issuance.ID
			attrs["delivery"] = string(d.Issuance.State())
		}
		if d.IssuancesEvicted > 0 {
			attrs["issuance_evicted"] = d.IssuancesEvicted
		}
		if d.IssuancesLost > 0 {
			attrs["issuance_lost"] = d.IssuancesLost
		}
		if c.termFailed {
			// The content was accepted; only the closing frame failed.
			attrs["terminal_frame"] = "failed"
		}
		if len(d.CanariesIssued) > 0 {
			attrs["canaries_issued"] = d.CanariesIssued
		}
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
		attrs["canary_credential_presented"] = canaryCredentialPresented(obs)
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
	c.emit(telemetry.Event{
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

// A scalar alert field avoids JSON-array path assumptions in the log backend.
// History copies and undelivered canaries do not prove credential presentation.
func canaryCredentialPresented(obs []responder.Observation) int {
	for _, o := range obs {
		if o.ProbeID != "canary-reuse" {
			continue
		}
		for _, key := range []string{"url_password", "two_part", "three_part", "payout"} {
			for _, state := range strings.Split(o.Result[key], ",") {
				if state == "credential_presented" {
					return 1
				}
			}
		}
	}
	return 0
}

// logRedactMargin is how far past MaxLogBody the redactor still looks. Redaction
// can shrink the text, so the cut before it keeps a little more than the cap.
const logRedactMargin = 4 << 10

// emitResponse writes the response body as its own edge event, so request and
// response each get the full MaxLogBody budget and their own chunk sequence.
func (s *Server) emitResponse(c *call, now time.Time, sessionID, ua, resource, result string, status int, probeID string) {
	pv := s.preview(c.w.head, c.w.n)
	attrs := map[string]any{
		"route":              c.endpoint,
		"direction":          "response",
		"response_bytes":     c.w.n,
		"capture_state":      "complete",
		"captured_bytes":     len(pv.text),
		"body_utf8_replaced": pv.replaced,
		"redactions":         pv.redactions,
	}
	if ct := c.w.Header().Get("Content-Type"); ct != "" {
		attrs["content_type"] = truncRunes(ct, 128)
	}
	if pv.cut {
		attrs["capture_state"] = "log_prefix"
		attrs["body_truncated"] = true
	}
	c.emit(telemetry.Event{
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
		Body:      pv.text,
	})
}

// captureState says how much of the request body the record holds. The read
// outcome decides it; the preview only tells a complete body from a prefix
// that the log limit cut.
func (c *call) captureState(cut bool) string {
	switch c.read {
	case readNone:
		return "none"
	case readLimit:
		return "body_limit_exceeded"
	case readError:
		return "read_error"
	case readDone:
		if cut {
			return "log_prefix"
		}
		return "complete"
	}
	return "not_read"
}

// declaredBytes is the length the client claimed, when it claimed one: a
// Content-Length greater than zero, or an explicit Content-Length of zero. A
// chunked body, or no header at all, claims nothing.
func (c *call) declaredBytes() (int64, bool) {
	n := c.r.ContentLength
	if n > 0 {
		return n, true
	}
	_, sent := c.r.Header["Content-Length"]
	return 0, n == 0 && sent
}

// logRawLimit is how many raw body bytes a log event needs: MaxLogBody plus
// the redaction margin and a few spare bytes so the cut can back off to a
// rune start.
func (s *Server) logRawLimit() int {
	return s.cfg.MaxLogBody + logRedactMargin + utf8.UTFMax
}

// preview is the log text of one body and what the transform did to it.
type preview struct {
	text       string
	cut        bool // text is a prefix of the redacted body
	replaced   bool // invalid UTF-8 in the scanned part became U+FFFD
	redactions int  // replacements the scrubber made in the scanned part
}

// preview turns a body into its log text, at most MaxLogBody bytes. b holds
// the first bytes of a body of total bytes; at least logRawLimit of them when
// the body is that long. The raw body is cut first, on a rune start, so the
// redactor never scans a megabyte for a log line that keeps a fraction of it
// and a cut rune is not counted as malformed. Invalid UTF-8 is replaced
// before the redactor runs, and the limit applies to the final text.
func (s *Server) preview(b []byte, total int64) preview {
	limit := s.cfg.MaxLogBody
	keep := limit + logRedactMargin
	p := preview{cut: total > int64(keep)}
	var raw string
	if p.cut {
		raw = truncBytes(string(b[:min(len(b), s.logRawLimit())]), keep)
	} else {
		raw = string(b)
	}
	if !utf8.ValidString(raw) {
		raw, p.replaced = strings.ToValidUTF8(raw, "�"), true
	}
	p.text, p.redactions = s.cfg.Redactor.TextCount(raw)
	if len(p.text) > limit {
		p.text, p.cut = truncBytes(p.text, limit), true
	}
	return p
}

// logBody returns the preview text and whether it was cut.
func (s *Server) logBody(b []byte, total int64) (string, bool) {
	p := s.preview(b, total)
	return p.text, p.cut
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

const (
	maxQueryParams = 64
	maxQueryValue  = 512
	truncatedMark  = "[truncated]"
)

// sensitiveParam judges a query key like a JSON or header key, plus the
// substring list for names the classifier does not split (apikeyfoo).
func sensitiveParam(name string) bool {
	if secret.IsCredentialName(name) {
		return true
	}
	lk := strings.ToLower(name)
	for _, f := range sensitiveQuery {
		if strings.Contains(lk, f) {
			return true
		}
	}
	return false
}

// redactQuery masks the value of credential-looking parameters and scrubs the
// rest with the body redactor. Parameter count and value size are capped
// before scrubbing so a hostile query cannot make the scrub expensive.
func (s *Server) redactQuery(raw string) string {
	if raw == "" {
		return ""
	}
	red := s.cfg.Redactor
	vals, err := url.ParseQuery(raw)
	if err != nil && len(vals) == 0 {
		return capQuery(red.Text(truncBytes(raw, 4*maxQueryLen)))
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		sensitive := sensitiveParam(k)
		name := red.Text(truncBytes(k, maxQueryValue))
		for _, v := range vals[k] {
			if len(parts) == maxQueryParams {
				parts = append(parts, truncatedMark)
				return capQuery(strings.Join(parts, "&"))
			}
			switch {
			case sensitive:
				v = "[redacted:" + red.Fingerprint(v) + "]"
			case len(v) > maxQueryValue:
				v = red.Text(truncBytes(v, maxQueryValue)) + truncatedMark
			default:
				v = red.Text(v)
			}
			parts = append(parts, name+"="+v)
		}
	}
	return capQuery(strings.Join(parts, "&"))
}

// capQuery bounds the logged query and says so when it cuts.
func capQuery(q string) string {
	if c := truncRunes(q, maxQueryLen); c != q {
		return c + truncatedMark
	}
	return q
}
