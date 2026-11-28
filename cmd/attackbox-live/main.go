// attackbox-live serves a loopback dashboard of public gateway traffic.
// It reads capture files, OTLP traces, and shipper events over SSH or from
// a local archive. Captured text is data: parsed, bounded, kept in memory,
// and served as JSON to the web UI.
package main

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web
var webFS embed.FS

const (
	maxLineLength      = 128 << 10
	maxPreviewRuns     = 80
	feedSize           = 300
	flowSize           = 10
	timelineBuckets    = 60
	flowOtherSources   = "__other_sources__"
	flowOtherEndpoints = "__other_endpoints__"
)

type event struct {
	Time          time.Time   `json:"time"`
	Seq           uint64      `json:"seq"`
	Kind          string      `json:"kind"`
	Source        string      `json:"source"`
	Origin        string      `json:"origin"`
	IP            string      `json:"ip"`
	Port          int         `json:"port"`
	Route         string      `json:"route"`
	Method        string      `json:"method"`
	Target        string      `json:"target"`
	Host          string      `json:"host,omitempty"`
	UserAgent     string      `json:"user_agent"`
	Status        int         `json:"status"`
	Probe         string      `json:"probe"`
	Proto         string      `json:"proto,omitempty"`
	Headers       [][2]string `json:"headers,omitempty"`
	SNI           string      `json:"sni,omitempty"`
	Outcome       string      `json:"outcome,omitempty"`
	ContentType   string      `json:"content_type,omitempty"`
	Model         string      `json:"model,omitempty"`
	Stream        bool        `json:"stream,omitempty"`
	Tools         string      `json:"tools,omitempty"`
	SystemMsg     bool        `json:"system_msg,omitempty"`
	MCPMethod     string      `json:"mcp_method,omitempty"`
	CanaryKey     string      `json:"canary_key,omitempty"`
	Credential    string      `json:"credential,omitempty"`
	BodyBytes     int64       `json:"body_bytes"`
	BodySHA256    string      `json:"body_sha256,omitempty"`
	BodyTruncated bool        `json:"body_truncated,omitempty"`
	RuleName      string      `json:"rule_name,omitempty"`
	Priority      string      `json:"priority,omitempty"`
	BlockType     string      `json:"block_type,omitempty"`
	Body          string      `json:"body,omitempty"`
	Preview       string      `json:"preview"`
	HasPrompt     bool        `json:"has_prompt"`
	spanMerged    bool
}

func parseCapture(line []byte, port int) (event, bool) {
	var raw struct {
		Time          string      `json:"time"`
		Peer          string      `json:"peer"`
		Port          int         `json:"port"`
		Method        string      `json:"method"`
		Target        string      `json:"target"`
		Route         string      `json:"route"`
		Status        int         `json:"status"`
		Body          string      `json:"body"`
		BodyBytes     int64       `json:"body_bytes"`
		BodySHA256    string      `json:"body_sha256"`
		BodyTruncated bool        `json:"body_truncated"`
		Host          string      `json:"host"`
		UA            string      `json:"user_agent"`
		CT            string      `json:"content_type"`
		Probe         string      `json:"probe"`
		Proto         string      `json:"proto"`
		Headers       [][2]string `json:"headers"`
	}
	if err := json.Unmarshal(line, &raw); err != nil {
		return event{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, raw.Time)
	if err != nil {
		return event{}, false
	}
	if raw.Port != 0 {
		port = raw.Port
	}
	if raw.BodyBytes == 0 && raw.Body != "" {
		raw.BodyBytes = int64(len(raw.Body))
	}
	e := event{
		Time:          t,
		Kind:          "request",
		Source:        "capture",
		IP:            raw.Peer,
		Port:          port,
		Method:        raw.Method,
		Target:        raw.Target,
		Route:         raw.Route,
		Status:        raw.Status,
		Body:          raw.Body,
		BodyBytes:     raw.BodyBytes,
		BodySHA256:    raw.BodySHA256,
		BodyTruncated: raw.BodyTruncated,
		Host:          raw.Host,
		UserAgent:     raw.UA,
		ContentType:   raw.CT,
		Probe:         raw.Probe,
		Proto:         raw.Proto,
		Headers:       raw.Headers,
	}
	if raw.Body != "" {
		var obj map[string]any
		preview := raw.Body
		if json.Unmarshal([]byte(raw.Body), &obj) == nil {
			preview, e.HasPrompt = extractPreview(obj, raw.Target, raw.Body)
			if model, ok := obj["model"].(string); ok {
				e.Model = model
			}
			if stream, ok := obj["stream"].(bool); ok {
				e.Stream = stream
			}
			if tools, ok := obj["tools"].([]any); ok {
				var names []string
				for _, tool := range tools {
					if tm, ok := tool.(map[string]any); ok {
						if fn, ok := tm["function"].(map[string]any); ok {
							if name, ok := fn["name"].(string); ok {
								names = append(names, name)
							}
						} else if name, ok := tm["name"].(string); ok {
							names = append(names, name)
						}
					}
				}
				if len(names) > 0 {
					e.Tools = strings.Join(names, ",")
				}
			}
			if messages, ok := obj["messages"].([]any); ok {
				for _, message := range messages {
					if m, ok := message.(map[string]any); ok {
						if role, ok := m["role"].(string); ok && role == "system" {
							e.SystemMsg = true
							break
						}
					}
				}
			}
		}
		e.Preview = cleanPreview(preview)
	}
	return e, true
}

func parseOTLP(line []byte, port int) ([]event, bool) {
	var raw struct {
		ResourceSpans []struct {
			ScopeSpans []struct {
				Spans []struct {
					Name              string `json:"name"`
					StartTimeUnixNano string `json:"startTimeUnixNano"`
					Attributes        any    `json:"attributes"`
				} `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, false
	}
	var events []event
	for _, rs := range raw.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				attrs, ok := sp.Attributes.([]any)
				if !ok {
					return nil, false
				}
				m := make(map[string]string)
				for _, attr := range attrs {
					am, ok := attr.(map[string]any)
					if !ok {
						continue
					}
					key, _ := am["key"].(string)
					val, ok := am["value"].(map[string]any)
					if !ok {
						continue
					}
					if sv, ok := val["stringValue"].(string); ok {
						m[key] = sv
					} else if iv, ok := val["intValue"].(string); ok {
						m[key] = iv
					} else if bv, ok := val["boolValue"].(bool); ok {
						m[key] = strconv.FormatBool(bv)
					}
				}
				nano, _ := strconv.ParseInt(sp.StartTimeUnixNano, 10, 64)
				e := event{
					Time:   time.Unix(0, nano),
					Source: "otel",
					IP:     m["client.address"],
					Port:   port,
				}
				if parsedPort, _ := strconv.Atoi(m["server.port"]); parsedPort > 0 {
					e.Port = parsedPort
				}
				switch sp.Name {
				case "public.connection":
					e.Kind = "connection"
					e.Outcome = m["attackbox.connection.outcome"]
					e.SNI = m["attackbox.tls.sni"]
				case "public.request":
					e.Kind = "request"
					e.Route = m["http.route"]
					e.Method = m["http.request.method"]
					e.Status, _ = strconv.Atoi(m["http.response.status_code"])
					e.Model = m["gen_ai.request.model"]
					if e.Model == "" {
						e.Model = m["attackbox.model"]
					}
					e.Stream = m["attackbox.stream"] == "true"
					e.MCPMethod = m["attackbox.mcp.method"]
					e.CanaryKey = m["attackbox.canary.key"]
					e.Credential = m["attackbox.credential.value"]
				default:
					continue
				}
				events = append(events, e)
			}
		}
	}
	return events, true
}

func parseShipperEnvelope(line []byte) ([]event, bool) {
	var env struct {
		Ts   string `json:"ts"`
		Role string `json:"role"`
		Seq  int    `json:"seq"`
		Rec  struct {
			Event struct {
				Timestamp string `json:"timestamp"`
				Stream    string `json:"stream"`
				Action    string `json:"action"`
				Body      string `json:"body"`
				SrcIP     string `json:"src_ip"`
			} `json:"event"`
		} `json:"record"`
	}
	if err := json.Unmarshal(line, &env); err != nil {
		return nil, false
	}
	if env.Rec.Event.Stream == "heartbeat" {
		return []event{}, true
	}
	if env.Role == "bait" {
		t, _ := time.Parse(time.RFC3339, env.Rec.Event.Timestamp)
		return []event{{Time: t, Kind: "bait", Source: "shipper"}}, true
	}
	if env.Role == "runtime" && env.Rec.Event.Action == "falco" {
		body := strings.TrimPrefix(env.Rec.Event.Body, "base64:")
		data, _ := base64.StdEncoding.DecodeString(body)
		var falco struct {
			Rule   string `json:"rule"`
			Prio   string `json:"priority"`
			Fields struct {
				SIP string `json:"fd.sip"`
			} `json:"output_fields"`
		}
		if json.Unmarshal(data, &falco) == nil {
			t, _ := time.Parse(time.RFC3339, env.Rec.Event.Timestamp)
			return []event{{
				Time:     t,
				Kind:     "security",
				Source:   "shipper",
				IP:       falco.Fields.SIP,
				RuleName: falco.Rule,
				Priority: falco.Prio,
			}}, true
		}
	}
	if env.Role == "egress" && env.Rec.Event.Action == "egress_blocked" {
		body := strings.TrimPrefix(env.Rec.Event.Body, "base64:")
		data, _ := base64.StdEncoding.DecodeString(body)
		var jrnl struct {
			Msg string `json:"MESSAGE"`
		}
		if json.Unmarshal(data, &jrnl) == nil {
			msg := jrnl.Msg
			var ip, blockType, prio string
			if strings.Contains(msg, "METADATA-BLOCK") {
				blockType = "metadata"
			} else {
				blockType = "container_egress"
				if strings.Contains(msg, " SYN") {
					prio = "outbound"
				} else {
					prio = "reply"
				}
			}
			if idx := strings.Index(msg, "SRC="); idx >= 0 {
				rest := msg[idx+4:]
				if sp := strings.Index(rest, " "); sp > 0 {
					ip = rest[:sp]
				}
			}
			t, _ := time.Parse(time.RFC3339, env.Rec.Event.Timestamp)
			return []event{{
				Time:      t,
				Kind:      "security",
				Source:    "shipper",
				IP:        ip,
				RuleName:  "egress_block",
				Priority:  prio,
				BlockType: blockType,
			}}, true
		}
	}
	return nil, false
}

// Generic body previews remain visible, but only captured user input earns a prompt marker.
func extractPreview(obj map[string]any, target, body string) (string, bool) {
	if p, ok := obj["prompt"].(string); ok && strings.TrimSpace(p) != "" {
		return p, true
	}
	path, _, _ := strings.Cut(target, "?")
	responses := strings.HasSuffix(strings.TrimSuffix(path, "/"), "/responses")
	messages, _ := obj["messages"].([]any)
	if responses && len(messages) == 0 {
		messages, _ = obj["input"].([]any)
	}
	for i := len(messages) - 1; i >= 0; i-- {
		m, _ := messages[i].(map[string]any)
		if m["role"] != "user" {
			continue
		}
		switch content := m["content"].(type) {
		case string:
			if strings.TrimSpace(content) != "" {
				return content, true
			}
		case []any:
			var text strings.Builder
			for _, part := range content {
				p, _ := part.(map[string]any)
				if s, ok := p["text"].(string); ok && (p["type"] == "text" || p["type"] == "input_text") && strings.TrimSpace(s) != "" {
					if text.Len() > 0 {
						text.WriteByte(' ')
					}
					text.WriteString(s)
				}
			}
			if text.Len() > 0 {
				return text.String(), true
			}
		}
	}
	if s, ok := obj["input"].(string); ok {
		return s, responses && strings.TrimSpace(s) != ""
	}
	if s, ok := obj["text"].(string); ok {
		return s, false
	}
	if a, ok := obj["input"].([]any); ok && len(a) != 0 {
		if s, ok := a[0].(string); ok {
			return s, false
		}
	}
	return body, false
}

func cleanPreview(s string) string {
	n, last := 0, 0
	for i := range s {
		if n == maxPreviewRuns {
			return s[:last] + "…"
		}
		last = i
		n++
	}
	return s
}

type requestKey struct {
	ip     string
	port   int
	route  string
	second int64
}

type store struct {
	mu       sync.RWMutex
	events   []event
	requests map[requestKey][]int
	seq      uint64
	keep     int
	own      map[string]bool
	host     string
}

func newStore(keep int) *store {
	return &store{
		keep:     keep,
		own:      make(map[string]bool),
		requests: make(map[requestKey][]int),
	}
}

func (s *store) classifyOrigin(e event) string {
	switch {
	case strings.HasPrefix(e.IP, "127."), e.IP == "::1":
		return "test"
	case s.own[e.IP], e.IP == s.host:
		return "test"
	case strings.HasPrefix(e.UserAgent, "attackbox-deploy-test/"):
		return "test"
	case e.Kind == "bait", e.Kind == "security":
		return "test"
	default:
		return "internet"
	}
}

func mergeRequestSpan(capture *event, span event) {
	if span.Method != "" && capture.Method == "" {
		capture.Method = span.Method
	}
	if span.Status != 0 && capture.Status == 0 {
		capture.Status = span.Status
	}
	if span.Model != "" {
		capture.Model = span.Model
	}
	if span.MCPMethod != "" {
		capture.MCPMethod = span.MCPMethod
	}
	if span.CanaryKey != "" {
		capture.CanaryKey = span.CanaryKey
	}
	if span.Credential != "" {
		capture.Credential = span.Credential
	}
	capture.Stream = capture.Stream || span.Stream
}

func (s *store) rebuildRequestIndex() {
	s.requests = make(map[requestKey][]int)
	for i, e := range s.events {
		if e.Kind != "request" {
			continue
		}
		key := requestKey{ip: e.IP, port: e.Port, route: e.Route, second: e.Time.Unix()}
		s.requests[key] = append(s.requests[key], i)
	}
}

func (s *store) correlatedRequest(e event, source string) int {
	best := -1
	bestDelta := 2*time.Second + 1
	for offset := int64(-2); offset <= 2; offset++ {
		key := requestKey{ip: e.IP, port: e.Port, route: e.Route, second: e.Time.Unix() + offset}
		for _, i := range s.requests[key] {
			if i >= len(s.events) {
				continue
			}
			other := s.events[i]
			if other.Source != source || source == "capture" && other.spanMerged {
				continue
			}
			delta := e.Time.Sub(other.Time).Abs()
			if delta <= 2*time.Second && delta < bestDelta {
				best = i
				bestDelta = delta
			}
		}
	}
	return best
}

func (s *store) add(e event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !e.Time.IsZero() {
		e.Time = e.Time.UTC()
	}
	if e.Origin == "" {
		e.Origin = s.classifyOrigin(e)
	}
	if e.Kind == "request" && e.Source == "otel" {
		if i := s.correlatedRequest(e, "capture"); i >= 0 {
			mergeRequestSpan(&s.events[i], e)
			s.events[i].spanMerged = true
			return
		}
	}
	if e.Kind == "request" && e.Source == "capture" {
		if i := s.correlatedRequest(e, "otel"); i >= 0 {
			mergeRequestSpan(&e, s.events[i])
			e.spanMerged = true
			copy(s.events[i:], s.events[i+1:])
			s.events = s.events[:len(s.events)-1]
			s.rebuildRequestIndex()
		}
	}
	s.seq++
	e.Seq = s.seq
	s.events = append(s.events, e)
	if e.Kind == "request" {
		key := requestKey{ip: e.IP, port: e.Port, route: e.Route, second: e.Time.Unix()}
		s.requests[key] = append(s.requests[key], len(s.events)-1)
	}
	if len(s.events) > s.keep {
		copy(s.events, s.events[len(s.events)-s.keep:])
		s.events = s.events[:s.keep]
		s.rebuildRequestIndex()
	}
}

type sourceStatus struct {
	mu      sync.RWMutex
	capture string
	otel    string
	shipper string
	capLast time.Time
	otlLast time.Time
	shpLast time.Time
}

func (s *sourceStatus) set(src, state string, last time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch src {
	case "capture":
		s.capture = state
		if last.After(s.capLast) {
			s.capLast = last.UTC()
		}
	case "otel":
		s.otel = state
		if last.After(s.otlLast) {
			s.otlLast = last.UTC()
		}
	case "shipper":
		s.shipper = state
		if last.After(s.shpLast) {
			s.shpLast = last.UTC()
		}
	}
}

func (s *sourceStatus) get() map[string]map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]map[string]any{
		"capture": {"state": s.capture, "last": ""},
		"otel":    {"state": s.otel, "last": ""},
		"shipper": {"state": s.shipper, "last": ""},
	}
	if !s.capLast.IsZero() {
		out["capture"]["last"] = s.capLast.UTC().Format(time.RFC3339)
	}
	if !s.otlLast.IsZero() {
		out["otel"]["last"] = s.otlLast.UTC().Format(time.RFC3339)
	}
	if !s.shpLast.IsZero() {
		out["shipper"]["last"] = s.shpLast.UTC().Format(time.RFC3339)
	}
	return out
}

type viewState struct {
	Now             string                    `json:"now"`
	Since           string                    `json:"since"`
	InternetEvents  int                       `json:"internet_events"`
	TestEvents      int                       `json:"test_events"`
	InternetSources int                       `json:"internet_sources"`
	TestSources     int                       `json:"test_sources"`
	Sources         []map[string]any          `json:"sources"`
	Endpoints       []map[string]any          `json:"endpoints"`
	Ports           []map[string]any          `json:"ports"`
	Timeline        [][2]int                  `json:"timeline"`
	Flow            map[string]any            `json:"flow"`
	Feed            []event                   `json:"feed"`
	AIActivity      []map[string]any          `json:"ai_activity"`
	Chains          []map[string]any          `json:"chains"`
	HostSecurity    map[string]any            `json:"host_security"`
	TestEnv         map[string]any            `json:"test_env"`
	SourcesStatus   map[string]map[string]any `json:"sources_status"`
}

func (s *store) state(now time.Time, window time.Duration, who, ip, endpoint, q string, port int, ports []int, status *sourceStatus) viewState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cutoff := now.Add(-window)
	filtered := make([]event, 0)
	var internetEvents, testEvents, ownTraffic, privateBait int
	internetSources := make(map[string]bool)
	testSources := make(map[string]bool)
	query := strings.ToLower(q)
	for i := len(s.events) - 1; i >= 0; i-- {
		e := s.events[i]
		if e.Time.Before(cutoff) {
			continue
		}
		if ip != "" && e.IP != ip {
			continue
		}
		if port > 0 && e.Port != port {
			continue
		}
		if endpoint != "" && e.Route != endpoint {
			continue
		}
		if query != "" {
			hay := strings.ToLower(e.IP + " " + e.Target + " " + e.Route + " " + e.UserAgent + " " + strconv.Itoa(e.Status) + " " + e.Body)
			if !strings.Contains(hay, query) {
				continue
			}
		}
		if e.Kind == "request" || e.Kind == "connection" {
			if e.Origin == "internet" {
				internetEvents++
				if e.IP != "" {
					internetSources[e.IP] = true
				}
			} else {
				testEvents++
				ownTraffic++
				if e.IP != "" {
					testSources[e.IP] = true
				}
			}
		} else if e.Kind == "bait" && e.Origin == "test" {
			privateBait++
		}
		if who == "internet" && e.Origin != "internet" {
			continue
		}
		if (who == "test" || who == "own") && e.Origin != "test" {
			continue
		}
		filtered = append(filtered, e)
	}
	timeline := make([][2]int, timelineBuckets)
	for _, e := range filtered {
		if e.Kind != "request" && e.Kind != "connection" {
			continue
		}
		bucket := int(e.Time.Sub(cutoff) * timelineBuckets / window)
		if bucket >= timelineBuckets {
			bucket = timelineBuckets - 1
		}
		if e.Kind == "connection" {
			timeline[bucket][1]++
		} else {
			timeline[bucket][0]++
		}
	}
	feed := make([]event, 0, min(len(filtered), feedSize))
	for i := 0; i < len(filtered) && i < feedSize; i++ {
		e := filtered[i]
		e.Body = ""
		feed = append(feed, e)
	}
	srcAgg := make(map[string]map[string]any)
	for _, e := range filtered {
		if e.IP == "" {
			continue
		}
		if srcAgg[e.IP] == nil {
			srcAgg[e.IP] = map[string]any{
				"ip": e.IP, "own": e.Origin == "test", "count": 0, "last": e.Time, "ua": e.UserAgent,
			}
		}
		srcAgg[e.IP]["count"] = srcAgg[e.IP]["count"].(int) + 1
		if e.Origin == "test" {
			srcAgg[e.IP]["own"] = true
		}
		if e.Time.After(srcAgg[e.IP]["last"].(time.Time)) {
			srcAgg[e.IP]["last"] = e.Time
			if e.UserAgent != "" {
				srcAgg[e.IP]["ua"] = e.UserAgent
			}
		}
	}
	sources := make([]map[string]any, 0, len(srcAgg))
	for _, m := range srcAgg {
		sources = append(sources, m)
	}
	sort.Slice(sources, func(i, j int) bool {
		return sources[i]["count"].(int) > sources[j]["count"].(int)
	})
	epAgg := make(map[string]map[string]any)
	for _, e := range filtered {
		if e.Route == "" {
			continue
		}
		if epAgg[e.Route] == nil {
			epAgg[e.Route] = map[string]any{"route": e.Route, "count": 0, "last": e.Time, "endpoint": e.Route}
		}
		epAgg[e.Route]["count"] = epAgg[e.Route]["count"].(int) + 1
		if e.Time.After(epAgg[e.Route]["last"].(time.Time)) {
			epAgg[e.Route]["last"] = e.Time
		}
	}
	endpoints := make([]map[string]any, 0, len(epAgg))
	for _, m := range epAgg {
		endpoints = append(endpoints, m)
	}
	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i]["count"].(int) > endpoints[j]["count"].(int)
	})
	portAgg := make(map[int]map[string]any)
	for _, p := range ports {
		portAgg[p] = map[string]any{"port": p, "requests": 0, "connections": 0, "sources": 0, "last": time.Time{}}
	}
	portSources := make(map[int]map[string]bool)
	for _, e := range filtered {
		if portAgg[e.Port] == nil {
			continue
		}
		if e.Kind == "request" {
			portAgg[e.Port]["requests"] = portAgg[e.Port]["requests"].(int) + 1
		} else if e.Kind == "connection" {
			portAgg[e.Port]["connections"] = portAgg[e.Port]["connections"].(int) + 1
		}
		if e.IP != "" {
			if portSources[e.Port] == nil {
				portSources[e.Port] = make(map[string]bool)
			}
			portSources[e.Port][e.IP] = true
		}
		last, ok := portAgg[e.Port]["last"].(time.Time)
		if !ok || e.Time.After(last) {
			portAgg[e.Port]["last"] = e.Time
		}
	}
	for p, m := range portAgg {
		m["sources"] = len(portSources[p])
	}
	portsOut := make([]map[string]any, 0, len(portAgg))
	for _, m := range portAgg {
		portsOut = append(portsOut, m)
	}
	sort.Slice(portsOut, func(i, j int) bool {
		return portsOut[i]["port"].(int) < portsOut[j]["port"].(int)
	})
	rawFlow := make(map[[2]string]int)
	sourceCounts := make(map[string]int)
	targetCounts := make(map[string]int)
	for _, e := range filtered {
		if e.IP == "" || e.Route == "" {
			continue
		}
		rawFlow[[2]string{e.IP, e.Route}]++
		sourceCounts[e.IP]++
		targetCounts[e.Route]++
	}
	top := func(counts map[string]int) map[string]bool {
		ids := make([]string, 0, len(counts))
		for id := range counts {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool {
			if counts[ids[i]] != counts[ids[j]] {
				return counts[ids[i]] > counts[ids[j]]
			}
			return ids[i] < ids[j]
		})
		keep := make(map[string]bool, min(len(ids), flowSize))
		for _, id := range ids[:min(len(ids), flowSize)] {
			keep[id] = true
		}
		return keep
	}
	topSources, topTargets := top(sourceCounts), top(targetCounts)
	flowAgg := make(map[[2]string]int)
	for key, value := range rawFlow {
		if !topSources[key[0]] {
			key[0] = flowOtherSources
		}
		if !topTargets[key[1]] {
			key[1] = flowOtherEndpoints
		}
		flowAgg[key] += value
	}
	sourceNodeCounts := make(map[string]int)
	targetNodeCounts := make(map[string]int)
	links := make([]map[string]any, 0, len(flowAgg))
	for key, value := range flowAgg {
		sourceNodeCounts[key[0]] += value
		targetNodeCounts[key[1]] += value
		links = append(links, map[string]any{"source": key[0], "target": key[1], "value": value})
	}
	sort.Slice(links, func(i, j int) bool {
		if links[i]["value"].(int) != links[j]["value"].(int) {
			return links[i]["value"].(int) > links[j]["value"].(int)
		}
		return links[i]["source"].(string)+"\n"+links[i]["target"].(string) <
			links[j]["source"].(string)+"\n"+links[j]["target"].(string)
	})
	makeNodes := func(counts map[string]int, side, otherID, otherName string) []map[string]any {
		nodes := make([]map[string]any, 0, len(counts))
		for id, value := range counts {
			name := id
			isOther := id == otherID
			if isOther {
				name = otherName
			}
			nodes = append(nodes, map[string]any{
				"id": id, "name": name, "count": value, "side": side, "other": isOther,
			})
		}
		sort.Slice(nodes, func(i, j int) bool {
			if nodes[i]["other"].(bool) != nodes[j]["other"].(bool) {
				return !nodes[i]["other"].(bool)
			}
			if nodes[i]["count"].(int) != nodes[j]["count"].(int) {
				return nodes[i]["count"].(int) > nodes[j]["count"].(int)
			}
			return nodes[i]["name"].(string) < nodes[j]["name"].(string)
		})
		return nodes
	}
	nodes := makeNodes(sourceNodeCounts, "source", flowOtherSources, "other sources")
	nodes = append(nodes, makeNodes(targetNodeCounts, "target", flowOtherEndpoints, "other endpoints")...)
	flow := map[string]any{"nodes": nodes, "links": links}
	aiAgg := make(map[string]map[string]any)
	for _, e := range filtered {
		if e.Model == "" && !e.Stream && e.Tools == "" && !e.SystemMsg {
			continue
		}
		if aiAgg[e.IP] == nil {
			aiAgg[e.IP] = map[string]any{
				"ip": e.IP, "chat": 0, "gen": 0, "models": make(map[string]bool),
				"tools": make(map[string]bool), "has_system": false, "has_stream": false,
				"user_agents": make(map[string]bool),
			}
		}
		if strings.Contains(e.Route, "/chat/") || strings.Contains(e.Route, "/messages") {
			aiAgg[e.IP]["chat"] = aiAgg[e.IP]["chat"].(int) + 1
		} else if strings.Contains(e.Route, "/completions") || strings.Contains(e.Route, "/generate") {
			aiAgg[e.IP]["gen"] = aiAgg[e.IP]["gen"].(int) + 1
		}
		if e.Model != "" {
			aiAgg[e.IP]["models"].(map[string]bool)[e.Model] = true
		}
		if e.Tools != "" {
			for _, tool := range strings.Split(e.Tools, ",") {
				aiAgg[e.IP]["tools"].(map[string]bool)[tool] = true
			}
		}
		if e.SystemMsg {
			aiAgg[e.IP]["has_system"] = true
		}
		if e.Stream {
			aiAgg[e.IP]["has_stream"] = true
		}
		if e.UserAgent != "" {
			aiAgg[e.IP]["user_agents"].(map[string]bool)[e.UserAgent] = true
		}
	}
	aiActivity := make([]map[string]any, 0, len(aiAgg))
	for _, m := range aiAgg {
		models := make([]string, 0)
		for k := range m["models"].(map[string]bool) {
			models = append(models, k)
		}
		sort.Strings(models)
		tools := make([]string, 0)
		for k := range m["tools"].(map[string]bool) {
			tools = append(tools, k)
		}
		sort.Strings(tools)
		if len(tools) > 10 {
			tools = tools[:10]
		}
		uas := make([]string, 0)
		for k := range m["user_agents"].(map[string]bool) {
			uas = append(uas, k)
		}
		sort.Strings(uas)
		aiActivity = append(aiActivity, map[string]any{
			"ip":          m["ip"],
			"chat":        m["chat"],
			"gen":         m["gen"],
			"models":      models,
			"tools":       tools,
			"has_system":  m["has_system"],
			"has_stream":  m["has_stream"],
			"user_agents": uas,
		})
	}
	sort.Slice(aiActivity, func(i, j int) bool {
		return aiActivity[i]["chat"].(int)+aiActivity[i]["gen"].(int) >
			aiActivity[j]["chat"].(int)+aiActivity[j]["gen"].(int)
	})
	cd := newChainDetector()
	for _, e := range filtered {
		cd.add(e)
	}
	chains := cd.report()
	falcoRules := make(map[string]int)
	falcoPrios := make(map[string]int)
	egressBlocks := make(map[string]int)
	for _, e := range s.events {
		if e.Kind != "security" {
			continue
		}
		if e.Time.Before(cutoff) {
			continue
		}
		if e.RuleName != "" && e.RuleName != "egress_block" {
			falcoRules[e.RuleName]++
			if e.Priority != "" {
				falcoPrios[e.Priority]++
			}
		}
		if e.BlockType != "" {
			if e.BlockType == "container_egress" {
				if e.Priority == "reply" {
					egressBlocks["reply"]++
				} else {
					egressBlocks["container"]++
				}
			} else if e.BlockType == "metadata" {
				egressBlocks["metadata"]++
			} else if e.BlockType == "reply" {
				egressBlocks["reply"]++
			} else if e.BlockType == "container" {
				egressBlocks["container"]++
			}
		}
	}
	hostSec := map[string]any{
		"falco_rules":      falcoRules,
		"falco_priorities": falcoPrios,
		"egress_blocks":    egressBlocks,
	}
	testEnv := map[string]any{
		"own_traffic":  ownTraffic,
		"private_bait": privateBait,
	}
	return viewState{
		Now:             now.UTC().Format(time.RFC3339),
		Since:           cutoff.UTC().Format(time.RFC3339),
		InternetEvents:  internetEvents,
		TestEvents:      testEvents,
		InternetSources: len(internetSources),
		TestSources:     len(testSources),
		Sources:         sources,
		Endpoints:       endpoints,
		Ports:           portsOut,
		Timeline:        timeline,
		Flow:            flow,
		Feed:            feed,
		AIActivity:      aiActivity,
		Chains:          chains,
		HostSecurity:    hostSec,
		TestEnv:         testEnv,
		SourcesStatus:   status.get(),
	}
}

type chainDetector struct {
	chains map[string]map[string]map[string]time.Time
}

func newChainDetector() *chainDetector {
	return &chainDetector{chains: make(map[string]map[string]map[string]time.Time)}
}

func (c *chainDetector) add(e event) {
	key := e.IP
	if key == "" {
		return
	}
	if c.chains[key] == nil {
		c.chains[key] = make(map[string]map[string]time.Time)
	}
	if strings.HasPrefix(e.Route, "/api/v1/auths/signup") {
		if c.chains[key]["open_webui"] == nil {
			c.chains[key]["open_webui"] = make(map[string]time.Time)
		}
		c.chains[key]["open_webui"]["signup"] = e.Time
	}
	if strings.Contains(e.Route, "/tools/create") || strings.Contains(e.Route, "/functions/create") {
		if c.chains[key]["open_webui"] == nil {
			c.chains[key]["open_webui"] = make(map[string]time.Time)
		}
		c.chains[key]["open_webui"]["create"] = e.Time
	}
	if strings.Contains(e.Route, "/tools/") && strings.Contains(e.Route, "/delete") ||
		strings.Contains(e.Route, "/functions/") && strings.Contains(e.Route, "/delete") {
		if c.chains[key]["open_webui"] == nil {
			c.chains[key]["open_webui"] = make(map[string]time.Time)
		}
		c.chains[key]["open_webui"]["delete"] = e.Time
	}
	if e.MCPMethod == "initialize" {
		if c.chains[key]["mcp"] == nil {
			c.chains[key]["mcp"] = make(map[string]time.Time)
		}
		c.chains[key]["mcp"]["initialize"] = e.Time
	}
	if e.MCPMethod == "tools/list" {
		if c.chains[key]["mcp"] == nil {
			c.chains[key]["mcp"] = make(map[string]time.Time)
		}
		c.chains[key]["mcp"]["tools_list"] = e.Time
	}
	if e.MCPMethod == "tools/call" {
		if c.chains[key]["mcp"] == nil {
			c.chains[key]["mcp"] = make(map[string]time.Time)
		}
		c.chains[key]["mcp"]["tools_call"] = e.Time
	}
}

func (c *chainDetector) report() []map[string]any {
	var out []map[string]any
	for ip, kinds := range c.chains {
		for kind, steps := range kinds {
			if len(steps) == 0 {
				continue
			}
			var complete bool
			if kind == "open_webui" {
				_, hasSignup := steps["signup"]
				_, hasCreate := steps["create"]
				_, hasDelete := steps["delete"]
				complete = hasSignup && (hasCreate || hasDelete)
			} else if kind == "mcp" {
				_, hasInit := steps["initialize"]
				_, hasList := steps["tools_list"]
				_, hasCall := steps["tools_call"]
				complete = hasInit && hasList && hasCall
			}
			var stepList []map[string]any
			for name, t := range steps {
				stepList = append(stepList, map[string]any{"name": name, "time": t.UTC().Format(time.RFC3339)})
			}
			sort.Slice(stepList, func(i, j int) bool {
				return stepList[i]["time"].(string) < stepList[j]["time"].(string)
			})
			m := map[string]any{"kind": kind, "chain": kind, "ip": ip, "steps": stepList, "complete": complete}
			for name, t := range steps {
				m[name] = t.UTC().Format(time.RFC3339)
			}
			out = append(out, m)
		}
	}
	return out
}

func (s *store) event(seq uint64) (event, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].Seq == seq {
			return s.events[i], true
		}
	}
	return event{}, false
}

type capture struct {
	dir      string
	port     int
	lines    map[string]int
	lastTime time.Time
}

func (c *capture) read(ctx context.Context, st *store, day string, isTail bool) string {
	path := filepath.Join(c.dir, "capture-"+day+".jsonl")
	if isTail {
		return "pending"
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "missing"
		}
		return "error"
	}
	defer f.Close()
	skip := c.lines[day]
	var n int
	var last time.Time
	readLines(f, func(line []byte) {
		n++
		if n <= skip {
			return
		}
		if e, ok := parseCapture(line, c.port); ok {
			st.add(e)
			if e.Time.After(last) {
				last = e.Time
			}
		}
	})
	c.lines[day] = n
	c.lastTime = last
	if !last.IsZero() {
		return "ok"
	}
	return "no_data"
}

type otelSource struct {
	dir      string
	port     int
	lines    map[string]int
	lastTime time.Time
}

func (o *otelSource) read(ctx context.Context, st *store, day string, isTail bool) string {
	if isTail {
		return "pending"
	}
	if o.lines == nil {
		o.lines = make(map[string]int)
	}
	dir := filepath.Join(o.dir, "var/lib/attackbox-evidence/public-otel")
	var paths []string
	paths = append(paths, filepath.Join(dir, "traces.jsonl"))
	paths = append(paths, filepath.Join(dir, "traces-"+day+".jsonl"))
	var last time.Time
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		skip := o.lines[path]
		var n int
		readLines(f, func(line []byte) {
			n++
			if n <= skip {
				return
			}
			if events, ok := parseOTLP(line, o.port); ok {
				for _, e := range events {
					st.add(e)
					if e.Time.After(last) {
						last = e.Time
					}
				}
			}
		})
		f.Close()
		o.lines[path] = n
	}
	o.lastTime = last
	if !last.IsZero() {
		return "ok"
	}
	return "no_data"
}

type shipperSource struct {
	dir      string
	lines    map[string]int
	lastTime time.Time
}

func (s *shipperSource) read(ctx context.Context, st *store, day string, isTail bool) string {
	if isTail {
		return "pending"
	}
	if s.lines == nil {
		s.lines = make(map[string]int)
	}
	path := filepath.Join(s.dir, "var/lib/attackbox-evidence/shipper/events-"+day+".jsonl")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "missing"
		}
		return "error"
	}
	defer f.Close()
	skip := s.lines[day]
	var n int
	var last time.Time
	readLines(f, func(line []byte) {
		n++
		if n <= skip {
			return
		}
		if events, ok := parseShipperEnvelope(line); ok {
			for _, e := range events {
				st.add(e)
				if e.Time.After(last) {
					last = e.Time
				}
			}
		}
	})
	s.lines[day] = n
	s.lastTime = last
	if !last.IsZero() {
		return "ok"
	}
	return "no_data"
}

func readLines(r io.Reader, fn func([]byte)) error {
	sc := bufio.NewScanner(r)
	buf := make([]byte, maxLineLength)
	sc.Buffer(buf, maxLineLength*2)
	for sc.Scan() {
		line := make([]byte, len(sc.Bytes()))
		copy(line, sc.Bytes())
		fn(line)
	}
	return sc.Err()
}

func handler(st *store, allowedHosts map[string]bool, ports []int, status *sourceStatus) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		if !allowedHosts[r.Host] || r.Method != "GET" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		who := r.URL.Query().Get("who")
		if who == "" {
			who = "internet"
		}
		ip := r.URL.Query().Get("ip")
		endpoint := r.URL.Query().Get("endpoint")
		q := r.URL.Query().Get("q")
		port := 0
		if p := r.URL.Query().Get("port"); p != "" {
			port, _ = strconv.Atoi(p)
		}
		win := r.URL.Query().Get("window")
		if win == "" {
			win = "1h"
		}
		var window time.Duration
		switch win {
		case "15m":
			window = 15 * time.Minute
		case "1h":
			window = time.Hour
		case "6h":
			window = 6 * time.Hour
		case "24h":
			window = 24 * time.Hour
		case "7d":
			window = 7 * 24 * time.Hour
		default:
			window = time.Hour
		}
		state := st.state(time.Now(), window, who, ip, endpoint, q, port, ports, status)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state)
	})
	mux.HandleFunc("/api/event", func(w http.ResponseWriter, r *http.Request) {
		if !allowedHosts[r.Host] || r.Method != "GET" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		seq, _ := strconv.ParseUint(r.URL.Query().Get("seq"), 10, 64)
		e, ok := st.event(seq)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(e)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !allowedHosts[r.Host] || r.Method != "GET" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		path = "web" + path
		data, err := webFS.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		ct := "text/plain"
		if strings.HasSuffix(path, ".html") {
			ct = "text/html"
		} else if strings.HasSuffix(path, ".js") {
			ct = "application/javascript"
		} else if strings.HasSuffix(path, ".css") {
			ct = "text/css"
		}
		w.Header().Set("Content-Type", ct)
		if ct == "text/html" {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
		}
		w.Write(data)
	})
	return mux
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8765", "loopback listen address")
	ssh := flag.String("ssh", "attackbox", "SSH alias")
	dir := flag.String("dir", "", "local archive root")
	days := flag.Int("days", 2, "days of history")
	ownFlag := flag.String("own", "", "comma-separated own addresses")
	portsFlag := flag.String("ports", "80,443,1234,3000,4000,8000,8080,8188,8888,11434", "listener ports")
	keep := flag.Int("keep", 200000, "events to keep")
	flag.Parse()

	if !strings.HasPrefix(*listen, "127.") && !strings.HasPrefix(*listen, "[::1]") {
		log.Fatal("listen must be loopback")
	}

	var ports []int
	for _, p := range strings.Split(*portsFlag, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n > 0 && n < 65536 {
			ports = append(ports, n)
		}
	}

	st := newStore(*keep)
	for _, a := range strings.Split(*ownFlag, ",") {
		a = strings.TrimSpace(a)
		if a != "" {
			st.own[a] = true
		}
	}

	if *dir == "" && *ssh != "" {
		cmd := exec.Command("ssh", *ssh, "echo ${SSH_CLIENT%% *}")
		if out, err := cmd.Output(); err == nil {
			egress := strings.TrimSpace(string(out))
			if egress != "" {
				st.own[egress] = true
			}
		}
		cmd = exec.Command("ssh", "-G", *ssh)
		if out, err := cmd.Output(); err == nil {
			sc := bufio.NewScanner(bytes.NewReader(out))
			for sc.Scan() {
				line := sc.Text()
				if strings.HasPrefix(line, "hostname ") {
					st.host = strings.TrimSpace(strings.TrimPrefix(line, "hostname "))
					break
				}
			}
		}
	}

	status := &sourceStatus{}
	if *dir != "" {
		var daysToRead []string
		for i := range *days {
			daysToRead = append(daysToRead, time.Now().UTC().AddDate(0, 0, -i).Format("20060102"))
		}
		c := &capture{
			dir:   filepath.Join(*dir, "var/lib/attackbox-public-capture/requests"),
			port:  443,
			lines: make(map[string]int),
		}
		for _, day := range daysToRead {
			if c.read(context.Background(), st, day, false) == "ok" {
				status.set("capture", "following", c.lastTime)
			}
		}
		o := &otelSource{dir: *dir, port: 443}
		for _, day := range daysToRead {
			if o.read(context.Background(), st, day, false) == "ok" {
				status.set("otel", "following", o.lastTime)
			}
		}
		s := &shipperSource{dir: *dir}
		for _, day := range daysToRead {
			if s.read(context.Background(), st, day, false) == "ok" {
				status.set("shipper", "following", s.lastTime)
			}
		}
	}

	allowedHosts := map[string]bool{*listen: true}
	srv := &http.Server{Addr: *listen, Handler: handler(st, allowedHosts, ports, status)}

	go func() {
		log.Printf("Listening on http://%s/", *listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	<-ctx.Done()
	srv.Shutdown(context.Background())
}
