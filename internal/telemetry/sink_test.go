package telemetry

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type recorder struct {
	events []Event
	counts []string
}

func (r *recorder) Emit(e Event) { r.events = append(r.events, e) }
func (r *recorder) Count(n string, _ float64, _ map[string]string) {
	r.counts = append(r.counts, "c:"+n)
}
func (r *recorder) Gauge(n string, _ float64, _ map[string]string) {
	r.counts = append(r.counts, "g:"+n)
}

func TestMulti(t *testing.T) {
	a, b := &recorder{}, &recorder{}
	m := Multi{a, b}
	m.Emit(Event{Action: "x"})
	m.Count("n", 1, nil)
	m.Gauge("g", 1, nil)
	for _, r := range []*recorder{a, b} {
		if len(r.events) != 1 || len(r.counts) != 2 {
			t.Errorf("fan-out incomplete: %+v", r)
		}
	}
}

func TestSafeLabels(t *testing.T) {
	got := SafeLabels(map[string]string{
		"persona": "openai", "probe_id": "Bad Value!", "endpoint": "/v1/chat/completions",
		"status_class": "4xx", "src_ip": "1.2.3.4", "session_id": "abc", "task": "",
		"stream": "edge", "result": "ok", "reason": strings.Repeat("a", 49),
	})
	want := map[string]string{
		"persona": "openai", "probe_id": "other", "endpoint": "/v1/chat/completions",
		"status_class": "4xx", "task": "other", "stream": "edge", "result": "ok", "reason": "other",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestSafeLabelsEndpointAndStatus(t *testing.T) {
	cases := map[string]map[string]string{
		"endpoint": {
			"/v1/models/{id}":             "/v1/models/{id}",
			"/v1/models/12345":            "other",
			"/v1/models/gpt?x=1":          "other",
			"v1/models":                   "other",
			"/" + strings.Repeat("a", 70): "other",
		},
		"status_class": {"2xx": "2xx", "5xx": "5xx", "6xx": "other", "200": "other", "0xx": "other"},
	}
	for k, vs := range cases {
		for in, want := range vs {
			if got := SafeLabels(map[string]string{k: in})[k]; got != want {
				t.Errorf("%s %q = %q, want %q", k, in, got, want)
			}
		}
	}
}

func TestJSONLog(t *testing.T) {
	var buf bytes.Buffer
	l := NewJSONLog(&buf)
	l.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	l.Emit(Event{Stream: StreamEdge, SessionID: "s1", Body: strings.Repeat("\u4e16", 7001)})
	l.Count("attackbox.requests_total", 2, map[string]string{"persona": "vllm", "src_ip": "9.9.9.9"})
	l.Gauge("attackbox.heartbeat", 1, nil)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("lines = %d: %s", len(lines), buf.String())
	}
	var sha string
	for i, line := range lines[:3] {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line %d invalid: %v", i, err)
		}
		if m["chunk_index"] != float64(i) || m["chunk_count"] != float64(3) {
			t.Errorf("line %d chunk fields: %v", i, m)
		}
		if i == 0 {
			sha = m["body_sha256"].(string)
		} else if m["body_sha256"] != sha {
			t.Error("sha differs across chunks")
		}
		if m["timestamp"] != "2026-01-02T03:04:05Z" || m["session_id"] != "s1" {
			t.Errorf("line %d: %v", i, m)
		}
	}
	var metric map[string]any
	json.Unmarshal([]byte(lines[3]), &metric)
	attrs := metric["attrs"].(map[string]any)
	if metric["stream"] != "metric" || metric["type"] != "count" || metric["value"] != float64(2) ||
		len(attrs) != 1 || attrs["persona"] != "vllm" {
		t.Errorf("metric line = %v", metric)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, bytes.ErrTooLarge }

func TestJSONLogWriteError(t *testing.T) {
	l := NewJSONLog(failWriter{})
	var got error
	l.OnError = func(err error) { got = err }
	l.Emit(Event{Action: "x"})
	if got == nil {
		t.Error("write error not reported")
	}
}

func TestJSONLogEncodeFailureWritesMarker(t *testing.T) {
	var buf bytes.Buffer
	l := NewJSONLog(&buf)
	var seen int
	l.OnError = func(error) { seen++ }
	l.Emit(Event{Stream: StreamEdge, Action: "x", Attrs: map[string]any{"bad": make(chan int)}})
	l.Emit(Event{Stream: StreamEdge, Action: "after"})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d: %s", len(lines), buf.String())
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("marker line invalid: %v: %s", err, lines[0])
	}
	if m["event"] != "log_encode_error" || m["stream"] != StreamEdge || m["error"] == nil || m["timestamp"] == nil {
		t.Errorf("marker = %v", m)
	}
	if l.Errors() != 1 || seen != 1 {
		t.Errorf("errors=%d seen=%d", l.Errors(), seen)
	}
}

func TestJSONLogCountsWriteErrors(t *testing.T) {
	l := NewJSONLog(failWriter{})
	var seen int
	l.OnError = func(error) { seen++ }
	l.Emit(Event{Action: "x"})
	l.Count("attackbox.requests", 1, nil)
	if l.Errors() != 2 || seen != 2 {
		t.Errorf("errors=%d seen=%d", l.Errors(), seen)
	}
}

func TestSafeLabelsAllKeys(t *testing.T) {
	cases := []struct {
		key  string
		good []string
		bad  []string
	}{
		{
			key:  "persona",
			good: []string{"openai", "anthropic", "gemini", "test-persona"},
			bad:  []string{"", "OPENAI", "Open AI", strings.Repeat("a", 49), "open.ai", "open/ai"},
		},
		{
			key:  "probe_id",
			good: []string{"timeout-silent", "prompt-extraction", "test-123"},
			bad:  []string{"", "Bad Value!", "probe ID", strings.Repeat("a", 49), "probe.id", "probe/id"},
		},
		{
			key:  "task",
			good: []string{"credential-access", "shell-execution", "test_task"},
			bad:  []string{"", "TASK", "task name", strings.Repeat("a", 49), "task.name", "task/name"},
		},
		{
			key:  "stream",
			good: []string{"edge", "probe", "runtime", "egress", "heartbeat", "transcript"},
			bad:  []string{"", "EDGE", "edge stream", strings.Repeat("a", 49), "edge.stream"},
		},
		{
			key:  "result",
			good: []string{"ok", "error", "timeout", "test-result"},
			bad:  []string{"", "OK", "result value", strings.Repeat("a", 49), "result.value"},
		},
		{
			key:  "reason",
			good: []string{"timeout", "error", "rejected", "test-reason"},
			bad:  []string{"", "TIMEOUT", "timeout reason", strings.Repeat("a", 49), "reason.value"},
		},
	}

	for _, c := range cases {
		for _, good := range c.good {
			got := SafeLabels(map[string]string{c.key: good})
			if got[c.key] != good {
				t.Errorf("%s %q = %q, want %q", c.key, good, got[c.key], good)
			}
		}
		for _, bad := range c.bad {
			got := SafeLabels(map[string]string{c.key: bad})
			if got[c.key] != "other" {
				t.Errorf("%s %q = %q, want %q", c.key, bad, got[c.key], "other")
			}
		}
	}
}
