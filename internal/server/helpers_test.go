package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"attackbox/internal/responder"
	"attackbox/internal/telemetry"
)

const (
	testAddr = "192.0.2.10:5000"
	testUA   = "probe-test/1.0"
	chatBody = `{"model":"qwen3:8b","messages":[{"role":"user","content":"hello there"}]}`
)

var fixedNow = time.Unix(1760000000, 0).UTC()

type count struct {
	name  string
	value float64
	attrs map[string]string
}

// memSink records everything the server logs.
type memSink struct {
	mu     sync.Mutex
	events []telemetry.Event
	counts []count
}

func (m *memSink) Emit(e telemetry.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
}

func (m *memSink) Count(name string, v float64, attrs map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts = append(m.counts, count{name, v, attrs})
}

func (m *memSink) Gauge(string, float64, map[string]string) {}

func (m *memSink) stream(name string) []telemetry.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []telemetry.Event
	for _, e := range m.events {
		if e.Stream == name {
			out = append(out, e)
		}
	}
	return out
}

func (m *memSink) lastEdge(t *testing.T) telemetry.Event {
	t.Helper()
	ev := m.stream(telemetry.StreamEdge)
	if len(ev) == 0 {
		t.Fatal("no edge event")
	}
	return ev[len(ev)-1]
}

func (m *memSink) lastTranscript(t *testing.T) telemetry.Event {
	t.Helper()
	ev := m.stream(telemetry.StreamTranscript)
	if len(ev) == 0 {
		t.Fatal("no transcript event")
	}
	return ev[len(ev)-1]
}

// clock replaces Config.After. By default every wait ends at once; with a
// gate set, a wait lasts until the gate closes.
type clock struct {
	mu      sync.Mutex
	waits   []time.Duration
	gate    chan time.Time
	entered chan struct{}
}

func newClock() *clock { return &clock{entered: make(chan struct{}, 256)} }

func (c *clock) after(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	c.waits = append(c.waits, d)
	gate := c.gate
	c.mu.Unlock()
	select {
	case c.entered <- struct{}{}:
	default:
	}
	if gate != nil {
		return gate
	}
	ch := make(chan time.Time, 1)
	ch <- time.Time{}
	return ch
}

func (c *clock) setGate(g chan time.Time) {
	c.mu.Lock()
	c.gate = g
	c.mu.Unlock()
}

func (c *clock) recorded() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.waits...)
}

func (c *clock) waitEntered(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-c.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("request never reached its wait")
		}
	}
}

type rig struct {
	t     *testing.T
	srv   *Server
	h     http.Handler
	sink  *memSink
	clk   *clock
	store *responder.Store
}

func newRig(t *testing.T, persona string, mut ...func(*Config)) *rig {
	t.Helper()
	store := responder.NewStore(responder.StoreConfig{})
	r := &rig{t: t, sink: &memSink{}, clk: newClock(), store: store}
	cfg := Config{
		Persona:    persona,
		Responder:  responder.New(responder.Config{}, store),
		Sink:       r.sink,
		SessionKey: []byte("test-session-key"),
		EmbedSeed:  []byte("test-embed-seed"),
		Now:        func() time.Time { return fixedNow },
		After:      r.clk.after,
		HoldSilent: 100 * time.Millisecond,
	}
	for _, m := range mut {
		m(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.srv, r.h = srv, srv.Handler()
	return r
}

// request builds a request from a default source and agent; hdr is a list of
// name, value pairs that override the defaults.
func request(method, path, body string, hdr ...string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = testAddr
	req.Header.Set("User-Agent", testUA)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	return req
}

func (r *rig) do(method, path, body string, hdr ...string) *httptest.ResponseRecorder {
	return r.serve(request(method, path, body, hdr...))
}

func (r *rig) serve(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	return rec
}

// pin forces the behavioral gate of the default client session.
func (r *rig) pin(behavior string) {
	r.t.Helper()
	key := r.srv.sessionKey("192.0.2.10", testUA, http.Header{})
	sess, _ := r.store.Get(key)
	sess.Behavior = behavior
}

// warm sends the two registration requests that come before the behavioral gate.
func (r *rig) warm() {
	r.t.Helper()
	for i := 0; i < 2; i++ {
		if rec := r.do("POST", "/v1/chat/completions", chatBody); rec.Code != 200 {
			r.t.Fatalf("warm-up %d: status %d", i, rec.Code)
		}
	}
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body is not a JSON object: %v\n%s", err, rec.Body.String())
	}
	return m
}

func sub(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	v, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("%q is not an object in %v", key, m)
	}
	return v
}

func list(t *testing.T, m map[string]any, key string) []any {
	t.Helper()
	v, ok := m[key].([]any)
	if !ok {
		t.Fatalf("%q is not an array in %v", key, m)
	}
	return v
}

// sseBlock is one server-sent event.
type sseBlock struct {
	event string
	data  string
}

// parseSSE splits a stream into events and counts the comment keepalives.
func parseSSE(body string) (blocks []sseBlock, keepalives int) {
	for _, raw := range strings.Split(body, "\n\n") {
		if raw == "" {
			continue
		}
		var b sseBlock
		for _, line := range strings.Split(raw, "\n") {
			switch {
			case strings.HasPrefix(line, ":"):
				keepalives++
			case strings.HasPrefix(line, "event: "):
				b.event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				b.data = strings.TrimPrefix(line, "data: ")
			}
		}
		if b.data != "" || b.event != "" {
			blocks = append(blocks, b)
		}
	}
	return blocks, keepalives
}

func ndjsonLines(t *testing.T, body string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad NDJSON line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func withCancel(req *http.Request) (*http.Request, context.CancelFunc) {
	ctx, cancel := context.WithCancel(req.Context())
	return req.WithContext(ctx), cancel
}

func attr[T any](t *testing.T, e telemetry.Event, key string) T {
	t.Helper()
	v, ok := e.Attrs[key].(T)
	if !ok {
		t.Fatalf("attr %q = %#v, wrong type or missing", key, e.Attrs[key])
	}
	return v
}
