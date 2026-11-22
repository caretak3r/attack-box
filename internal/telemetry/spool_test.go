package telemetry

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// spoolListener accepts unix connections and collects every line written.
type spoolListener struct {
	path  string
	ln    net.Listener
	lines chan string
	conns chan net.Conn
}

func newSpoolListener(t *testing.T) *spoolListener {
	t.Helper()
	// t.TempDir paths on macOS exceed sun_path, so use a short directory.
	dir, err := os.MkdirTemp("", "abx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	l := &spoolListener{path: filepath.Join(dir, "s.sock"), lines: make(chan string, 1024), conns: make(chan net.Conn, 16)}
	l.ln, err = net.Listen("unix", l.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.ln.Close() })
	go func() {
		for {
			c, err := l.ln.Accept()
			if err != nil {
				return
			}
			l.conns <- c
			go func() {
				r := bufio.NewReader(c)
				for {
					s, err := r.ReadString('\n')
					if err != nil {
						return
					}
					l.lines <- s
				}
			}()
		}
	}()
	return l
}

func (l *spoolListener) next(t *testing.T) Record {
	t.Helper()
	select {
	case s := <-l.lines:
		var r Record
		dec := json.NewDecoder(strings.NewReader(s))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("bad line %q: %v", s, err)
		}
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no spool line")
	}
	return Record{}
}

func closeSpool(t *testing.T, s *Spool) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.Close(ctx)
}

func TestSpoolRoundTrip(t *testing.T) {
	l := newSpoolListener(t)
	at := time.Date(2026, 11, 21, 10, 0, 0, 123456789, time.UTC)
	s, err := NewSpool(SpoolConfig{Socket: l.path, Heartbeat: -1, Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("ünïcødé <b>&", 1000) // > 10 KiB, would be 4 chunks
	want := Event{
		Timestamp: at.Add(-time.Second), Stream: StreamEdge, SessionID: "s1", RequestID: "r1",
		Persona: "openai", Action: "POST /v1/chat/completions", Status: 200, ProbeID: "p1",
		TaskLabels: []string{"a"}, Attrs: map[string]any{"direction": "request", "nested": map[string]any{"k": []any{"v", 1.5}}},
		Body: body,
	}
	sent := want
	sent.BodySHA256, sent.ChunkIndex, sent.ChunkCount = "forged", 3, 9 // a caller cannot claim chunk provenance
	s.Emit(sent)
	s.Count("attackbox.requests", 2, map[string]string{"persona": "openai", "src_ip": "203.0.113.9"})
	s.Gauge("attackbox.sessions", math.Inf(1), nil) // +Inf: skipped, takes no seq
	s.Gauge("attackbox.sessions", 7, nil)
	if err := closeSpool(t, s); err != nil {
		t.Fatal(err)
	}

	r := l.next(t)
	if r.ID != s.Boot()+"-1" || len(s.Boot()) != 16 || r.Metric != nil || r.Event == nil {
		t.Fatalf("record 1 = %+v", r)
	}
	got := *r.Event
	if !got.Timestamp.Equal(want.Timestamp) {
		t.Errorf("timestamp %v, want %v", got.Timestamp, want.Timestamp)
	}
	got.Timestamp = want.Timestamp
	if !reflect.DeepEqual(got, want) {
		t.Errorf("event did not round-trip:\n got %+v\nwant %+v", got, want)
	}
	r = l.next(t)
	wantM := &MetricRecord{Name: "attackbox.requests", Kind: "count", Value: 2, At: at, Attrs: map[string]string{"persona": "openai"}}
	if r.ID != s.Boot()+"-2" || !reflect.DeepEqual(r.Metric, wantM) {
		t.Errorf("record 2 = %s %+v, want %+v (src_ip must not survive SafeLabels)", r.ID, r.Metric, wantM)
	}
	r = l.next(t)
	if r.ID != s.Boot()+"-3" || r.Metric == nil || r.Metric.Kind != "gauge" || r.Metric.Value != 7 {
		t.Errorf("record 3 = %s %+v", r.ID, r.Metric)
	}
	if st := s.Stats(); st.Written != 3 || st.Dropped != 0 || st.Lost != 0 {
		t.Errorf("stats = %+v", st)
	}
}

// newIdleSpool builds a Spool with no writer, so put's admission is tested
// without a race against delivery.
func newIdleSpool(cfg SpoolConfig) *Spool {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Spool{cfg: cfg, boot: "0123456789abcdef", queue: make(chan []byte, cfg.QueueSize)}
}

func TestSpoolAdmissionBounds(t *testing.T) {
	at := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	now := func() time.Time { return at }
	// Measure one line of each kind, then set the budget to fit exactly two
	// events and one metric.
	probe := newIdleSpool(SpoolConfig{QueueSize: 2, QueueBytes: 1 << 20, MaxRecord: 1 << 20, Now: now})
	probe.Emit(Event{Stream: StreamEdge, Body: strings.Repeat("y", 200)})
	probe.Count("attackbox.requests", 1, nil)
	ev, met := len(<-probe.queue), len(<-probe.queue)
	if ev <= met {
		t.Fatalf("event line %d must be longer than metric line %d", ev, met)
	}
	budget := 2*ev + met
	s := newIdleSpool(SpoolConfig{QueueSize: 3, QueueBytes: budget, MaxRecord: ev + 50, Now: now})
	s.Emit(Event{Stream: StreamEdge, Body: strings.Repeat("x", 500)}) // seq 1: oversize
	s.Emit(Event{Stream: StreamEdge, Body: strings.Repeat("y", 200)}) // seq 2: queued
	s.Emit(Event{Stream: StreamEdge, Body: strings.Repeat("z", 200)}) // seq 3: queued
	s.Emit(Event{Stream: StreamEdge, Body: strings.Repeat("w", 200)}) // seq 4: over the byte budget
	s.Count("attackbox.requests", 1, nil)                             // seq 5: queued, small
	s.Count("attackbox.requests", 1, nil)                             // seq 6: queue full by count
	st := s.Stats()
	if st.Dropped != 3 || st.Oversize != 1 || len(s.queue) != 3 {
		t.Fatalf("stats = %+v, queued %d", st, len(s.queue))
	}
	var total int64
	var ids []string
	for range 3 {
		line := <-s.queue
		total += int64(len(line))
		if len(line) > s.cfg.MaxRecord || line[len(line)-1] != '\n' {
			t.Errorf("line of %d bytes breaks the record bound", len(line))
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.ID)
	}
	if got := strings.Join(ids, ","); got != "0123456789abcdef-2,0123456789abcdef-3,0123456789abcdef-5" {
		t.Errorf("ids = %s; dropped records must still take a seq so the shipper sees the gap", got)
	}
	if s.bytes.Load() != total || total != int64(budget) {
		t.Errorf("accounted %d bytes, queued %d (budget %d)", s.bytes.Load(), total, budget)
	}

	s.Emit(Event{Stream: StreamEdge, Attrs: map[string]any{"bad": make(chan int)}}) // unencodable
	if st := s.Stats(); st.Dropped != 4 || st.Errors != 1 {
		t.Errorf("unencodable event: %+v", st)
	}
	s.closed = true
	s.Count("attackbox.requests", 1, nil)
	if st := s.Stats(); st.Dropped != 5 {
		t.Errorf("after close: %+v", st)
	}
}

// scriptConn is a net.Conn whose writes fail, or record into a buffer.
type scriptConn struct {
	net.Conn
	fail bool
	mu   *sync.Mutex
	out  *strings.Builder
}

func (c *scriptConn) Write(p []byte) (int, error) {
	if c.fail {
		return 0, errors.New("broken pipe")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Write(p)
}
func (c *scriptConn) Close() error                     { return nil }
func (c *scriptConn) SetWriteDeadline(time.Time) error { return nil }

func TestSpoolResendsBatchAfterReconnect(t *testing.T) {
	var mu sync.Mutex
	var out strings.Builder
	var dials int
	dial := func() (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		dials++
		if dials == 1 {
			return &scriptConn{fail: true}, nil
		}
		return &scriptConn{mu: &mu, out: &out}, nil
	}
	var errs []error
	var emu sync.Mutex
	s, err := NewSpool(SpoolConfig{Socket: "/unused", Heartbeat: -1, dial: dial,
		OnError: func(e error) { emu.Lock(); errs = append(errs, e); emu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		s.Emit(Event{Stream: StreamProbe, Action: "decision", Attrs: map[string]any{"i": i}})
	}
	if err := closeSpool(t, s); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	text := out.String()
	mu.Unlock()
	for i := 1; i <= 5; i++ {
		if !strings.Contains(text, `"id":"`+s.Boot()+"-"+strconv.Itoa(i)+`"`) {
			t.Errorf("record %d lost across the reconnect:\n%s", i, text)
		}
	}
	st := s.Stats()
	if st.Written != 5 || st.Lost != 0 || st.Errors != 1 || st.Reconnects != 1 || st.Resent != 1 {
		t.Errorf("stats = %+v", st)
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "broken pipe") {
		t.Errorf("OnError got %v", errs)
	}
}

func TestSpoolCloseDeadlineCountsLost(t *testing.T) {
	first := true
	dial := func() (net.Conn, error) {
		if first {
			first = false
			return &scriptConn{fail: true}, nil
		}
		return nil, errors.New("connection refused")
	}
	s, err := NewSpool(SpoolConfig{Socket: "/unused", Heartbeat: -1, dial: dial})
	if err != nil {
		t.Fatal(err)
	}
	for range 4 {
		s.Emit(Event{Stream: StreamEdge, Action: "x"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = s.Close(ctx)
	if err == nil || !strings.Contains(err.Error(), "drain") {
		t.Fatalf("Close = %v, want a drain error", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("Close took %v after its deadline", d)
	}
	if st := s.Stats(); st.Lost != 4 || st.Written != 0 || s.bytes.Load() != 0 {
		t.Errorf("stats = %+v bytes %d; every unwritten record must count as lost", st, s.bytes.Load())
	}
}

func TestSpoolLiveSocketAndHeartbeat(t *testing.T) {
	l := newSpoolListener(t)
	s, err := NewSpool(SpoolConfig{Socket: l.path, Heartbeat: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	for range 50 {
		s.Emit(Event{Stream: StreamTranscript, Body: "hello"})
	}
	beat := false
	for i := 0; i < 50+20 && !beat; i++ {
		r := l.next(t)
		if r.Event != nil && r.Event.Stream == StreamHeartbeat {
			beat = r.Event.Action == "bait_heartbeat" && r.Event.Attrs["dropped_total"] == 0.0
		}
	}
	if !beat {
		t.Fatal("no bait_heartbeat record")
	}
	if err := closeSpool(t, s); err != nil {
		t.Fatal(err)
	}
	s.Emit(Event{Stream: StreamEdge})
	if err := closeSpool(t, s); err == nil || !strings.Contains(err.Error(), "1 dropped") {
		t.Errorf("Close after a post-close Emit = %v", err)
	}
}

func TestSpoolPeerRestart(t *testing.T) {
	l := newSpoolListener(t)
	s, err := NewSpool(SpoolConfig{Socket: l.path, Heartbeat: -1})
	if err != nil {
		t.Fatal(err)
	}
	s.Emit(Event{Stream: StreamEdge, Action: "before"})
	if r := l.next(t); r.Event.Action != "before" {
		t.Fatalf("got %+v", r)
	}
	(<-l.conns).Close() // shipper drops the connection
	deadline := time.Now().Add(5 * time.Second)
	seen := map[string]bool{}
	for i := 0; !seen["after"] && time.Now().Before(deadline); i++ {
		s.Emit(Event{Stream: StreamEdge, Action: "after"})
		select {
		case line := <-l.lines:
			var r Record
			if json.Unmarshal([]byte(line), &r) == nil {
				seen[r.Event.Action] = true
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !seen["after"] {
		t.Fatal("no record arrived after the peer closed the connection")
	}
	if err := closeSpool(t, s); err != nil {
		t.Fatal(err)
	}
	if st := s.Stats(); st.Reconnects < 1 || st.Errors < 1 || st.Lost != 0 {
		t.Errorf("stats = %+v", st)
	}
}

func TestNewSpoolErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg  SpoolConfig
		want string
	}{
		"relative": {SpoolConfig{Socket: "run/s.sock"}, "absolute"},
		"nul":      {SpoolConfig{Socket: "/run/s\x00.sock"}, "NUL"},
		"long":     {SpoolConfig{Socket: "/" + strings.Repeat("a", MaxSocketPath)}, "at most 107"},
		"budget":   {SpoolConfig{Socket: "/run/s.sock", QueueBytes: 10, MaxRecord: 11}, "MaxRecord"},
		"no peer":  {SpoolConfig{Socket: "/nonexistent-abx/s.sock"}, "spool:"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSpool(tc.cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
