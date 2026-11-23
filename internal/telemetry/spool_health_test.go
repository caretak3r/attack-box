package telemetry

import (
	"bytes"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// gateConn blocks every write until release is closed, so a test can hold a
// batch in flight and fill the queue behind it. entered closes on the first
// write.
type gateConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	out     bytes.Buffer
}

func newGateConn() *gateConn {
	return &gateConn{entered: make(chan struct{}), release: make(chan struct{})}
}

func (c *gateConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Write(p)
}
func (c *gateConn) Close() error                     { return nil }
func (c *gateConn) SetWriteDeadline(time.Time) error { return nil }

// records returns every line written so far.
func (c *gateConn) records(t *testing.T) []Record {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var recs []Record
	for _, line := range strings.Split(strings.TrimSuffix(c.out.String(), "\n"), "\n") {
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("bad line %q: %v", line, err)
		}
		recs = append(recs, r)
	}
	return recs
}

func seqOf(t *testing.T, r Record) int {
	t.Helper()
	n, err := strconv.Atoi(r.ID[strings.LastIndexByte(r.ID, '-')+1:])
	if err != nil {
		t.Fatalf("id %q: %v", r.ID, err)
	}
	return n
}

// gatedSpool starts a Spool whose writer holds its first record in flight.
func gatedSpool(t *testing.T, cfg SpoolConfig) (*Spool, *gateConn) {
	t.Helper()
	gc := newGateConn()
	cfg.Socket, cfg.Heartbeat = "/unused", -1
	cfg.dial = func() (net.Conn, error) { return gc, nil }
	s, err := NewSpool(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.Emit(Event{Stream: StreamEdge, Action: "in_flight"})
	select {
	case <-gc.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("writer never took the first record")
	}
	return s, gc
}

// drainGated lets the writer run and closes the Spool. Close reports the
// drops, which the caller has already checked, so its error is ignored.
func drainGated(t *testing.T, s *Spool, gc *gateConn) []Record {
	t.Helper()
	close(gc.release)
	_ = closeSpool(t, s)
	return gc.records(t)
}

func checkAscending(t *testing.T, recs []Record) {
	t.Helper()
	prev := 0
	for _, r := range recs {
		if n := seqOf(t, r); n <= prev {
			t.Errorf("seq %d after %d: the wire order must be ascending", n, prev)
		} else {
			prev = n
		}
	}
}

func heartbeatNow(s *Spool) Event {
	return Event{Stream: StreamHeartbeat, Action: "bait_heartbeat", Result: "ok", Attrs: s.Counters()}
}

func TestSpoolCounters(t *testing.T) {
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
	s, err := NewSpool(SpoolConfig{Socket: "/unused", Heartbeat: -1, MaxRecord: 4096, dial: dial})
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		s.Emit(Event{Stream: StreamProbe, Action: "decision"})
	}
	s.Emit(Event{Stream: StreamEdge, Body: strings.Repeat("x", 8192)}) // oversize
	_ = closeSpool(t, s)                                               // reports the drop
	want := map[string]int64{
		"written_total": 5, "dropped_total": 1, "oversize_total": 1, "lost_total": 0,
		"resent_total": 1, "errors_total": 1, "reconnects": 1,
	}
	got := s.Counters()
	for name, v := range want {
		if got[name] != v {
			t.Errorf("%s = %v, want %d", name, got[name], v)
		}
	}
	if up, ok := got["uptime_ms"].(int64); !ok || up < 0 {
		t.Errorf("uptime_ms = %v", got["uptime_ms"])
	}
	if len(got) != len(want)+1 {
		t.Errorf("counters = %v, want exactly the 8 names of the contract", got)
	}
}

func TestSpoolHeartbeatAttrs(t *testing.T) {
	l := newSpoolListener(t)
	s, err := NewSpool(SpoolConfig{
		Socket: l.path, Heartbeat: 20 * time.Millisecond,
		Stamp: map[string]any{"fp_scope": "boot"},
		HeartbeatAttrs: func() map[string]any {
			return map[string]any{"local_dropped_total": 7, "written_total": "forged", "fp_scope": "forged"}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeSpool(t, s)
	for {
		r := l.next(t)
		if r.Event == nil || r.Event.Action != "bait_heartbeat" {
			continue
		}
		a := r.Event.Attrs
		if a["local_dropped_total"] != 7.0 {
			t.Errorf("local_dropped_total = %v, want 7", a["local_dropped_total"])
		}
		if a["written_total"] == "forged" {
			t.Error("the callback overrode a spool counter")
		}
		if a["fp_scope"] != "boot" {
			t.Errorf("fp_scope = %v, the stamp must win over the callback", a["fp_scope"])
		}
		return
	}
}

func TestSpoolHeartbeatCarriesCounters(t *testing.T) {
	l := newSpoolListener(t)
	s, err := NewSpool(SpoolConfig{Socket: l.path, Heartbeat: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer closeSpool(t, s)
	var uptimes []float64
	for len(uptimes) < 2 {
		r := l.next(t)
		if r.Event == nil || r.Event.Action != "bait_heartbeat" {
			continue
		}
		for _, name := range []string{
			"written_total", "dropped_total", "oversize_total", "lost_total", "resent_total", "errors_total",
			"reconnects", "uptime_ms", "queue_len", "queue_bytes",
		} {
			if _, ok := r.Event.Attrs[name]; !ok {
				t.Errorf("heartbeat lacks %s: %v", name, r.Event.Attrs)
			}
		}
		up, _ := r.Event.Attrs["uptime_ms"].(float64)
		uptimes = append(uptimes, up)
	}
	if uptimes[1] < uptimes[0] {
		t.Errorf("uptime_ms went from %v to %v", uptimes[0], uptimes[1])
	}
}

func TestSpoolReserveSize(t *testing.T) {
	for _, tc := range []struct {
		size, bytes int
		wantRecs    int
		wantBytes   int64
	}{
		{DefaultSpoolQueue, DefaultSpoolBytes, 4, 64 << 10},
		{3, DefaultSpoolBytes, 0, 0},
		{DefaultSpoolQueue, 100 << 10, 4, 25 << 10},
		{8, DefaultSpoolBytes, 2, 64 << 10},
	} {
		recs, b := reserve(tc.size, tc.bytes)
		if recs != tc.wantRecs || b != tc.wantBytes {
			t.Errorf("reserve(%d, %d) = %d, %d; want %d, %d", tc.size, tc.bytes, recs, b, tc.wantRecs, tc.wantBytes)
		}
	}
}

func TestSpoolReserveRefusesPayloadKeepsHealth(t *testing.T) {
	s, gc := gatedSpool(t, SpoolConfig{QueueSize: 8}) // reserve 2 records
	for range 6 {
		s.Emit(Event{Stream: StreamEdge, Action: "payload"})
	}
	s.Emit(Event{Stream: StreamEdge, Action: "refused"})
	s.Count("attackbox.requests", 1, nil)
	if st := s.Stats(); st.Dropped != 2 {
		t.Fatalf("dropped = %d, want the payload event and the metric", st.Dropped)
	}
	s.Emit(heartbeatNow(s))
	s.Emit(Event{Stream: StreamRuntime, Action: "stopped", Result: "ok"})
	if st := s.Stats(); st.Dropped != 2 {
		t.Fatalf("dropped = %d after the health records, want 2", st.Dropped)
	}
	recs := drainGated(t, s, gc)
	if len(recs) != 1+6+2 {
		t.Fatalf("%d lines on the wire, want 9", len(recs))
	}
	checkAscending(t, recs)
	beat, last := recs[len(recs)-2], recs[len(recs)-1]
	if beat.Event.Action != "bait_heartbeat" || beat.Event.Attrs["dropped_total"] != 2.0 {
		t.Errorf("heartbeat = %+v", beat.Event)
	}
	if last.Event.Action != "stopped" {
		t.Errorf("last = %+v", last.Event)
	}
}

func TestSpoolByteReserveRefusesPayloadKeepsHealth(t *testing.T) {
	s, gc := gatedSpool(t, SpoolConfig{QueueBytes: 256 << 10, MaxRecord: 64 << 10}) // reserve 64 KiB
	fill := func(emit func()) {
		for before := s.Stats().Dropped; s.Stats().Dropped == before; {
			emit()
		}
	}
	// Big events first, then metrics until even a metric is refused: nothing
	// payload-sized is left under the reserve.
	fill(func() { s.Emit(Event{Stream: StreamEdge, Body: strings.Repeat("x", 30000)}) })
	fill(func() { s.Count("attackbox.requests", 1, nil) })
	if free := int64(256<<10) - s.bytes.Load(); free < 64<<10 {
		t.Fatalf("payload used the reserve: %d bytes free", free)
	}
	dropped := s.Stats().Dropped
	s.Emit(Event{Stream: StreamEdge, Body: strings.Repeat("x", 30000)})
	s.Count("attackbox.requests", 1, nil)
	if st := s.Stats(); st.Dropped != dropped+2 {
		t.Fatalf("dropped %d, want %d: the payload event and the metric must be refused", st.Dropped, dropped+2)
	}
	s.Emit(heartbeatNow(s))
	s.Emit(Event{Stream: StreamRuntime, Action: "stopped", Result: "ok"})
	if st := s.Stats(); st.Dropped != dropped+2 {
		t.Fatalf("dropped %d after the health records, want %d", st.Dropped, dropped+2)
	}
	recs := drainGated(t, s, gc)
	checkAscending(t, recs)
	beat, last := recs[len(recs)-2], recs[len(recs)-1]
	if beat.Event.Action != "bait_heartbeat" || beat.Event.Attrs["dropped_total"] != float64(dropped+2) {
		t.Errorf("heartbeat = %+v, want dropped_total %d", beat.Event, dropped+2)
	}
	if last.Event.Action != "stopped" {
		t.Errorf("last = %+v", last.Event)
	}
}

func TestSpoolHealthClassification(t *testing.T) {
	for _, tc := range []struct {
		e    Event
		want bool
	}{
		{Event{Stream: StreamHeartbeat, Action: "bait_heartbeat"}, true},
		{Event{Stream: StreamRuntime, Action: "start"}, true},
		{Event{Stream: StreamRuntime, Action: "stop"}, true},
		{Event{Stream: StreamRuntime, Action: "stopped"}, true},
		{Event{Stream: StreamRuntime, Action: "local_dropped"}, false},
		{Event{Stream: StreamEdge, Action: "stopped"}, false},
	} {
		if got := isHealth(tc.e); got != tc.want {
			t.Errorf("isHealth(%s/%s) = %v", tc.e.Stream, tc.e.Action, got)
		}
	}
}

func TestSpoolStopHeartbeat(t *testing.T) {
	l := newSpoolListener(t)
	s, err := NewSpool(SpoolConfig{Socket: l.path, Heartbeat: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	for r := l.next(t); r.Event == nil || r.Event.Action != "bait_heartbeat"; r = l.next(t) {
	}
	returns := func(f func()) bool {
		done := make(chan struct{})
		go func() { f(); close(done) }()
		select {
		case <-done:
			return true
		case <-time.After(2 * time.Second):
			return false
		}
	}
	if !returns(s.StopHeartbeat) {
		t.Fatal("StopHeartbeat did not return")
	}
	seqAt := func() uint64 { s.mu.Lock(); defer s.mu.Unlock(); return s.seq }
	stopped := seqAt()
	time.Sleep(100 * time.Millisecond) // five intervals
	if got := seqAt(); got != stopped {
		t.Fatalf("seq moved from %d to %d after StopHeartbeat: a heartbeat was emitted", stopped, got)
	}
	if !returns(s.StopHeartbeat) {
		t.Fatal("second StopHeartbeat did not return")
	}
	s.Emit(Event{Stream: StreamRuntime, Action: "stopped", Result: "ok"})
	if err := closeSpool(t, s); err != nil {
		t.Fatalf("Close after StopHeartbeat = %v", err)
	}
	var lastSeq int
	var lastAction string
	for done := false; !done; {
		select {
		case line := <-l.lines:
			var r Record
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				t.Fatal(err)
			}
			lastSeq, lastAction = seqOf(t, r), r.Event.Action
		case <-time.After(200 * time.Millisecond):
			done = true
		}
	}
	if lastSeq != int(stopped)+1 || lastAction != "stopped" {
		t.Errorf("last line is seq %d %q, want seq %d \"stopped\"", lastSeq, lastAction, stopped+1)
	}

	off, err := NewSpool(SpoolConfig{Socket: l.path, Heartbeat: -1})
	if err != nil {
		t.Fatal(err)
	}
	if !returns(off.StopHeartbeat) || !returns(off.StopHeartbeat) {
		t.Fatal("StopHeartbeat blocked on a Spool with the heartbeat disabled")
	}
	if err := closeSpool(t, off); err != nil {
		t.Errorf("Close = %v", err)
	}
}
