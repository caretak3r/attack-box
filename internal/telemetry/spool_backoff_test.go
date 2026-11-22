package telemetry

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// A peer that accepts and closes at once makes every dial succeed and every
// write fail. The redial backoff must survive the successful dials.
func TestSpoolBackoffSurvivesAcceptThenClose(t *testing.T) {
	dial := func() (net.Conn, error) {
		c, peer := net.Pipe()
		peer.Close()
		return c, nil
	}
	var emu sync.Mutex
	var reported int
	s, err := NewSpool(SpoolConfig{Socket: "/unused", Heartbeat: -1, dial: dial,
		OnError: func(error) { emu.Lock(); reported++; emu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	s.Emit(Event{Stream: StreamEdge, Action: "x"})
	time.Sleep(300 * time.Millisecond)
	st := s.Stats()
	emu.Lock()
	n := reported
	emu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = s.Close(ctx)
	if st.Reconnects > 2 || st.Resent > 2 {
		t.Errorf("redial spun: %+v", st)
	}
	if n > 2 {
		t.Errorf("OnError called %d times in 300ms; failures must be rate limited", n)
	}
}

func TestSpoolRateLimitsErrorReports(t *testing.T) {
	var got []string
	s := newIdleSpool(SpoolConfig{OnError: func(e error) { got = append(got, e.Error()) }})
	for range 50 {
		s.failIO(errors.New("boom"))
	}
	if st := s.Stats(); st.Errors != 50 {
		t.Errorf("Errors = %d, want every failure counted", st.Errors)
	}
	if len(got) != 1 || got[0] != "boom" {
		t.Fatalf("reports = %q, want one", got)
	}
	s.lastReport = s.lastReport.Add(-2 * time.Second)
	s.failIO(errors.New("boom"))
	if len(got) != 2 || !strings.Contains(got[1], "49 similar") {
		t.Errorf("reports = %q, want the suppressed count on the next one", got)
	}
}

// slowConn takes slowWrite per Write and honors its write deadline.
type slowConn struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
}

const slowWrite = 20 * time.Millisecond

func (c *slowConn) Write(p []byte) (int, error) {
	time.Sleep(slowWrite)
	c.mu.Lock()
	d := c.deadline
	c.mu.Unlock()
	if !d.IsZero() && time.Now().After(d) {
		return 0, os.ErrDeadlineExceeded
	}
	return len(p), nil
}
func (c *slowConn) Close() error { return nil }
func (c *slowConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

// A peer that accepts every batch within WriteTimeout must not stretch Close
// past its context.
func TestSpoolCloseDeadlineWithSlowPeer(t *testing.T) {
	c := &slowConn{}
	s, err := NewSpool(SpoolConfig{Socket: "/unused", Heartbeat: -1, dial: func() (net.Conn, error) { return c, nil }})
	if err != nil {
		t.Fatal(err)
	}
	for range 500 { // five batches of 100 writes, two seconds each
		s.Emit(Event{Stream: StreamEdge, Action: "x"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = s.Close(ctx)
	if err == nil || !strings.Contains(err.Error(), "drain") {
		t.Fatalf("Close = %v, want a drain error", err)
	}
	if d := time.Since(start); d > 200*time.Millisecond+400*time.Millisecond {
		t.Errorf("Close took %v with a 200ms context", d)
	}
	st := s.Stats()
	if st.Lost == 0 || st.Written+st.Lost != 500 || s.bytes.Load() != 0 {
		t.Errorf("stats = %+v bytes %d; every record is written or lost", st, s.bytes.Load())
	}
}
