package main

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
)

type fakeQueue struct {
	mu       sync.Mutex
	batches  [][]shipper.Entry // each Read returns the next batch; empty once drained
	readErr  error
	ackErr   error
	reads    int
	acked    int
	ackCalls int
}

func (f *fakeQueue) Read(max, maxBytes int) ([]shipper.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.readErr != nil {
		return nil, f.readErr
	}
	if len(f.batches) == 0 {
		return nil, nil
	}
	b := f.batches[0]
	f.batches = f.batches[1:]
	return b, nil
}

func (f *fakeQueue) Ack(n int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ackCalls++
	if f.ackErr != nil {
		return f.ackErr
	}
	f.acked += n
	return nil
}

func (f *fakeQueue) snapshot() (reads, acked int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads, f.acked
}

type fakeSink struct {
	mu      sync.Mutex
	refuse  int // fail this many ShipEvent calls first
	tries   int
	events  []telemetry.Event
	metrics []string // "<kind>:<name>"
}

func (s *fakeSink) ShipEvent(e telemetry.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tries++
	if s.refuse > 0 {
		s.refuse--
		return errors.New("transient failure")
	}
	s.events = append(s.events, e)
	return nil
}

func (s *fakeSink) ShipMetric(name, kind string, _ float64, _ time.Time, _ map[string]string) error {
	s.mu.Lock()
	s.metrics = append(s.metrics, kind+":"+name)
	s.mu.Unlock()
	return nil
}

func (s *fakeSink) snapshot() (events, tries int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events), s.tries
}

func (s *fakeSink) shippedMetrics() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.metrics)
}

// entry is what the ingest path stores: the JSON of the admitted telemetry.Record.
func eventEntry(t *testing.T, seq uint64) shipper.Entry {
	t.Helper()
	b, err := json.Marshal(telemetry.Record{
		ID:    "0123456789abcdef-1",
		Event: &telemetry.Event{Stream: telemetry.StreamEdge, Action: "x", Timestamp: time.Now()},
	})
	if err != nil {
		t.Fatal(err)
	}
	return shipper.Entry{Seq: seq, Role: shipper.RoleBait, Data: b}
}

func metricEntry(t *testing.T, seq uint64, kind string) shipper.Entry {
	t.Helper()
	b, err := json.Marshal(telemetry.Record{
		ID:     "0123456789abcdef-2",
		Metric: &telemetry.MetricRecord{Name: "attackbox.requests", Kind: kind, Value: 1, At: time.Now()},
	})
	if err != nil {
		t.Fatal(err)
	}
	return shipper.Entry{Seq: seq, Role: shipper.RoleBait, Data: b}
}

// runDrain starts drain and returns a stop func that cancels it and returns its error.
func runDrain(t *testing.T, q drainQueue, s drainSink, uncertain bool, through uint64) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- drain(ctx, q, s, uncertain, through) }()
	return func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("drain did not stop")
			return nil
		}
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestDrainDeliversAndAcks(t *testing.T) {
	q := &fakeQueue{batches: [][]shipper.Entry{{
		eventEntry(t, 1), metricEntry(t, 2, "count"), metricEntry(t, 3, "gauge"), metricEntry(t, 4, "count"),
	}}}
	s := &fakeSink{}
	// Metrics at or below seq 3 are suppressed after an uncertain recovery.
	stop := runDrain(t, q, s, true, 3)
	waitFor(t, "delivery", func() bool { e, _ := s.snapshot(); return e == 1 })
	waitFor(t, "metrics", func() bool { return len(s.shippedMetrics()) == 2 })
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("drain returned %v, want context.Canceled", err)
	}
	if _, acked := q.snapshot(); acked != 4 {
		t.Fatalf("acked %d entries, want 4", acked)
	}
	want := []string{"gauge:attackbox.metric_replay_gap", "count:attackbox.requests"}
	if got := s.shippedMetrics(); !slices.Equal(got, want) {
		t.Fatalf("shipped metrics %v, want %v (suppressed ones must not ship)", got, want)
	}
}

// An empty queue, or delivered entries waiting for the next checkpoint, must
// block on the poll timer and not spin.
func TestDrainWaitsWhenIdle(t *testing.T) {
	q := &fakeQueue{batches: [][]shipper.Entry{{eventEntry(t, 1)}}}
	s := &fakeSink{}
	stop := runDrain(t, q, s, false, 0)
	time.Sleep(1300 * time.Millisecond)
	reads, acked := q.snapshot()
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("drain returned %v", err)
	}
	if reads > 30 {
		t.Fatalf("%d reads in 1.3s: drain is spinning", reads)
	}
	if acked != 1 {
		t.Fatalf("acked %d, want the checkpoint to land within the ack interval", acked)
	}
}

func TestDrainRetriesRefusedEventWithBackoff(t *testing.T) {
	q := &fakeQueue{batches: [][]shipper.Entry{{eventEntry(t, 1)}}}
	s := &fakeSink{refuse: 2}
	stop := runDrain(t, q, s, false, 0)
	waitFor(t, "delivery after refusals", func() bool { e, _ := s.snapshot(); return e == 1 })
	if _, tries := s.snapshot(); tries != 3 {
		t.Fatalf("%d ShipEvent calls, want 3 (2 failed, 1 accepted)", tries)
	}
	stop()
}

func TestDrainReturnsQueueBrokenFromRead(t *testing.T) {
	q := &fakeQueue{readErr: shipper.ErrQueueBroken}
	err := drain(context.Background(), q, &fakeSink{}, false, 0)
	if !errors.Is(err, shipper.ErrQueueBroken) {
		t.Fatalf("got %v, want ErrQueueBroken", err)
	}
}

// The checkpoint at shutdown is the one that decides what replays; its
// failure must not be swallowed behind context.Canceled.
func TestDrainReturnsFinalAckError(t *testing.T) {
	q := &fakeQueue{batches: [][]shipper.Entry{{eventEntry(t, 1)}}, ackErr: shipper.ErrQueueBroken}
	s := &fakeSink{}
	stop := runDrain(t, q, s, false, 0)
	waitFor(t, "delivery", func() bool { e, _ := s.snapshot(); return e == 1 })
	if err := stop(); !errors.Is(err, shipper.ErrQueueBroken) {
		t.Fatalf("got %v, want ErrQueueBroken from the final ack", err)
	}
}
