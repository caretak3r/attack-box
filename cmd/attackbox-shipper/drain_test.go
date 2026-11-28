package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
)

type fakeQueue struct {
	mu      sync.Mutex
	entries []shipper.Entry
	batches [][]shipper.Entry
	read    int
	acked   int
	readErr error
	ackErr  error
}

func (f *fakeQueue) Read(max, maxBytes int) ([]shipper.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.read++
	if f.readErr != nil {
		return nil, f.readErr
	}
	if len(f.batches) > 0 && len(f.batches[0]) > 0 {
		batch := f.batches[0]
		f.batches = f.batches[1:]
		return batch, nil
	}
	if len(f.entries) == 0 {
		return nil, nil
	}
	take := len(f.entries)
	if take > max {
		take = max
	}
	out := f.entries[:take]
	f.entries = f.entries[take:]
	return out, nil
}

func (f *fakeQueue) Ack(n int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ackErr != nil {
		return f.ackErr
	}
	f.acked += n
	return nil
}

func (f *fakeQueue) snapshot() (reads, acked int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.read, f.acked
}

type fakeEvidence struct {
	mu      sync.Mutex
	written []struct {
		Seq  uint64
		Data []byte
	}
	tries    int
	failNext int
}

func (e *fakeEvidence) Write(role string, records []struct {
	Seq  uint64
	Data []byte
}) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tries++
	if e.failNext > 0 {
		e.failNext--
		return fmt.Errorf("write failed")
	}
	e.written = append(e.written, records...)
	return nil
}

func (e *fakeEvidence) snapshot() (written, tries int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.written), e.tries
}

func eventEntry(t *testing.T, seq uint64) shipper.Entry {
	t.Helper()
	rec := telemetry.Record{Event: &telemetry.Event{Stream: "edge", Action: "request", Timestamp: time.Now()}}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return shipper.Entry{Seq: seq, Data: data}
}

func metricEntry(t *testing.T, seq uint64, kind string) shipper.Entry {
	t.Helper()
	rec := telemetry.Record{Metric: &telemetry.MetricRecord{Name: "test.metric", Kind: kind, Value: 1, At: time.Now()}}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return shipper.Entry{Seq: seq, Data: data}
}

func runDrain(t *testing.T, q drainQueue, e *fakeEvidence, uncertain bool, through uint64) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- drain(ctx, q, e, "bait", uncertain, through)
	}()
	return func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(3 * time.Second):
			t.Fatal("drain did not stop")
			return nil
		}
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestDrainDeliversAndAcks(t *testing.T) {
	q := &fakeQueue{entries: []shipper.Entry{eventEntry(t, 1), eventEntry(t, 2)}}
	e := &fakeEvidence{}
	stop := runDrain(t, q, e, false, 0)
	waitFor(t, "drain to deliver", func() bool { w, _ := e.snapshot(); return w == 2 })
	waitFor(t, "queue to ack", func() bool { _, acked := q.snapshot(); return acked == 2 })
	if err := stop(); err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatal(err)
	}
}

func TestDrainWaitsWhenIdle(t *testing.T) {
	q := &fakeQueue{}
	e := &fakeEvidence{}
	stop := runDrain(t, q, e, false, 0)
	time.Sleep(50 * time.Millisecond)
	reads, _ := q.snapshot()
	if reads > 5 {
		t.Errorf("idle drain read %d times in 50ms", reads)
	}
	if err := stop(); err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatal(err)
	}
}

func TestDrainRetriesRefusedEventWithBackoff(t *testing.T) {
	q := &fakeQueue{entries: []shipper.Entry{eventEntry(t, 1)}}
	e := &fakeEvidence{failNext: 2}
	stop := runDrain(t, q, e, false, 0)
	waitFor(t, "drain to deliver after retries", func() bool { w, _ := e.snapshot(); return w == 1 })
	if err := stop(); err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatal(err)
	}
}

func TestDrainReturnsQueueBrokenFromRead(t *testing.T) {
	q := &fakeQueue{readErr: fmt.Errorf("queue broken")}
	e := &fakeEvidence{}
	stop := runDrain(t, q, e, false, 0)
	time.Sleep(10 * time.Millisecond) // let drain start and hit the error
	if err := stop(); err == nil || !strings.Contains(err.Error(), "queue broken") {
		t.Errorf("got %v, want queue broken", err)
	}
}

func TestDrainReturnsFinalAckError(t *testing.T) {
	q := &fakeQueue{entries: []shipper.Entry{eventEntry(t, 1)}, ackErr: fmt.Errorf("ack failed")}
	e := &fakeEvidence{}
	stop := runDrain(t, q, e, false, 0)
	waitFor(t, "drain to deliver", func() bool { w, _ := e.snapshot(); return w == 1 })
	if err := stop(); err == nil || !strings.Contains(err.Error(), "ack failed") {
		t.Errorf("got %v, want ack failed", err)
	}
}

func TestDrainSuppressesUncertainMetrics(t *testing.T) {
	q := &fakeQueue{entries: []shipper.Entry{
		metricEntry(t, 1, "count"),
		metricEntry(t, 2, "gauge"),
		metricEntry(t, 3, "count"),
	}}
	e := &fakeEvidence{}
	stop := runDrain(t, q, e, true, 2)
	waitFor(t, "drain to skip uncertain and write rest", func() bool { w, _ := e.snapshot(); return w == 1 })
	if err := stop(); err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatal(err)
	}
	written, _ := e.snapshot()
	if written != 1 {
		t.Errorf("wrote %d records, want 1 (seq 3 only)", written)
	}
}

func TestDrainCrashAndReplayIdempotent(t *testing.T) {
	q := &fakeQueue{batches: [][]shipper.Entry{
		{eventEntry(t, 1)},
		{eventEntry(t, 1)},
	}}
	e := &fakeEvidence{}
	stop := runDrain(t, q, e, false, 0)
	waitFor(t, "drain to replay", func() bool { w, _ := e.snapshot(); return w == 2 })
	if err := stop(); err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatal(err)
	}
}

func TestDeliverRejectsCorruptPayload(t *testing.T) {
	entries := []shipper.Entry{{Seq: 1, Data: []byte("{corrupt}")}}
	e := &fakeEvidence{}
	_, _, err := deliver(context.Background(), e, "bait", entries, 0)
	if err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("got %v, want corrupt payload error", err)
	}
}

func TestDeliverWriteErrorBlocks(t *testing.T) {
	entries := []shipper.Entry{eventEntry(t, 1)}
	e := &fakeEvidence{failNext: 1}
	n, blocked, err := deliver(context.Background(), e, "bait", entries, 0)
	if !blocked || err != nil || n != 0 {
		t.Errorf("got n=%d blocked=%v err=%v, want 0, true, nil", n, blocked, err)
	}
}
