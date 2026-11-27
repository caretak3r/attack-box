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

type batchSink struct {
	fakeSink
	ship func([]telemetry.Record) error
}

func (s *batchSink) ShipRecords(records []telemetry.Record) error { return s.ship(records) }

func TestDeliverBatchKeepsEntireBatchOnFailure(t *testing.T) {
	entries := []shipper.Entry{eventEntry(t, 1), metricEntry(t, 2, "count"), eventEntry(t, 3)}
	var calls [][]telemetry.Record
	s := &batchSink{ship: func(records []telemetry.Record) error {
		calls = append(calls, records)
		if len(calls) == 1 {
			// Simulate earlier POST acceptance followed by a later failure.
			return errors.New("second HTTP request failed")
		}
		return nil
	}}
	n, blocked, err := deliver(context.Background(), s, entries, 0)
	if n != 0 || !blocked || err != nil {
		t.Fatalf("partial failure: n=%d blocked=%v err=%v", n, blocked, err)
	}
	n, blocked, err = deliver(context.Background(), s, entries, 0)
	if n != 3 || blocked || err != nil || len(calls) != 2 {
		t.Fatalf("replay: n=%d blocked=%v err=%v calls=%d", n, blocked, err, len(calls))
	}
	for i := range calls[0] {
		a, _ := json.Marshal(calls[0][i])
		b, _ := json.Marshal(calls[1][i])
		if string(a) != string(b) {
			t.Fatalf("record %d changed on replay", i)
		}
	}
}

func TestDeliverBatchSuppressesUncertainMetricsAndHonorsAcceptance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entries := []shipper.Entry{eventEntry(t, 1), metricEntry(t, 2, "count"), metricEntry(t, 3, "count")}
	s := &batchSink{ship: func(records []telemetry.Record) error {
		if len(records) != 2 || records[0].Event == nil || records[1].Metric == nil {
			t.Fatalf("uncertain metrics not suppressed: %+v", records)
		}
		cancel() // accepted remote response races with shutdown
		return nil
	}}
	n, blocked, err := deliver(ctx, s, entries, 2)
	if n != 3 || blocked || err != nil {
		t.Fatalf("accepted batch must count: n=%d blocked=%v err=%v", n, blocked, err)
	}
}

func TestDeliverBatchRejectsCorruptPayloadBeforeSending(t *testing.T) {
	s := &batchSink{ship: func([]telemetry.Record) error {
		t.Fatal("corrupt batch must not be sent")
		return nil
	}}
	for _, bad := range []string{"invalid JSON", `{}`, `{"event":{},"metric":{}}`} {
		entries := []shipper.Entry{eventEntry(t, 1), {Seq: 2, Data: []byte(bad)}}
		n, blocked, err := deliver(context.Background(), s, entries, 0)
		if n != 0 || blocked || err == nil {
			t.Fatalf("bad payload %q: n=%d blocked=%v err=%v", bad, n, blocked, err)
		}
	}
}

func TestDrainSingleRecordDoesNotWaitForFullBatch(t *testing.T) {
	q := &fakeQueue{}
	got := make(chan int, 1)
	s := &batchSink{ship: func(records []telemetry.Record) error {
		got <- len(records)
		return nil
	}}
	stop := runDrain(t, q, s, false, 0)
	defer stop()
	waitFor(t, "initial idle poll", func() bool { reads, _ := q.snapshot(); return reads > 0 })
	q.mu.Lock()
	q.batches = append(q.batches, []shipper.Entry{eventEntry(t, 1)})
	q.mu.Unlock()
	select {
	case n := <-got:
		if n != 1 {
			t.Fatalf("got batch size %d", n)
		}
	case <-time.After(time.Second):
		t.Fatal("quiet record waited for a batch or flush interval")
	}
}

type fakeRejectedStore struct {
	mu       sync.Mutex
	rejected []shipper.Entry
	reasons  []string
	putErr   error
}

func (s *fakeRejectedStore) Put(e shipper.Entry, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.putErr != nil {
		return s.putErr
	}
	s.rejected = append(s.rejected, e)
	s.reasons = append(s.reasons, reason)
	return nil
}

func (s *fakeRejectedStore) snapshot() ([]shipper.Entry, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.rejected), slices.Clone(s.reasons)
}

type statusBatchSink struct {
	batchSink
	status int
	calls  int
}

func (s *statusBatchSink) ShipRecords(records []telemetry.Record) error {
	s.calls++
	if s.status == 0 || s.status == 202 {
		return nil
	}
	if s.status == 400 || s.status == 413 || s.status == 422 {
		return &telemetry.RecordRejection{Reason: "http_4xx"}
	}
	return errors.New("http error")
}

func TestDrainHTTP400QuarantinesPermanentRejection(t *testing.T) {
	entries := []shipper.Entry{eventEntry(t, 1), eventEntry(t, 2)}
	store := &fakeRejectedStore{}
	s := &statusBatchSink{status: 400}
	n, blocked, err := deliver(context.Background(), s, entries, 0, store)
	if n != 2 || blocked || err != nil {
		t.Fatalf("400: n=%d blocked=%v err=%v", n, blocked, err)
	}
	rejected, reasons := store.snapshot()
	if len(rejected) != 2 || reasons[0] != "http_4xx" || reasons[1] != "http_4xx" {
		t.Fatalf("quarantine: %d records, reasons %v", len(rejected), reasons)
	}
}

func TestDrainHTTP401BlocksWithoutQuarantine(t *testing.T) {
	entries := []shipper.Entry{eventEntry(t, 1)}
	store := &fakeRejectedStore{}
	s := &statusBatchSink{status: 401}
	n, blocked, err := deliver(context.Background(), s, entries, 0, store)
	if n != 0 || !blocked || err != nil {
		t.Fatalf("401: n=%d blocked=%v err=%v (want blocked, no ack)", n, blocked, err)
	}
	rejected, _ := store.snapshot()
	if len(rejected) != 0 {
		t.Fatal("401 must not quarantine (account issue)")
	}
}

func TestDrainHTTP403BlocksWithoutQuarantine(t *testing.T) {
	entries := []shipper.Entry{eventEntry(t, 1)}
	store := &fakeRejectedStore{}
	s := &statusBatchSink{status: 403}
	n, blocked, err := deliver(context.Background(), s, entries, 0, store)
	if n != 0 || !blocked || err != nil {
		t.Fatalf("403: n=%d blocked=%v err=%v", n, blocked, err)
	}
	rejected, _ := store.snapshot()
	if len(rejected) != 0 {
		t.Fatal("403 must not quarantine (auth issue)")
	}
}

func TestDrainHTTP413QuarantinesPermanentRejection(t *testing.T) {
	entries := []shipper.Entry{eventEntry(t, 1), eventEntry(t, 2)}
	store := &fakeRejectedStore{}
	s := &statusBatchSink{status: 413}
	n, blocked, err := deliver(context.Background(), s, entries, 0, store)
	if n != 2 || blocked || err != nil {
		t.Fatalf("413: n=%d blocked=%v err=%v", n, blocked, err)
	}
	rejected, reasons := store.snapshot()
	if len(rejected) != 2 || reasons[0] != "http_4xx" {
		t.Fatalf("quarantine: %d records, reason %v", len(rejected), reasons)
	}
}

func TestDrainHTTP429BlocksAndRetries(t *testing.T) {
	entries := []shipper.Entry{eventEntry(t, 1)}
	store := &fakeRejectedStore{}
	s := &statusBatchSink{status: 429}
	n, blocked, err := deliver(context.Background(), s, entries, 0, store)
	if n != 0 || !blocked || err != nil {
		t.Fatalf("429: n=%d blocked=%v err=%v (want retry, no quarantine)", n, blocked, err)
	}
	rejected, _ := store.snapshot()
	if len(rejected) != 0 {
		t.Fatal("429 is transient, must not quarantine")
	}
}

func TestDrainHTTP5xxBlocksAndRetries(t *testing.T) {
	for _, status := range []int{500, 502, 503, 504} {
		t.Run(string(rune('0'+status/100))+"xx", func(t *testing.T) {
			entries := []shipper.Entry{eventEntry(t, 1)}
			store := &fakeRejectedStore{}
			s := &statusBatchSink{status: status}
			n, blocked, err := deliver(context.Background(), s, entries, 0, store)
			if n != 0 || !blocked || err != nil {
				t.Fatalf("%d: n=%d blocked=%v err=%v", status, n, blocked, err)
			}
			rejected, _ := store.snapshot()
			if len(rejected) != 0 {
				t.Fatalf("%d is transient, must not quarantine", status)
			}
		})
	}
}

func TestDrainCrashAndReplayIdempotent(t *testing.T) {
	entries := []shipper.Entry{
		eventEntry(t, 1), metricEntry(t, 2, "count"), eventEntry(t, 3), metricEntry(t, 4, "count"),
	}
	var batches [][]telemetry.Record
	s := &batchSink{ship: func(records []telemetry.Record) error {
		batches = append(batches, records)
		return nil
	}}
	// First delivery
	n, blocked, err := deliver(context.Background(), s, entries, 0)
	if n != 4 || blocked || err != nil {
		t.Fatalf("first: n=%d blocked=%v err=%v", n, blocked, err)
	}
	// Replay after crash (before ack)
	n, blocked, err = deliver(context.Background(), s, entries, 0)
	if n != 4 || blocked || err != nil {
		t.Fatalf("replay: n=%d blocked=%v err=%v", n, blocked, err)
	}
	if len(batches) != 2 {
		t.Fatalf("got %d batches, want 2", len(batches))
	}
	// Record IDs must be stable across replay
	for i := range batches[0] {
		if batches[0][i].ID != batches[1][i].ID {
			t.Errorf("record %d ID changed: %s → %s", i, batches[0][i].ID, batches[1][i].ID)
		}
	}
}

func TestDrainFullQuarantineStopsDrain(t *testing.T) {
	entries := []shipper.Entry{eventEntry(t, 1), eventEntry(t, 2)}
	store := &fakeRejectedStore{putErr: errors.New("quarantine full")}
	s := &statusBatchSink{status: 400}
	n, blocked, err := deliver(context.Background(), s, entries, 0, store)
	if n != 0 || blocked || err == nil {
		t.Fatalf("full quarantine: n=%d blocked=%v err=%v (want error, no ack)", n, blocked, err)
	}
	if err.Error() != "retain rejected record at seq 1: quarantine full" {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestDrainHostProgressUnderBaitFailure(t *testing.T) {
	// This test verifies that when permanent rejection causes batch splitting,
	// all records get quarantined individually, not leaving some blocked
	baitEntry := eventEntry(t, 1)
	baitEntry.Role = shipper.RoleBait
	hostEntry := eventEntry(t, 2)
	hostEntry.Role = shipper.RoleRuntime
	entries := []shipper.Entry{baitEntry, hostEntry}

	s := &statusBatchSink{status: 400}
	store := &fakeRejectedStore{}

	n, blocked, err := deliver(context.Background(), s, entries, 0, store)
	// With permanent rejection and quarantine, both records should be acknowledged after quarantine
	if n != 2 || blocked || err != nil {
		t.Fatalf("n=%d blocked=%v err=%v (want 2 acked after quarantine)", n, blocked, err)
	}
	rejected, _ := store.snapshot()
	if len(rejected) != 2 {
		t.Fatalf("quarantined %d records, want 2 (batch splits and quarantines both)", len(rejected))
	}
	// Verify both roles were quarantined
	roles := map[shipper.Role]bool{}
	for _, r := range rejected {
		roles[r.Role] = true
	}
	if !roles[shipper.RoleBait] || !roles[shipper.RoleRuntime] {
		t.Fatal("both bait and host records must be quarantined")
	}
}
