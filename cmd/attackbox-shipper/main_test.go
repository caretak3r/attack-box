package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
)

// fakeNewRelic is a test double for the New Relic endpoints that tracks
// received logs and metrics and can simulate failures.
type fakeNewRelic struct {
	mu          sync.Mutex
	logs        []telemetry.Event
	metrics     []metricPost
	failNext    int  // fail the next N requests
	failPartial bool // fail only part of a batch
	logURL      string
	metricURL   string
	t           *testing.T
}

type metricPost struct {
	Name       string
	Type       string
	Value      float64
	Timestamp  int64
	Attributes map[string]string
}

func (f *fakeNewRelic) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.failNext > 0 {
		f.failNext--
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		f.t.Fatal(err)
	}

	// Decompress if gzipped
	if r.Header.Get("Content-Encoding") == "gzip" {
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			f.t.Fatal(err)
		}
		body, err = io.ReadAll(gr)
		gr.Close()
		if err != nil {
			f.t.Fatal(err)
		}
	}

	var envelope []map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		f.t.Fatal(err)
	}

	for _, item := range envelope {
		if logs, ok := item["logs"].([]any); ok {
			for _, l := range logs {
				lm := l.(map[string]any)
				attrs := lm["attributes"].(map[string]any)
				e := telemetry.Event{}
				if ts, ok := lm["timestamp"].(float64); ok {
					e.Timestamp = time.UnixMilli(int64(ts))
				}
				if msg, ok := lm["message"].(string); ok {
					e.Body = msg
				}
				if a, ok := attrs["action"].(string); ok {
					e.Action = a
				}
				if s, ok := attrs["stream"].(string); ok {
					e.Stream = s
				}
				if bs, ok := attrs["body_sha256"].(string); ok {
					e.BodySHA256 = bs
				}
				if ci, ok := attrs["chunk_index"].(float64); ok {
					e.ChunkIndex = int(ci)
				}
				if cc, ok := attrs["chunk_count"].(float64); ok {
					e.ChunkCount = int(cc)
				}
				f.logs = append(f.logs, e)
			}
		}
		if metrics, ok := item["metrics"].([]any); ok {
			for _, m := range metrics {
				mm := m.(map[string]any)
				mp := metricPost{
					Name:      mm["name"].(string),
					Type:      mm["type"].(string),
					Value:     mm["value"].(float64),
					Timestamp: int64(mm["timestamp"].(float64)),
				}
				if attrs, ok := mm["attributes"].(map[string]any); ok {
					mp.Attributes = make(map[string]string)
					for k, v := range attrs {
						mp.Attributes[k] = fmt.Sprint(v)
					}
				}
				f.metrics = append(f.metrics, mp)
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}

func TestDrainAcksOnlyAfterDelivery(t *testing.T) {
	dir := t.TempDir()
	qcfg := shipper.QueueConfig{
		Dir:          filepath.Join(dir, "queue"),
		SegmentBytes: 1 << 20,
		MaxBytes:     10 << 20,
		RoleBytes:    map[shipper.Role]int64{shipper.RoleBait: 10 << 20},
		MaxPayload:   telemetry.MinPayloadBytes - shipper.FrameHeader,
	}
	q, _, err := shipper.OpenQueue(qcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	// Enqueue two log records
	rec1 := telemetry.Record{
		ID: "0123456789abcdef-1",
		Event: &telemetry.Event{
			Stream:    telemetry.StreamEdge,
			Action:    "test1",
			Timestamp: time.Now(),
		},
	}
	data1, _ := json.Marshal(rec1)
	rec2 := telemetry.Record{
		ID: "0123456789abcdef-2",
		Event: &telemetry.Event{
			Stream:    telemetry.StreamEdge,
			Action:    "test2",
			Timestamp: time.Now(),
		},
	}
	data2, _ := json.Marshal(rec2)

	seqs, err := q.Append([]shipper.Item{
		{Role: shipper.RoleBait, Data: data1},
		{Role: shipper.RoleBait, Data: data2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seqs) != 2 || seqs[0] == 0 || seqs[1] == 0 {
		t.Fatalf("bad seqs: %v", seqs)
	}

	fake := &fakeNewRelic{t: t}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	nr, err := telemetry.NewNewRelic(telemetry.NRConfig{
		LicenseKey: "0123456789abcdef0123456789abcdef01234567",
		LogURL:     srv.URL,
		MetricURL:  srv.URL,
		QueueSize:  100,
		Now:        time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer nr.Close(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Drain should deliver both and Ack
	done := make(chan error, 1)
	go func() {
		done <- drain(ctx, q, nr, false, 0)
	}()

	time.Sleep(500 * time.Millisecond)
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("drain: %v", err)
	}

	fake.mu.Lock()
	logCount := len(fake.logs)
	fake.mu.Unlock()

	if logCount != 2 {
		t.Fatalf("got %d logs, want 2", logCount)
	}

	// Checkpoint should have advanced
	stats := q.Stats()
	if stats.Inflight != 0 {
		t.Fatalf("inflight %d, want 0 (checkpoint should have advanced)", stats.Inflight)
	}
}

func TestDrainFailureLeavesPrefixUnacknowledged(t *testing.T) {
	dir := t.TempDir()
	qcfg := shipper.QueueConfig{
		Dir:          filepath.Join(dir, "queue"),
		SegmentBytes: 1 << 20,
		MaxBytes:     10 << 20,
		RoleBytes:    map[shipper.Role]int64{shipper.RoleBait: 10 << 20},
		MaxPayload:   telemetry.MinPayloadBytes - shipper.FrameHeader,
	}
	q, _, err := shipper.OpenQueue(qcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	// Enqueue three records
	var items []shipper.Item
	for i := 1; i <= 3; i++ {
		rec := telemetry.Record{
			ID: fmt.Sprintf("0123456789abcdef-%d", i),
			Event: &telemetry.Event{
				Stream:    telemetry.StreamEdge,
				Action:    fmt.Sprintf("test%d", i),
				Timestamp: time.Now(),
			},
		}
		data, _ := json.Marshal(rec)
		items = append(items, shipper.Item{Role: shipper.RoleBait, Data: data})
	}
	if _, err := q.Append(items); err != nil {
		t.Fatal(err)
	}

	fake := &fakeNewRelic{t: t, failNext: 1} // fail the first POST
	srv := httptest.NewServer(fake)
	defer srv.Close()

	nr, err := telemetry.NewNewRelic(telemetry.NRConfig{
		LicenseKey: "0123456789abcdef0123456789abcdef01234567",
		LogURL:     srv.URL,
		MetricURL:  srv.URL,
		QueueSize:  100,
		Now:        time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer nr.Close(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- drain(ctx, q, nr, false, 0)
	}()

	time.Sleep(500 * time.Millisecond)
	cancel()
	<-done

	// First record retries after 1s backoff and succeeds before the 1s mark,
	// so it's accepted before full cancellation and should be Ack'd.
	// Records 2 and 3 were never attempted, so they remain unacknowledged.
	q2, rec2, err := shipper.OpenQueue(qcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer q2.Close()

	if rec2.Uncertain {
		t.Fatal("unexpected uncertain recovery")
	}

	entries, err := q2.Read(10, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d unacknowledged entries, want 2 (first was accepted before cancel)", len(entries))
	}
}

func TestDrainAcksAcceptedPrefixBeforeRewind(t *testing.T) {
	dir := t.TempDir()
	qcfg := shipper.QueueConfig{
		Dir:          filepath.Join(dir, "queue"),
		SegmentBytes: 1 << 20,
		MaxBytes:     10 << 20,
		RoleBytes:    map[shipper.Role]int64{shipper.RoleBait: 10 << 20},
		MaxPayload:   telemetry.MinPayloadBytes - shipper.FrameHeader,
	}
	q, _, err := shipper.OpenQueue(qcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	// Enqueue two records
	var items []shipper.Item
	for i := 1; i <= 2; i++ {
		rec := telemetry.Record{
			ID: fmt.Sprintf("ack-before-rewind-%d", i),
			Event: &telemetry.Event{
				Stream:    telemetry.StreamEdge,
				Action:    fmt.Sprintf("test%d", i),
				Timestamp: time.Now(),
			},
		}
		data, _ := json.Marshal(rec)
		items = append(items, shipper.Item{Role: shipper.RoleBait, Data: data})
	}
	if _, err := q.Append(items); err != nil {
		t.Fatal(err)
	}

	// First POST succeeds, all subsequent POSTs fail
	var postCount atomic.Int32
	fake := &fakeNewRelic{t: t}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := postCount.Add(1)
		if count == 1 {
			// First POST succeeds
			fake.ServeHTTP(w, r)
			return
		}
		// All subsequent POSTs fail
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	nr, err := telemetry.NewNewRelic(telemetry.NRConfig{
		LicenseKey: "0123456789abcdef0123456789abcdef01234567",
		LogURL:     srv.URL,
		MetricURL:  srv.URL,
		QueueSize:  100,
		Now:        time.Now,
		Backoff:    []time.Duration{100 * time.Millisecond, 100 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer nr.Close(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- drain(ctx, q, nr, false, 0)
	}()

	// Wait for retries to complete (~300ms total)
	time.Sleep(500 * time.Millisecond)
	cancel()
	<-done

	// Record 1 should be delivered and Ack'd, record 2 should replay
	fake.mu.Lock()
	delivered := len(fake.logs)
	fake.mu.Unlock()

	if delivered != 1 {
		t.Fatalf("got %d delivered logs, want 1 (only first record)", delivered)
	}

	q2, rec2, err := shipper.OpenQueue(qcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer q2.Close()

	if rec2.Uncertain {
		t.Fatal("unexpected uncertain recovery")
	}

	entries, err := q2.Read(10, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d unacknowledged entries, want 1 (record 2 should replay, not record 1)", len(entries))
	}

	// Verify the replayed record is 2, not 1
	var rec telemetry.Record
	json.Unmarshal(entries[0].Data, &rec)
	if rec.Event == nil || rec.Event.Action != "test2" {
		t.Fatalf("replayed record action %q, want test2", rec.Event.Action)
	}
}

func TestUncertainRecoveryEmitsGap(t *testing.T) {
	dir := t.TempDir()
	qcfg := shipper.QueueConfig{
		Dir:          filepath.Join(dir, "queue"),
		SegmentBytes: 1 << 20,
		MaxBytes:     10 << 20,
		RoleBytes:    map[shipper.Role]int64{shipper.RoleBait: 10 << 20},
		MaxPayload:   telemetry.MinPayloadBytes - shipper.FrameHeader,
	}
	q, _, err := shipper.OpenQueue(qcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	// Enqueue one metric
	rec := telemetry.Record{
		ID: "0123456789abcdef-1",
		Metric: &telemetry.MetricRecord{
			Name:  "attackbox.test_counter",
			Kind:  "count",
			Value: 5,
			At:    time.Now(),
		},
	}
	data, _ := json.Marshal(rec)
	seqs, err := q.Append([]shipper.Item{{Role: shipper.RoleBait, Data: data}})
	if err != nil {
		t.Fatal(err)
	}

	// Close and corrupt the checkpoint to trigger uncertain recovery
	q.Close()
	os.Remove(filepath.Join(dir, "queue", "checkpoint"))

	// Reopen
	q2, rec2, err := shipper.OpenQueue(qcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer q2.Close()

	if !rec2.Uncertain {
		t.Fatal("expected uncertain recovery")
	}

	fake := &fakeNewRelic{t: t}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	nr, err := telemetry.NewNewRelic(telemetry.NRConfig{
		LicenseKey: "0123456789abcdef0123456789abcdef01234567",
		LogURL:     srv.URL,
		MetricURL:  srv.URL,
		QueueSize:  100,
		Now:        time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer nr.Close(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- drain(ctx, q2, nr, rec2.Uncertain, seqs[0])
	}()

	time.Sleep(500 * time.Millisecond)
	cancel()
	<-done

	fake.mu.Lock()
	defer fake.mu.Unlock()

	// Should have metric_replay_gap
	found := false
	for _, m := range fake.metrics {
		if m.Name == "attackbox.metric_replay_gap" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("metric_replay_gap not emitted")
	}

	// Original metric should NOT be delivered (suppressed)
	for _, m := range fake.metrics {
		if m.Name == "attackbox.test_counter" {
			t.Fatal("uncertain metric was not suppressed")
		}
	}
}

func TestChunkPreservation(t *testing.T) {
	dir := t.TempDir()
	qcfg := shipper.QueueConfig{
		Dir:          filepath.Join(dir, "queue"),
		SegmentBytes: 1 << 20,
		MaxBytes:     10 << 20,
		RoleBytes:    map[shipper.Role]int64{shipper.RoleBait: 10 << 20},
		MaxPayload:   telemetry.MinPayloadBytes - shipper.FrameHeader,
	}
	q, _, err := shipper.OpenQueue(qcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	// Create a large body that will be chunked
	largeBody := ""
	for i := range 20000 {
		largeBody += string(byte('a' + i%26))
	}
	expectedSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(largeBody)))

	rec := telemetry.Record{
		ID: "0123456789abcdef-1",
		Event: &telemetry.Event{
			Stream:    telemetry.StreamEdge,
			Action:    "large_test",
			Body:      largeBody,
			Timestamp: time.Now(),
		},
	}
	data, _ := json.Marshal(rec)
	if _, err := q.Append([]shipper.Item{{Role: shipper.RoleBait, Data: data}}); err != nil {
		t.Fatal(err)
	}

	fake := &fakeNewRelic{t: t}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	nr, err := telemetry.NewNewRelic(telemetry.NRConfig{
		LicenseKey: "0123456789abcdef0123456789abcdef01234567",
		LogURL:     srv.URL,
		MetricURL:  srv.URL,
		QueueSize:  100,
		Now:        time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer nr.Close(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- drain(ctx, q, nr, false, 0)
	}()

	time.Sleep(500 * time.Millisecond)
	cancel()
	<-done

	fake.mu.Lock()
	defer fake.mu.Unlock()

	// Should have multiple chunks
	if len(fake.logs) < 2 {
		t.Fatalf("expected at least 2 chunks, got %d", len(fake.logs))
	}

	// All chunks should have the same body_sha256 matching the original
	var bodySHA256 string
	for i, log := range fake.logs {
		if i == 0 {
			bodySHA256 = log.BodySHA256
			if bodySHA256 == "" {
				t.Fatal("first chunk missing body_sha256")
			}
			if bodySHA256 != expectedSHA {
				t.Fatalf("body_sha256 %q does not match actual SHA-256 %q", bodySHA256, expectedSHA)
			}
		} else {
			if log.BodySHA256 != bodySHA256 {
				t.Fatalf("chunk %d has body_sha256 %q, want %q", i, log.BodySHA256, bodySHA256)
			}
		}
		if log.ChunkCount != len(fake.logs) {
			t.Fatalf("chunk %d has chunk_count %d, want %d", i, log.ChunkCount, len(fake.logs))
		}
		if log.ChunkIndex != i {
			t.Fatalf("chunk %d has chunk_index %d", i, log.ChunkIndex)
		}
	}
}

func TestDecodeRegression(t *testing.T) {
	// This test would have passed with the old buggy decode that unmarshaled
	// into shipper.Admitted instead of telemetry.Record, because shipper.Admitted
	// also has a Record field. But the Record field would be nil, so no events
	// would be delivered. This test verifies that events ARE delivered.
	dir := t.TempDir()
	qcfg := shipper.QueueConfig{
		Dir:          filepath.Join(dir, "queue"),
		SegmentBytes: 1 << 20,
		MaxBytes:     10 << 20,
		RoleBytes:    map[shipper.Role]int64{shipper.RoleBait: 10 << 20},
		MaxPayload:   telemetry.MinPayloadBytes - shipper.FrameHeader,
	}
	q, _, err := shipper.OpenQueue(qcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	rec := telemetry.Record{
		ID: "0123456789abcdef-1",
		Event: &telemetry.Event{
			Stream:    telemetry.StreamEdge,
			Action:    "regression_test",
			Timestamp: time.Now(),
		},
	}
	data, _ := json.Marshal(rec)
	if _, err := q.Append([]shipper.Item{{Role: shipper.RoleBait, Data: data}}); err != nil {
		t.Fatal(err)
	}

	fake := &fakeNewRelic{t: t}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	nr, err := telemetry.NewNewRelic(telemetry.NRConfig{
		LicenseKey: "0123456789abcdef0123456789abcdef01234567",
		LogURL:     srv.URL,
		MetricURL:  srv.URL,
		QueueSize:  100,
		Now:        time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer nr.Close(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- drain(ctx, q, nr, false, 0)
	}()

	time.Sleep(500 * time.Millisecond)
	cancel()
	<-done

	fake.mu.Lock()
	delivered := len(fake.logs)
	fake.mu.Unlock()

	if delivered == 0 {
		t.Fatal("REGRESSION: event was not delivered (decode bug reproduced)")
	}
	if delivered != 1 {
		t.Fatalf("expected 1 event, got %d", delivered)
	}
}

func TestShipperIntegration(t *testing.T) {
	dir := t.TempDir()
	qcfg := shipper.QueueConfig{
		Dir:          filepath.Join(dir, "queue"),
		SegmentBytes: 1 << 20,
		MaxBytes:     10 << 20,
		RoleBytes:    map[shipper.Role]int64{shipper.RoleBait: 10 << 20},
		MaxPayload:   telemetry.MinPayloadBytes - shipper.FrameHeader,
	}
	q, _, err := shipper.OpenQueue(qcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	// Enqueue one log and one metric
	logRec := telemetry.Record{
		ID: "log-integration-test",
		Event: &telemetry.Event{
			Stream:    telemetry.StreamEdge,
			Action:    "integration_test",
			Timestamp: time.Now(),
		},
	}
	metricRec := telemetry.Record{
		ID: "metric-integration-test",
		Metric: &telemetry.MetricRecord{
			Name:  "test.counter",
			Kind:  "count",
			Value: 42,
			At:    time.Now(),
		},
	}
	logData, _ := json.Marshal(logRec)
	metricData, _ := json.Marshal(metricRec)

	if _, err := q.Append([]shipper.Item{
		{Role: shipper.RoleBait, Data: logData},
		{Role: shipper.RoleBait, Data: metricData},
	}); err != nil {
		t.Fatal(err)
	}

	fake := &fakeNewRelic{t: t}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	nr, err := telemetry.NewNewRelic(telemetry.NRConfig{
		LicenseKey: "0123456789abcdef0123456789abcdef01234567",
		LogURL:     srv.URL,
		MetricURL:  srv.URL,
		QueueSize:  100,
		Now:        time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer nr.Close(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- drain(ctx, q, nr, false, 0)
	}()

	time.Sleep(500 * time.Millisecond)
	cancel()
	<-done

	fake.mu.Lock()
	logCount := len(fake.logs)
	metricCount := len(fake.metrics)
	fake.mu.Unlock()

	if logCount != 1 {
		t.Errorf("got %d logs, want 1", logCount)
	}
	if metricCount != 1 {
		t.Errorf("got %d metrics, want 1", metricCount)
	}

	// Verify checkpoint advanced
	if q.Stats().Inflight != 0 {
		t.Error("expected inflight=0 after delivery")
	}
}

func TestSixStreams(t *testing.T) {
	dir := t.TempDir()
	qcfg := shipper.QueueConfig{
		Dir:          filepath.Join(dir, "queue"),
		SegmentBytes: 1 << 20,
		MaxBytes:     10 << 20,
		RoleBytes: map[shipper.Role]int64{
			shipper.RoleBait:    10 << 20,
			shipper.RoleRuntime: 10 << 20,
			shipper.RoleEgress:  10 << 20,
		},
		MaxPayload: telemetry.MinPayloadBytes - shipper.FrameHeader,
	}
	q, _, err := shipper.OpenQueue(qcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	now := time.Now()
	// Use valid role/action combinations through shipper.Admit
	streamTests := []struct {
		role   shipper.Role
		stream string
		action string
	}{
		{shipper.RoleBait, telemetry.StreamEdge, "request"},
		{shipper.RoleBait, telemetry.StreamTranscript, "transcript"},
		{shipper.RoleBait, telemetry.StreamProbe, "probe_start"},
		{shipper.RoleEgress, telemetry.StreamEgress, "egress_blocked"},
		{shipper.RoleRuntime, telemetry.StreamRuntime, "falco"},
		{shipper.RoleBait, telemetry.StreamHeartbeat, "bait_heartbeat"},
	}

	for i, st := range streamTests {
		rec := telemetry.Record{
			ID: fmt.Sprintf("0123456789abcdef-%d", i+1),
			Event: &telemetry.Event{
				Stream:    st.stream,
				Action:    st.action,
				Timestamp: now,
			},
		}
		line, _ := json.Marshal(rec)
		admitted, err := shipper.Admit(st.role, line, now)
		if err != nil {
			t.Fatalf("admit %s/%s: %v", st.stream, st.action, err)
		}
		if _, err := q.Append([]shipper.Item{{Role: st.role, Data: admitted.Data}}); err != nil {
			t.Fatal(err)
		}
	}

	fake := &fakeNewRelic{t: t}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	nr, err := telemetry.NewNewRelic(telemetry.NRConfig{
		LicenseKey: "0123456789abcdef0123456789abcdef01234567",
		LogURL:     srv.URL,
		MetricURL:  srv.URL,
		QueueSize:  100,
		Now:        time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer nr.Close(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- drain(ctx, q, nr, false, 0)
	}()

	time.Sleep(500 * time.Millisecond)
	cancel()
	<-done

	fake.mu.Lock()
	receivedStreams := make(map[string]int)
	for _, e := range fake.logs {
		receivedStreams[e.Stream]++
	}
	fake.mu.Unlock()

	expectedStreams := []string{
		telemetry.StreamEdge,
		telemetry.StreamTranscript,
		telemetry.StreamProbe,
		telemetry.StreamEgress,
		telemetry.StreamRuntime,
		telemetry.StreamHeartbeat,
	}
	for _, stream := range expectedStreams {
		if receivedStreams[stream] != 1 {
			t.Errorf("stream %s: got %d events, want 1", stream, receivedStreams[stream])
		}
	}

	if len(fake.logs) != 6 {
		t.Errorf("got %d total events, want 6", len(fake.logs))
	}
}

func TestFullMetric(t *testing.T) {
	dir := t.TempDir()
	qcfg := shipper.QueueConfig{
		Dir:          filepath.Join(dir, "queue"),
		SegmentBytes: 1 << 20,
		MaxBytes:     10 << 20,
		RoleBytes: map[shipper.Role]int64{
			shipper.RoleBait:   10 << 20,
			shipper.RoleEgress: 10 << 20,
		},
		MaxPayload: telemetry.MinPayloadBytes - shipper.FrameHeader,
	}
	q, _, err := shipper.OpenQueue(qcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	now := time.Now()
	// 10 bait metrics through shipper.Admit with RoleBait
	baitMetrics := []struct {
		name string
		kind string
	}{
		{"attackbox.requests", "count"},
		{"attackbox.sessions", "count"},
		{"attackbox.request_bytes", "count"},
		{"attackbox.response_bytes", "count"},
		{"attackbox.probes", "count"},
		{"attackbox.probe_followups", "count"},
		{"attackbox.session_duration_seconds", "gauge"},
		{"attackbox.stream_disconnect_seconds", "gauge"},
		{"attackbox.retry_delay_seconds", "gauge"},
		{"attackbox.concurrent_status_requests", "gauge"},
	}
	for i, m := range baitMetrics {
		rec := telemetry.Record{
			ID: fmt.Sprintf("fedcba9876543210-%d", i+1),
			Metric: &telemetry.MetricRecord{
				Name:  m.name,
				Kind:  m.kind,
				Value: 1,
				At:    now,
			},
		}
		line, _ := json.Marshal(rec)
		admitted, err := shipper.Admit(shipper.RoleBait, line, now)
		if err != nil {
			t.Fatalf("admit %s: %v", m.name, err)
		}
		if _, err := q.Append([]shipper.Item{{Role: shipper.RoleBait, Data: admitted.Data}}); err != nil {
			t.Fatal(err)
		}
	}

	// 1 egress metric through shipper.Admit with RoleEgress
	egressRec := telemetry.Record{
		ID: "fedcba9876543210-99",
		Metric: &telemetry.MetricRecord{
			Name:  "attackbox.egress_blocked",
			Kind:  "count",
			Value: 1,
			At:    now,
		},
	}
	egressLine, _ := json.Marshal(egressRec)
	egressAdmitted, err := shipper.Admit(shipper.RoleEgress, egressLine, now)
	if err != nil {
		t.Fatalf("admit egress_blocked: %v", err)
	}
	if _, err := q.Append([]shipper.Item{{Role: shipper.RoleEgress, Data: egressAdmitted.Data}}); err != nil {
		t.Fatal(err)
	}

	fake := &fakeNewRelic{t: t}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	nr, err := telemetry.NewNewRelic(telemetry.NRConfig{
		LicenseKey: "0123456789abcdef0123456789abcdef01234567",
		LogURL:     srv.URL,
		MetricURL:  srv.URL,
		QueueSize:  100,
		Now:        time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer nr.Close(context.Background())

	// Exercise sink self metrics directly (not through queue)
	nr.ShipMetric("attackbox.telemetry.ingest_errors_total", "count", 0, now, nil)
	nr.ShipMetric("attackbox.telemetry.ingest_retries_total", "count", 0, now, nil)
	nr.ShipMetric("attackbox.heartbeat", "gauge", 1, now, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- drain(ctx, q, nr, false, 0)
	}()

	time.Sleep(500 * time.Millisecond)
	cancel()
	<-done

	fake.mu.Lock()
	receivedMetrics := make(map[string]int)
	for _, m := range fake.metrics {
		receivedMetrics[m.Name]++
	}
	fake.mu.Unlock()

	// Verify all 14 metrics were received
	expectedMetrics := []string{
		"attackbox.requests",
		"attackbox.sessions",
		"attackbox.request_bytes",
		"attackbox.response_bytes",
		"attackbox.probes",
		"attackbox.probe_followups",
		"attackbox.session_duration_seconds",
		"attackbox.stream_disconnect_seconds",
		"attackbox.retry_delay_seconds",
		"attackbox.concurrent_status_requests",
		"attackbox.egress_blocked",
		"attackbox.telemetry.ingest_errors_total",
		"attackbox.telemetry.ingest_retries_total",
		"attackbox.heartbeat",
	}
	for _, name := range expectedMetrics {
		if receivedMetrics[name] != 1 {
			t.Errorf("metric %s: got %d, want 1", name, receivedMetrics[name])
		}
	}

	if len(fake.metrics) != 14 {
		t.Errorf("got %d total metrics, want 14", len(fake.metrics))
	}
}
