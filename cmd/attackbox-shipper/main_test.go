package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
)

func TestQuietAdapterHeartbeat(t *testing.T) {
	for _, role := range []string{"runtime", "egress"} {
		t.Run(role, func(t *testing.T) {
			dir, err := os.MkdirTemp("/tmp", "abx-beat-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			path := filepath.Join(dir, "s")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			_ = listener.(*net.UnixListener).SetDeadline(time.Now().Add(3 * time.Second))
			input, writer := io.Pipe()
			defer input.Close()
			defer writer.Close()
			done := make(chan error, 1)
			go func() { done <- runAdapter(role, func(string) string { return path }, input, io.Discard) }()
			conn, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			var record telemetry.Record
			if err := json.NewDecoder(conn).Decode(&record); err != nil {
				t.Fatal(err)
			}
			if record.Event == nil || record.Event.Stream != telemetry.StreamHeartbeat || record.Event.Action != role+"_heartbeat" {
				t.Fatalf("wrong quiet adapter heartbeat: %+v", record.Event)
			}
			_ = writer.Close()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("adapter did not stop on EOF")
			}
		})
	}
}

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
				if msg, ok := attrs["body_chunk"].(string); ok {
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

func TestDrainAcceptedBatchAfterCancellationIsAcknowledged(t *testing.T) {
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

	// All three records share one POST. Its retry can complete after the
	// drain context is canceled. Confirmed acceptance still checkpoints all
	// three; cancellation must not split an accepted batch.
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
	if len(entries) != 0 {
		t.Fatalf("got %d unacknowledged entries, want 0 after full batch acceptance", len(entries))
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.logs) != 3 {
		t.Fatalf("accepted %d logs, want 3", len(fake.logs))
	}
}

func TestDrainPartialHTTPBatchReplaysAllRecords(t *testing.T) {
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

	// Enqueue one log and one metric, forcing two HTTP signal requests.
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
		if i == 2 {
			rec.Event = nil
			rec.Metric = &telemetry.MetricRecord{Name: "attackbox.requests", Kind: "count", Value: 1, At: time.Now()}
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

	// The log POST succeeded but the metric POST failed. Both records must
	// replay because the batch has not been fully accepted.
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
	if len(entries) != 2 {
		t.Fatalf("got %d unacknowledged entries, want 2 after partial batch failure", len(entries))
	}

	// Replay starts with the accepted log; its stable record ID permits dedup.
	var rec telemetry.Record
	json.Unmarshal(entries[0].Data, &rec)
	if rec.Event == nil || rec.Event.Action != "test1" {
		t.Fatalf("replayed record action %q, want test1", rec.Event.Action)
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

const testLicenseKey = "0123456789abcdef0123456789abcdef01234567"

// shortDir returns a directory under /tmp: socket paths are limited to about
// 100 bytes and t.TempDir can exceed that.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "abs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func testEnv(t *testing.T, extra map[string]string) func(string) string {
	t.Helper()
	dir := shortDir(t)
	env := map[string]string{
		"ATTACKBOX_SHIP_QUEUE_DIR":        filepath.Join(dir, "queue"),
		"ATTACKBOX_NR_LICENSE_KEY":        testLicenseKey,
		"ATTACKBOX_SPOOL_SOCKET":          filepath.Join(dir, "spool.sock"),
		"ATTACKBOX_RUNTIME_SOCKET":        filepath.Join(dir, "runtime.sock"),
		"ATTACKBOX_EGRESS_SOCKET":         filepath.Join(dir, "egress.sock"),
		"ATTACKBOX_SHIP_SHUTDOWN_TIMEOUT": "1s",
	}
	for k, v := range extra {
		env[k] = v
	}
	return func(k string) string { return env[k] }
}

// Every optional socket set: the burst of each must clear MaxLine, or
// NewIngest refuses the whole config at startup.
func TestLoadConfigAllSocketsBindsIngest(t *testing.T) {
	cfg, err := loadConfig(testEnv(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.endpoints) != 3 {
		t.Fatalf("got %d endpoints, want 3", len(cfg.endpoints))
	}
	q, _, err := shipper.OpenQueue(queueConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	ing, err := shipper.NewIngest(shipper.IngestConfig{Endpoints: cfg.endpoints, Queue: q})
	if err != nil {
		t.Fatalf("NewIngest: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ing.Serve(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestLoadConfigRejectsQueueBelowOneMaxFramePerRole(t *testing.T) {
	_, err := loadConfig(testEnv(t, map[string]string{"ATTACKBOX_SHIP_QUEUE_BYTES": "16777216"}))
	if err == nil || !strings.Contains(err.Error(), "ATTACKBOX_SHIP_QUEUE_BYTES") {
		t.Fatalf("got %v, want a queue size error", err)
	}
}

func TestLoadConfigSensorAndDeploymentID(t *testing.T) {
	max63 := strings.Repeat("a", 63)
	cases := []struct {
		name           string
		env            map[string]string
		sensor, deploy string
		errFor         string // setting named in the error; "" means none
	}{
		{"defaults", map[string]string{"HOSTNAME": "bait-01"}, "bait-01", "unset", ""},
		{"host name lower-cased", map[string]string{"HOSTNAME": "Bait-01.Lab"}, "bait-01.lab", "unset", ""},
		{"host name breaks the rule", map[string]string{"HOSTNAME": "bait_01!"}, "attackbox", "unset", ""},
		{"host name leads with a dash", map[string]string{"HOSTNAME": "-bait"}, "attackbox", "unset", ""},
		{"host name too long", map[string]string{"HOSTNAME": strings.Repeat("a", 64)}, "attackbox", "unset", ""},
		{"explicit values", map[string]string{"HOSTNAME": "bait-01", "ATTACKBOX_SENSOR_ID": "edge.eu-1_a", "ATTACKBOX_DEPLOYMENT_ID": "build-42"}, "edge.eu-1_a", "build-42", ""},
		{"explicit sensor beats a bad host name", map[string]string{"HOSTNAME": "Bad Host", "ATTACKBOX_SENSOR_ID": "s1"}, "s1", "unset", ""},
		{"longest valid", map[string]string{"ATTACKBOX_SENSOR_ID": max63, "ATTACKBOX_DEPLOYMENT_ID": max63}, max63, max63, ""},
		{"sensor upper case", map[string]string{"ATTACKBOX_SENSOR_ID": "Sensor"}, "", "", "ATTACKBOX_SENSOR_ID"},
		{"sensor leading dot", map[string]string{"ATTACKBOX_SENSOR_ID": ".s"}, "", "", "ATTACKBOX_SENSOR_ID"},
		{"sensor space", map[string]string{"ATTACKBOX_SENSOR_ID": "a b"}, "", "", "ATTACKBOX_SENSOR_ID"},
		{"sensor too long", map[string]string{"ATTACKBOX_SENSOR_ID": strings.Repeat("a", 64)}, "", "", "ATTACKBOX_SENSOR_ID"},
		{"deployment upper case", map[string]string{"ATTACKBOX_DEPLOYMENT_ID": "Build"}, "", "", "ATTACKBOX_DEPLOYMENT_ID"},
		{"deployment slash", map[string]string{"ATTACKBOX_DEPLOYMENT_ID": "a/b"}, "", "", "ATTACKBOX_DEPLOYMENT_ID"},
		{"deployment leading dash", map[string]string{"ATTACKBOX_DEPLOYMENT_ID": "-b"}, "", "", "ATTACKBOX_DEPLOYMENT_ID"},
		{"deployment too long", map[string]string{"ATTACKBOX_DEPLOYMENT_ID": strings.Repeat("a", 64)}, "", "", "ATTACKBOX_DEPLOYMENT_ID"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := loadConfig(testEnv(t, c.env))
			if c.errFor != "" {
				if err == nil || !strings.Contains(err.Error(), c.errFor+" must match") {
					t.Fatalf("got %v, want an error for %s", err, c.errFor)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.sensorID != c.sensor || cfg.deploymentID != c.deploy {
				t.Fatalf("sensor %q deployment %q, want %q %q", cfg.sensorID, cfg.deploymentID, c.sensor, c.deploy)
			}
		})
	}

	// Both settings broken: one error names each.
	_, err := loadConfig(testEnv(t, map[string]string{"ATTACKBOX_SENSOR_ID": "S", "ATTACKBOX_DEPLOYMENT_ID": "D"}))
	if err == nil || !strings.Contains(err.Error(), "ATTACKBOX_SENSOR_ID") || !strings.Contains(err.Error(), "ATTACKBOX_DEPLOYMENT_ID") {
		t.Fatalf("got %v, want both settings named", err)
	}
}

// The Common attributes of a real run reach New Relic with the sensor and
// deployment IDs.
func TestRunSendsSensorAndDeploymentCommonAttributes(t *testing.T) {
	commons := make(chan map[string]any, 16)
	nr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Content-Encoding") == "gzip" {
			if gr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
				body, _ = io.ReadAll(gr)
			}
		}
		var env []struct {
			Common struct {
				Attributes map[string]any `json:"attributes"`
			} `json:"common"`
		}
		if json.Unmarshal(body, &env) == nil {
			for _, e := range env {
				select {
				case commons <- e.Common.Attributes:
				default:
				}
			}
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer nr.Close()
	cfg, err := loadConfig(testEnv(t, map[string]string{
		"ATTACKBOX_NR_LOG_URL":    nr.URL + "/log/v1",
		"ATTACKBOX_NR_METRIC_URL": nr.URL + "/metric/v1",
		"ATTACKBOX_SENSOR_ID":     "sensor-7",
		"ATTACKBOX_DEPLOYMENT_ID": "build-9",
	}))
	if err != nil {
		t.Fatal(err)
	}
	cfg.endpoints[0].UIDs = []uint32{uint32(os.Getuid())} // the test is the bait

	ctx, cancel := context.WithCancel(context.Background())
	var stderr bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, &stderr) }()
	defer func() {
		cancel()
		<-done
	}()

	waitForSocket(t, cfg.endpoints[0].Path)
	c, err := net.Dial("unix", cfg.endpoints[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	line := fmt.Sprintf(`{"id":"0123456789abcdef-1","v":1,"event":{"stream":"edge","action":"request","timestamp":%q}}`+"\n", time.Now().Format(time.RFC3339Nano))
	if _, err := c.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-commons:
		if got["sensor_id"] != "sensor-7" || got["deployment_id"] != "build-9" || got["service.name"] != "attackbox" {
			t.Fatalf("common attributes = %v", got)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("no New Relic post\nstderr: %s", stderr.String())
	}
}

func TestNewShipperBoot(t *testing.T) {
	a, b := newShipperBoot(), newShipperBoot()
	for _, id := range []string{a, b} {
		if len(id) != 16 || strings.Trim(id, "0123456789abcdef") != "" {
			t.Fatalf("shipper boot %q is not 16 lowercase hex characters", id)
		}
	}
	if a == b {
		t.Fatalf("two shipper boots are both %q", a)
	}
}

// A run reports its accounting rows at start, on the log endpoint, with one
// shipper_boot on every row.
func TestRunSendsAccountingAtStart(t *testing.T) {
	reports := make(chan []map[string]any, 4)
	nr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if gr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
			body, _ = io.ReadAll(gr)
		}
		var env []struct {
			Logs []struct {
				Attributes map[string]any `json:"attributes"`
			} `json:"logs"`
		}
		if r.URL.Path == "/log/v1" && json.Unmarshal(body, &env) == nil && len(env) == 1 {
			var rows []map[string]any
			for _, l := range env[0].Logs {
				if l.Attributes["source"] == "shipper_accounting" {
					rows = append(rows, l.Attributes)
				}
			}
			if len(rows) > 0 {
				select {
				case reports <- rows:
				default:
				}
			}
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer nr.Close()
	cfg, err := loadConfig(testEnv(t, map[string]string{
		"ATTACKBOX_NR_LOG_URL":    nr.URL + "/log/v1",
		"ATTACKBOX_NR_METRIC_URL": nr.URL + "/metric/v1",
	}))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var stderr bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, &stderr) }()
	defer func() {
		cancel()
		<-done
	}()

	select {
	case rows := <-reports:
		roles := map[any]bool{}
		for _, row := range rows {
			boot, _ := row["shipper_boot"].(string)
			if len(boot) != 16 || strings.Trim(boot, "0123456789abcdef") != "" || boot != rows[0]["shipper_boot"] {
				t.Fatalf("row %v: shipper_boot %q", row["action"], boot)
			}
			if row["action"] == "ingest_stats" {
				roles[row["role"]] = true
			}
		}
		if len(roles) != len(cfg.endpoints) {
			t.Fatalf("ingest_stats rows cover roles %v, want %d roles", roles, len(cfg.endpoints))
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("no accounting report\nstderr: %s", stderr.String())
	}
}

// The largest record the admission layer lets through must be appendable on
// every role at the smallest allowed queue, not dropped as oversize.
func TestMaxAdmittedRecordIsAppendable(t *testing.T) {
	cfg, err := loadConfig(testEnv(t, map[string]string{
		"ATTACKBOX_SHIP_QUEUE_BYTES": strconv.FormatInt(minQueueBytes, 10),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.queueBytes != minQueueBytes {
		t.Fatalf("test queue size %d is not minQueueBytes %d", cfg.queueBytes, int64(minQueueBytes))
	}
	q, _, err := shipper.OpenQueue(queueConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	// '<' encodes as <: six bytes per body byte, the worst case.
	body := strings.Repeat("<", shipper.MaxBody)
	lines := map[shipper.Role]string{
		shipper.RoleBait:    `{"stream":"edge","action":"x","body":"` + body + `"}`,
		shipper.RoleRuntime: `{"stream":"runtime","action":"falco","body":"` + body + `"}`,
		shipper.RoleEgress:  `{"stream":"egress","action":"egress_blocked","body":"` + body + `"}`,
	}
	for role, ev := range lines {
		line := []byte(`{"id":"0123456789abcdef-1","v":1,"event":` + ev + `}`)
		a, err := shipper.Admit(role, line, time.Now())
		if err != nil {
			t.Fatalf("%s: Admit: %v", role, err)
		}
		if len(a.Data) <= telemetry.MinPayloadBytes {
			t.Fatalf("%s: record is %d bytes, not a large record", role, len(a.Data))
		}
		seqs, err := q.Append([]shipper.Item{{Role: a.Role, Data: a.Data}})
		if err != nil || seqs[0] == 0 {
			t.Fatalf("%s: Append of %d bytes: seq=%v err=%v (oversize=%d)", role, len(a.Data), seqs, err, q.Stats().Oversize[role])
		}
	}
}

// A graceful stop must return promptly with no error: both goroutines are
// started and both channels are read exactly once.
func TestRunGracefulShutdown(t *testing.T) {
	nr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }))
	defer nr.Close()
	cfg, err := loadConfig(testEnv(t, map[string]string{
		"ATTACKBOX_NR_LOG_URL":    nr.URL + "/log/v1",
		"ATTACKBOX_NR_METRIC_URL": nr.URL + "/metric/v1",
	}))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var stderr bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, &stderr) }()

	waitForSocket(t, cfg.endpoints[0].Path)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v on a graceful stop\nstderr: %s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after the context ended")
	}
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	waitFor(t, "socket "+path, func() bool {
		fi, err := os.Lstat(path)
		return err == nil && fi.Mode().Type() == os.ModeSocket
	})
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
			V:  telemetry.SchemaVersion,
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
			V:  telemetry.SchemaVersion,
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
		V:  telemetry.SchemaVersion,
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
