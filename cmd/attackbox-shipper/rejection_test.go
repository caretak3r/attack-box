package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
)

type rejectStoreFunc func(shipper.Entry, string) error

func (f rejectStoreFunc) Put(e shipper.Entry, s string) error { return f(e, s) }

func rejectionClient(t *testing.T, handler func([]byte) int) *telemetry.NewRelic {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		z, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		defer z.Close()
		body, err := io.ReadAll(z)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(handler(body))
	}))
	t.Cleanup(srv.Close)
	nr, err := telemetry.NewNewRelic(telemetry.NRConfig{
		LicenseKey: "0123456789abcdef0123456789abcdef01234567", LogURL: srv.URL, MetricURL: srv.URL,
		HeartbeatInterval: -1, FlushInterval: time.Hour, Backoff: []time.Duration{}, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nr.Close(context.Background()) })
	return nr
}

func rejectionEntries(t *testing.T) []shipper.Entry {
	t.Helper()
	entries := []shipper.Entry{eventEntry(t, 1), eventEntry(t, 2), eventEntry(t, 3)}
	var rec telemetry.Record
	if err := json.Unmarshal(entries[1].Data, &rec); err != nil {
		t.Fatal(err)
	}
	rec.Event.Action = "poison"
	rec.Event.Body = "original synthetic evidence"
	entries[1].Data, _ = json.Marshal(rec)
	return entries
}

func TestRejectedRecordDoesNotBlockHealthyRecordsAndCrashReplay(t *testing.T) {
	dir := t.TempDir()
	qc := shipper.QueueConfig{Dir: filepath.Join(dir, "queue"), SegmentBytes: 1 << 20, MaxBytes: 8 << 20, MaxPayload: 1 << 20}
	q, _, err := shipper.OpenQueue(qc)
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := shipper.OpenQuarantine(filepath.Join(qc.Dir, "quarantine"))
	if err != nil {
		t.Fatal(err)
	}
	entries := rejectionEntries(t)
	for _, e := range entries {
		if _, err := q.Append([]shipper.Item{{Role: e.Role, Data: e.Data}}); err != nil {
			t.Fatal(err)
		}
	}
	var accepted atomic.Int64
	nr := rejectionClient(t, func(body []byte) int {
		if strings.Contains(string(body), "poison") {
			return 400
		}
		accepted.Add(1)
		return 202
	})
	for attempt := 0; attempt < 2; attempt++ {
		pending, err := q.Read(10, 1<<20)
		if err != nil || len(pending) != 3 {
			t.Fatalf("read=%d err=%v", len(pending), err)
		}
		n, blocked, err := deliver(context.Background(), nr, pending, 0, rejected)
		if n != 3 || blocked || err != nil {
			t.Fatalf("n=%d blocked=%v err=%v", n, blocked, err)
		}
		if count, _ := rejected.Stats(); count != 1 {
			t.Fatalf("quarantine count=%d", count)
		}
		if attempt == 1 {
			if err := q.Ack(n); err != nil {
				t.Fatal(err)
			}
		}
		// First close intentionally leaves the queue checkpoint behind the
		// quarantine receipt, the crash window that must not duplicate storage.
		q.Close()
		rejected.Close()
		q, _, err = shipper.OpenQueue(qc)
		if err != nil {
			t.Fatal(err)
		}
		rejected, err = shipper.OpenQuarantine(filepath.Join(qc.Dir, "quarantine"))
		if err != nil {
			t.Fatal(err)
		}
	}
	defer q.Close()
	defer rejected.Close()
	if q.Stats().Total != 0 || accepted.Load() != 4 {
		t.Fatalf("backlog=%d accepted=%d", q.Stats().Total, accepted.Load())
	}
	files, err := filepath.Glob(filepath.Join(qc.Dir, "quarantine", "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("files=%v err=%v", files, err)
	}
}

func TestQuarantineFailureKeepsContiguousAcknowledgement(t *testing.T) {
	entries := rejectionEntries(t)
	nr := rejectionClient(t, func(body []byte) int {
		if strings.Contains(string(body), "poison") {
			return 422
		}
		return 202
	})
	full := errors.New("disk full")
	store := rejectStoreFunc(func(e shipper.Entry, reason string) error {
		if e.Seq != 2 || reason != "http_422" {
			t.Fatal(e.Seq, reason)
		}
		return full
	})
	n, blocked, err := deliver(context.Background(), nr, entries, 0, store)
	if n != 1 || blocked || !errors.Is(err, full) {
		t.Fatalf("n=%d blocked=%v err=%v", n, blocked, err)
	}
}

func TestAccountAndOutageErrorsNeverQuarantine(t *testing.T) {
	for _, code := range []int{401, 403, 404, 408, 429, 500, 503} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var recovered atomic.Bool
			nr := rejectionClient(t, func([]byte) int {
				if recovered.Load() {
					return 202
				}
				return code
			})
			store := rejectStoreFunc(func(shipper.Entry, string) error { t.Fatal("account/outage quarantined"); return nil })
			entries := rejectionEntries(t)
			n, blocked, err := deliver(context.Background(), nr, entries, 0, store)
			if n != 0 || !blocked || err != nil {
				t.Fatalf("n=%d blocked=%v err=%v", n, blocked, err)
			}
			recovered.Store(true)
			n, blocked, err = deliver(context.Background(), nr, entries, 0, store)
			if n != 3 || blocked || err != nil {
				t.Fatalf("recovery n=%d blocked=%v err=%v", n, blocked, err)
			}
		})
	}
}

func TestDrainCheckpointsOnlyAfterQuarantineReceipt(t *testing.T) {
	entries := rejectionEntries(t)
	q := &fakeQueue{batches: [][]shipper.Entry{entries}}
	nr := rejectionClient(t, func(body []byte) int {
		if strings.Contains(string(body), "poison") {
			return 400
		}
		return 202
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := rejectStoreFunc(func(e shipper.Entry, reason string) error { cancel(); return errors.New("fsync failed") })
	err := drain(ctx, q, nr, false, 0, store)
	_, acked := q.snapshot()
	if err == nil || acked != 1 {
		t.Fatalf("ack=%d err=%v", acked, err)
	}
}
