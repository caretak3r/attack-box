package telemetry

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

func batchClient(t *testing.T, handle func(string, []byte) int) *NewRelic {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		z, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("gzip: %v", err)
			w.WriteHeader(400)
			return
		}
		defer z.Close()
		body, err := io.ReadAll(z)
		if err != nil {
			t.Errorf("read: %v", err)
		}
		w.WriteHeader(handle(r.URL.Path, body))
	}))
	t.Cleanup(srv.Close)
	n := start(t, NRConfig{
		LicenseKey: testKey, LogURL: srv.URL + "/log/v1", MetricURL: srv.URL + "/metric/v1",
		FlushInterval: time.Hour, HeartbeatInterval: -1, Backoff: []time.Duration{},
		Now: func() time.Time { return time.Unix(1_800_000_020, 0) },
	})
	t.Cleanup(func() { closeNR(t, n) })
	return n
}

func TestShipRecordsBatchesMixedSignalsAndWindows(t *testing.T) {
	var mu sync.Mutex
	posts := map[string][][]byte{}
	n := batchClient(t, func(path string, b []byte) int {
		mu.Lock()
		posts[path] = append(posts[path], b)
		mu.Unlock()
		return 202
	})
	at := time.Unix(1_800_000_000, 0)
	var records []Record
	for i := 0; i < 50; i++ {
		records = append(records,
			Record{Event: &Event{Timestamp: at, Stream: StreamEdge, Action: "POST", Body: "evidence"}},
			Record{Metric: &MetricRecord{Name: "attackbox.requests", Kind: "count", Value: 1, At: at.Add(time.Duration(i) * time.Millisecond), Attrs: map[string]string{"persona": "openai", "src_ip": "discard"}}},
		)
	}
	if err := n.ShipRecords(records); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(posts["/log/v1"]) != 1 || len(posts["/metric/v1"]) != 1 {
		t.Fatalf("POST counts: logs=%d metrics=%d", len(posts["/log/v1"]), len(posts["/metric/v1"]))
	}
	var logs logPayload
	var metrics metricPayload
	if err := json.Unmarshal(posts["/log/v1"][0], &logs); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(posts["/metric/v1"][0], &metrics); err != nil {
		t.Fatal(err)
	}
	if len(logs[0].Logs) != 50 || len(metrics[0].Metrics) != 1 {
		t.Fatalf("items: logs=%d metrics=%d", len(logs[0].Logs), len(metrics[0].Metrics))
	}
	m := metrics[0].Metrics[0]
	if m.Value != 50 || m.IntervalMS != 1000 || m.Timestamp != at.UnixMilli() || len(m.Attributes) != 1 {
		t.Fatalf("count window: %+v", m)
	}
	a := logs[0].Logs[0].Attributes
	if a["export_lag_ms"] != float64(20_000) || a["export_attempt_at_ms"] != float64(n.cfg.Now().UnixMilli()) {
		t.Fatalf("export timing: %+v", a)
	}
	if records[0].Event.Attrs != nil {
		t.Fatal("exporter mutated caller's event")
	}
}

func TestDurableMetricWindowsStableAcrossReplay(t *testing.T) {
	at := time.Unix(1_800_000_000, 100_000_000)
	records := []Record{
		{Metric: &MetricRecord{Name: "counter", Kind: "count", Value: 2, At: at}},
		{Metric: &MetricRecord{Name: "counter", Kind: "count", Value: 3, At: at.Add(800 * time.Millisecond)}},
		{Metric: &MetricRecord{Name: "counter", Kind: "count", Value: 7, At: at.Add(time.Second)}},
		{Metric: &MetricRecord{Name: "gauge", Kind: "gauge", Value: 9, At: at}},
	}
	a, err := durableMetrics(records)
	if err != nil {
		t.Fatal(err)
	}
	b, err := durableMetrics(records)
	if err != nil || !reflect.DeepEqual(a, b) {
		t.Fatalf("replay changed windows: %v", err)
	}
	var got metricPayload
	if err := json.Unmarshal(envelope([]byte(`{"attributes":{}}`), "metrics", a...), &got); err != nil {
		t.Fatal(err)
	}
	m := got[0].Metrics
	if len(m) != 3 || m[0].Timestamp != at.UnixMilli() || m[0].IntervalMS != 0 || m[1].Value != 5 || m[2].Value != 7 || m[1].IntervalMS != 1000 || m[2].Timestamp-m[1].Timestamp != 1000 {
		t.Fatalf("unexpected windows: %+v", m)
	}
}

func TestShipRecordsByteBoundsAndOpaqueBody(t *testing.T) {
	var mu sync.Mutex
	var posts [][]byte
	n := batchClient(t, func(path string, b []byte) int {
		if path == "/log/v1" {
			mu.Lock()
			posts = append(posts, b)
			mu.Unlock()
		}
		return 202
	})
	n.cfg.MaxPayloadBytes = MinPayloadBytes
	body := `{"source":"shipper","trace.id":"forged","message":"` + strings.Repeat("界", 24_000) + `"}`
	sum := sha256.Sum256([]byte(body))
	if err := n.ShipRecords([]Record{{Event: &Event{Action: `{"source":"forged"}`, Body: body, Attrs: map[string]any{"source": "bait", "body_chunk": "forged"}}}}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(posts) < 2 {
		t.Fatal("expected multiple byte-bounded POSTs")
	}
	var rebuilt strings.Builder
	index := 0
	for _, p := range posts {
		if len(p) > MinPayloadBytes {
			t.Fatalf("payload exceeds cap: %d", len(p))
		}
		var logs logPayload
		if err := json.Unmarshal(p, &logs); err != nil {
			t.Fatal(err)
		}
		for _, l := range logs[0].Logs {
			chunk := l.Attributes["body_chunk"].(string)
			if !strings.HasPrefix(l.Message, "attackbox ") || json.Valid([]byte(l.Message)) || utf8.RuneCountInString(chunk) > MaxChunk {
				t.Fatalf("unsafe message/chunk: %q", l.Message)
			}
			if l.Attributes["source"] != "bait" || l.Attributes["chunk_index"] != float64(index) || l.Attributes["body_sha256"] != hex.EncodeToString(sum[:]) {
				t.Fatalf("identity changed: %+v", l.Attributes)
			}
			rebuilt.WriteString(chunk)
			index++
		}
	}
	if rebuilt.String() != body {
		t.Fatal("body did not reconstruct byte-for-byte")
	}
}

func TestShipRecordsPartialFailureReplaysEveryChunk(t *testing.T) {
	var mu sync.Mutex
	fail := true
	var accepted []string
	n := batchClient(t, func(path string, b []byte) int {
		mu.Lock()
		defer mu.Unlock()
		if path == "/metric/v1" && fail {
			return 503
		}
		if path == "/log/v1" {
			var p logPayload
			if err := json.Unmarshal(b, &p); err != nil {
				t.Error(err)
			}
			for _, l := range p[0].Logs {
				accepted = append(accepted, l.Attributes["body_chunk"].(string))
			}
		}
		return 202
	})
	records := []Record{
		{Event: &Event{Body: "base64:" + strings.Repeat("abcd", 2000), Timestamp: time.Unix(1_800_000_000, 0)}},
		{Metric: &MetricRecord{Name: "counter", Kind: "count", Value: 1, At: time.Unix(1_800_000_000, 0)}},
	}
	if err := n.ShipRecords(records); err == nil {
		t.Fatal("metric rejection must fail the entire batch")
	}
	mu.Lock()
	first := slices.Clone(accepted)
	fail = false
	mu.Unlock()
	if err := n.ShipRecords(records); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(first) == 0 || !reflect.DeepEqual(accepted, append(slices.Clone(first), first...)) {
		t.Fatal("replay lost or changed an already accepted chunk")
	}
}

func TestShipRecordsPartialLogPostsRetainAllRecordIdentities(t *testing.T) {
	var mu sync.Mutex
	post := 0
	seen := map[string]int{}
	n := batchClient(t, func(path string, b []byte) int {
		if path != "/log/v1" {
			return 202
		}
		mu.Lock()
		defer mu.Unlock()
		post++
		if post == 2 {
			return 503
		}
		var p logPayload
		if err := json.Unmarshal(b, &p); err != nil {
			t.Error(err)
		}
		for _, l := range p[0].Logs {
			seen[l.Attributes["record_id"].(string)]++
		}
		return 202
	})
	n.cfg.MaxPayloadBytes = MinPayloadBytes
	var records []Record
	for i := 0; i < 40; i++ {
		records = append(records, Record{Event: &Event{
			Timestamp: time.Unix(1_800_000_000, 0), Body: strings.Repeat("x", MaxChunk),
			Attrs: map[string]any{"record_id": "record-" + strconv.Itoa(i)},
		}})
	}
	if err := n.ShipRecords(records); err == nil {
		t.Fatal("partial log POST failure was hidden")
	}
	if err := n.ShipRecords(records); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != len(records) || seen["record-0"] != 2 {
		t.Fatalf("replay identities: %v", seen)
	}
	if st := n.Stats(); st.Lost != 0 {
		t.Fatalf("durable retry incorrectly counted as abandoned: %+v", st)
	}
}

func TestShipRecordsRefusesOversizedItemAndInvalidBatch(t *testing.T) {
	n := batchClient(t, func(string, []byte) int { return 202 })
	n.cfg.MaxPayloadBytes = MinPayloadBytes
	n.cfg.Common = map[string]any{"too_large": strings.Repeat("x", MinPayloadBytes)}
	if err := n.ShipRecords([]Record{{Event: &Event{Body: "retained"}}}); err == nil {
		t.Fatal("oversize item cannot be reported as accepted")
	}
	if n.Stats().Sent != 0 || n.Stats().Lost != 0 {
		t.Fatal("durable rejection must neither accept nor abandon an item")
	}
	if err := n.ShipRecords(make([]Record, MaxShipRecords+1)); err == nil {
		t.Fatal("unbounded batch accepted")
	}
	if err := n.ShipRecords([]Record{{}}); err == nil {
		t.Fatal("empty record accepted")
	}
}

func TestShipMetricCountHasWindow(t *testing.T) {
	var metric []byte
	n := batchClient(t, func(path string, b []byte) int {
		if path == "/metric/v1" {
			metric = append([]byte(nil), b...)
		}
		return 202
	})
	at := time.Unix(1_800_000_000, 900_000_000)
	if err := n.ShipMetric("counter", "count", 1, at, nil); err != nil {
		t.Fatal(err)
	}
	var p metricPayload
	if err := json.Unmarshal(metric, &p); err != nil {
		t.Fatal(err)
	}
	if m := p[0].Metrics[0]; m.IntervalMS != 1000 || m.Timestamp != at.Truncate(time.Second).UnixMilli() {
		t.Fatalf("invalid metric: %+v", m)
	}
	// Close must remain safe after a direct synchronous batch send.
	if err := n.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
