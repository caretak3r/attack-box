package telemetry

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func logAttrs(t *testing.T, srv *nrServer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, p := range srv.posts("/log/v1") {
		var lp logPayload
		if err := json.Unmarshal(p.Payload, &lp); err != nil {
			t.Fatal(err)
		}
		for _, l := range lp[0].Logs {
			out = append(out, l.Attributes)
		}
	}
	return out
}

func TestEmitOwnsAttrsAndLabels(t *testing.T) {
	srv := newServer(t, 202)
	n := start(t, srv.cfg())
	attrs := map[string]any{"k": "first"}
	labels := []string{"a"}
	n.Emit(Event{Action: "x", Attrs: attrs, TaskLabels: labels})
	attrs["k"] = "mutated"
	labels[0] = "mutated"
	closeNR(t, n)

	got := logAttrs(t, srv)
	if len(got) != 1 || got[0]["k"] != "first" {
		t.Fatalf("attrs = %v", got)
	}
	if tl, _ := got[0]["task_labels"].([]any); len(tl) != 1 || tl[0] != "a" {
		t.Errorf("task_labels = %v", got[0]["task_labels"])
	}
}

func TestCommonOwnedByShipper(t *testing.T) {
	srv := newServer(t, 202)
	cfg := srv.cfg()
	n := start(t, cfg)
	cfg.Common["service"] = "mutated"
	n.Emit(Event{Action: "x"})
	closeNR(t, n)

	var lp logPayload
	if err := json.Unmarshal(srv.posts("/log/v1")[0].Payload, &lp); err != nil {
		t.Fatal(err)
	}
	if lp[0].Common.Attributes["service"] != "attackbox" {
		t.Errorf("common = %v", lp[0].Common.Attributes)
	}
}

func TestAttributeLimits(t *testing.T) {
	srv := newServer(t, 202)
	n := start(t, srv.cfg())
	attrs := map[string]any{
		"long":                   strings.Repeat("é", 4500),
		strings.Repeat("k", 300): "v",
	}
	for i := 0; i < 300; i++ {
		attrs["extra_"+string(rune('a'+i/26))+string(rune('a'+i%26))] = i
	}
	n.Emit(Event{Action: "big", Attrs: attrs, TaskLabels: []string{strings.Repeat("t", 5000)}})
	n.Emit(Event{Action: "small", Attrs: map[string]any{"k": "v"}})
	closeNR(t, n)

	seen := 0
	for _, a := range logAttrs(t, srv) {
		seen++
		if a["action"] == "small" {
			if _, ok := a["attrs_truncated"]; ok {
				t.Error("untouched event flagged attrs_truncated")
			}
			continue
		}
		if len(a) >= 255 {
			t.Errorf("attribute count = %d", len(a))
		}
		for k, v := range a {
			if utf8.RuneCountInString(k) > 255 {
				t.Errorf("key of %d runes", utf8.RuneCountInString(k))
			}
			if s, ok := v.(string); ok && utf8.RuneCountInString(s) > 4000 {
				t.Errorf("%.20s value of %d runes", k, utf8.RuneCountInString(s))
			}
		}
		for _, l := range a["task_labels"].([]any) {
			if utf8.RuneCountInString(l.(string)) > 4000 {
				t.Error("task label not truncated")
			}
		}
		if a["attrs_truncated"] != true {
			t.Errorf("attrs_truncated = %v", a["attrs_truncated"])
		}
	}
	if seen != 2 {
		t.Errorf("events shipped = %d", seen)
	}
}

func TestNilCommonNotNull(t *testing.T) {
	srv := newServer(t, 202)
	cfg := srv.cfg()
	cfg.Common = nil
	cfg.HeartbeatInterval = 5 * time.Millisecond
	n := start(t, cfg)
	n.Emit(Event{Action: "x"})
	deadline := time.Now().Add(2 * time.Second)
	for (len(srv.posts("/log/v1")) < 2 || len(srv.posts("/metric/v1")) < 2) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	closeNR(t, n)
	for _, path := range []string{"/log/v1", "/metric/v1"} {
		ps := srv.posts(path)
		if len(ps) == 0 {
			t.Fatalf("no POST to %s", path)
		}
		for _, p := range ps {
			if strings.Contains(string(p.Payload), `"attributes":null`) {
				t.Errorf("%s payload has null attributes: %s", path, p.Payload)
			}
		}
	}
}

func TestSelfMetricsSurviveSeriesCap(t *testing.T) {
	srv := newServer(t, 202)
	n := start(t, srv.cfg())
	n.mu.Lock()
	for i := 0; i < maxSeries; i++ {
		n.series[string(rune(0x100+i))] = &series{name: "live", count: true, value: 1}
	}
	n.mu.Unlock()
	n.Count("one.more", 1, nil)
	n.Emit(Event{Action: "x"})
	closeNR(t, n)

	var mp metricPayload
	if err := json.Unmarshal(srv.posts("/metric/v1")[0].Payload, &mp); err != nil {
		t.Fatal(err)
	}
	seen := map[string]float64{}
	for _, m := range mp[0].Metrics {
		seen[m.Name] = m.Value
	}
	for _, name := range []string{"attackbox.telemetry.dropped_logs_total", "attackbox.telemetry.dropped_metrics_total",
		"attackbox.telemetry.ingest_errors_total", "attackbox.telemetry.ingest_retries_total"} {
		if _, ok := seen[name]; !ok {
			t.Errorf("self metric %s missing", name)
		}
	}
	if seen["attackbox.telemetry.dropped_metrics_total"] != 1 || seen["attackbox.telemetry.dropped_logs_total"] != 0 {
		t.Errorf("dropped metrics/logs = %v/%v", seen["attackbox.telemetry.dropped_metrics_total"], seen["attackbox.telemetry.dropped_logs_total"])
	}
}

func TestDroppedLogsAndMetricsSeparate(t *testing.T) {
	srv := newServer(t, 202)
	n := start(t, srv.cfg())
	closeNR(t, n)
	n.Emit(Event{Action: "late"})
	n.Emit(Event{Action: "late"})
	n.Count("late", 1, nil)
	st := n.Stats()
	if st.DroppedLogs != 2 || st.DroppedMetrics != 1 || st.Dropped != 3 {
		t.Errorf("stats %+v", st)
	}
}

func TestPayloadBytesClamped(t *testing.T) {
	srv := newServer(t, 202)
	cfg := srv.cfg()
	cfg.MaxPayloadBytes = 5_000_000
	n := start(t, cfg)
	defer closeNR(t, n)
	if n.cfg.MaxPayloadBytes > 950_000 {
		t.Errorf("MaxPayloadBytes = %d", n.cfg.MaxPayloadBytes)
	}
}

// sizeLimitServer answers 413 to log bodies over limit bytes and counts the
// log events it accepted.
func sizeLimitServer(t *testing.T, limit int) (*httptest.Server, *atomic.Int32, func() int) {
	t.Helper()
	var posts atomic.Int32
	var mu sync.Mutex
	events := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zr, _ := gzip.NewReader(r.Body)
		b, _ := io.ReadAll(zr)
		if r.URL.Path != "/log" {
			w.WriteHeader(202)
			return
		}
		posts.Add(1)
		if len(b) > limit {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		var lp logPayload
		json.Unmarshal(b, &lp)
		mu.Lock()
		events += len(lp[0].Logs)
		mu.Unlock()
		w.WriteHeader(202)
	}))
	t.Cleanup(srv.Close)
	return srv, &posts, func() int { mu.Lock(); defer mu.Unlock(); return events }
}

func TestPayloadTooLargeIsSplit(t *testing.T) {
	srv, _, delivered := sizeLimitServer(t, 1200)
	n := start(t, NRConfig{
		LicenseKey: testKey, LogURL: srv.URL + "/log", MetricURL: srv.URL + "/metric",
		HeartbeatInterval: -1, Backoff: []time.Duration{time.Millisecond},
	})
	for i := 0; i < 10; i++ {
		n.Emit(Event{Stream: StreamEdge, Body: strings.Repeat("x", 300)})
	}
	closeNR(t, n)
	if st := n.Stats(); delivered() != 10 || st.Lost != 0 || st.Errors != 0 {
		t.Errorf("delivered %d, stats %+v", delivered(), st)
	}
}

func TestPayloadTooLargeSingleItemLost(t *testing.T) {
	srv, posts, delivered := sizeLimitServer(t, 10)
	n := start(t, NRConfig{
		LicenseKey: testKey, LogURL: srv.URL + "/log", MetricURL: srv.URL + "/metric",
		HeartbeatInterval: -1, Backoff: []time.Duration{time.Millisecond},
	})
	for i := 0; i < 4; i++ {
		n.Emit(Event{Stream: StreamEdge, Body: "x"})
	}
	closeNR(t, n)
	st := n.Stats()
	if delivered() != 0 || st.Lost != 4 || posts.Load() > 12 {
		t.Errorf("delivered %d, posts %d, stats %+v", delivered(), posts.Load(), st)
	}
}

func TestRequestTimeoutRetried(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/log" && hits.Add(1) == 1 {
			w.WriteHeader(http.StatusRequestTimeout)
			return
		}
		w.WriteHeader(202)
	}))
	defer srv.Close()
	n := start(t, NRConfig{
		LicenseKey: testKey, LogURL: srv.URL + "/log", MetricURL: srv.URL + "/metric",
		HeartbeatInterval: -1, Backoff: []time.Duration{time.Millisecond},
	})
	n.Emit(Event{Action: "x"})
	closeNR(t, n)
	if st := n.Stats(); st.Retries != 1 || st.Lost != 0 || st.Errors != 0 || hits.Load() != 2 {
		t.Errorf("hits %d, stats %+v", hits.Load(), st)
	}
}

func TestFailedMetricPostMergedIntoNextFlush(t *testing.T) {
	var metricHits atomic.Int32
	var mu sync.Mutex
	total := 0.0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metric" {
			w.WriteHeader(202)
			return
		}
		if metricHits.Add(1) <= 3 { // the whole retry run of the first flush
			w.WriteHeader(500)
			return
		}
		zr, _ := gzip.NewReader(r.Body)
		b, _ := io.ReadAll(zr)
		var mp metricPayload
		json.Unmarshal(b, &mp)
		mu.Lock()
		for _, m := range mp[0].Metrics {
			if m.Name == "attackbox.requests_total" {
				total += m.Value
			}
		}
		mu.Unlock()
		w.WriteHeader(202)
	}))
	defer srv.Close()
	n := start(t, NRConfig{
		LicenseKey: testKey, LogURL: srv.URL + "/log", MetricURL: srv.URL + "/metric",
		HeartbeatInterval: -1, FlushInterval: 20 * time.Millisecond,
		Backoff: []time.Duration{time.Millisecond, time.Millisecond},
	})
	n.Count("attackbox.requests_total", 2, nil)
	deadline := time.Now().Add(2 * time.Second)
	for metricHits.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	closeNR(t, n)
	mu.Lock()
	defer mu.Unlock()
	if total != 2 {
		t.Errorf("shipped total = %v, want 2", total)
	}
}

func TestRequeueBounded(t *testing.T) {
	srv := newServer(t, 202)
	n := start(t, srv.cfg())
	defer closeNR(t, n)
	live := string(rune(0x100))
	n.mu.Lock()
	for i := 0; i < maxSeries; i++ {
		n.series[string(rune(0x100+i))] = &series{name: "live", count: true, value: 1}
	}
	n.mu.Unlock()
	n.requeue(map[string]*series{
		"new":  {name: "new", count: true, value: 1},
		live:   {name: "live", count: true, value: 4},
		"self": {name: "self", internal: true},
	})
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.series) != maxSeries || n.series[live].value != 5 {
		t.Errorf("series = %d, merged = %v", len(n.series), n.series[live].value)
	}
	if got := n.droppedMetrics.Load(); got != 1 {
		t.Errorf("droppedMetrics = %d", got)
	}
}

func TestCloseTimeoutCountsQueuedEvents(t *testing.T) {
	entered := make(chan struct{})
	var once sync.Once
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	n := start(t, NRConfig{
		LicenseKey: testKey, LogURL: srv.URL, MetricURL: srv.URL,
		BatchSize: 1, HeartbeatInterval: -1, Backoff: []time.Duration{time.Millisecond},
	})
	n.Emit(Event{Action: "in-flight"})
	<-entered
	for i := 0; i < 5; i++ {
		n.Emit(Event{Action: "queued"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := n.Close(ctx); err == nil {
		t.Fatal("Close ignored its deadline")
	}
	if lost := n.Stats().Lost; lost < 6 {
		t.Errorf("lost = %d, want at least the 6 undelivered events", lost)
	}
}

func TestMetricRejectionRequeueByStatus(t *testing.T) {
	for status, requeued := range map[int]bool{
		400: false, 401: false, 403: false, 404: false, 413: false,
		408: true, 429: true, 500: true, 503: true,
	} {
		srv := newServer(t, status)
		n := start(t, srv.cfg())
		n.Count("attackbox.rejected", 1, nil)
		n.flushMetrics(false)

		n.mu.Lock()
		_, queued := n.series[seriesKey("attackbox.rejected", true, nil)]
		n.mu.Unlock()
		if queued != requeued {
			t.Errorf("status %d: requeued = %v, want %v", status, queued, requeued)
		}
		wantLost := int64(0)
		if !requeued {
			wantLost = 1 // the internal gauges are not counted
		}
		if lost := n.Stats().Lost; lost != wantLost {
			t.Errorf("status %d: lost = %d, want %d", status, lost, wantLost)
		}
		closeNR(t, n)
	}
}

func TestRejectedMetricNotResent(t *testing.T) {
	srv := newServer(t, 400)
	n := start(t, srv.cfg())
	n.Count("attackbox.rejected", 1, nil)
	n.flushMetrics(false)
	srv.status.Store(202)
	n.flushMetrics(false)
	for _, p := range srv.posts("/metric/v1")[1:] {
		if strings.Contains(string(p.Payload), "attackbox.rejected") {
			t.Error("permanently rejected metric was sent again")
		}
	}
	closeNR(t, n)
}

func TestFinalFlushLostSkipsInternalGauges(t *testing.T) {
	srv := newServer(t, 500)
	n := start(t, srv.cfg())
	n.Count("attackbox.requests", 1, nil)
	closeNR(t, n)
	if lost := n.Stats().Lost; lost != 1 {
		t.Errorf("lost = %d, want 1 (only the real series)", lost)
	}
}

func TestNestedAttrValuesLimited(t *testing.T) {
	long := strings.Repeat("é", 4500)
	e := Event{Action: "nested", Attrs: map[string]any{
		"headers":      map[string]string{"X-Long": long},
		"declarations": []struct{ Name string }{{Name: long}},
		"small":        map[string]string{"a": "b"},
		"bad":          make(chan int),
		"count":        7,
		"flag":         true,
	}}
	a := limitAttrs(e)
	for _, k := range []string{"headers", "declarations", "small", "bad"} {
		if _, ok := a[k].(string); !ok {
			t.Errorf("%s = %T, want a JSON string", k, a[k])
		}
	}
	for k, v := range a {
		if s, ok := v.(string); ok && utf8.RuneCountInString(s) > maxAttrValue {
			t.Errorf("%s value of %d runes", k, utf8.RuneCountInString(s))
		}
	}
	if a["small"] != `{"a":"b"}` {
		t.Errorf("small = %v", a["small"])
	}
	if s, _ := a["bad"].(string); !strings.Contains(s, "unmarshalable") {
		t.Errorf("bad = %v", a["bad"])
	}
	if a["count"] != 7 || a["flag"] != true {
		t.Errorf("scalars changed: %v %v", a["count"], a["flag"])
	}
	if a["attrs_truncated"] != true {
		t.Error("attrs_truncated not set")
	}
	short := limitAttrs(Event{Action: "x", Attrs: map[string]any{"h": map[string]string{"a": "b"}}})
	if _, ok := short["attrs_truncated"]; ok {
		t.Error("short nested value flagged attrs_truncated")
	}
}

func TestMaxPayloadBytesFloor(t *testing.T) {
	srv := newServer(t, 202)
	cfg := srv.cfg()
	cfg.MaxPayloadBytes = 10
	n := start(t, cfg)
	defer closeNR(t, n)
	if n.cfg.MaxPayloadBytes != minPayloadBytes {
		t.Errorf("MaxPayloadBytes = %d, want %d", n.cfg.MaxPayloadBytes, minPayloadBytes)
	}
}
