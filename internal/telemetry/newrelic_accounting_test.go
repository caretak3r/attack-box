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
)

const acctBoot = "feedfacefeedface"

var (
	acctStatsKeys = []string{
		"source", "shipper_boot", "role", "lines", "oversize", "rejected_total", "duplicates", "gaps",
		"queued", "queue_full", "boots_unreported", "rows_omitted",
	}
	acctBootKeys = []string{
		"source", "shipper_boot", "role", "boot", "first_seq", "last_seq", "admitted", "missing", "rejected",
		"queue_refused", "duplicates", "reported_dropped", "reported_at_seq", "max_skew_ms", "clamped",
		"last_ingest_ts", "state", "loss", "loss_scope", "loss_reason",
	}
)

// acctEvents builds a report of n events shaped like Ingest.Accounting: 3
// ingest_stats rows and n-3 producer_boot rows. call is stamped on every row.
func acctEvents(n int, call int64, now time.Time) []Event {
	var out []Event
	for i := 0; i < n; i++ {
		action, keys := "producer_boot", acctBootKeys
		if i < 3 {
			action, keys = "ingest_stats", acctStatsKeys
		}
		attrs := map[string]any{}
		for _, k := range keys {
			attrs[k] = int64(i)
		}
		attrs["source"], attrs["shipper_boot"] = "shipper_accounting", acctBoot
		attrs["call"] = call
		out = append(out, Event{Timestamp: now, Stream: StreamHeartbeat, Action: action, Attrs: attrs})
	}
	return out
}

// acctServer is a New Relic stand-in that splits accounting POSTs from the
// rest. onAcct picks the status of the i-th accounting POST (counted from 0)
// and may block.
type acctServer struct {
	*httptest.Server
	onAcct func(i int, r *http.Request) int

	mu      sync.Mutex
	acct    []posted
	times   []time.Time
	metrics atomic.Int32
}

func newAcctServer(t *testing.T, onAcct func(i int, r *http.Request) int) *acctServer {
	t.Helper()
	s := &acctServer{onAcct: onAcct}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("body not gzip: %v", err)
			w.WriteHeader(400)
			return
		}
		b, _ := io.ReadAll(zr)
		switch {
		case r.URL.Path == "/metric/v1":
			s.metrics.Add(1)
		case strings.Contains(string(b), `"source":"shipper_accounting"`):
			s.mu.Lock()
			i := len(s.acct)
			s.acct = append(s.acct, posted{r.URL.Path, r.URL.RawQuery, r.Header.Clone(), b})
			s.times = append(s.times, time.Now())
			s.mu.Unlock()
			w.WriteHeader(s.onAcct(i, r))
			return
		}
		w.WriteHeader(202)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *acctServer) reports() []posted {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]posted(nil), s.acct...)
}

func (s *acctServer) cfg(report func(time.Time) []Event, beat time.Duration) NRConfig {
	return NRConfig{
		LicenseKey: testKey, LogURL: s.URL + "/log/v1", MetricURL: s.URL + "/metric/v1",
		HeartbeatInterval: beat, FlushInterval: time.Hour,
		Backoff:          []time.Duration{time.Millisecond, time.Millisecond},
		Common:           map[string]any{"service": "attackbox"},
		AccountingReport: report,
	}
}

func (s *acctServer) waitReports(t *testing.T, n int) []posted {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := s.reports(); len(got) >= n {
			return got
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("got %d accounting POSTs, want %d", len(s.reports()), n)
	return nil
}

func decodeLogs(t *testing.T, p posted) logPayload {
	t.Helper()
	var lp logPayload
	if err := json.Unmarshal(p.Payload, &lp); err != nil {
		t.Fatalf("payload is not a log envelope: %v", err)
	}
	return lp
}

func accept(int, *http.Request) int { return 202 }

// The first report goes out at start, before any heartbeat tick, on the log
// endpoint with the common attributes.
func TestAccountingReportAtStart(t *testing.T) {
	var calls atomic.Int32
	srv := newAcctServer(t, accept)
	n := start(t, srv.cfg(func(now time.Time) []Event {
		return acctEvents(5, int64(calls.Add(1)), now)
	}, time.Hour))
	defer closeNR(t, n)

	p := srv.waitReports(t, 1)[0]
	if p.Path != "/log/v1" || p.Header.Get("Api-Key") != testKey {
		t.Fatalf("report went to %s with key %q", p.Path, p.Header.Get("Api-Key"))
	}
	lp := decodeLogs(t, p)
	if len(lp) != 1 || len(lp[0].Logs) != 5 || lp[0].Common.Attributes["service"] != "attackbox" {
		t.Fatalf("report = %s", p.Payload)
	}
	if calls.Load() != 1 || srv.metrics.Load() != 0 {
		t.Fatalf("report calls = %d, metric posts = %d; want 1 and 0 before the first tick", calls.Load(), srv.metrics.Load())
	}
}

// The largest honest report, 33 rows, is one POST with every attribute.
func TestAccountingFullReportIsOnePost(t *testing.T) {
	srv := newAcctServer(t, accept)
	n := start(t, srv.cfg(func(now time.Time) []Event { return acctEvents(33, 1, now) }, time.Hour))
	defer closeNR(t, n)

	posts := srv.waitReports(t, 1)
	lp := decodeLogs(t, posts[0])
	if len(lp[0].Logs) != 33 {
		t.Fatalf("got %d events in the POST, want 33", len(lp[0].Logs))
	}
	stats := 0
	for _, l := range lp[0].Logs {
		keys := acctBootKeys
		if l.Attributes["action"] == "ingest_stats" {
			stats++
			keys = acctStatsKeys
		}
		for _, k := range keys {
			if _, ok := l.Attributes[k]; !ok {
				t.Fatalf("%v row lost attribute %q: %v", l.Attributes["action"], k, l.Attributes)
			}
		}
		if _, cut := l.Attributes["attrs_truncated"]; cut {
			t.Fatalf("row was cut: %v", l.Attributes)
		}
		if l.Attributes["source"] != "shipper_accounting" || l.Attributes["shipper_boot"] != acctBoot || l.Attributes["stream"] != StreamHeartbeat {
			t.Fatalf("row source/boot/stream = %v/%v/%v", l.Attributes["source"], l.Attributes["shipper_boot"], l.Attributes["stream"])
		}
	}
	if stats != 3 {
		t.Fatalf("got %d ingest_stats rows, want 3", stats)
	}
	time.Sleep(50 * time.Millisecond)
	if got := len(srv.reports()); got != 1 {
		t.Fatalf("got %d accounting POSTs, want 1", got)
	}
}

// Reports share the error callback, not the durable delivery counters.
func accountingErrors(cfg *NRConfig) <-chan error {
	errs := make(chan error, 8)
	cfg.OnError = func(err error) { errs <- err }
	return errs
}

func assertAccountingError(t *testing.T, n *NewRelic, errs <-chan error, want string) {
	t.Helper()
	select {
	case err := <-errs:
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("accounting error = %v; want %q", err, want)
		}
	default:
		t.Fatal("missing accounting error")
	}
	if st := n.Stats(); st.Errors != 0 || st.Lost != 0 || st.Retries != 0 {
		t.Fatalf("accounting report affected delivery failure counters: %+v", st)
	}
}

// A report over the event limit loses its tail, never a second POST.
func TestAccountingEventLimit(t *testing.T) {
	srv := newAcctServer(t, accept)
	cfg := srv.cfg(func(now time.Time) []Event { return acctEvents(MaxAccountingEvents+5, 1, now) }, time.Hour)
	errs := accountingErrors(&cfg)
	n := start(t, cfg)
	defer closeNR(t, n)

	lp := decodeLogs(t, srv.waitReports(t, 1)[0])
	if len(lp[0].Logs) != MaxAccountingEvents {
		t.Fatalf("got %d events, want %d", len(lp[0].Logs), MaxAccountingEvents)
	}
	assertAccountingError(t, n, errs, "cut to its event and payload bounds")
}

// A report over the configured uncompressed payload size is cut to fit.
func TestAccountingPayloadBound(t *testing.T) {
	srv := newAcctServer(t, accept)
	big := strings.Repeat("x", 3000)
	cfg := srv.cfg(func(now time.Time) []Event {
		var out []Event
		for i := 0; i < MaxAccountingEvents; i++ {
			out = append(out, Event{Timestamp: now, Stream: StreamHeartbeat, Action: "producer_boot",
				Attrs: map[string]any{"source": "shipper_accounting", "a": big, "b": big, "c": big}})
		}
		return out
	}, time.Hour)
	cfg.MaxPayloadBytes = MinPayloadBytes
	errs := accountingErrors(&cfg)
	n := start(t, cfg)
	defer closeNR(t, n)

	p := srv.waitReports(t, 1)[0]
	if len(p.Payload) > MinPayloadBytes {
		t.Fatalf("payload is %d bytes, bound is %d", len(p.Payload), MinPayloadBytes)
	}
	if got := len(decodeLogs(t, p)[0].Logs); got == 0 || got >= MaxAccountingEvents {
		t.Fatalf("got %d events, want some but not all", got)
	}
	assertAccountingError(t, n, errs, "cut to its event and payload bounds")
}

// A failed report is not retried and does not move the schedule: the next one
// is a new report, one interval later.
func TestAccountingFailureNotRetried(t *testing.T) {
	const beat = 60 * time.Millisecond
	var calls atomic.Int64
	srv := newAcctServer(t, func(i int, _ *http.Request) int {
		if i == 0 {
			return 500
		}
		return 202
	})
	cfg := srv.cfg(func(now time.Time) []Event { return acctEvents(4, calls.Add(1), now) }, beat)
	errs := accountingErrors(&cfg)
	n := start(t, cfg)
	defer closeNR(t, n)

	posts := srv.waitReports(t, 3)
	for i, p := range posts[:3] {
		lp := decodeLogs(t, p)
		if got := lp[0].Logs[0].Attributes["call"]; got != float64(i+1) {
			t.Fatalf("POST %d carries report %v; a retry or a stale report was sent", i, got)
		}
	}
	srv.mu.Lock()
	gap := srv.times[1].Sub(srv.times[0])
	srv.mu.Unlock()
	if gap < beat/2 {
		t.Fatalf("report 2 came %v after the failed one; want about %v", gap, beat)
	}
	assertAccountingError(t, n, errs, "accounting report:")
}

// A report POST that never answers leaves the heartbeat on schedule, starts no
// second report, and does not hold Close.
func TestAccountingStallDoesNotDelayHeartbeat(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	srv := newAcctServer(t, func(_ int, r *http.Request) int {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		return 202
	})
	var calls atomic.Int32
	n := start(t, srv.cfg(func(now time.Time) []Event { return acctEvents(4, int64(calls.Add(1)), now) }, 10*time.Millisecond))

	srv.waitReports(t, 1)
	deadline := time.Now().Add(3 * time.Second)
	for srv.metrics.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := srv.metrics.Load(); got < 3 {
		t.Fatalf("heartbeat gauges = %d while a report POST stalled", got)
	}
	if got, posts := calls.Load(), len(srv.reports()); got != 1 || posts != 1 {
		t.Fatalf("report calls = %d, POSTs = %d during the stall, want 1 and 1", got, posts)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	begin := time.Now()
	if err := n.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if d := time.Since(begin); d > time.Second {
		t.Fatalf("Close took %v with a stalled report", d)
	}
	if st := n.Stats(); st.Lost != 0 || st.Errors != 0 {
		t.Fatalf("a report cut by Close was counted as a failure: %+v", st)
	}
}
