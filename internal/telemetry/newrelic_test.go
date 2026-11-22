package telemetry

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testKey = "0123456789abcdef0123456789abcdef0123NRAL"

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(time.Second)
	return c.t
}

type posted struct {
	Path    string
	Query   string
	Header  http.Header
	Payload []byte
}

type nrServer struct {
	*httptest.Server
	mu     sync.Mutex
	got    []posted
	status atomic.Int32
}

func newServer(t *testing.T, status int) *nrServer {
	t.Helper()
	s := &nrServer{}
	s.status.Store(int32(status))
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("body not gzip: %v", err)
			w.WriteHeader(400)
			return
		}
		b, _ := io.ReadAll(zr)
		s.mu.Lock()
		s.got = append(s.got, posted{r.URL.Path, r.URL.RawQuery, r.Header.Clone(), b})
		s.mu.Unlock()
		w.WriteHeader(int(s.status.Load()))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *nrServer) posts(path string) []posted {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []posted
	for _, p := range s.got {
		if p.Path == path {
			out = append(out, p)
		}
	}
	return out
}

func (s *nrServer) cfg() NRConfig {
	return NRConfig{
		LicenseKey:        testKey,
		LogURL:            s.URL + "/log/v1",
		MetricURL:         s.URL + "/metric/v1",
		HeartbeatInterval: -1,
		Backoff:           []time.Duration{time.Millisecond, time.Millisecond},
		Now:               (&fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}).Now,
		Common:            map[string]any{"service": "attackbox"},
	}
}

func start(t *testing.T, cfg NRConfig) *NewRelic {
	t.Helper()
	n, err := NewNewRelic(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func closeNR(t *testing.T, n *NewRelic) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := n.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
}

type logPayload []struct {
	Common struct {
		Attributes map[string]any `json:"attributes"`
	} `json:"common"`
	Logs []struct {
		Timestamp  int64          `json:"timestamp"`
		Message    string         `json:"message"`
		Attributes map[string]any `json:"attributes"`
	} `json:"logs"`
}

type metricPayload []struct {
	Common struct {
		Timestamp  int64          `json:"timestamp"`
		IntervalMS int64          `json:"interval.ms"`
		Attributes map[string]any `json:"attributes"`
	} `json:"common"`
	Metrics []struct {
		Name       string            `json:"name"`
		Type       string            `json:"type"`
		Value      float64           `json:"value"`
		IntervalMS int64             `json:"interval.ms"`
		Timestamp  int64             `json:"timestamp"`
		Attributes map[string]string `json:"attributes"`
	} `json:"metrics"`
}

func TestLogShape(t *testing.T) {
	srv := newServer(t, 202)
	n := start(t, srv.cfg())
	n.Emit(Event{Stream: StreamEdge, SessionID: "s1", Action: "POST", Body: strings.Repeat("a", 3501)})
	closeNR(t, n)

	ps := srv.posts("/log/v1")
	if len(ps) != 1 {
		t.Fatalf("log posts = %d", len(ps))
	}
	p := ps[0]
	if p.Query != "" || strings.Contains(p.Query, testKey) {
		t.Errorf("query = %q", p.Query)
	}
	if p.Header.Get("Api-Key") != testKey || p.Header.Get("Content-Encoding") != "gzip" ||
		p.Header.Get("Content-Type") != "application/json" {
		t.Errorf("headers = %v", p.Header)
	}
	if strings.Contains(string(p.Payload), testKey) {
		t.Error("key in payload")
	}
	var lp logPayload
	if err := json.Unmarshal(p.Payload, &lp); err != nil {
		t.Fatal(err)
	}
	if len(lp) != 1 || len(lp[0].Logs) != 2 {
		t.Fatalf("payload = %s", p.Payload)
	}
	if lp[0].Common.Attributes["service"] != "attackbox" {
		t.Errorf("common = %v", lp[0].Common)
	}
	for i, l := range lp[0].Logs {
		if l.Timestamp < 1_700_000_000_000 {
			t.Errorf("timestamp not ms: %d", l.Timestamp)
		}
		a := l.Attributes
		if a["chunk_index"] != float64(i) || a["chunk_count"] != float64(2) ||
			a["body_sha256"] == "" || a["session_id"] != "s1" || a["stream"] != "edge" {
			t.Errorf("attrs = %v", a)
		}
		if _, ok := a["message"]; ok {
			t.Error("message duplicated in attributes")
		}
	}
	if len(lp[0].Logs[0].Message) != 3500 || len(lp[0].Logs[1].Message) != 1 {
		t.Error("chunk sizes wrong")
	}
	if st := n.Stats(); st.Sent < 2 || st.Errors != 0 {
		t.Errorf("stats = %+v", st)
	}
}

func TestMetricShape(t *testing.T) {
	srv := newServer(t, 202)
	n := start(t, srv.cfg())
	lbl := map[string]string{"persona": "openai", "src_ip": "1.2.3.4"}
	n.Count("attackbox.requests_total", 1, lbl)
	n.Count("attackbox.requests_total", 2, lbl)
	n.Gauge("attackbox.concurrent_status_requests", 5, nil)
	n.Gauge("attackbox.concurrent_status_requests", 7, nil)
	closeNR(t, n)

	ps := srv.posts("/metric/v1")
	if len(ps) != 1 {
		t.Fatalf("metric posts = %d", len(ps))
	}
	if ps[0].Header.Get("Api-Key") != testKey || ps[0].Header.Get("Content-Encoding") != "gzip" {
		t.Errorf("headers = %v", ps[0].Header)
	}
	var mp metricPayload
	if err := json.Unmarshal(ps[0].Payload, &mp); err != nil {
		t.Fatal(err)
	}
	if mp[0].Common.IntervalMS <= 0 || mp[0].Common.Timestamp == 0 || mp[0].Common.Attributes["service"] != "attackbox" {
		t.Errorf("common = %+v", mp[0].Common)
	}
	seen := map[string]bool{}
	for _, m := range mp[0].Metrics {
		seen[m.Name] = true
		switch m.Name {
		case "attackbox.requests_total":
			if m.Type != "count" || m.Value != 3 || m.IntervalMS <= 0 {
				t.Errorf("count = %+v", m)
			}
			if len(m.Attributes) != 1 || m.Attributes["persona"] != "openai" {
				t.Errorf("labels = %v", m.Attributes)
			}
		case "attackbox.concurrent_status_requests":
			if m.Type != "gauge" || m.Value != 7 || m.Timestamp == 0 {
				t.Errorf("gauge = %+v", m)
			}
		}
	}
	for _, name := range []string{"attackbox.requests_total", "attackbox.concurrent_status_requests",
		"attackbox.telemetry.dropped_total", "attackbox.telemetry.ingest_errors_total"} {
		if !seen[name] {
			t.Errorf("metric %s missing", name)
		}
	}
}

func TestBatchSplitByPayloadSize(t *testing.T) {
	srv := newServer(t, 202)
	cfg := srv.cfg()
	cfg.MaxPayloadBytes = 1500
	n := start(t, cfg)
	for i := 0; i < 10; i++ {
		n.Emit(Event{Stream: StreamEdge, Body: strings.Repeat("x", 300)})
	}
	closeNR(t, n)

	ps := srv.posts("/log/v1")
	if len(ps) < 4 {
		t.Fatalf("posts = %d, want several", len(ps))
	}
	total := 0
	for _, p := range ps {
		if len(p.Payload) > cfg.MaxPayloadBytes {
			t.Errorf("payload %d bytes > %d", len(p.Payload), cfg.MaxPayloadBytes)
		}
		var lp logPayload
		if err := json.Unmarshal(p.Payload, &lp); err != nil {
			t.Fatal(err)
		}
		total += len(lp[0].Logs)
	}
	if total != 10 {
		t.Errorf("events delivered = %d", total)
	}
}

func TestOversizedItemDropped(t *testing.T) {
	srv := newServer(t, 202)
	cfg := srv.cfg()
	cfg.MaxPayloadBytes = 400
	n := start(t, cfg)
	n.Emit(Event{Stream: StreamEdge, Body: strings.Repeat("x", 1000)})
	closeNR(t, n)
	st := n.Stats()
	if st.Errors != 1 || st.Lost != 1 || len(srv.posts("/log/v1")) != 0 {
		t.Errorf("stats = %+v", st)
	}
}

func TestQueueFullDropsWithoutBlocking(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	entered := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		<-release
		w.WriteHeader(202)
	}))
	defer srv.Close()

	n := start(t, NRConfig{
		LicenseKey: testKey, LogURL: srv.URL, MetricURL: srv.URL,
		QueueSize: 2, BatchSize: 1, HeartbeatInterval: -1,
		Backoff: []time.Duration{time.Millisecond},
	})
	n.Emit(Event{Action: "first"})
	<-entered // worker is now stuck in the POST

	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			n.Emit(Event{Action: "flood"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Emit blocked on a full queue")
	}
	if d := n.Stats().Dropped; d < 40 {
		t.Errorf("dropped = %d", d)
	}
	close(release)
	closeNR(t, n)
}

func TestServerErrorRetriesThenCounts(t *testing.T) {
	srv := newServer(t, 500)
	n := start(t, srv.cfg())
	n.Emit(Event{Action: "x"})
	closeNR(t, n)

	if got := len(srv.posts("/log/v1")); got != 3 {
		t.Errorf("log attempts = %d, want 3", got)
	}
	st := n.Stats()
	if st.Sent != 0 {
		t.Errorf("Sent = %d after failed delivery", st.Sent)
	}
	if st.Errors != 2 { // one failed log POST, one failed metric POST
		t.Errorf("Errors = %d", st.Errors)
	}
	if st.LastError == "" || strings.Contains(st.LastError, testKey) {
		t.Errorf("LastError = %q", st.LastError)
	}
}

func TestClientErrorNotRetried(t *testing.T) {
	srv := newServer(t, 403)
	var hook []error
	var mu sync.Mutex
	cfg := srv.cfg()
	cfg.OnError = func(err error) { mu.Lock(); hook = append(hook, err); mu.Unlock() }
	n := start(t, cfg)
	n.Emit(Event{Action: "x"})
	closeNR(t, n)

	if got := len(srv.posts("/log/v1")); got != 1 {
		t.Errorf("attempts = %d, want 1", got)
	}
	if n.Stats().Sent != 0 || n.Stats().Errors != 2 {
		t.Errorf("stats = %+v", n.Stats())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hook) != 2 {
		t.Fatalf("OnError calls = %d", len(hook))
	}
	for _, e := range hook {
		if strings.Contains(e.Error(), testKey) {
			t.Error("key in error")
		}
	}
}

func TestRetryRecovers(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.WriteHeader(429)
			return
		}
		w.WriteHeader(202)
	}))
	defer srv.Close()
	n := start(t, NRConfig{
		LicenseKey: testKey, LogURL: srv.URL, MetricURL: srv.URL, HeartbeatInterval: -1,
		Backoff: []time.Duration{time.Millisecond, time.Millisecond},
	})
	n.Emit(Event{Action: "x"})
	closeNR(t, n)
	if n.Stats().Errors != 0 || n.Stats().Sent == 0 {
		t.Errorf("stats = %+v", n.Stats())
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Store(true)
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	n := start(t, NRConfig{
		LicenseKey: testKey, LogURL: srv.URL, MetricURL: srv.URL, HeartbeatInterval: -1,
	})
	n.Emit(Event{Action: "x"})
	closeNR(t, n)
	if leaked.Load() || n.Stats().Sent != 0 {
		t.Errorf("redirect followed; stats = %+v", n.Stats())
	}
}

type denyTransport struct{}

func (denyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("network disabled in tests")
}

var noNet = &http.Client{Transport: denyTransport{}}

func TestConfigValidation(t *testing.T) {
	cases := map[string]NRConfig{
		"empty key":       {},
		"http non-local":  {LicenseKey: testKey, LogURL: "http://log-api.newrelic.com/log/v1"},
		"http metric":     {LicenseKey: testKey, MetricURL: "http://example.com/metric"},
		"key in url":      {LicenseKey: testKey, LogURL: "https://example.com/log?api_key=" + testKey},
		"userinfo":        {LicenseKey: testKey, LogURL: "https://user:pw@example.com/log"},
		"bad scheme":      {LicenseKey: testKey, LogURL: "ftp://example.com/log"},
		"no host":         {LicenseKey: testKey, LogURL: "https:///log"},
		"http near-local": {LicenseKey: testKey, LogURL: "http://127.0.0.1.evil.com/log"},
	}
	for name, cfg := range cases {
		if n, err := NewNewRelic(cfg); err == nil {
			closeNR(t, n)
			t.Errorf("%s: accepted", name)
		}
	}
	for _, u := range []string{"http://127.0.0.1:8080/x", "http://localhost/x", "http://[::1]:9/x", "https://example.com/x"} {
		n, err := NewNewRelic(NRConfig{LicenseKey: testKey, LogURL: u, MetricURL: u, Client: noNet, Backoff: []time.Duration{}})
		if err != nil {
			t.Errorf("%s: %v", u, err)
			continue
		}
		closeNR(t, n)
	}
}

func TestHeartbeat(t *testing.T) {
	srv := newServer(t, 202)
	cfg := srv.cfg()
	cfg.HeartbeatInterval = 5 * time.Millisecond
	cfg.FlushInterval = 10 * time.Millisecond
	n := start(t, cfg)
	defer closeNR(t, n)

	var logs, metrics bool
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !(logs && metrics) {
		for _, p := range srv.posts("/log/v1") {
			logs = logs || strings.Contains(string(p.Payload), `"stream":"heartbeat"`)
		}
		for _, p := range srv.posts("/metric/v1") {
			metrics = metrics || strings.Contains(string(p.Payload), `"attackbox.heartbeat"`)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !logs || !metrics {
		t.Errorf("heartbeat log=%v metric=%v", logs, metrics)
	}
}

func TestCloseIdempotentAndRejectsLate(t *testing.T) {
	srv := newServer(t, 202)
	n := start(t, srv.cfg())
	closeNR(t, n)
	closeNR(t, n)
	n.Emit(Event{Action: "late"})
	if n.Stats().Dropped != 1 {
		t.Errorf("late emit not counted: %+v", n.Stats())
	}
}

func TestCloseHonorsContext(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	n := start(t, NRConfig{LicenseKey: testKey, LogURL: srv.URL, MetricURL: srv.URL, HeartbeatInterval: -1})
	n.Emit(Event{Action: "x"})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := n.Close(ctx); err == nil {
		t.Error("Close ignored its deadline")
	}
	closeNR(t, n) // aborted delivery lets the worker finish
}

func TestSeriesCap(t *testing.T) {
	srv := newServer(t, 202)
	n := start(t, srv.cfg())
	for i := 0; i < maxSeries+50; i++ {
		n.Count("m"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+string(rune('a'+i/26%26))+string(rune('a'+i/676)), 1, nil)
	}
	if n.Stats().Dropped == 0 {
		t.Error("series cap not enforced")
	}
	closeNR(t, n)
}

func TestValidLicenseKey(t *testing.T) {
	good := []string{
		testKey,
		"0123456789abcdef0123456789abcdef01234567", // original 40-hex key
		"eu01xx0123456789abcdef0123456789abcdNRAL", // region-prefixed ingest key
	}
	for _, k := range good {
		if err := ValidLicenseKey(k); err != nil {
			t.Errorf("%q rejected: %v", k, err)
		}
	}
	bad := map[string]string{
		"user key":    "NRAK-example",
		"insert key":  "NRII-example",
		"query key":   "NRIQ-example",
		"browser key": "NRJS-example",
		"short":       "0123456789abcdef",
		"long":        testKey + "0",
		"mixed no sx": "0123456789ABCDEF0123456789abcdef01234567",
		"symbols":     "0123456789abcdef0123456789abcdef012-NRAL",
	}
	for name, k := range bad {
		err := ValidLicenseKey(k)
		if err == nil {
			t.Errorf("%s accepted", name)
			continue
		}
		if len(k) > 5 && strings.Contains(err.Error(), k[5:]) {
			t.Errorf("%s: error echoes key: %v", name, err)
		}
		if _, err := NewNewRelic(NRConfig{LicenseKey: k, Client: noNet}); err == nil {
			t.Errorf("%s: NewNewRelic accepted", name)
		}
	}
}

func TestEncodedKeyInURLRejected(t *testing.T) {
	enc := strings.ReplaceAll(testKey, "0", "%30")
	for _, u := range []string{
		"https://example.com/log?k=" + enc,
		"https://example.com/" + strings.ToUpper(testKey) + "/log",
		"https://example.com/log?k=" + strings.ReplaceAll(testKey, "a", "%61"),
	} {
		if n, err := NewNewRelic(NRConfig{LicenseKey: testKey, LogURL: u, Client: noNet}); err == nil {
			closeNR(t, n)
			t.Errorf("%s accepted", u)
		}
	}
}

func TestRetryAfterParse(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := map[string]time.Duration{
		"":                                 0,
		"7":                                7 * time.Second,
		" 2 ":                              2 * time.Second,
		"0":                                0,
		"-5":                               0,
		"soon":                             0,
		"99999999999":                      24 * time.Hour,
		"Thu, 01 Jan 2026 00:00:30 GMT":    30 * time.Second,
		"Wed, 31 Dec 2025 23:59:00 GMT":    0,
		"Thursday, 01-Jan-26 00:01:00 GMT": time.Minute,
	}
	for in, want := range cases {
		if got := retryAfter(in, now); got != want {
			t.Errorf("retryAfter(%q) = %v, want %v", in, got, want)
		}
	}
}

// retryServer answers the first log POST with 429 and the given Retry-After,
// then 202, recording when each attempt arrived.
func retryServer(t *testing.T, header string) (*httptest.Server, func() []time.Time) {
	t.Helper()
	var mu sync.Mutex
	var at []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/log" {
			w.WriteHeader(202)
			return
		}
		mu.Lock()
		at = append(at, time.Now())
		first := len(at) == 1
		mu.Unlock()
		if first {
			w.Header().Set("Retry-After", header)
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(202)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []time.Time {
		mu.Lock()
		defer mu.Unlock()
		return append([]time.Time(nil), at...)
	}
}

func TestRetryAfterHonoredAndBounded(t *testing.T) {
	cases := []struct {
		header  string
		max     time.Duration
		atLeast time.Duration
		under   time.Duration
	}{
		{"1", 5 * time.Second, time.Second, 3 * time.Second},
		{"3600", 80 * time.Millisecond, 80 * time.Millisecond, time.Second},
	}
	for _, c := range cases {
		srv, attempts := retryServer(t, c.header)
		n := start(t, NRConfig{
			LicenseKey: testKey, LogURL: srv.URL + "/log", MetricURL: srv.URL + "/metric",
			HeartbeatInterval: -1, Backoff: []time.Duration{time.Millisecond}, MaxRetryAfter: c.max,
		})
		n.Emit(Event{Action: "x"})
		closeNR(t, n)
		at := attempts()
		if len(at) != 2 {
			t.Fatalf("Retry-After %s: attempts = %d", c.header, len(at))
		}
		if gap := at[1].Sub(at[0]); gap < c.atLeast || gap > c.under {
			t.Errorf("Retry-After %s: gap %v, want [%v, %v]", c.header, gap, c.atLeast, c.under)
		}
		if st := n.Stats(); st.Retries != 1 || st.Lost != 0 || st.Errors != 0 {
			t.Errorf("Retry-After %s: stats %+v", c.header, st)
		}
	}
}

func TestHeartbeatIndependentOfStalledWorker(t *testing.T) {
	var heartbeats atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		b, _ := io.ReadAll(zr)
		if strings.Contains(string(b), `"stream":"heartbeat"`) {
			if !strings.Contains(string(b), `"queue_len"`) || !strings.Contains(string(b), `"dropped_total"`) {
				t.Errorf("heartbeat lacks health attributes: %s", b)
			}
			heartbeats.Add(1)
			w.WriteHeader(202)
			return
		}
		if r.URL.Path == "/log" {
			// Normal log batches are rate-limited for a long time.
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(202)
	}))
	defer srv.Close()
	n := start(t, NRConfig{
		LicenseKey: testKey, LogURL: srv.URL + "/log", MetricURL: srv.URL + "/metric",
		HeartbeatInterval: 10 * time.Millisecond, FlushInterval: time.Millisecond,
		QueueSize: 4, BatchSize: 1, Backoff: []time.Duration{time.Millisecond}, MaxRetryAfter: time.Minute,
	})
	for i := 0; i < 20; i++ { // fill the queue while the worker sleeps
		n.Emit(Event{Action: "flood"})
	}
	deadline := time.Now().Add(3 * time.Second)
	for heartbeats.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if heartbeats.Load() < 3 {
		t.Errorf("heartbeats = %d while worker stalled", heartbeats.Load())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = n.Close(ctx)
	closeNR(t, n)
	if st := n.Stats(); st.Dropped == 0 || st.Lost == 0 {
		t.Errorf("stalled delivery not accounted: %+v", st)
	}
}

func TestMetricsAfterCloseDropped(t *testing.T) {
	srv := newServer(t, 202)
	n := start(t, srv.cfg())
	closeNR(t, n)
	n.Count("attackbox.requests", 1, nil)
	n.Gauge("attackbox.x", 1, nil)
	if d := n.Stats().Dropped; d != 2 {
		t.Errorf("post-close metrics dropped = %d, want 2", d)
	}
	for _, p := range srv.posts("/metric/v1") {
		if strings.Contains(string(p.Payload), "attackbox.requests") {
			t.Error("post-close count was shipped")
		}
	}
}

func TestTransientFailuresCounted(t *testing.T) {
	srv := newServer(t, 500)
	n := start(t, srv.cfg())
	n.Emit(Event{Action: "x"})
	closeNR(t, n)
	st := n.Stats()
	// two backoff steps: each failing payload (logs, metrics) retries twice.
	if st.Retries != 4 || st.Errors != 2 {
		t.Errorf("stats %+v", st)
	}
}

func TestNestedEncodedKeyAndCredentialQueryRejected(t *testing.T) {
	double := strings.ReplaceAll(testKey, "0", "%2530")
	triple := strings.ReplaceAll(testKey, "a", "%252561")
	urls := []string{
		"https://example.com/log?k=" + double,
		"https://example.com/" + triple + "/log",
		"https://example.com/log?api_key=another-secret",
		"https://example.com/log?token=x",
		"https://example.com/log?password=x",
		"https://example.com/log?X-License-Key=x",
		"https://example.com/log?api%255Fkey=x",
	}
	for _, u := range urls {
		for _, cfg := range []NRConfig{
			{LicenseKey: testKey, LogURL: u, Client: noNet},
			{LicenseKey: testKey, MetricURL: u, Client: noNet},
		} {
			if n, err := NewNewRelic(cfg); err == nil {
				closeNR(t, n)
				t.Errorf("%s accepted", u)
			}
		}
	}
	// Ordinary query parameters stay allowed.
	n, err := NewNewRelic(NRConfig{LicenseKey: testKey, LogURL: "https://example.com/log?region=eu", Client: noNet, HeartbeatInterval: -1, Backoff: []time.Duration{}})
	if err != nil {
		t.Fatalf("plain query rejected: %v", err)
	}
	closeNR(t, n)
}

func TestFailureScrubsEscapedKey(t *testing.T) {
	var hook []string
	var mu sync.Mutex
	n := start(t, NRConfig{
		LicenseKey: testKey, Client: noNet, HeartbeatInterval: -1, Backoff: []time.Duration{},
		OnError: func(err error) { mu.Lock(); hook = append(hook, err.Error()); mu.Unlock() },
	})
	defer closeNR(t, n)
	forms := []string{
		testKey,
		strings.ToUpper(testKey),
		strings.ReplaceAll(testKey, "0", "%30"),
		strings.ReplaceAll(testKey, "0", "%2530"),
		strings.ReplaceAll(strings.ToUpper(testKey), "A", "%2541"),
		strings.ReplaceAll(testKey, "N", "%4e"),
	}
	for _, f := range forms {
		n.fail(errors.New(`Post "https://x.test/log?k=`+f+`": dial failed`), 1)
		last := n.Stats().LastError
		if containsKey(last, testKey) || !strings.Contains(last, "[redacted]") {
			t.Errorf("form %q survived: %q", f, last)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hook) != len(forms) {
		t.Fatalf("OnError calls = %d", len(hook))
	}
	for _, h := range hook {
		if containsKey(h, testKey) {
			t.Errorf("OnError leaked key: %q", h)
		}
	}
}

func TestRecoveredFailureShipped(t *testing.T) {
	var mu sync.Mutex
	var metrics [][]byte
	var logHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/log" && logHits.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if r.URL.Path == "/metric" {
			zr, _ := gzip.NewReader(r.Body)
			b, _ := io.ReadAll(zr)
			mu.Lock()
			metrics = append(metrics, b)
			mu.Unlock()
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
	st := n.Stats()
	if st.Sent == 0 || st.Lost != 0 || st.Retries != 1 || st.Errors != 0 {
		t.Fatalf("stats %+v", st)
	}
	mu.Lock()
	defer mu.Unlock()
	var last metricPayload
	if len(metrics) == 0 {
		t.Fatal("no metric POST")
	}
	if err := json.Unmarshal(metrics[len(metrics)-1], &last); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range last[0].Metrics {
		if m.Name == "attackbox.telemetry.ingest_retries_total" {
			found = true
			if m.Value != 1 {
				t.Errorf("ingest_retries_total = %v", m.Value)
			}
		}
	}
	if !found {
		t.Error("ingest_retries_total not shipped")
	}
}

func TestRetryWaitCappedForCustomBackoff(t *testing.T) {
	srv, attempts := retryServer(t, "1")
	n := start(t, NRConfig{
		LicenseKey: testKey, LogURL: srv.URL + "/log", MetricURL: srv.URL + "/metric",
		HeartbeatInterval: -1, Backoff: []time.Duration{2 * time.Second}, MaxRetryAfter: 100 * time.Millisecond,
	})
	n.Emit(Event{Action: "x"})
	closeNR(t, n)
	at := attempts()
	if len(at) != 2 {
		t.Fatalf("attempts = %d", len(at))
	}
	if gap := at[1].Sub(at[0]); gap < 100*time.Millisecond || gap > time.Second {
		t.Errorf("gap %v, want about 100ms", gap)
	}
}

func TestCancelledRetryNotCounted(t *testing.T) {
	srv, attempts := retryServer(t, "60")
	n := start(t, NRConfig{
		LicenseKey: testKey, LogURL: srv.URL + "/log", MetricURL: srv.URL + "/metric",
		HeartbeatInterval: -1, Backoff: []time.Duration{time.Millisecond}, MaxRetryAfter: time.Minute,
		FlushInterval: time.Millisecond,
	})
	n.Emit(Event{Action: "x"})
	deadline := time.Now().Add(2 * time.Second)
	for len(attempts()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	began := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := n.Close(ctx); err == nil {
		t.Fatal("Close returned nil while a 60s retry wait was pending")
	}
	closeNR(t, n)
	if el := time.Since(began); el > 2*time.Second {
		t.Errorf("close took %v", el)
	}
	if got := len(attempts()); got != 1 {
		t.Errorf("log POSTs = %d, want 1", got)
	}
	if st := n.Stats(); st.Retries != 0 || st.Lost == 0 {
		t.Errorf("stats %+v", st)
	}
}
