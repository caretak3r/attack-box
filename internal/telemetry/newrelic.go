package telemetry

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultLogURL    = "https://log-api.newrelic.com/log/v1"
	defaultMetricURL = "https://metric-api.newrelic.com/metric/v1"
	maxSeries        = 2000
)

// NRConfig configures the New Relic shipper. Zero values take defaults.
type NRConfig struct {
	LicenseKey        string
	LogURL            string
	MetricURL         string
	BatchSize         int           // log events per batch; default 200
	FlushInterval     time.Duration // default 5s
	QueueSize         int           // default 10000
	MaxPayloadBytes   int           // uncompressed bytes per POST; default 900_000
	Client            *http.Client  // default timeout 10s
	Now               func() time.Time
	Common            map[string]any
	HeartbeatInterval time.Duration // 0 means 30s; negative disables
	Backoff           []time.Duration
	OnError           func(error)
}

// Stats is a snapshot of shipper counters. Sent counts log events and metrics
// New Relic accepted; Dropped counts items refused by a full queue or series
// cap; Lost counts items abandoned after failed delivery; Errors counts failed
// POSTs.
type Stats struct {
	Sent      int64
	Dropped   int64
	Lost      int64
	Errors    int64
	LastError string
}

type series struct {
	name   string
	count  bool
	value  float64
	labels map[string]string
	at     time.Time
}

// NewRelic ships events to the Log API and metrics to the Metric API. Emit,
// Count and Gauge never block.
type NewRelic struct {
	cfg    NRConfig
	client *http.Client
	queue  chan Event

	closeMu sync.RWMutex
	closed  bool
	quit    chan struct{}
	done    chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc

	mu        sync.Mutex
	series    map[string]*series
	lastFlush time.Time

	sent, dropped, lost, errs atomic.Int64
	errMu                     sync.Mutex
	lastErr                   string
}

func NewNewRelic(cfg NRConfig) (*NewRelic, error) {
	if cfg.LicenseKey == "" {
		return nil, errors.New("newrelic: license key required")
	}
	if cfg.LogURL == "" {
		cfg.LogURL = defaultLogURL
	}
	if cfg.MetricURL == "" {
		cfg.MetricURL = defaultMetricURL
	}
	for _, u := range []string{cfg.LogURL, cfg.MetricURL} {
		if err := validateURL(u, cfg.LicenseKey); err != nil {
			return nil, err
		}
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 200
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 10000
	}
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = 900_000
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 30 * time.Second
	}
	if cfg.Backoff == nil {
		cfg.Backoff = []time.Duration{time.Second, 2 * time.Second}
	}
	client := &http.Client{Timeout: 10 * time.Second}
	if cfg.Client != nil {
		c := *cfg.Client
		client = &c
	}
	// Api-Key is not stripped on cross-host redirects, so never follow them.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	n := &NewRelic{
		cfg:       cfg,
		client:    client,
		queue:     make(chan Event, cfg.QueueSize),
		quit:      make(chan struct{}),
		done:      make(chan struct{}),
		series:    map[string]*series{},
		lastFlush: cfg.Now(),
	}
	n.ctx, n.cancel = context.WithCancel(context.Background())
	go n.run()
	return n, nil
}

func validateURL(raw, key string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("newrelic: invalid endpoint URL")
	}
	if u.User != nil || strings.Contains(raw, key) {
		return errors.New("newrelic: credentials must not be in the endpoint URL")
	}
	switch u.Scheme {
	case "https":
	case "http":
		switch u.Hostname() {
		case "127.0.0.1", "localhost", "::1":
		default:
			return errors.New("newrelic: http endpoint only allowed on loopback")
		}
	default:
		return errors.New("newrelic: endpoint must be https")
	}
	return nil
}

// Emit chunks the event and queues each chunk, dropping when the queue is full.
func (n *NewRelic) Emit(e Event) {
	if e.Timestamp.IsZero() {
		e.Timestamp = n.cfg.Now()
	}
	chunks := Chunk(e, MaxChunk)
	n.closeMu.RLock()
	defer n.closeMu.RUnlock()
	for _, c := range chunks {
		if n.closed {
			n.dropped.Add(1)
			continue
		}
		select {
		case n.queue <- c:
		default:
			n.dropped.Add(1)
		}
	}
}

// Count adds value to a counter, summed until the next flush.
func (n *NewRelic) Count(name string, value float64, attrs map[string]string) {
	n.record(name, true, value, attrs)
}

// Gauge sets a gauge; the last value before the flush is sent.
func (n *NewRelic) Gauge(name string, value float64, attrs map[string]string) {
	n.record(name, false, value, attrs)
}

func (n *NewRelic) record(name string, count bool, value float64, attrs map[string]string) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return
	}
	labels := SafeLabels(attrs)
	key := seriesKey(name, count, labels)
	now := n.cfg.Now()
	n.mu.Lock()
	defer n.mu.Unlock()
	s, ok := n.series[key]
	if !ok {
		if len(n.series) >= maxSeries {
			n.dropped.Add(1)
			return
		}
		s = &series{name: name, count: count, labels: labels}
		n.series[key] = s
	}
	if count {
		s.value += value
	} else {
		s.value = value
	}
	s.at = now
}

func seriesKey(name string, count bool, labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(name)
	if count {
		b.WriteString("|c")
	} else {
		b.WriteString("|g")
	}
	for _, k := range keys {
		b.WriteString("|" + k + "=" + labels[k])
	}
	return b.String()
}

// Stats returns a snapshot of the counters.
func (n *NewRelic) Stats() Stats {
	n.errMu.Lock()
	last := n.lastErr
	n.errMu.Unlock()
	return Stats{
		Sent: n.sent.Load(), Dropped: n.dropped.Load(), Lost: n.lost.Load(),
		Errors: n.errs.Load(), LastError: last,
	}
}

// Close stops intake, drains the queue and flushes logs and metrics. If ctx
// ends first, in-flight delivery is aborted and ctx.Err() returned. It is safe
// to call more than once.
func (n *NewRelic) Close(ctx context.Context) error {
	n.closeMu.Lock()
	if !n.closed {
		n.closed = true
		close(n.quit)
	}
	n.closeMu.Unlock()
	select {
	case <-n.done:
		return nil
	case <-ctx.Done():
		n.cancel()
		return ctx.Err()
	}
}

func (n *NewRelic) run() {
	defer close(n.done)
	defer n.cancel()
	flush := time.NewTicker(n.cfg.FlushInterval)
	defer flush.Stop()
	var hb <-chan time.Time
	if n.cfg.HeartbeatInterval > 0 {
		t := time.NewTicker(n.cfg.HeartbeatInterval)
		defer t.Stop()
		hb = t.C
	}
	batch := make([]Event, 0, n.cfg.BatchSize)
	send := func() {
		n.flushLogs(batch)
		batch = batch[:0]
	}
	for {
		select {
		case e := <-n.queue:
			batch = append(batch, e)
			if len(batch) >= n.cfg.BatchSize {
				send()
			}
		case <-flush.C:
			send()
			n.flushMetrics()
		case <-hb:
			n.Emit(Event{Stream: StreamHeartbeat, Action: "heartbeat"})
			n.Gauge("attackbox.heartbeat", 1, nil)
		case <-n.quit:
			for {
				select {
				case e := <-n.queue:
					batch = append(batch, e)
					if len(batch) >= n.cfg.BatchSize {
						send()
					}
					continue
				default:
				}
				break
			}
			send()
			n.flushMetrics()
			return
		}
	}
}

func (n *NewRelic) flushLogs(events []Event) {
	if len(events) == 0 {
		return
	}
	items := make([][]byte, 0, len(events))
	for _, e := range events {
		attrs := e.Attributes()
		delete(attrs, "timestamp")
		delete(attrs, "message")
		b, err := json.Marshal(map[string]any{
			"timestamp":  e.Timestamp.UnixMilli(),
			"message":    e.Message(),
			"attributes": attrs,
		})
		if err != nil {
			n.fail(fmt.Errorf("newrelic: marshal event: %w", err), 1)
			continue
		}
		items = append(items, b)
	}
	common, err := json.Marshal(map[string]any{"attributes": n.cfg.Common})
	if err != nil {
		n.fail(fmt.Errorf("newrelic: marshal common: %w", err), len(items))
		return
	}
	n.postAll(n.cfg.LogURL, common, "logs", items)
}

func (n *NewRelic) flushMetrics() {
	n.Gauge("attackbox.telemetry.dropped_total", float64(n.dropped.Load()), nil)
	n.Gauge("attackbox.telemetry.ingest_errors_total", float64(n.errs.Load()), nil)

	now := n.cfg.Now()
	n.mu.Lock()
	pending := n.series
	n.series = map[string]*series{}
	start := n.lastFlush
	n.lastFlush = now
	n.mu.Unlock()

	interval := now.Sub(start).Milliseconds()
	if interval < 1 {
		interval = 1
	}
	keys := make([]string, 0, len(pending))
	for k := range pending {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	items := make([][]byte, 0, len(keys))
	for _, k := range keys {
		s := pending[k]
		m := map[string]any{"name": s.name, "value": s.value}
		if s.count {
			m["type"] = "count"
			m["interval.ms"] = interval
		} else {
			m["type"] = "gauge"
			m["timestamp"] = s.at.UnixMilli()
		}
		if len(s.labels) > 0 {
			m["attributes"] = s.labels
		}
		b, err := json.Marshal(m)
		if err != nil {
			n.fail(fmt.Errorf("newrelic: marshal metric: %w", err), 1)
			continue
		}
		items = append(items, b)
	}
	common, err := json.Marshal(map[string]any{
		"timestamp":   start.UnixMilli(),
		"interval.ms": interval,
		"attributes":  n.cfg.Common,
	})
	if err != nil {
		n.fail(fmt.Errorf("newrelic: marshal common: %w", err), len(items))
		return
	}
	n.postAll(n.cfg.MetricURL, common, "metrics", items)
}

// postAll packs items into POSTs of at most MaxPayloadBytes uncompressed. An
// item too large for any POST is dropped and counted.
func (n *NewRelic) postAll(endpoint string, common []byte, field string, items [][]byte) {
	head := append(append([]byte(`[{"common":`), common...), []byte(`,"`+field+`":[`)...)
	const tail = `]}]`
	limit := n.cfg.MaxPayloadBytes - len(head) - len(tail)

	var buf []byte
	count := 0
	flush := func() {
		if count == 0 {
			return
		}
		payload := append(append(append([]byte(nil), head...), buf...), tail...)
		n.post(endpoint, payload, count)
		buf, count = buf[:0], 0
	}
	for _, it := range items {
		if len(it) > limit {
			n.fail(errors.New("newrelic: item exceeds max payload size"), 1)
			continue
		}
		extra := len(it)
		if count > 0 {
			extra++
		}
		if len(buf)+extra > limit {
			flush()
			extra = len(it)
		}
		if count > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, it...)
		count++
	}
	flush()
}

func (n *NewRelic) post(endpoint string, payload []byte, items int) {
	var zbuf bytes.Buffer
	zw := gzip.NewWriter(&zbuf)
	zw.Write(payload)
	if err := zw.Close(); err != nil {
		n.fail(fmt.Errorf("newrelic: gzip: %w", err), items)
		return
	}
	body := zbuf.Bytes()

	var err error
	for attempt := 0; ; attempt++ {
		var retry bool
		retry, err = n.try(endpoint, body)
		if err == nil {
			n.sent.Add(int64(items))
			return
		}
		if !retry || attempt >= len(n.cfg.Backoff) {
			break
		}
		select {
		case <-time.After(n.cfg.Backoff[attempt]):
		case <-n.ctx.Done():
			n.fail(err, items)
			return
		}
	}
	n.fail(err, items)
}

// try makes one POST. retry reports whether the failure is worth another go.
func (n *NewRelic) try(endpoint string, body []byte) (retry bool, err error) {
	req, err := http.NewRequestWithContext(n.ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return false, errors.New("newrelic: build request failed")
	}
	req.Header.Set("Api-Key", n.cfg.LicenseKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := n.client.Do(req)
	if err != nil {
		return n.ctx.Err() == nil, fmt.Errorf("newrelic: transport error: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, nil
	}
	return resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500,
		fmt.Errorf("newrelic: %s returned status %d", req.URL.Path, resp.StatusCode)
}

// fail records a failed delivery. The license key is scrubbed from the message.
func (n *NewRelic) fail(err error, items int) {
	err = errors.New(strings.ReplaceAll(err.Error(), n.cfg.LicenseKey, "[redacted]"))
	n.errs.Add(1)
	n.lost.Add(int64(items))
	n.errMu.Lock()
	n.lastErr = err.Error()
	n.errMu.Unlock()
	if n.cfg.OnError != nil {
		n.cfg.OnError(err)
	}
}
