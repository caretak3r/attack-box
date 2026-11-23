package telemetry

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"attackbox/internal/secret"
)

const (
	defaultLogURL    = "https://log-api.newrelic.com/log/v1"
	defaultMetricURL = "https://metric-api.newrelic.com/metric/v1"
	maxSeries        = 2000
	licenseKeyLen    = 40

	defaultPayloadBytes = 900_000
	// MinPayloadBytes is the smallest POST size MaxPayloadBytes is clamped to.
	// The host shipper bounds admitted log items by it.
	MinPayloadBytes = 64 << 10
	maxPayloadBytes = 950_000 // New Relic rejects bodies over 1MB
	closeGrace      = time.Second

	// New Relic drops a record with more than 254 attributes, names over 255
	// characters or string values over 4094 characters.
	maxAttrKey    = 255
	maxAttrValue  = 4000
	maxExtraAttrs = 230 // leaves room for the fixed fields and the marker
)

// ValidLicenseKey accepts only the documented New Relic license-key shape: 40
// alphanumeric characters, either lowercase hex (original account keys) or
// ending in "NRAL" (Ingest - License keys, including region-prefixed ones).
// User, Insert, Query, browser and admin keys are rejected by prefix because
// they grant more than write-only ingest.
func ValidLicenseKey(k string) error {
	for _, p := range []string{"NRAK-", "NRAA-", "NRII-", "NRIQ-", "NRJS-", "NRBR-"} {
		if strings.HasPrefix(k, p) {
			return fmt.Errorf("newrelic: %s... is not an ingest license key; create an Ingest - License key", p)
		}
	}
	if len(k) != licenseKeyLen {
		return fmt.Errorf("newrelic: license key must be %d characters, got %d", licenseKeyLen, len(k))
	}
	hex := true
	for _, c := range k {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'Z', c >= 'g' && c <= 'z':
			hex = false
		default:
			return errors.New("newrelic: license key must be alphanumeric")
		}
	}
	if !hex && !strings.HasSuffix(k, "NRAL") {
		return errors.New("newrelic: license key must be 40 hex characters or end in NRAL")
	}
	return nil
}

// NRConfig configures the New Relic shipper. Zero values take defaults.
type NRConfig struct {
	LicenseKey        string
	LogURL            string
	MetricURL         string
	BatchSize         int           // log events per batch; default 200
	FlushInterval     time.Duration // default 5s
	QueueSize         int           // default 10000
	MaxPayloadBytes   int           // uncompressed bytes per POST; default 900_000, max 950_000
	Client            *http.Client  // default timeout 10s
	Now               func() time.Time
	Common            map[string]any
	HeartbeatInterval time.Duration // 0 means 30s; negative disables
	Backoff           []time.Duration
	MaxRetryAfter     time.Duration         // cap on a 429 Retry-After wait; default 30s
	HeartbeatAttrs    func() map[string]any // merged into each heartbeat, must not block
	OnError           func(error)
}

// Stats is a snapshot of shipper counters. Sent counts log events and metrics
// New Relic accepted; DroppedLogs counts events refused by a full queue or
// arriving after Close; DroppedMetrics counts metrics refused by the series cap
// or arriving after Close; Dropped is their sum; Lost counts items abandoned
// after failed delivery, including events still queued when Close timed out;
// Errors counts POSTs that finally failed; Retries counts transient failed
// attempts that were retried.
type Stats struct {
	Sent           int64
	Dropped        int64
	DroppedLogs    int64
	DroppedMetrics int64
	Lost           int64
	Errors         int64
	Retries        int64
	LastError      string
}

type series struct {
	name   string
	count  bool
	value  float64
	labels map[string]string
	at     time.Time

	// internal series are the shipper's own health metrics. They are rebuilt
	// on every flush, so a failed POST does not requeue them.
	internal bool
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

	sent, lost, errs, retries   atomic.Int64
	droppedLogs, droppedMetrics atomic.Int64
	errMu                       sync.Mutex
	lastErr                     string
	keyRe                       *regexp.Regexp
}

func NewNewRelic(cfg NRConfig) (*NewRelic, error) {
	if cfg.LicenseKey == "" {
		return nil, errors.New("newrelic: license key required")
	}
	if err := ValidLicenseKey(cfg.LicenseKey); err != nil {
		return nil, err
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
		cfg.MaxPayloadBytes = defaultPayloadBytes
	}
	cfg.MaxPayloadBytes = min(max(cfg.MaxPayloadBytes, MinPayloadBytes), maxPayloadBytes)
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 30 * time.Second
	}
	if cfg.Backoff == nil {
		cfg.Backoff = []time.Duration{time.Second, 2 * time.Second}
	}
	if cfg.MaxRetryAfter <= 0 {
		cfg.MaxRetryAfter = 30 * time.Second
	}
	// The shipper marshals Common from several goroutines and New Relic
	// rejects "attributes":null, so keep a private non-nil copy.
	cfg.Common = maps.Clone(cfg.Common)
	if cfg.Common == nil {
		cfg.Common = map[string]any{}
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
		keyRe:     keyPattern(cfg.LicenseKey),
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
	if u.User != nil || containsKey(raw, key) {
		return errors.New("newrelic: credentials must not be in the endpoint URL")
	}
	// Authentication is header-only, so any credential-named query
	// parameter is a misconfiguration even when it is not the license key.
	for name := range u.Query() {
		if secret.IsCredentialName(unescapeAll(name)) {
			return errors.New("newrelic: credential query parameters are not allowed in the endpoint URL")
		}
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

// containsKey also catches case-folded and percent-encoded copies of the key,
// including nested encodings such as %2530.
func containsKey(raw, key string) bool {
	key = strings.ToLower(key)
	for f := raw; ; {
		if strings.Contains(strings.ToLower(f), key) {
			return true
		}
		next := unescapeOnce(f)
		if next == f {
			return false
		}
		f = next
	}
}

// unescapeOnce decodes one percent-encoding layer. Invalid escapes are kept
// as they are, so a stray % cannot stop the decoding of later bytes.
func unescapeOnce(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// unescapeAll peels percent-encoding until the value is stable. A capped
// loop would accept a name nested one layer deeper than the cap, so there is
// no cap: every changing pass shortens the string by at least two bytes, which
// bounds the work by the length of the operator-supplied URL.
func unescapeAll(s string) string {
	for {
		next := unescapeOnce(s)
		if next == s {
			return s
		}
		s = next
	}
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// keyPattern matches the license key case-insensitively, with any character
// written literally or percent-encoded through any number of %25 layers.
// The key is validated as alphanumeric, so QuoteMeta is not needed.
func keyPattern(key string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("(?i)")
	for i := 0; i < len(key); i++ {
		lo, up := strings.ToLower(key[i:i+1]), strings.ToUpper(key[i:i+1])
		fmt.Fprintf(&b, "(?:%s|%%(?:25)*(?:%02x|%02x))", lo, lo[0], up[0])
	}
	return regexp.MustCompile(b.String())
}

// Emit chunks the event and queues each chunk, dropping when the queue is full.
// Attrs and TaskLabels are copied, so the caller may reuse them afterwards.
func (n *NewRelic) Emit(e Event) {
	if e.Timestamp.IsZero() {
		e.Timestamp = n.cfg.Now()
	}
	e.Attrs = maps.Clone(e.Attrs)
	e.TaskLabels = slices.Clone(e.TaskLabels)
	chunks := Chunk(e, MaxChunk)
	n.closeMu.RLock()
	defer n.closeMu.RUnlock()
	for _, c := range chunks {
		if n.closed {
			n.droppedLogs.Add(1)
			continue
		}
		select {
		case n.queue <- c:
		default:
			n.droppedLogs.Add(1)
		}
	}
}

// TryEmit queues e like Emit but reports false and queues nothing when the
// client is closed or the queue cannot take every chunk, so a caller with a
// durable buffer keeps the event instead of dropping it. TryEmit must not be
// called concurrently with Emit or with itself.
func (n *NewRelic) TryEmit(e Event) bool {
	if e.Timestamp.IsZero() {
		e.Timestamp = n.cfg.Now()
	}
	e.Attrs = maps.Clone(e.Attrs)
	e.TaskLabels = slices.Clone(e.TaskLabels)
	chunks := Chunk(e, MaxChunk)
	n.closeMu.RLock()
	defer n.closeMu.RUnlock()
	if n.closed || cap(n.queue)-len(n.queue) < len(chunks) {
		return false
	}
	for _, c := range chunks {
		n.queue <- c // room was checked; ship() only frees space
	}
	return true
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
	n.closeMu.RLock()
	defer n.closeMu.RUnlock()
	if n.closed {
		n.droppedMetrics.Add(1)
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
			n.droppedMetrics.Add(1)
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

// ShipEvent ships one event synchronously, chunking and POSTing it directly
// without using the queue. It returns only when New Relic accepts it or the
// error is permanent. Use this for the shipper's durable queue drain, where
// delivery must be confirmed before checkpointing.
func (n *NewRelic) ShipEvent(e Event) error {
	return n.ShipRecords([]Record{{Event: &e}})
}

// ShipMetric ships one metric synchronously, POSTing it directly without
// using the in-memory series aggregation. It returns only when New Relic
// accepts it or the error is permanent.
func (n *NewRelic) ShipMetric(name string, kind string, value float64, at time.Time, attrs map[string]string) error {
	return n.ShipRecords([]Record{{Metric: &MetricRecord{Name: name, Kind: kind, Value: value, At: at, Attrs: attrs}}})
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
	dl, dm := n.droppedLogs.Load(), n.droppedMetrics.Load()
	return Stats{
		Sent: n.sent.Load(), Dropped: dl + dm, DroppedLogs: dl, DroppedMetrics: dm,
		Lost: n.lost.Load(), Errors: n.errs.Load(), Retries: n.retries.Load(), LastError: last,
	}
}

// Close stops intake, drains the queue and flushes logs and metrics. If ctx
// ends first, in-flight delivery is aborted, the events not yet delivered are
// counted in Lost, and ctx.Err() is returned. It is safe to call more than
// once.
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
		select { // the worker counts what it abandons
		case <-n.done:
		case <-time.After(closeGrace):
		}
		return ctx.Err()
	}
}

func (n *NewRelic) run() {
	var wg sync.WaitGroup
	if n.cfg.HeartbeatInterval > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n.heartbeatLoop()
		}()
	}
	n.ship()
	wg.Wait()
	n.cancel()
	close(n.done)
}

// heartbeatLoop posts heartbeats directly, one attempt each, so a full queue
// or a worker sleeping through retries cannot hide a live host. A failed
// heartbeat is counted as lost; the next tick is the retry.
func (n *NewRelic) heartbeatLoop() {
	t := time.NewTicker(n.cfg.HeartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-n.quit:
			return
		case <-t.C:
		}
		now := n.cfg.Now()
		e := Event{Stream: StreamHeartbeat, Action: "heartbeat", Timestamp: now, Attrs: map[string]any{
			"queue_len":     len(n.queue),
			"dropped_total": n.droppedLogs.Load() + n.droppedMetrics.Load(),
			"lost_total":    n.lost.Load(),
			"errors_total":  n.errs.Load(),
		}}
		if n.cfg.HeartbeatAttrs != nil {
			for k, v := range n.cfg.HeartbeatAttrs() {
				e.Attrs[k] = v
			}
		}
		if item, err := logItem(e); err == nil {
			common, _ := json.Marshal(map[string]any{"attributes": n.cfg.Common})
			n.postOnce(n.cfg.LogURL, envelope(common, "logs", item), 1)
		}
		metric, _ := json.Marshal(map[string]any{"name": "attackbox.heartbeat", "type": "gauge", "value": 1, "timestamp": now.UnixMilli()})
		common, _ := json.Marshal(map[string]any{"attributes": n.cfg.Common})
		n.postOnce(n.cfg.MetricURL, envelope(common, "metrics", metric), 1)
	}
}

func envelope(common []byte, field string, items ...[]byte) []byte {
	b := append([]byte(`[{"common":`), common...)
	b = append(b, `,"`+field+`":[`...)
	for i, it := range items {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, it...)
	}
	return append(b, `]}]`...)
}

func logItem(e Event) ([]byte, error) {
	attrs := limitAttrs(e)
	// Never put captured input in message: New Relic parses JSON messages
	// into attributes after our admission checks. Keep the original chunk
	// opaque and use a non-JSON message even when Action is hostile input.
	attrs["body_chunk"] = e.Body
	return json.Marshal(map[string]any{
		"timestamp":  e.Timestamp.UnixMilli(),
		"message":    "attackbox " + truncate(e.Action, maxAttrValue-10),
		"attributes": attrs,
	})
}

// limitAttrs flattens e within New Relic's attribute limits, which otherwise
// make it drop the whole record. Extra Attrs past maxExtraAttrs are dropped in
// key order, and long keys and values are cut; any cut sets attrs_truncated.
// Values that are not scalars or string slices are shipped as a JSON string,
// because New Relic would flatten them into one attribute per leaf.
func limitAttrs(e Event) map[string]any {
	cut := len(e.Attrs) > maxExtraAttrs
	if cut {
		kept := make(map[string]any, maxExtraAttrs)
		for _, k := range slices.Sorted(maps.Keys(e.Attrs))[:maxExtraAttrs] {
			kept[k] = e.Attrs[k]
		}
		e.Attrs = kept
	}
	attrs := e.Attributes()
	delete(attrs, "timestamp")
	delete(attrs, "message")
	out := make(map[string]any, len(attrs)+1)
	clip := func(s string, limit int) string {
		t := truncate(s, limit)
		cut = cut || len(t) != len(s)
		return t
	}
	for k, v := range attrs {
		switch x := v.(type) {
		case string:
			v = clip(x, maxAttrValue)
		case []string:
			c := make([]string, len(x))
			for i, s := range x {
				c[i] = clip(s, maxAttrValue)
			}
			v = c
		case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64,
			float32, float64, json.Number:
		default:
			b, err := json.Marshal(x)
			if err != nil {
				b = []byte(fmt.Sprintf("[unmarshalable %T]", x))
			}
			v = clip(string(b), maxAttrValue)
		}
		out[clip(k, maxAttrKey)] = v
	}
	if cut {
		out["attrs_truncated"] = true
	}
	return out
}

func (n *NewRelic) ship() {
	flush := time.NewTicker(n.cfg.FlushInterval)
	defer flush.Stop()
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
			n.flushMetrics(false)
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
			n.flushMetrics(true)
			return
		}
	}
}

func (n *NewRelic) flushLogs(events []Event) {
	if len(events) == 0 {
		return
	}
	if n.ctx.Err() != nil {
		n.lost.Add(int64(len(events)))
		return
	}
	items := make([][]byte, 0, len(events))
	for _, e := range events {
		b, err := logItem(e)
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
	retry, perm := n.postAll(n.cfg.LogURL, common, "logs", items)
	n.lost.Add(int64(len(retry) + len(perm)))
}

// flushMetrics ships the pending series. Series from a POST that failed for a
// transient reason are merged back for the next flush, or counted lost when
// final is set. A permanently rejected POST is counted lost at once, so the
// same payload is not sent again. The shipper's own gauges are never counted.
func (n *NewRelic) flushMetrics(final bool) {
	now := n.cfg.Now()
	n.mu.Lock()
	for name, v := range map[string]int64{
		"attackbox.telemetry.dropped_total":         n.droppedLogs.Load() + n.droppedMetrics.Load(),
		"attackbox.telemetry.dropped_logs_total":    n.droppedLogs.Load(),
		"attackbox.telemetry.dropped_metrics_total": n.droppedMetrics.Load(),
		"attackbox.telemetry.ingest_errors_total":   n.errs.Load(),
		"attackbox.telemetry.ingest_retries_total":  n.retries.Load(),
	} {
		n.series[seriesKey(name, false, nil)] = &series{name: name, value: float64(v), at: now, internal: true}
	}
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
	itemKeys := make([]string, 0, len(keys))
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
		itemKeys = append(itemKeys, k)
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
	retry, perm := n.postAll(n.cfg.MetricURL, common, "metrics", items)
	lost := 0
	for _, i := range perm {
		if !pending[itemKeys[i]].internal {
			lost++
		}
	}
	if final {
		for _, i := range retry {
			if !pending[itemKeys[i]].internal {
				lost++
			}
		}
		n.lost.Add(int64(lost))
		return
	}
	n.lost.Add(int64(lost))
	requeue := make(map[string]*series, len(retry))
	for _, i := range retry {
		requeue[itemKeys[i]] = pending[itemKeys[i]]
	}
	n.requeue(requeue)
}

// requeue folds series from a failed POST back into the live set: counts add
// up, gauges keep the newest value. It stays within maxSeries; what does not
// fit is counted in DroppedMetrics.
func (n *NewRelic) requeue(failed map[string]*series) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for k, s := range failed {
		if s.internal {
			continue
		}
		cur, ok := n.series[k]
		switch {
		case !ok && len(n.series) >= maxSeries:
			n.droppedMetrics.Add(1)
		case !ok:
			n.series[k] = s
		case s.count:
			cur.value += s.value
		case s.at.After(cur.at):
			cur.value, cur.at = s.value, s.at
		}
	}
}

const payloadTail = `]}]`

// postAll packs items into POSTs of at most MaxPayloadBytes uncompressed and
// returns the indexes of items whose POST failed: retry for transient
// failures, perm for rejections that a resend will not clear. An item too
// large for any POST is returned as permanently rejected. Durable callers
// must retain it, rather than treating an omitted item as delivered.
func (n *NewRelic) postAll(endpoint string, common []byte, field string, items [][]byte) (retry, perm []int) {
	head := append(append([]byte(`[{"common":`), common...), []byte(`,"`+field+`":[`)...)
	limit := n.cfg.MaxPayloadBytes - len(head) - len(payloadTail)

	var group []int
	size := 0
	flush := func() {
		if len(group) > 0 {
			r, p := n.postGroup(endpoint, head, items, group)
			retry, perm = append(retry, r...), append(perm, p...)
		}
		group, size = nil, 0
	}
	for i, it := range items {
		if len(it) > limit {
			n.recordErr(errors.New("newrelic: item exceeds max payload size"))
			perm = append(perm, i)
			continue
		}
		extra := len(it)
		if len(group) > 0 {
			extra++
		}
		if size+extra > limit {
			flush()
			extra = len(it)
		}
		group = append(group, i)
		size += extra
	}
	flush()
	return retry, perm
}

// postGroup sends items[group] in one POST. On 413 a multi-item group is split
// in half and each half sent on its own. It returns the indexes that failed,
// split by whether a later resend could succeed.
func (n *NewRelic) postGroup(endpoint string, head []byte, items [][]byte, group []int) (retry, perm []int) {
	if n.ctx.Err() != nil {
		return group, nil
	}
	payload := append([]byte(nil), head...)
	for i, idx := range group {
		if i > 0 {
			payload = append(payload, ',')
		}
		payload = append(payload, items[idx]...)
	}
	payload = append(payload, payloadTail...)

	transient, err := n.post(endpoint, payload)
	if err == nil {
		n.sent.Add(int64(len(group)))
		return nil, nil
	}
	var se *statusError
	if errors.As(err, &se) && se.status == http.StatusRequestEntityTooLarge && len(group) > 1 {
		mid := len(group) / 2
		r1, p1 := n.postGroup(endpoint, head, items, group[:mid])
		r2, p2 := n.postGroup(endpoint, head, items, group[mid:])
		return append(r1, r2...), append(p1, p2...)
	}
	n.recordErr(err)
	if transient {
		return group, nil
	}
	return nil, group
}

func gzipBody(payload []byte) ([]byte, error) {
	var zbuf bytes.Buffer
	zw := gzip.NewWriter(&zbuf)
	zw.Write(payload)
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("newrelic: gzip: %w", err)
	}
	return zbuf.Bytes(), nil
}

// postOnce makes a single delivery attempt with no retry.
func (n *NewRelic) postOnce(endpoint string, payload []byte, items int) {
	body, err := gzipBody(payload)
	if err == nil {
		if _, _, err = n.try(endpoint, body); err == nil {
			n.sent.Add(int64(items))
			return
		}
	}
	n.fail(err, items)
}

// post gzips and sends payload, retrying transient failures. The caller
// counts the outcome. transient reports whether the final failure is one a
// later resend could clear.
func (n *NewRelic) post(endpoint string, payload []byte) (transient bool, err error) {
	body, err := gzipBody(payload)
	if err != nil {
		return false, err
	}
	for attempt := 0; ; attempt++ {
		var retry bool
		var after time.Duration
		retry, after, err = n.try(endpoint, body)
		if err == nil {
			return false, nil
		}
		if !retry || attempt >= len(n.cfg.Backoff) {
			return retry, err
		}
		// The larger of the backoff step and Retry-After, always capped.
		wait := min(max(n.cfg.Backoff[attempt], after), n.cfg.MaxRetryAfter)
		select {
		case <-time.After(wait):
		case <-n.ctx.Done():
			return true, err
		}
		// Counted only once the next POST is certain to run.
		n.retries.Add(1)
	}
}

type statusError struct {
	path   string
	status int
}

func (e *statusError) Error() string {
	return fmt.Sprintf("newrelic: %s returned status %d", e.path, e.status)
}

// try makes one POST. retry reports whether the failure is worth another go;
// after is the server's Retry-After on a 429, or zero.
func (n *NewRelic) try(endpoint string, body []byte) (retry bool, after time.Duration, err error) {
	req, err := http.NewRequestWithContext(n.ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return false, 0, errors.New("newrelic: build request failed")
	}
	req.Header.Set("Api-Key", n.cfg.LicenseKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := n.client.Do(req)
	if err != nil {
		return n.ctx.Err() == nil, 0, fmt.Errorf("newrelic: transport error: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false, 0, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		after = retryAfter(resp.Header.Get("Retry-After"), time.Now())
	}
	retry = resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= 500
	return retry, after, &statusError{path: req.URL.Path, status: resp.StatusCode}
}

// retryAfter parses delay-seconds or an HTTP-date. Invalid or past values give
// zero; the caller applies the upper bound.
func retryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs <= 0 {
			return 0
		}
		if secs > int64(24*time.Hour/time.Second) {
			secs = int64(24 * time.Hour / time.Second)
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

// fail records a failed delivery of items.
func (n *NewRelic) fail(err error, items int) {
	n.lost.Add(int64(items))
	n.recordErr(err)
}

// recordErr counts a failed POST. The license key is scrubbed from the message.
func (n *NewRelic) recordErr(err error) {
	err = errors.New(n.keyRe.ReplaceAllString(err.Error(), "[redacted]"))
	n.errs.Add(1)
	n.errMu.Lock()
	n.lastErr = err.Error()
	n.errMu.Unlock()
	if n.cfg.OnError != nil {
		n.cfg.OnError(err)
	}
}

// LogItemSize returns the encoded size of e as one New Relic log item, the
// same bytes the client posts. The host shipper uses it to bound a record's
// expanded size before it admits the record to disk.
func LogItemSize(e Event) (int, error) {
	b, err := logItem(e)
	return len(b), err
}
