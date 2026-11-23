package telemetry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Record is one spooled telemetry item, written as one JSON line to the host
// shipper's unix socket. Exactly one of Event or Metric is set.
//
// ID is "<boot>-<seq>": boot is 16 lowercase hex digits drawn once per
// process and seq a decimal counter that starts at 1. Every Emit, Count and
// Gauge call takes the next seq, including calls that are dropped, so a gap
// in seq at the shipper shows bait-side loss. A hostile producer can forge
// both, so the shipper treats gaps as advisory.
//
// Event is unchunked, and BodySHA256, ChunkIndex and ChunkCount are zero on
// the wire: Chunk at the last hop is the only producer of chunk metadata.
// Attrs round-trip through JSON, so integers above 2^53 lose precision.
//
// V is the wire version. Every producer writes SchemaVersion, and the shipper
// rejects any other value, an absent one included.
type Record struct {
	ID     string        `json:"id"`
	V      int           `json:"v"`
	Event  *Event        `json:"event,omitempty"`
	Metric *MetricRecord `json:"metric,omitempty"`
}

// MetricRecord is one Count or Gauge call. Attrs are already SafeLabels.
type MetricRecord struct {
	Name  string            `json:"name"`
	Kind  string            `json:"kind"` // "count" or "gauge"
	Value float64           `json:"value"`
	At    time.Time         `json:"at"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

// SchemaVersion is the wire version of Record that this build writes and the
// shipper accepts.
const SchemaVersion = 1

// Spool limits and defaults.
const (
	MaxSocketPath       = 107 // Linux sun_path minus the NUL
	DefaultSpoolQueue   = 10000
	DefaultSpoolBytes   = 32 << 20
	DefaultSpoolRecord  = 2 << 20
	DefaultSpoolTimeout = 5 * time.Second
	DefaultSpoolBeat    = 30 * time.Second

	spoolBatchRecords = 100
	spoolBatchBytes   = 1 << 20
)

// spoolBackoff is the redial schedule after a failed write or dial. The first
// redial is immediate because the usual cause is a shipper restart. The
// position survives successful dials and resets only after a successful write,
// so a peer that accepts and then closes is not redialled in a tight loop.
var spoolBackoff = []time.Duration{0, 500 * time.Millisecond, time.Second, 2 * time.Second, 5 * time.Second}

// SpoolConfig configures a Spool.
type SpoolConfig struct {
	Socket       string        // absolute unix socket path, at most MaxSocketPath bytes
	QueueSize    int           // records queued or in flight; default DefaultSpoolQueue
	QueueBytes   int           // encoded bytes queued or in flight; default DefaultSpoolBytes
	MaxRecord    int           // bytes per line including the newline; default DefaultSpoolRecord
	WriteTimeout time.Duration // per batch write; default DefaultSpoolTimeout
	Heartbeat    time.Duration // bait_heartbeat interval; 0 means DefaultSpoolBeat, <0 disables
	Now          func() time.Time
	OnError      func(error)    // write and redial failures; must not call back into the Spool
	Stamp        map[string]any // added to every event, the heartbeat included; wins over an event attribute

	// HeartbeatAttrs adds attributes the spool cannot know, such as the
	// caller's own drop counter, to each bait_heartbeat. Spool counters win over
	// it. It must not block or call back into the Spool.
	HeartbeatAttrs func() map[string]any

	dial func() (net.Conn, error) // tests only; nil dials Socket
}

// SpoolStats counts records. Written records were handed to the kernel by a
// successful write, which says nothing about the shipper having read them;
// Lost records were in flight when Close gave up.
type SpoolStats struct {
	Written    int64
	Dropped    int64 // queue full, over budget, oversize, unencodable or after Close
	Oversize   int64 // subset of Dropped
	Lost       int64
	Errors     int64
	Reconnects int64
	Resent     int64 // batches written again after a failed write
}

// Spool is the bait-side Sink for the spool deployment: it streams Records to
// the host shipper and never holds a New Relic key. Calls never block. One
// writer goroutine owns the connection; a batch it has taken from the queue
// stays in its memory budget until a write of the whole batch succeeds, and
// is written again after a redial, so a reconnect can duplicate records. A
// successful write only means the kernel took the bytes: records the shipper
// had not yet read when it crashed are gone, and show as a seq gap at the
// shipper. The application protocol is one-way: the Spool never reads from
// the socket.
type Spool struct {
	cfg  SpoolConfig
	boot string
	born time.Time // monotonic start of uptime_ms; zero for a Spool built without NewSpool

	mu     sync.Mutex // orders seq with queue order; guards closed
	seq    uint64
	closed bool
	queue  chan []byte
	bytes  atomic.Int64 // encoded bytes queued or in flight

	stop     chan struct{} // Close deadline passed: abandon the batch
	stopOnce sync.Once
	beatStop chan struct{}
	beatOnce sync.Once
	done     chan struct{}
	beatDone chan struct{}

	connMu sync.Mutex // guards conn assignment and write deadlines against Close
	conn   net.Conn   // assigned by the writer goroutine only

	// Writer goroutine only.
	backoff    int       // index into spoolBackoff of the next redial wait
	lastReport time.Time // last OnError call from the I/O path
	suppressed int64     // I/O errors counted but not reported since lastReport

	written, dropped, oversize, lost, errs, reconnects, resent atomic.Int64
}

// ValidSocketPath checks a unix socket path for the spool.
func ValidSocketPath(p string) error {
	switch {
	case !strings.HasPrefix(p, "/"):
		return errors.New("spool: socket path must be absolute")
	case strings.ContainsRune(p, 0):
		return errors.New("spool: socket path contains NUL")
	case len(p) > MaxSocketPath:
		return fmt.Errorf("spool: socket path is %d bytes; at most %d are allowed", len(p), MaxSocketPath)
	}
	return nil
}

// NewSpool dials the socket once and starts the writer. A failed first dial
// is an error: a missing shipper at startup is a unit-ordering bug. Later
// failures are counted and redialled.
func NewSpool(cfg SpoolConfig) (*Spool, error) {
	if err := ValidSocketPath(cfg.Socket); err != nil {
		return nil, err
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = DefaultSpoolQueue
	}
	if cfg.QueueBytes <= 0 {
		cfg.QueueBytes = DefaultSpoolBytes
	}
	if cfg.MaxRecord <= 0 {
		cfg.MaxRecord = DefaultSpoolRecord
	}
	if cfg.MaxRecord > cfg.QueueBytes {
		return nil, errors.New("spool: MaxRecord exceeds QueueBytes")
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = DefaultSpoolTimeout
	}
	if cfg.Heartbeat == 0 {
		cfg.Heartbeat = DefaultSpoolBeat
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.Stamp = maps.Clone(cfg.Stamp)
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	if cfg.dial == nil {
		cfg.dial = func() (net.Conn, error) { return net.DialTimeout("unix", cfg.Socket, cfg.WriteTimeout) }
	}
	conn, err := cfg.dial()
	if err != nil {
		return nil, fmt.Errorf("spool: %w", err)
	}
	s := &Spool{
		cfg:      cfg,
		boot:     hex.EncodeToString(b[:]),
		born:     time.Now(), // wall clock with monotonic reading: Now may be a test clock
		queue:    make(chan []byte, cfg.QueueSize),
		stop:     make(chan struct{}),
		beatStop: make(chan struct{}),
		done:     make(chan struct{}),
		beatDone: make(chan struct{}),
		conn:     conn,
	}
	go s.run()
	if cfg.Heartbeat > 0 {
		go s.heartbeat()
	} else {
		close(s.beatDone)
	}
	return s, nil
}

// Boot returns the per-process ID prefix.
func (s *Spool) Boot() string { return s.boot }

func (s *Spool) Emit(e Event) {
	if e.Timestamp.IsZero() {
		e.Timestamp = s.cfg.Now()
	}
	e.BodySHA256, e.ChunkIndex, e.ChunkCount = "", 0, 0
	e.Attrs = mergeStamp(e.Attrs, s.cfg.Stamp)
	s.put("event", e, isHealth(e))
}

// isHealth reports whether e may use the reserved part of the queue: the
// heartbeat stream and the lifecycle actions of the runtime stream.
func isHealth(e Event) bool {
	switch e.Stream {
	case StreamHeartbeat:
		return true
	case StreamRuntime:
		return e.Action == "start" || e.Action == "stop" || e.Action == "stopped"
	}
	return false
}

// Reserved part of the queue that only health records may use.
const (
	spoolReserveRecords = 4
	spoolReserveBytes   = 64 << 10
)

// reserve returns the records and bytes that payload may not take. A queue
// too small for a whole record in reserve has none, bytes included.
func reserve(queueSize, queueBytes int) (records int, bytes int64) {
	records = min(spoolReserveRecords, queueSize/4)
	if records == 0 {
		return 0, 0
	}
	return records, int64(min(spoolReserveBytes, queueBytes/4))
}

func (s *Spool) Count(name string, value float64, attrs map[string]string) {
	s.metric("count", name, value, attrs)
}

func (s *Spool) Gauge(name string, value float64, attrs map[string]string) {
	s.metric("gauge", name, value, attrs)
}

func (s *Spool) metric(kind, name string, value float64, attrs map[string]string) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return // JSONLog and NewRelic skip these too
	}
	s.put("metric", MetricRecord{Name: name, Kind: kind, Value: value, At: s.cfg.Now(), Attrs: SafeLabels(attrs)}, false)
}

// put encodes v outside the lock, then takes a seq and queues the line under
// it, so queue order matches seq order. A payload record (health false) is
// refused when it would leave less than the reserve free.
func (s *Spool) put(field string, v any, health bool) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(v)
	payload := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))

	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	if err != nil {
		s.drop(false)
		s.fail(fmt.Errorf("spool: encode %s: %w", field, err))
		return
	}
	if s.closed {
		s.drop(false)
		return
	}
	id := s.boot + "-" + strconv.FormatUint(s.seq, 10)
	ver := strconv.Itoa(SchemaVersion)
	size := len(`{"id":"","v":,"":}`) + len(id) + len(ver) + len(field) + len(payload) + 1
	if size > s.cfg.MaxRecord {
		s.drop(true)
		return
	}
	keepRecords, keepBytes := 0, int64(0)
	if !health {
		keepRecords, keepBytes = reserve(s.cfg.QueueSize, s.cfg.QueueBytes)
	}
	if s.bytes.Load()+int64(size)+keepBytes > int64(s.cfg.QueueBytes) || len(s.queue)+keepRecords >= cap(s.queue) {
		s.drop(false)
		return
	}
	line := make([]byte, 0, size)
	line = append(line, `{"id":"`...)
	line = append(line, id...)
	line = append(line, `","v":`...)
	line = append(line, ver...)
	line = append(line, `,"`...)
	line = append(line, field...)
	line = append(line, `":`...)
	line = append(line, payload...)
	line = append(line, "}\n"...)
	select {
	case s.queue <- line:
		s.bytes.Add(int64(len(line)))
	default:
		s.drop(false)
	}
}

func (s *Spool) drop(oversize bool) {
	s.dropped.Add(1)
	if oversize {
		s.oversize.Add(1)
	}
}

func (s *Spool) fail(err error) {
	s.errs.Add(1)
	if s.cfg.OnError != nil {
		s.cfg.OnError(err)
	}
}

// spoolReportEvery limits OnError calls from the I/O path. Every failure is
// still counted in Errors; the next report carries the suppressed count.
const spoolReportEvery = time.Second

// failIO counts a write or redial failure and reports it at most once per
// spoolReportEvery. Writer goroutine only.
func (s *Spool) failIO(err error) {
	s.errs.Add(1)
	now := time.Now() // wall clock: Now may be a test clock
	if !s.lastReport.IsZero() && now.Sub(s.lastReport) < spoolReportEvery {
		s.suppressed++
		return
	}
	if s.suppressed > 0 {
		err = fmt.Errorf("%w (%d similar errors suppressed)", err, s.suppressed)
	}
	s.lastReport, s.suppressed = now, 0
	if s.cfg.OnError != nil {
		s.cfg.OnError(err)
	}
}

func (s *Spool) run() {
	defer close(s.done)
	defer func() {
		if s.conn != nil {
			_ = s.conn.Close()
		}
	}()
	var batch [][]byte
	for {
		size := 0
		batch = batch[:0]
		if s.stopped() {
			s.abandon(0)
			return
		}
		line, ok := <-s.queue
		if !ok {
			return
		}
		batch, size = append(batch, line), len(line)
		open := true
	fill:
		for len(batch) < spoolBatchRecords && size < spoolBatchBytes {
			select {
			case line, ok := <-s.queue:
				if !ok {
					open = false
					break fill
				}
				batch, size = append(batch, line), size+len(line)
			default:
				break fill
			}
		}
		if s.flush(batch) {
			s.written.Add(int64(len(batch)))
		} else {
			s.abandon(int64(len(batch)))
			return
		}
		s.bytes.Add(-int64(size))
		if !open {
			return
		}
	}
}

// stopped reports whether Close has given up.
func (s *Spool) stopped() bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}

// abandon counts the held records and everything still queued as lost. Close
// closes the queue before it can give up, so the drain ends.
func (s *Spool) abandon(held int64) {
	for range s.queue {
		held++
	}
	s.lost.Add(held)
	s.bytes.Store(0)
}

// giveUp wakes a write blocked in the kernel. It runs after stop is closed, so
// a writer that arms a deadline under connMu either sees stop first or has its
// deadline overridden here.
func (s *Spool) giveUp() {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.conn != nil {
		_ = s.conn.SetWriteDeadline(time.Now())
	}
}

// arm sets the write deadline unless Close has given up.
func (s *Spool) arm() bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.stopped() {
		return false
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout)) // wall clock: Now may be a test clock
	return true
}

// setConn replaces the connection; the writer goroutine is its only caller.
func (s *Spool) setConn(c net.Conn) {
	s.connMu.Lock()
	s.conn = c
	s.connMu.Unlock()
}

// flush writes the whole batch, redialling and rewriting it after any
// failure. It returns false only when Close abandons the batch.
func (s *Spool) flush(batch [][]byte) bool {
	for attempt := 0; ; attempt++ {
		if s.stopped() {
			return false
		}
		if s.conn == nil && !s.redial() {
			return false
		}
		if !s.arm() {
			return false
		}
		if attempt > 0 {
			s.resent.Add(1)
		}
		bufs := net.Buffers(append([][]byte(nil), batch...))
		_, err := bufs.WriteTo(s.conn)
		if err == nil {
			s.backoff = 0
			return true
		}
		_ = s.conn.Close()
		s.setConn(nil)
		if s.stopped() {
			return false // the write was cut short by Close, not by the peer
		}
		s.failIO(fmt.Errorf("spool: write: %w", err))
	}
}

// redial reconnects after waiting out the current backoff step, until it
// succeeds or Close gives up. Every wait advances the step, whether or not the
// dial works: only a successful write resets it.
func (s *Spool) redial() bool {
	for {
		wait := spoolBackoff[s.backoff]
		s.backoff = min(s.backoff+1, len(spoolBackoff)-1)
		t := time.NewTimer(wait)
		select {
		case <-s.stop:
			t.Stop()
			return false
		case <-t.C:
		}
		conn, err := s.cfg.dial()
		if err == nil {
			s.setConn(conn)
			s.reconnects.Add(1)
			return true
		}
		s.failIO(fmt.Errorf("spool: redial: %w", err))
	}
}

// heartbeat proves a quiet bait is alive. The shipper assigns the source; the
// bait only says what it is.
func (s *Spool) heartbeat() {
	defer close(s.beatDone)
	t := time.NewTicker(s.cfg.Heartbeat)
	defer t.Stop()
	for {
		select {
		case <-s.beatStop:
			return
		case <-t.C:
			attrs := map[string]any{}
			if s.cfg.HeartbeatAttrs != nil {
				maps.Copy(attrs, s.cfg.HeartbeatAttrs())
			}
			maps.Copy(attrs, s.Counters())
			attrs["queue_len"], attrs["queue_bytes"] = len(s.queue), s.bytes.Load()
			s.Emit(Event{Stream: StreamHeartbeat, Action: "bait_heartbeat", Result: "ok", Attrs: attrs})
		}
	}
}

// StopHeartbeat stops the heartbeat and returns after its goroutine has
// ended, so no bait_heartbeat is emitted afterwards. It is safe to call more
// than once, with the heartbeat disabled, and before Close.
func (s *Spool) StopHeartbeat() {
	s.beatOnce.Do(func() { close(s.beatStop) })
	<-s.beatDone
}

// Counters returns the cumulative counters that bait_heartbeat carries.
// local_dropped_total is not a spool counter: the caller adds it.
func (s *Spool) Counters() map[string]any {
	st := s.Stats()
	var up int64
	if !s.born.IsZero() {
		up = time.Since(s.born).Milliseconds()
	}
	return map[string]any{
		"written_total": st.Written, "dropped_total": st.Dropped, "oversize_total": st.Oversize,
		"lost_total": st.Lost, "resent_total": st.Resent, "errors_total": st.Errors,
		"reconnects": st.Reconnects, "uptime_ms": up,
	}
}

// Stats returns the counters.
func (s *Spool) Stats() SpoolStats {
	return SpoolStats{
		Written: s.written.Load(), Dropped: s.dropped.Load(), Oversize: s.oversize.Load(),
		Lost: s.lost.Load(), Errors: s.errs.Load(), Reconnects: s.reconnects.Load(), Resent: s.resent.Load(),
	}
}

// Close stops intake and waits for every queued record to be written. When
// ctx ends first, the writer abandons what it holds, those records count as
// Lost and Close returns an error. It also returns an error when any record
// was dropped or lost. Repeated calls only wait.
func (s *Spool) Close(ctx context.Context) error {
	// Stop the heartbeat first and outside the lock: it calls put, which
	// takes the lock.
	s.StopHeartbeat()
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.queue)
	}
	s.mu.Unlock()
	var err error
	select {
	case <-s.done:
	case <-ctx.Done():
		s.stopOnce.Do(func() { close(s.stop) })
		s.giveUp()
		<-s.done
		err = fmt.Errorf("spool: drain: %w", ctx.Err())
	}
	st := s.Stats()
	if err == nil && (st.Dropped > 0 || st.Lost > 0) {
		err = fmt.Errorf("spool: %d dropped, %d lost", st.Dropped, st.Lost)
	}
	return err
}
