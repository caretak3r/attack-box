package telemetry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
type Record struct {
	ID     string        `json:"id"`
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

// spoolBackoff is the redial schedule after a failed write. The first redial
// is immediate because the usual cause is a shipper restart.
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
	OnError      func(error) // write and redial failures; must not call back into the Spool

	dial func() (net.Conn, error) // tests only; nil dials Socket
}

// SpoolStats counts records. Written records were fully written to a
// connection; Lost records were in flight when Close gave up.
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
// is written again after a redial, so a reconnect can duplicate records but
// does not silently lose them. The application protocol is one-way: the
// Spool never reads from the socket.
type Spool struct {
	cfg  SpoolConfig
	boot string

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

	conn net.Conn // writer goroutine only

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
	s.put("event", e)
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
	s.put("metric", MetricRecord{Name: name, Kind: kind, Value: value, At: s.cfg.Now(), Attrs: SafeLabels(attrs)})
}

// put encodes v outside the lock, then takes a seq and queues the line under
// it, so queue order matches seq order.
func (s *Spool) put(field string, v any) {
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
	size := len(`{"id":"","":}`) + len(id) + len(field) + len(payload) + 1
	if size > s.cfg.MaxRecord {
		s.drop(true)
		return
	}
	if s.bytes.Load()+int64(size) > int64(s.cfg.QueueBytes) {
		s.drop(false)
		return
	}
	line := make([]byte, 0, size)
	line = append(line, `{"id":"`...)
	line = append(line, id...)
	line = append(line, `","`...)
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
			// Close gave up: everything still held is lost.
			n := int64(len(batch))
			for range s.queue {
				n++
			}
			s.lost.Add(n)
			s.bytes.Store(0)
			return
		}
		s.bytes.Add(-int64(size))
		if !open {
			return
		}
	}
}

// flush writes the whole batch, redialling and rewriting it after any
// failure. It returns false only when Close abandons the batch.
func (s *Spool) flush(batch [][]byte) bool {
	for attempt := 0; ; attempt++ {
		if s.conn == nil && !s.redial() {
			return false
		}
		if attempt > 0 {
			s.resent.Add(1)
		}
		_ = s.conn.SetWriteDeadline(time.Now().Add(s.cfg.WriteTimeout)) // wall clock: Now may be a test clock
		bufs := net.Buffers(append([][]byte(nil), batch...))
		_, err := bufs.WriteTo(s.conn)
		if err == nil {
			return true
		}
		_ = s.conn.Close()
		s.conn = nil
		s.fail(fmt.Errorf("spool: write: %w", err))
		select {
		case <-s.stop:
			return false
		default:
		}
	}
}

// redial reconnects on the backoff schedule until it succeeds or Close gives
// up.
func (s *Spool) redial() bool {
	for i := 0; ; i++ {
		wait := spoolBackoff[min(i, len(spoolBackoff)-1)]
		t := time.NewTimer(wait)
		select {
		case <-s.stop:
			t.Stop()
			return false
		case <-t.C:
		}
		conn, err := s.cfg.dial()
		if err == nil {
			s.conn = conn
			s.reconnects.Add(1)
			return true
		}
		s.fail(fmt.Errorf("spool: redial: %w", err))
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
			st := s.Stats()
			s.Emit(Event{Stream: StreamHeartbeat, Action: "bait_heartbeat", Result: "ok", Attrs: map[string]any{
				"queue_len": len(s.queue), "queue_bytes": s.bytes.Load(),
				"dropped_total": st.Dropped, "errors_total": st.Errors, "reconnects": st.Reconnects,
			}})
		}
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
	s.beatOnce.Do(func() { close(s.beatStop) })
	<-s.beatDone
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
		<-s.done
		err = fmt.Errorf("spool: drain: %w", ctx.Err())
	}
	st := s.Stats()
	if err == nil && (st.Dropped > 0 || st.Lost > 0) {
		err = fmt.Errorf("spool: %d dropped, %d lost", st.Dropped, st.Lost)
	}
	return err
}
