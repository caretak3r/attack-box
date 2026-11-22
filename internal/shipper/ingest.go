package shipper

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"
)

// Ingest limits and defaults.
const (
	DefaultIdleTimeout = 2 * time.Minute  // the bait heartbeats every 30 s
	DefaultLineTimeout = 30 * time.Second // one line, first fragment to newline
	DefaultMaxBatch    = 256
	DefaultMaxInvalid  = 3
	maxBoots           = 8       // remembered producer boots per role
	maxBatchBytes      = 4 << 20 // admitted payload bytes per durable append
	readBuffer         = 64 << 10
)

// Endpoint is one listening unix socket. Every connection on it is pinned to
// Role; the role comes from the socket and the verified peer uid, never from
// record content. Give each role its own socket: Falco and the egress
// converter both run as root, so a uid alone cannot tell them apart.
type Endpoint struct {
	Path     string
	Role     Role
	Mode     os.FileMode // socket file mode; it only authorizes connect
	UIDs     []uint32    // allowed peer uids; a peer with any other uid is refused
	MaxConns int         // concurrent connections for this role
	Rate     int64       // bytes per second read for this role, before parsing
	Burst    int64       // bucket size; at least MaxLine+1
}

// IngestConfig configures an Ingest.
type IngestConfig struct {
	Queue       *Queue
	Endpoints   []Endpoint
	IdleTimeout time.Duration // longest wait for the first byte of a line
	LineTimeout time.Duration // longest read of one line after its first fragment
	MaxBatch    int           // lines per durable append
	MaxInvalid  int           // consecutive rejected lines before the connection is closed
	Now         func() time.Time
	OnError     func(error) // connection-level failures; must not block

	sleep func(context.Context, time.Duration) error // tests only
}

func (c *IngestConfig) setDefaults() error {
	if c.Queue == nil {
		return errors.New("shipper ingest: Queue is required")
	}
	if len(c.Endpoints) == 0 {
		return errors.New("shipper ingest: at least one endpoint is required")
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = DefaultIdleTimeout
	}
	if c.LineTimeout == 0 {
		c.LineTimeout = DefaultLineTimeout
	}
	if c.MaxBatch == 0 {
		c.MaxBatch = DefaultMaxBatch
	}
	if c.MaxInvalid == 0 {
		c.MaxInvalid = DefaultMaxInvalid
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.OnError == nil {
		c.OnError = func(error) {}
	}
	if c.sleep == nil {
		c.sleep = sleepCtx
	}
	if c.IdleTimeout < 0 || c.LineTimeout < 0 || c.MaxBatch < 0 || c.MaxInvalid < 0 {
		return errors.New("shipper ingest: timeouts and limits must be positive")
	}
	seen := map[Role]bool{}
	paths := map[string]bool{}
	for _, ep := range c.Endpoints {
		switch {
		case !ep.Role.valid():
			return fmt.Errorf("shipper ingest: endpoint %q: invalid role", ep.Path)
		case seen[ep.Role]:
			return fmt.Errorf("shipper ingest: role %s has two endpoints", ep.Role)
		case !filepath.IsAbs(ep.Path) || filepath.Clean(ep.Path) != ep.Path || paths[ep.Path]:
			return fmt.Errorf("shipper ingest: endpoint path %q must be absolute, clean and unique", ep.Path)
		case len(ep.UIDs) == 0:
			return fmt.Errorf("shipper ingest: endpoint %s allows no peer uid", ep.Role)
		case ep.Mode&^0o777 != 0 || ep.Mode&0o002 != 0:
			return fmt.Errorf("shipper ingest: endpoint %s mode %o must be a permission mode without other-write", ep.Role, ep.Mode)
		case ep.MaxConns < 1:
			return fmt.Errorf("shipper ingest: endpoint %s MaxConns must be positive", ep.Role)
		case ep.Rate < 1 || ep.Burst <= MaxLine:
			return fmt.Errorf("shipper ingest: endpoint %s needs Rate > 0 and Burst > MaxLine", ep.Role)
		}
		seen[ep.Role], paths[ep.Path] = true, true
	}
	return nil
}

// RoleStats counts one role's connections and lines.
type RoleStats struct {
	Conns      int               // open now
	Accepted   uint64            // connections that passed the peer check
	Refused    uint64            // peer uid not allowed or credentials unreadable
	Busy       uint64            // refused because MaxConns were open
	Closed     uint64            // closed for MaxInvalid rejected lines or a boot change
	TimedOut   uint64            // closed by the idle or line deadline
	Lines      uint64            // complete lines read
	Oversize   uint64            // lines over MaxLine, discarded
	Rejected   map[string]uint64 // by admission reason, plus "boot"
	Duplicates uint64            // seq at or below the boot's high-water mark
	Gaps       uint64            // seqs skipped by a boot; advisory, a producer can lie
	Queued     uint64            // durably appended
	QueueFull  uint64            // admitted but refused by a queue bound
	LastRecord time.Time         // last durable append
}

// IngestStats is a snapshot per role.
type IngestStats map[Role]RoleStats

// Ingest accepts producer connections, admits their records and appends them
// durably to the queue before it reads more from the connection, so socket
// backpressure bounds what is held in memory.
//
// Each connection is half-closed for writing at accept: the protocol sends no
// byte to a producer, so a producer learns nothing from the shipper. A
// connection carries one producer boot; dedup keeps a per-role high-water
// mark for the last maxBoots boots, so a resent batch after a reconnect is
// dropped, while a shipper restart forgets the marks and may let a resend
// through as a duplicate (the record key makes it detectable).
type Ingest struct {
	cfg   IngestConfig
	lns   []*net.UnixListener
	roles [roleSlots]*roleState

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu    sync.Mutex
	conns map[*net.UnixConn]struct{}
	fatal error
	done  chan struct{} // closed on the first fatal error
}

type roleState struct {
	ep     Endpoint
	slots  chan struct{}
	bucket *bucket

	mu    sync.Mutex
	boots map[string]*bootMark
	stats RoleStats
}

type bootMark struct {
	high uint64
	used uint64 // recency stamp for eviction
}

// NewIngest validates cfg and binds every endpoint socket. The parent
// directory of each socket must be a real directory that only its owner can
// write; a stale socket at the path is replaced, any other file is an error.
func NewIngest(cfg IngestConfig) (*Ingest, error) {
	if err := cfg.setDefaults(); err != nil {
		return nil, err
	}
	in := &Ingest{cfg: cfg, conns: map[*net.UnixConn]struct{}{}, done: make(chan struct{})}
	in.ctx, in.cancel = context.WithCancel(context.Background())
	for _, ep := range cfg.Endpoints {
		ln, err := listen(ep)
		if err != nil {
			in.closeListeners()
			return nil, err
		}
		in.lns = append(in.lns, ln)
		in.roles[ep.Role] = &roleState{
			ep:     ep,
			slots:  make(chan struct{}, ep.MaxConns),
			bucket: newBucket(ep.Rate, ep.Burst, cfg.Now),
			boots:  map[string]*bootMark{},
			stats:  RoleStats{Rejected: map[string]uint64{}},
		}
	}
	return in, nil
}

func listen(ep Endpoint) (*net.UnixListener, error) {
	dir := filepath.Dir(ep.Path)
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("shipper ingest: socket directory: %w", err)
	}
	if !fi.IsDir() || fi.Mode()&0o022 != 0 {
		return nil, fmt.Errorf("shipper ingest: socket directory %s must be a non-symlink directory without group or other write", dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid != 0 && int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("shipper ingest: socket directory %s is owned by uid %d, not root or %d", dir, st.Uid, os.Geteuid())
	}
	switch fi, err := os.Lstat(ep.Path); {
	case err == nil && fi.Mode().Type() == os.ModeSocket:
		if err := os.Remove(ep.Path); err != nil {
			return nil, fmt.Errorf("shipper ingest: remove stale socket: %w", err)
		}
	case err == nil:
		return nil, fmt.Errorf("shipper ingest: %s exists and is not a socket", ep.Path)
	case !errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("shipper ingest: %w", err)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: ep.Path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("shipper ingest: listen %s: %w", ep.Path, err)
	}
	// The directory admits no other writer, so the fresh path is ours.
	if err := os.Chmod(ep.Path, ep.Mode); err != nil {
		ln.Close()
		return nil, fmt.Errorf("shipper ingest: chmod socket: %w", err)
	}
	return ln, nil
}

// Serve accepts connections until ctx ends or the queue fails. It then
// closes the listeners, cuts every open read, appends each connection's
// already-read lines and returns the queue error, if any.
func (in *Ingest) Serve(ctx context.Context) error {
	for i, ln := range in.lns {
		in.wg.Add(1)
		go in.accept(ln, in.roles[in.cfg.Endpoints[i].Role])
	}
	select {
	case <-ctx.Done():
	case <-in.done:
	}
	in.shutdown()
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.fatal
}

func (in *Ingest) shutdown() {
	in.cancel()
	in.closeListeners()
	in.mu.Lock()
	for c := range in.conns {
		c.SetReadDeadline(time.Unix(1, 0))
	}
	in.mu.Unlock()
	in.wg.Wait()
}

func (in *Ingest) closeListeners() {
	for _, ln := range in.lns {
		ln.Close()
	}
}

func (in *Ingest) setFatal(err error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.fatal == nil {
		in.fatal = err
		close(in.done)
	}
}

func (in *Ingest) accept(ln *net.UnixListener, rs *roleState) {
	defer in.wg.Done()
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			if in.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			in.cfg.OnError(fmt.Errorf("shipper ingest: accept: %w", err))
			if in.cfg.sleep(in.ctx, 100*time.Millisecond) != nil {
				return
			}
			continue
		}
		in.admitConn(c, rs)
	}
}

func (in *Ingest) admitConn(c *net.UnixConn, rs *roleState) {
	c.CloseWrite()
	uid, _, err := peerCred(c)
	if err != nil || !slices.Contains(rs.ep.UIDs, uid) {
		rs.count(func(s *RoleStats) { s.Refused++ })
		if err != nil {
			in.cfg.OnError(fmt.Errorf("shipper ingest: %s peer credentials: %w", rs.ep.Role, err))
		}
		c.Close()
		return
	}
	select {
	case rs.slots <- struct{}{}:
	default:
		rs.count(func(s *RoleStats) { s.Busy++ })
		c.Close()
		return
	}
	in.mu.Lock()
	if in.ctx.Err() != nil {
		in.mu.Unlock()
		<-rs.slots
		c.Close()
		return
	}
	in.conns[c] = struct{}{}
	in.wg.Add(1)
	in.mu.Unlock()
	rs.count(func(s *RoleStats) { s.Accepted++; s.Conns++ })
	go func() {
		defer in.wg.Done()
		in.serveConn(c, rs)
		in.mu.Lock()
		delete(in.conns, c)
		in.mu.Unlock()
		c.Close()
		rs.count(func(s *RoleStats) { s.Conns-- })
		<-rs.slots
	}()
}

// errClose ends a connection for a protocol reason already counted.
var errClose = errors.New("close connection")

func (in *Ingest) serveConn(c *net.UnixConn, rs *roleState) {
	cn := &conn{in: in, rs: rs, c: c, br: bufio.NewReaderSize(c, readBuffer)}
	for {
		items, more, err := cn.batch()
		if len(items) > 0 {
			if aerr := in.append(rs, items); aerr != nil {
				return
			}
		}
		if err != nil || !more {
			if err != nil && !errors.Is(err, errClose) && !errors.Is(err, io.EOF) && in.ctx.Err() == nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					rs.count(func(s *RoleStats) { s.TimedOut++ })
				} else {
					in.cfg.OnError(fmt.Errorf("shipper ingest: %s read: %w", rs.ep.Role, err))
				}
			}
			return
		}
	}
}

func (in *Ingest) append(rs *roleState, items []Item) error {
	seqs, err := in.cfg.Queue.Append(items)
	queued, full := uint64(0), uint64(0)
	for _, s := range seqs {
		if s != 0 {
			queued++
		} else {
			full++
		}
	}
	if err != nil {
		in.setFatal(err)
		// Items rejected before the failure are not durable either.
		return err
	}
	now := in.cfg.Now()
	rs.count(func(s *RoleStats) {
		s.Queued += queued
		s.QueueFull += full
		if queued > 0 {
			s.LastRecord = now
		}
	})
	return nil
}

type conn struct {
	in      *Ingest
	rs      *roleState
	c       *net.UnixConn
	br      *bufio.Reader
	boot    string
	invalid int
}

// batch reads at least one line, then keeps reading while a complete line is
// already buffered, up to MaxBatch. It never waits on the network with
// admitted lines held, so every read line is appended before the next wait.
func (cn *conn) batch() (items []Item, more bool, err error) {
	cfg := &cn.in.cfg
	size := 0
	for len(items) < cfg.MaxBatch && size < maxBatchBytes {
		if len(items) > 0 && !cn.lineBuffered() {
			break
		}
		line, oversize, err := cn.readLine()
		if err != nil {
			return items, false, err
		}
		// A wait cut by shutdown still admits the line already read.
		werr := cfg.sleep(cn.in.ctx, cn.rs.bucket.take(int64(len(line))+1))
		item, ok, err := cn.admit(line, oversize)
		if ok {
			items = append(items, item)
			size += len(item.Data)
		}
		if err != nil {
			return items, false, err
		}
		if werr != nil {
			return items, false, werr
		}
	}
	return items, true, nil
}

func (cn *conn) admit(line []byte, oversize bool) (Item, bool, error) {
	if oversize {
		cn.rs.count(func(s *RoleStats) { s.Lines++; s.Oversize++ })
		return Item{}, false, cn.reject()
	}
	cn.rs.count(func(s *RoleStats) { s.Lines++ })
	a, err := Admit(cn.rs.ep.Role, line, cn.in.cfg.Now())
	if err != nil {
		reason := RejectReason(err)
		cn.rs.count(func(s *RoleStats) { s.Rejected[reason]++ })
		return Item{}, false, cn.reject()
	}
	if cn.boot == "" {
		cn.boot = a.Boot
	} else if a.Boot != cn.boot {
		cn.rs.count(func(s *RoleStats) { s.Rejected["boot"]++; s.Closed++ })
		return Item{}, false, errClose
	}
	cn.invalid = 0
	if !cn.rs.mark(a.Boot, a.Seq) {
		return Item{}, false, nil
	}
	return Item{Role: a.Role, Data: a.Data}, true, nil
}

// reject counts a rejected line and returns errClose at MaxInvalid in a row.
func (cn *conn) reject() error {
	cn.invalid++
	if cn.invalid >= cn.in.cfg.MaxInvalid {
		cn.rs.count(func(s *RoleStats) { s.Closed++ })
		return errClose
	}
	return nil
}

func (cn *conn) lineBuffered() bool {
	n := cn.br.Buffered()
	if n == 0 {
		return false
	}
	b, _ := cn.br.Peek(n)
	return bytes.IndexByte(b, '\n') >= 0
}

// readLine returns one line without its newline. A line over MaxLine is
// discarded through its newline and reported as oversize; the returned slice
// then holds no data but its length counts the discarded bytes for the rate
// limit. A final line without a newline is dropped at EOF.
func (cn *conn) readLine() (line []byte, oversize bool, err error) {
	cfg := &cn.in.cfg
	cn.c.SetReadDeadline(cfg.Now().Add(cfg.IdleTimeout))
	var buf []byte
	discarded := 0
	started := false
	for {
		frag, err := cn.br.ReadSlice('\n')
		if !started && len(frag) > 0 {
			started = true
			cn.c.SetReadDeadline(cfg.Now().Add(cfg.LineTimeout))
		}
		switch {
		case err == nil:
			frag = frag[:len(frag)-1]
			if discarded > 0 || len(buf)+len(frag) > MaxLine {
				return make([]byte, discarded+len(buf)+len(frag)), true, nil
			}
			if buf == nil {
				// The reader reuses its buffer; the caller keeps the line
				// past the next read.
				return bytes.Clone(frag), false, nil
			}
			return append(buf, frag...), false, nil
		case errors.Is(err, bufio.ErrBufferFull):
			if discarded > 0 || len(buf)+len(frag) > MaxLine {
				discarded += len(buf) + len(frag)
				buf = nil
				continue
			}
			buf = append(buf, frag...)
		default:
			return nil, false, err
		}
	}
}

// mark records seq for boot and reports whether it is new. A seq at or below
// the boot's high-water mark is a duplicate from a resent batch.
func (rs *roleState) mark(boot string, seq uint64) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	var stamp uint64
	for _, b := range rs.boots {
		stamp = max(stamp, b.used)
	}
	b, ok := rs.boots[boot]
	if !ok {
		if len(rs.boots) >= maxBoots {
			var oldest string
			for k, v := range rs.boots {
				if oldest == "" || v.used < rs.boots[oldest].used {
					oldest = k
				}
			}
			delete(rs.boots, oldest)
		}
		b = &bootMark{}
		rs.boots[boot] = b
	}
	b.used = stamp + 1
	switch {
	case seq <= b.high:
		rs.stats.Duplicates++
		return false
	case b.high > 0 && seq > b.high+1:
		rs.stats.Gaps += seq - b.high - 1
	}
	b.high = seq
	return true
}

func (rs *roleState) count(f func(*RoleStats)) {
	rs.mu.Lock()
	f(&rs.stats)
	rs.mu.Unlock()
}

// Stats returns a snapshot per configured role.
func (in *Ingest) Stats() IngestStats {
	out := IngestStats{}
	for _, rs := range in.roles {
		if rs == nil {
			continue
		}
		rs.mu.Lock()
		s := rs.stats
		s.Rejected = make(map[string]uint64, len(rs.stats.Rejected))
		for k, v := range rs.stats.Rejected {
			s.Rejected[k] = v
		}
		rs.mu.Unlock()
		out[rs.ep.Role] = s
	}
	return out
}

// bucket is a byte token bucket. take reserves n tokens, going negative if
// needed, and returns how long the caller must wait before using them, so a
// role over its rate is slowed by backpressure, not dropped.
type bucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newBucket(rate, burst int64, now func() time.Time) *bucket {
	return &bucket{rate: float64(rate), burst: float64(burst), tokens: float64(burst), last: now(), now: now}
}

func (b *bucket) take(n int64) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if el := now.Sub(b.last); el > 0 {
		b.tokens = min(b.burst, b.tokens+el.Seconds()*b.rate)
	}
	b.last = now
	b.tokens -= float64(n)
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / b.rate * float64(time.Second))
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
