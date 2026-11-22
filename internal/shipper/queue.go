// Package shipper holds the host-side telemetry shipper parts that do not
// depend on the process wiring: the crash-durable disk queue.
package shipper

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Queue is the shipper's bounded disk queue. Every record goes to disk
// before delivery, and the checkpoint moves only when the caller acknowledges
// a contiguous prefix of what it read, so a crash or a New Relic outage never
// skips a record.
//
// On-disk layout, all inside one directory that only the shipper uid can
// reach (mode 0700, owned by the effective uid, not a symlink):
//
//	seg-<20-digit uint64>.q   segments, created exclusively, numbers never reused
//	checkpoint                {"gen","segment","offset","seq"} JSON
//	checkpoint.tmp-<hex>      temp file, removed at open
//	seg-<n>.q.bad             quarantined segment, kept for forensics
//
// A segment is a sequence of frames:
//
//	u32 payload length | u64 disk seq | u8 role | u32 CRC32c | payload
//
// The CRC covers the first 13 header bytes and the payload. Disk seq is
// strictly increasing across segments and restarts.
//
// Durability: Append writes a whole batch then fsyncs the segment before it
// returns, so callers must not admit more input until Append returns; socket
// backpressure then bounds what is in memory. Segment creation and deletion
// and every checkpoint rename are followed by a directory fsync. Checkpoints
// are written to an O_EXCL temp file, fsynced, then renamed.
//
// Recovery at Open: an incomplete frame at the end of the newest segment is a
// torn write and is truncated. Any other bad frame (CRC mismatch, bad role,
// oversize length, seq not increasing, short frame in an older segment) stops
// that segment at the last good frame; the valid prefix is still delivered
// and the file is renamed to .bad instead of deleted once acknowledged. A
// missing, corrupt or inconsistent checkpoint means the replay start is
// unknown: the queue replays from the oldest segment and reports Uncertain,
// so the caller can replay logs (deduplicable by record key) and suppress
// metrics up to UncertainThrough rather than double count them.
//
// Bounds: unacknowledged frame bytes are capped in total and per role. Full
// roles are rejected at admission; the queue never deletes unacknowledged
// data, so a flood from one role cannot erase another role's records.
//
// Every Open appends to a new segment, so a recovered segment is never
// written again. One mutex covers append, roll, read-ahead, acknowledgement
// and checkpoint, so there is a single queue owner.
//
// Limit: an I/O error during Append, Ack or checkpoint leaves the on-disk
// state unknown, so the queue fails every later call; restart to recover.
type Queue struct {
	mu   sync.Mutex
	cfg  QueueConfig
	root *os.Root

	segs   []*segment // ascending by num; the last is the active append segment
	active *os.File

	nextSeq  uint64
	cur      position // acknowledged cursor, as in the checkpoint
	ackedSeq uint64
	gen      uint64

	rd       position // read-ahead position
	rfile    *os.File
	rfileNum uint64
	inflight []pending

	bytes    [roleSlots]int64 // unacknowledged frame bytes per role
	total    int64
	dropped  [roleSlots]uint64
	oversize [roleSlots]uint64

	err    error // sticky I/O failure
	closed bool
}

// Role is the verified producer role that wrote a record.
type Role uint8

// Producer roles. The shipper derives a role from the peer credentials of a
// connection, never from record content.
const (
	RoleBait Role = iota + 1
	RoleRuntime
	RoleEgress
)

const roleSlots = int(RoleEgress) + 1

// Roles lists every valid role.
var Roles = []Role{RoleBait, RoleRuntime, RoleEgress}

func (r Role) valid() bool { return r >= RoleBait && r <= RoleEgress }

func (r Role) String() string {
	switch r {
	case RoleBait:
		return "bait"
	case RoleRuntime:
		return "runtime"
	case RoleEgress:
		return "egress"
	}
	return "role(" + strconv.Itoa(int(r)) + ")"
}

// FrameHeader is the fixed per-frame overhead counted against every bound.
const FrameHeader = 17

// Queue file names.
const (
	segPrefix     = "seg-"
	segSuffix     = ".q"
	badSuffix     = ".bad"
	ckptName      = "checkpoint"
	ckptTmpPrefix = "checkpoint.tmp-"
	maxCkptBytes  = 4096
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Queue errors.
var (
	ErrQueueFull   = errors.New("shipper queue: role or total byte bound reached")
	ErrTooLarge    = errors.New("shipper queue: record can never fit the queue")
	ErrQueueClosed = errors.New("shipper queue: closed")
)

// QueueConfig bounds a Queue. All byte limits count FrameHeader plus payload.
type QueueConfig struct {
	Dir          string
	SegmentBytes int64          // roll the active segment past this size
	MaxBytes     int64          // all unacknowledged frames
	RoleBytes    map[Role]int64 // per-role cap; a missing role gets MaxBytes
	MaxPayload   int            // largest payload accepted
}

func (c QueueConfig) validate() error {
	switch {
	case c.Dir == "":
		return errors.New("shipper queue: Dir is required")
	case c.SegmentBytes < FrameHeader+1:
		return errors.New("shipper queue: SegmentBytes too small")
	case c.MaxBytes < FrameHeader+1:
		return errors.New("shipper queue: MaxBytes too small")
	case c.MaxPayload < 1 || c.MaxPayload > 1<<30:
		return errors.New("shipper queue: MaxPayload out of range")
	}
	for r, n := range c.RoleBytes {
		if !r.valid() {
			return fmt.Errorf("shipper queue: unknown role %d", r)
		}
		if n < FrameHeader+1 || n > c.MaxBytes {
			return fmt.Errorf("shipper queue: %s byte cap out of range", r)
		}
	}
	return nil
}

func (c QueueConfig) roleCap(r Role) int64 {
	if n, ok := c.RoleBytes[r]; ok {
		return n
	}
	return c.MaxBytes
}

// Item is one record offered to Append.
type Item struct {
	Role Role
	Data []byte
}

// Entry is one record read back from the queue.
type Entry struct {
	Seq  uint64
	Role Role
	Data []byte
}

// Recovery reports what Open found.
type Recovery struct {
	// Uncertain is set when the replay start is unknown. Entries with
	// Seq <= UncertainThrough may already have been delivered.
	Uncertain        bool
	UncertainThrough uint64
	Reason           string

	TruncatedBytes int64    // torn tail removed from the newest segment
	Quarantined    []string // segments with a bad frame; delivered up to it, then renamed .bad
	Removed        []string // fully acknowledged segments removed at open
	Replay         int64    // unacknowledged frame bytes to deliver
}

// QueueStats is a snapshot of the queue bounds and counters.
type QueueStats struct {
	Bytes    map[Role]int64  // unacknowledged frame bytes per role
	Total    int64           // unacknowledged frame bytes
	Dropped  map[Role]uint64 // rejected because a bound was reached
	Oversize map[Role]uint64 // rejected because the record can never fit
	Segments int
	Inflight int // read but not acknowledged
	NextSeq  uint64
}

type segment struct {
	num  uint64
	size int64 // readable end: file size, or the offset of the first bad frame
	bad  bool
}

type position struct {
	seg uint64
	off int64
}

type pending struct {
	pos  position // end of the frame
	seq  uint64
	role Role
	size int64
}

type checkpoint struct {
	Gen     uint64 `json:"gen"`
	Segment uint64 `json:"segment"`
	Offset  int64  `json:"offset"`
	Seq     uint64 `json:"seq"` // last acknowledged disk seq
}

func segName(n uint64) string { return fmt.Sprintf("%s%020d%s", segPrefix, n, segSuffix) }

func parseSegName(name string) (uint64, bool) {
	digits, ok := strings.CutPrefix(name, segPrefix)
	if !ok {
		return 0, false
	}
	digits, ok = strings.CutSuffix(digits, segSuffix)
	if !ok || len(digits) != 20 {
		return 0, false
	}
	for i := range len(digits) {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(digits, 10, 64)
	return n, err == nil
}

// OpenQueue opens or creates the queue in cfg.Dir and recovers its state.
func OpenQueue(cfg QueueConfig) (*Queue, Recovery, error) {
	var rec Recovery
	if err := cfg.validate(); err != nil {
		return nil, rec, err
	}
	root, err := openQueueDir(cfg.Dir)
	if err != nil {
		return nil, rec, err
	}
	q := &Queue{cfg: cfg, root: root}
	if err := q.recover(&rec); err != nil {
		q.closeFiles()
		return nil, rec, err
	}
	return q, rec, nil
}

// openQueueDir creates the directory if it is missing, then requires a real
// directory owned by the effective uid with no group or other access, and
// pins it as a Root so later operations cannot be redirected.
func openQueueDir(dir string) (*os.Root, error) {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("shipper queue: %w", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("shipper queue: %w", err)
	}
	if err := checkPrivateDir(dir, fi); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("shipper queue: %w", err)
	}
	pinned, err := root.Stat(".")
	if err == nil && !os.SameFile(fi, pinned) {
		err = fmt.Errorf("%s changed while opening", dir)
	}
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("shipper queue: %w", err)
	}
	return root, nil
}

func checkPrivateDir(dir string, fi os.FileInfo) error {
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("shipper queue: %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("shipper queue: %s mode %04o allows group or other access", dir, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("shipper queue: %s is owned by uid %d, not %d", dir, st.Uid, os.Geteuid())
	}
	return nil
}

// openRegular opens name without following a final symlink and requires a
// regular file.
func (q *Queue) openRegular(name string, flag int, perm os.FileMode) (*os.File, error) {
	f, err := q.root.OpenFile(name, flag|syscall.O_NOFOLLOW, perm)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err == nil && !fi.Mode().IsRegular() {
		err = fmt.Errorf("%s is not a regular file", name)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (q *Queue) syncDir() error {
	d, err := q.root.Open(".")
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

type segScan struct {
	end      int64
	lastSeq  uint64
	torn     bool // incomplete final frame
	corrupt  bool // any other bad frame
	boundary bool // the probed offset is a frame boundary
	after    [roleSlots]int64
}

// scanSegment walks the frames of one segment. Frames at or after probe add
// their bytes to after; probe < 0 counts nothing.
func scanSegment(f *os.File, size int64, minSeq uint64, maxPayload int, probe int64) (segScan, error) {
	s := segScan{lastSeq: minSeq, boundary: probe == 0}
	br := bufio.NewReaderSize(io.NewSectionReader(f, 0, size), 1<<16)
	var hdr [FrameHeader]byte
	var payload []byte
	for s.end < size {
		if size-s.end < FrameHeader {
			s.torn = true
			return s, nil
		}
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return s, err
		}
		n := binary.BigEndian.Uint32(hdr[0:4])
		seq := binary.BigEndian.Uint64(hdr[4:12])
		role := Role(hdr[12])
		if n == 0 || int64(n) > int64(maxPayload) || !role.valid() || seq <= s.lastSeq {
			s.corrupt = true
			return s, nil
		}
		if size-s.end-FrameHeader < int64(n) {
			s.torn = true
			return s, nil
		}
		payload = slices.Grow(payload[:0], int(n))[:n]
		if _, err := io.ReadFull(br, payload); err != nil {
			return s, err
		}
		if frameCRC(hdr[:13], payload) != binary.BigEndian.Uint32(hdr[13:17]) {
			s.corrupt = true
			return s, nil
		}
		frame := FrameHeader + int64(n)
		if probe >= 0 && s.end >= probe {
			s.after[role] += frame
		}
		s.end += frame
		s.lastSeq = seq
		if s.end == probe {
			s.boundary = true
		}
	}
	return s, nil
}

func frameCRC(head, payload []byte) uint32 {
	return crc32.Update(crc32.Checksum(head, castagnoli), castagnoli, payload)
}

func (q *Queue) recover(rec *Recovery) error {
	d, err := q.root.Open(".")
	if err != nil {
		return err
	}
	ents, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return err
	}
	var nums []uint64
	for _, e := range ents {
		name := e.Name()
		switch {
		case strings.HasPrefix(name, ckptTmpPrefix) && e.Type().IsRegular():
			if err := q.root.Remove(name); err != nil {
				return err
			}
		case e.Type().IsRegular():
			if n, ok := parseSegName(name); ok {
				nums = append(nums, n)
			}
		}
	}
	slices.Sort(nums)

	ck, ckErr := q.readCheckpoint()
	certain := ckErr == nil
	reason := ""
	switch {
	case errors.Is(ckErr, os.ErrNotExist) && len(nums) == 0:
		certain, ckErr = true, nil // fresh queue
	case ckErr != nil:
		reason = "checkpoint unreadable: " + ckErr.Error()
	case !slices.Contains(nums, ck.Segment):
		certain, reason = false, fmt.Sprintf("checkpoint names missing segment %d", ck.Segment)
	}
	if certain && ckErr == nil && len(nums) > 0 {
		// Segments before the checkpoint segment were fully acknowledged; a
		// crash came between the checkpoint rename and their removal.
		for len(nums) > 0 && nums[0] < ck.Segment {
			name := segName(nums[0])
			if err := q.root.Remove(name); err != nil {
				return err
			}
			rec.Removed = append(rec.Removed, name)
			nums = nums[1:]
		}
	}

	lastSeq := uint64(0)
	if ckErr == nil {
		lastSeq = ck.Seq
	}
	scanFloor := uint64(0)
	for i, n := range nums {
		name := segName(n)
		f, err := q.openRegular(name, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		probe := int64(-1)
		switch {
		case certain && n == ck.Segment:
			probe = ck.Offset
		case !certain || n > ck.Segment:
			probe = 0
		}
		s, err := scanSegment(f, fi.Size(), scanFloor, q.cfg.MaxPayload, probe)
		if err == nil && s.torn && i == len(nums)-1 {
			rec.TruncatedBytes = fi.Size() - s.end
			err = f.Truncate(s.end)
			if err == nil {
				err = f.Sync()
			}
			s.torn = false
		}
		f.Close()
		if err != nil {
			return err
		}
		seg := &segment{num: n, size: s.end, bad: s.torn || s.corrupt}
		if seg.bad {
			rec.Quarantined = append(rec.Quarantined, name)
		}
		if certain && n == ck.Segment && (!s.boundary || ck.Offset > s.end) {
			// The checkpoint is inconsistent with its segment: replay all
			// of it and everything after.
			certain, reason = false, fmt.Sprintf("checkpoint offset %d is not a frame boundary of %s", ck.Offset, name)
			s, err = q.rescan(name, scanFloor, seg)
			if err != nil {
				return err
			}
		}
		for r, b := range s.after {
			q.bytes[r] += b
			q.total += b
		}
		scanFloor = max(scanFloor, s.lastSeq)
		q.segs = append(q.segs, seg)
	}
	lastSeq = max(lastSeq, scanFloor)
	q.nextSeq = lastSeq + 1

	nextSeg := uint64(1)
	if len(nums) > 0 {
		nextSeg = nums[len(nums)-1] + 1
	}
	if ckErr == nil && ck.Segment >= nextSeg {
		nextSeg = ck.Segment + 1
	}

	if ckErr == nil {
		q.ackedSeq, q.gen = ck.Seq, ck.Gen
	}
	switch {
	case certain && len(q.segs) > 0:
		q.cur = position{ck.Segment, ck.Offset}
	case !certain:
		// Unknown start: every surviving frame was counted from offset 0
		// and is replayed from the oldest segment.
		if len(q.segs) > 0 {
			q.cur = position{q.segs[0].num, 0}
		}
		rec.Uncertain, rec.UncertainThrough, rec.Reason = true, lastSeq, reason
	}

	if err := q.openActive(nextSeg); err != nil {
		return err
	}
	if len(q.segs) == 1 {
		q.cur = position{nextSeg, 0} // nothing to replay
	}
	q.rd = q.cur
	rec.Replay = q.total
	return q.commitCursor()
}

// rescan recounts a segment from offset 0 up to its known readable end.
func (q *Queue) rescan(name string, floor uint64, seg *segment) (segScan, error) {
	f, err := q.openRegular(name, os.O_RDONLY, 0)
	if err != nil {
		return segScan{}, err
	}
	defer f.Close()
	return scanSegment(f, seg.size, floor, q.cfg.MaxPayload, 0)
}

func (q *Queue) readCheckpoint() (checkpoint, error) {
	var ck checkpoint
	f, err := q.openRegular(ckptName, os.O_RDONLY, 0)
	if err != nil {
		return ck, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxCkptBytes+1))
	if err != nil {
		return ck, err
	}
	if len(b) > maxCkptBytes {
		return ck, errors.New("checkpoint too large")
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ck); err != nil {
		return ck, err
	}
	if dec.More() {
		return ck, errors.New("trailing data in checkpoint")
	}
	if ck.Segment == 0 || ck.Offset < 0 || ck.Gen == 0 {
		return ck, errors.New("checkpoint fields out of range")
	}
	return ck, nil
}

func (q *Queue) openActive(num uint64) error {
	f, err := q.openRegular(segName(num), os.O_RDWR|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if err := q.syncDir(); err != nil {
		f.Close()
		return err
	}
	q.active = f
	q.segs = append(q.segs, &segment{num: num})
	return nil
}

// commitCursor moves the cursor past finished older segments, persists the
// checkpoint and removes every segment before the cursor.
func (q *Queue) commitCursor() error {
	for i := 0; i < len(q.segs)-1; i++ {
		seg := q.segs[i]
		if seg.num == q.cur.seg && q.cur.off >= seg.size {
			q.cur = position{q.segs[i+1].num, 0}
		}
	}
	if q.rd.seg < q.cur.seg {
		q.rd = q.cur
	}
	q.gen++
	if err := q.writeCheckpoint(); err != nil {
		return err
	}
	keep := q.segs[:0]
	removed := false
	for _, seg := range q.segs {
		if seg.num >= q.cur.seg {
			keep = append(keep, seg)
			continue
		}
		if q.rfile != nil && q.rfileNum == seg.num {
			q.rfile.Close()
			q.rfile = nil
		}
		name := segName(seg.num)
		var err error
		if seg.bad {
			err = q.root.Rename(name, name+badSuffix)
		} else {
			err = q.root.Remove(name)
		}
		if err != nil {
			return err
		}
		removed = true
	}
	q.segs = keep
	if removed {
		return q.syncDir()
	}
	return nil
}

func (q *Queue) writeCheckpoint() error {
	b, err := json.Marshal(checkpoint{Gen: q.gen, Segment: q.cur.seg, Offset: q.cur.off, Seq: q.ackedSeq})
	if err != nil {
		return err
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := ckptTmpPrefix + hex.EncodeToString(rnd[:])
	f, err := q.openRegular(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = q.root.Rename(tmp, ckptName)
	}
	if err != nil {
		q.root.Remove(tmp)
		return err
	}
	return q.syncDir()
}

func (q *Queue) usable() error {
	switch {
	case q.closed:
		return ErrQueueClosed
	case q.err != nil:
		return q.err
	}
	return nil
}

func (q *Queue) fail(err error) error {
	q.err = fmt.Errorf("shipper queue: %w (restart to recover)", err)
	return q.err
}

// Append writes items as one durable batch and returns each item's disk seq,
// or 0 for an item rejected by a bound (counted in QueueStats). It returns
// only after the segment data is fsynced.
func (q *Queue) Append(items []Item) ([]uint64, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.usable(); err != nil {
		return nil, err
	}
	seqs := make([]uint64, len(items))
	for _, it := range items {
		if !it.Role.valid() {
			return seqs, fmt.Errorf("shipper queue: invalid role %d", it.Role)
		}
	}
	bytes, total := q.bytes, q.total
	active := q.segs[len(q.segs)-1]
	size := active.size
	var buf []byte
	flush := func() error {
		if len(buf) == 0 {
			return nil
		}
		if _, err := q.active.Write(buf); err != nil {
			return err
		}
		if err := q.active.Sync(); err != nil {
			return err
		}
		active.size = size
		buf = buf[:0]
		return nil
	}
	for i, it := range items {
		frame := FrameHeader + int64(len(it.Data))
		if len(it.Data) == 0 || len(it.Data) > q.cfg.MaxPayload || frame > min(q.cfg.MaxBytes, q.cfg.roleCap(it.Role)) {
			q.oversize[it.Role]++
			continue
		}
		if total+frame > q.cfg.MaxBytes || bytes[it.Role]+frame > q.cfg.roleCap(it.Role) {
			q.dropped[it.Role]++
			continue
		}
		if size > 0 && size+frame > q.cfg.SegmentBytes {
			if err := flush(); err != nil {
				return seqs, q.fail(err)
			}
			if err := q.roll(); err != nil {
				return seqs, q.fail(err)
			}
			active, size = q.segs[len(q.segs)-1], 0
		}
		var hdr [FrameHeader]byte
		binary.BigEndian.PutUint32(hdr[0:4], uint32(len(it.Data)))
		binary.BigEndian.PutUint64(hdr[4:12], q.nextSeq)
		hdr[12] = byte(it.Role)
		binary.BigEndian.PutUint32(hdr[13:17], frameCRC(hdr[:13], it.Data))
		buf = append(append(buf, hdr[:]...), it.Data...)
		size += frame
		seqs[i] = q.nextSeq
		q.nextSeq++
		bytes[it.Role] += frame
		total += frame
	}
	if err := flush(); err != nil {
		return seqs, q.fail(err)
	}
	q.bytes, q.total = bytes, total
	return seqs, nil
}

func (q *Queue) roll() error {
	next := q.segs[len(q.segs)-1].num + 1
	old := q.active
	if err := q.openActive(next); err != nil {
		return err
	}
	return old.Close()
}

// Read returns up to max entries after the read-ahead position, stopping
// early once maxBytes of payload are returned (at least one entry is
// returned when one is available). Read entries stay unacknowledged until
// Ack.
func (q *Queue) Read(max, maxBytes int) ([]Entry, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.usable(); err != nil {
		return nil, err
	}
	var out []Entry
	got := 0
	for len(out) < max && (len(out) == 0 || got < maxBytes) {
		idx := slices.IndexFunc(q.segs, func(s *segment) bool { return s.num == q.rd.seg })
		if idx < 0 {
			return out, q.fail(fmt.Errorf("read position names missing segment %d", q.rd.seg))
		}
		seg := q.segs[idx]
		if q.rd.off >= seg.size {
			if idx == len(q.segs)-1 {
				break
			}
			q.rd = position{q.segs[idx+1].num, 0}
			continue
		}
		e, frame, err := q.readFrame(seg)
		if err != nil {
			return out, q.fail(err)
		}
		q.rd.off += frame
		q.inflight = append(q.inflight, pending{pos: q.rd, seq: e.Seq, role: e.Role, size: frame})
		out = append(out, e)
		got += len(e.Data)
	}
	return out, nil
}

func (q *Queue) readFrame(seg *segment) (Entry, int64, error) {
	if q.rfile == nil || q.rfileNum != seg.num {
		if q.rfile != nil {
			q.rfile.Close()
			q.rfile = nil
		}
		f, err := q.openRegular(segName(seg.num), os.O_RDONLY, 0)
		if err != nil {
			return Entry{}, 0, err
		}
		q.rfile, q.rfileNum = f, seg.num
	}
	var hdr [FrameHeader]byte
	if _, err := q.rfile.ReadAt(hdr[:], q.rd.off); err != nil {
		return Entry{}, 0, err
	}
	n := int64(binary.BigEndian.Uint32(hdr[0:4]))
	frame := FrameHeader + n
	if n == 0 || n > int64(q.cfg.MaxPayload) || q.rd.off+frame > seg.size {
		return Entry{}, 0, fmt.Errorf("%s: bad frame at %d", segName(seg.num), q.rd.off)
	}
	data := make([]byte, n)
	if _, err := q.rfile.ReadAt(data, q.rd.off+FrameHeader); err != nil {
		return Entry{}, 0, err
	}
	if frameCRC(hdr[:13], data) != binary.BigEndian.Uint32(hdr[13:17]) {
		return Entry{}, 0, fmt.Errorf("%s: frame at %d changed on disk", segName(seg.num), q.rd.off)
	}
	return Entry{Seq: binary.BigEndian.Uint64(hdr[4:12]), Role: Role(hdr[12]), Data: data}, frame, nil
}

// Ack acknowledges the first n entries returned by Read and not yet
// acknowledged, persists the checkpoint and removes finished segments. The
// caller passes the length of the contiguous delivered prefix only.
func (q *Queue) Ack(n int) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.usable(); err != nil {
		return err
	}
	if n < 0 || n > len(q.inflight) {
		return fmt.Errorf("shipper queue: ack %d of %d in flight", n, len(q.inflight))
	}
	if n == 0 {
		return nil
	}
	for _, p := range q.inflight[:n] {
		q.bytes[p.role] -= p.size
		q.total -= p.size
	}
	q.cur = q.inflight[n-1].pos
	q.ackedSeq = max(q.ackedSeq, q.inflight[n-1].seq)
	q.inflight = slices.Delete(q.inflight, 0, n)
	if err := q.commitCursor(); err != nil {
		return q.fail(err)
	}
	return nil
}

// Rewind drops the read-ahead so the next Read starts again at the first
// unacknowledged entry, for a delivery attempt that failed.
func (q *Queue) Rewind() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.inflight = q.inflight[:0]
	q.rd = q.cur
}

// Stats returns a snapshot of the bounds and counters.
func (q *Queue) Stats() QueueStats {
	q.mu.Lock()
	defer q.mu.Unlock()
	st := QueueStats{
		Bytes:    map[Role]int64{},
		Dropped:  map[Role]uint64{},
		Oversize: map[Role]uint64{},
		Total:    q.total,
		Segments: len(q.segs),
		Inflight: len(q.inflight),
		NextSeq:  q.nextSeq,
	}
	for _, r := range Roles {
		st.Bytes[r], st.Dropped[r], st.Oversize[r] = q.bytes[r], q.dropped[r], q.oversize[r]
	}
	return st
}

// Close syncs and closes the queue files. Unacknowledged entries stay on
// disk for the next Open.
func (q *Queue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil
	}
	q.closed = true
	var err error
	if q.active != nil && q.err == nil {
		err = q.active.Sync()
	}
	if cerr := q.closeFiles(); err == nil {
		err = cerr
	}
	return err
}

func (q *Queue) closeFiles() error {
	var errs []error
	if q.active != nil {
		errs = append(errs, q.active.Close())
		q.active = nil
	}
	if q.rfile != nil {
		errs = append(errs, q.rfile.Close())
		q.rfile = nil
	}
	errs = append(errs, q.root.Close())
	return errors.Join(errs...)
}
