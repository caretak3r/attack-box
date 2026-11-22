package shipper

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func testConfig(dir string) QueueConfig {
	return QueueConfig{Dir: dir, SegmentBytes: 1 << 20, MaxBytes: 1 << 20, MaxPayload: 4096}
}

func queueDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "queue")
}

func mustOpen(t *testing.T, cfg QueueConfig) (*Queue, Recovery) {
	t.Helper()
	q, rec, err := OpenQueue(cfg)
	if err != nil {
		t.Fatalf("OpenQueue: %v", err)
	}
	t.Cleanup(func() { q.Close() })
	return q, rec
}

func payload(i int) []byte { return fmt.Appendf(nil, `{"id":"r%03d"}`, i) }

func mustAppend(t *testing.T, q *Queue, role Role, from, to int) []uint64 {
	t.Helper()
	var items []Item
	for i := from; i < to; i++ {
		items = append(items, Item{Role: role, Data: payload(i)})
	}
	seqs, err := q.Append(items)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	for i, s := range seqs {
		if s == 0 {
			t.Fatalf("item %d rejected", from+i)
		}
	}
	return seqs
}

// readAll reads every available entry and returns their payloads.
func readAll(t *testing.T, q *Queue) []Entry {
	t.Helper()
	var out []Entry
	for {
		es, err := q.Read(3, 1<<20)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if len(es) == 0 {
			return out
		}
		out = append(out, es...)
	}
}

func wantPayloads(t *testing.T, es []Entry, from, to int) {
	t.Helper()
	if len(es) != to-from {
		t.Fatalf("got %d entries, want %d", len(es), to-from)
	}
	for i, e := range es {
		if !bytes.Equal(e.Data, payload(from+i)) {
			t.Fatalf("entry %d = %s, want %s", i, e.Data, payload(from+i))
		}
		if i > 0 && e.Seq <= es[i-1].Seq {
			t.Fatalf("seq not increasing: %d after %d", e.Seq, es[i-1].Seq)
		}
	}
}

func segFiles(t *testing.T, dir, suffix string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, "seg-*"+suffix))
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(m)
	return m
}

func TestQueueRoundTripAndRestart(t *testing.T) {
	dir := queueDir(t)
	cfg := testConfig(dir)
	q, rec := mustOpen(t, cfg)
	if rec.Uncertain || rec.Replay != 0 {
		t.Fatalf("fresh recovery = %+v", rec)
	}
	seqs := mustAppend(t, q, RoleBait, 0, 5)
	if !slices.Equal(seqs, []uint64{1, 2, 3, 4, 5}) {
		t.Fatalf("seqs = %v", seqs)
	}
	es := readAll(t, q)
	wantPayloads(t, es, 0, 5)
	if err := q.Ack(5); err != nil {
		t.Fatal(err)
	}
	if st := q.Stats(); st.Total != 0 || st.Bytes[RoleBait] != 0 || st.Inflight != 0 {
		t.Fatalf("stats after ack = %+v", st)
	}
	q.Close()

	q2, rec := mustOpen(t, cfg)
	if rec.Uncertain || rec.Replay != 0 || len(rec.Quarantined) != 0 {
		t.Fatalf("clean restart recovery = %+v", rec)
	}
	if got := readAll(t, q2); len(got) != 0 {
		t.Fatalf("replayed %d acknowledged entries", len(got))
	}
	if seqs := mustAppend(t, q2, RoleRuntime, 5, 6); seqs[0] != 6 {
		t.Fatalf("seq after restart = %d, want 6", seqs[0])
	}
	// Every Open starts a new segment; acknowledged ones are gone.
	if files := segFiles(t, dir, ".q"); len(files) != 1 || !strings.HasSuffix(files[0], segName(2)) {
		t.Fatalf("segments = %v", files)
	}
}

func TestQueueReplaysUnacknowledged(t *testing.T) {
	dir := queueDir(t)
	cfg := testConfig(dir)
	q, _ := mustOpen(t, cfg)
	mustAppend(t, q, RoleBait, 0, 5)
	wantPayloads(t, readAll(t, q), 0, 5)
	if err := q.Ack(2); err != nil {
		t.Fatal(err)
	}
	if err := q.Ack(4); err == nil {
		t.Fatal("acking more than in flight succeeded")
	}
	q.Close()

	q2, rec := mustOpen(t, cfg)
	if rec.Uncertain {
		t.Fatalf("uncertain after a clean partial ack: %+v", rec)
	}
	if rec.Replay != q2.Stats().Total || rec.Replay != int64(3*(FrameHeader+len(payload(0)))) {
		t.Fatalf("replay bytes = %d", rec.Replay)
	}
	es := readAll(t, q2)
	wantPayloads(t, es, 2, 5)
	if es[0].Seq != 3 {
		t.Fatalf("first replayed seq = %d, want 3", es[0].Seq)
	}
}

func TestQueueRewindRedelivers(t *testing.T) {
	q, _ := mustOpen(t, testConfig(queueDir(t)))
	mustAppend(t, q, RoleEgress, 0, 4)
	es, err := q.Read(10, 1<<20)
	if err != nil || len(es) != 4 {
		t.Fatalf("Read = %d, %v", len(es), err)
	}
	if err := q.Ack(1); err != nil {
		t.Fatal(err)
	}
	q.Rewind()
	wantPayloads(t, readAll(t, q), 1, 4)
}

func TestQueueReadByteLimit(t *testing.T) {
	q, _ := mustOpen(t, testConfig(queueDir(t)))
	mustAppend(t, q, RoleBait, 0, 4)
	es, err := q.Read(10, 1)
	if err != nil || len(es) != 1 {
		t.Fatalf("Read with tiny byte budget = %d entries, %v; want 1", len(es), err)
	}
}

func TestQueueRollsAndRemovesSegments(t *testing.T) {
	dir := queueDir(t)
	cfg := testConfig(dir)
	frame := int64(FrameHeader + len(payload(0)))
	cfg.SegmentBytes = 3 * frame
	q, _ := mustOpen(t, cfg)
	for i := range 10 {
		mustAppend(t, q, RoleBait, i, i+1)
	}
	if n := len(segFiles(t, dir, ".q")); n != 4 {
		t.Fatalf("segments after 10 frames of 3 per segment = %d, want 4", n)
	}
	wantPayloads(t, readAll(t, q), 0, 10)
	if err := q.Ack(7); err != nil {
		t.Fatal(err)
	}
	if files := segFiles(t, dir, ".q"); len(files) != 2 {
		t.Fatalf("segments after acking 7 = %v", files)
	}
	if err := q.Ack(3); err != nil {
		t.Fatal(err)
	}
	if files := segFiles(t, dir, ".q"); len(files) != 1 {
		t.Fatalf("segments after acking all = %v", files)
	}
	q.Close()

	// Numbers keep increasing even though every older segment is gone.
	q2, _ := mustOpen(t, cfg)
	mustAppend(t, q2, RoleBait, 10, 11)
	files := segFiles(t, dir, ".q")
	if len(files) != 1 || !strings.HasSuffix(files[0], segName(5)) {
		t.Fatalf("segments after restart = %v, want only %s", files, segName(5))
	}
}

func TestQueueRoleIsolation(t *testing.T) {
	cfg := testConfig(queueDir(t))
	frame := int64(FrameHeader + len(payload(0)))
	cfg.MaxBytes = 6 * frame
	cfg.RoleBytes = map[Role]int64{RoleBait: 3 * frame}
	q, _ := mustOpen(t, cfg)

	var flood []Item
	for i := range 10 {
		flood = append(flood, Item{Role: RoleBait, Data: payload(i)})
	}
	seqs, err := q.Append(flood)
	if err != nil {
		t.Fatal(err)
	}
	accepted := slices.DeleteFunc(slices.Clone(seqs), func(s uint64) bool { return s == 0 })
	if len(accepted) != 3 {
		t.Fatalf("bait accepted %d frames past its 3-frame cap", len(accepted))
	}
	// The bait flood leaves the reserved share for host roles.
	mustAppend(t, q, RoleRuntime, 10, 12)
	mustAppend(t, q, RoleEgress, 12, 13)
	seqs, err = q.Append([]Item{{Role: RoleRuntime, Data: payload(13)}})
	if err != nil || seqs[0] != 0 {
		t.Fatalf("append past total cap = %v, %v; want rejected", seqs, err)
	}
	big := bytes.Repeat([]byte("x"), int(cfg.RoleBytes[RoleBait]))
	seqs, err = q.Append([]Item{{Role: RoleBait, Data: big}, {Role: RoleBait}})
	if err != nil || seqs[0] != 0 || seqs[1] != 0 {
		t.Fatalf("never-fitting and empty records = %v, %v", seqs, err)
	}
	st := q.Stats()
	if st.Dropped[RoleBait] != 7 || st.Dropped[RoleRuntime] != 1 || st.Oversize[RoleBait] != 2 {
		t.Fatalf("drop counters = %+v / %+v", st.Dropped, st.Oversize)
	}
	if st.Total != 6*frame || st.Bytes[RoleBait] != 3*frame || st.Bytes[RoleRuntime] != 2*frame {
		t.Fatalf("byte accounting = %+v", st)
	}
	if _, err := q.Append([]Item{{Role: 9, Data: payload(0)}}); err == nil {
		t.Fatal("invalid role accepted")
	}

	// Acknowledging frees the share again.
	es := readAll(t, q)
	if err := q.Ack(len(es)); err != nil {
		t.Fatal(err)
	}
	mustAppend(t, q, RoleBait, 20, 23)
}

func TestQueueTruncatesTornTail(t *testing.T) {
	dir := queueDir(t)
	cfg := testConfig(dir)
	q, _ := mustOpen(t, cfg)
	mustAppend(t, q, RoleBait, 0, 3)
	q.Close()

	seg := segFiles(t, dir, ".q")[0]
	f, err := os.OpenFile(seg, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	// A header that promises more payload than reached the disk.
	var hdr [FrameHeader]byte
	binary.BigEndian.PutUint32(hdr[0:4], 100)
	binary.BigEndian.PutUint64(hdr[4:12], 4)
	hdr[12] = byte(RoleBait)
	f.Write(append(hdr[:], "partial"...))
	f.Close()

	q2, rec := mustOpen(t, cfg)
	if rec.TruncatedBytes != FrameHeader+7 || rec.Uncertain || len(rec.Quarantined) != 0 {
		t.Fatalf("recovery = %+v", rec)
	}
	wantPayloads(t, readAll(t, q2), 0, 3)
	if seqs := mustAppend(t, q2, RoleBait, 3, 4); seqs[0] != 4 {
		t.Fatalf("seq after truncation = %d", seqs[0])
	}
}

// A frame cut short at EOF, whatever the cut point, is dropped without
// quarantine and later appends continue from the last whole frame.
func TestQueueTornTailAnyCut(t *testing.T) {
	var whole [FrameHeader]byte
	binary.BigEndian.PutUint32(whole[0:4], 40)
	binary.BigEndian.PutUint64(whole[4:12], 4)
	whole[12] = byte(RoleBait)
	for name, tail := range map[string][]byte{
		"one byte":         whole[:1],
		"short header":     whole[:9],
		"header minus one": whole[:FrameHeader-1],
		"header only":      whole[:],
		"zero header":      make([]byte, FrameHeader),
		"short payload":    append(slices.Clone(whole[:]), "abc"...),
		"payload minus 1":  append(slices.Clone(whole[:]), bytes.Repeat([]byte("p"), 39)...),
	} {
		t.Run(name, func(t *testing.T) {
			dir := queueDir(t)
			cfg := testConfig(dir)
			q, _ := mustOpen(t, cfg)
			mustAppend(t, q, RoleBait, 0, 3)
			q.Close()
			seg := segFiles(t, dir, ".q")[0]
			f, err := os.OpenFile(seg, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			f.Write(tail)
			f.Close()

			q2, rec := mustOpen(t, cfg)
			if rec.TruncatedBytes != int64(len(tail)) || rec.Uncertain || len(rec.Quarantined) != 0 {
				t.Fatalf("recovery = %+v", rec)
			}
			if bad := segFiles(t, dir, ".bad"); len(bad) != 0 {
				t.Fatalf("quarantined files = %v", bad)
			}
			wantPayloads(t, readAll(t, q2), 0, 3)
			if err := q2.Ack(3); err != nil {
				t.Fatal(err)
			}
			if seqs := mustAppend(t, q2, RoleBait, 3, 4); seqs[0] != 4 {
				t.Fatalf("seq after truncation = %d", seqs[0])
			}
			if bad := segFiles(t, dir, ".bad"); len(bad) != 0 {
				t.Fatalf("quarantined files after ack = %v", bad)
			}
		})
	}
}

// The last frame of the newest segment with a bad checksum and nothing after
// it is a write that did not finish, not mid-file corruption.
func TestQueueBadChecksumOnLastFrameIsTorn(t *testing.T) {
	dir := queueDir(t)
	cfg := testConfig(dir)
	q, _ := mustOpen(t, cfg)
	mustAppend(t, q, RoleBait, 0, 3)
	q.Close()
	seg := segFiles(t, dir, ".q")[0]
	b, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-2] ^= 0xff
	if err := os.WriteFile(seg, b, 0o600); err != nil {
		t.Fatal(err)
	}

	q2, rec := mustOpen(t, cfg)
	if rec.TruncatedBytes != int64(FrameHeader+len(payload(2))) || len(rec.Quarantined) != 0 {
		t.Fatalf("recovery = %+v", rec)
	}
	wantPayloads(t, readAll(t, q2), 0, 2)
	if seqs := mustAppend(t, q2, RoleBait, 2, 3); seqs[0] != 3 {
		t.Fatalf("seq after truncation = %d", seqs[0])
	}
}

// A torn tail followed by another restart must not pile up .bad files.
func TestQueueRepeatedTornRestartsLeaveNoBad(t *testing.T) {
	dir := queueDir(t)
	cfg := testConfig(dir)
	for i := range 4 {
		q, _ := mustOpen(t, cfg)
		mustAppend(t, q, RoleBait, i, i+1)
		q.Close()
		segs := segFiles(t, dir, ".q")
		f, err := os.OpenFile(segs[len(segs)-1], os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte{0, 0, 0, 9, 1})
		f.Close()
	}
	q, rec := mustOpen(t, cfg)
	if len(rec.Quarantined) != 0 {
		t.Fatalf("recovery = %+v", rec)
	}
	wantPayloads(t, readAll(t, q), 0, 4)
	if err := q.Ack(4); err != nil {
		t.Fatal(err)
	}
	if bad := segFiles(t, dir, ".bad"); len(bad) != 0 {
		t.Fatalf("quarantined files = %v", bad)
	}
}

// Frames past a corrupt one are still on disk, so new records must not reuse
// their sequence numbers.
func TestQueueSeqSurvivesMidFileCorruption(t *testing.T) {
	dir := queueDir(t)
	cfg := testConfig(dir)
	q, _ := mustOpen(t, cfg)
	mustAppend(t, q, RoleBait, 0, 5)
	q.Close()
	seg := segFiles(t, dir, ".q")[0]
	b, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	frame := FrameHeader + len(payload(0))
	b[frame+FrameHeader+2] ^= 0xff // second frame, seq 2
	if err := os.WriteFile(seg, b, 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, ckptName))

	q2, rec := mustOpen(t, cfg)
	if len(rec.Quarantined) != 1 {
		t.Fatalf("recovery = %+v", rec)
	}
	if seqs := mustAppend(t, q2, RoleBait, 5, 6); seqs[0] != 6 {
		t.Fatalf("seq after recovery = %d, want 6", seqs[0])
	}
}

// A checkpoint that fell behind the segments must not pull seq backwards.
func TestQueueSeqNeverRegresses(t *testing.T) {
	for name, ck := range map[string]string{
		"corrupt":      "{not json",
		"behind":       `{"gen":9,"segment":1,"offset":0,"seq":1}`,
		"missing":      "",
		"other offset": `{"gen":9,"segment":1,"offset":5,"seq":0}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := queueDir(t)
			cfg := testConfig(dir)
			q, _ := mustOpen(t, cfg)
			mustAppend(t, q, RoleBait, 0, 6)
			q.Close()
			path := filepath.Join(dir, ckptName)
			if ck == "" {
				os.Remove(path)
			} else if err := os.WriteFile(path, []byte(ck), 0o600); err != nil {
				t.Fatal(err)
			}
			q2, _ := mustOpen(t, cfg)
			if seqs := mustAppend(t, q2, RoleBait, 6, 7); seqs[0] != 7 {
				t.Fatalf("seq = %d, want 7", seqs[0])
			}
			q2.Close()
			q3, _ := mustOpen(t, cfg)
			if seqs := mustAppend(t, q3, RoleBait, 7, 8); seqs[0] != 8 {
				t.Fatalf("seq after second restart = %d, want 8", seqs[0])
			}
		})
	}
}

func TestQueueQuarantinesCorruption(t *testing.T) {
	dir := queueDir(t)
	cfg := testConfig(dir)
	q, _ := mustOpen(t, cfg)
	mustAppend(t, q, RoleBait, 0, 3)
	q.Close()

	seg := segFiles(t, dir, ".q")[0]
	b, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	frame := FrameHeader + len(payload(0))
	b[frame+FrameHeader+2] ^= 0xff // payload byte of the second frame
	if err := os.WriteFile(seg, b, 0o600); err != nil {
		t.Fatal(err)
	}

	q2, rec := mustOpen(t, cfg)
	if len(rec.Quarantined) != 1 || rec.TruncatedBytes != 0 {
		t.Fatalf("recovery = %+v", rec)
	}
	// The valid prefix is still delivered; the bad tail is not.
	wantPayloads(t, readAll(t, q2), 0, 1)
	if err := q2.Ack(1); err != nil {
		t.Fatal(err)
	}
	if bad := segFiles(t, dir, ".q.bad"); len(bad) != 1 {
		t.Fatalf("quarantined files = %v", bad)
	}
	kept, err := os.ReadFile(seg + badSuffix)
	if err != nil || !bytes.Equal(kept, b) {
		t.Fatalf("quarantined bytes changed: %v", err)
	}
}

func TestQueueUncertainCheckpoint(t *testing.T) {
	for name, mangle := range map[string]func(t *testing.T, dir string){
		"corrupt": func(t *testing.T, dir string) {
			os.WriteFile(filepath.Join(dir, ckptName), []byte("{not json"), 0o600)
		},
		"missing": func(t *testing.T, dir string) {
			os.Remove(filepath.Join(dir, ckptName))
		},
		"unknown field": func(t *testing.T, dir string) {
			os.WriteFile(filepath.Join(dir, ckptName), []byte(`{"gen":9,"segment":1,"offset":0,"seq":2,"x":1}`), 0o600)
		},
		"off boundary": func(t *testing.T, dir string) {
			os.WriteFile(filepath.Join(dir, ckptName), []byte(`{"gen":9,"segment":1,"offset":5,"seq":2}`), 0o600)
		},
		"past end": func(t *testing.T, dir string) {
			os.WriteFile(filepath.Join(dir, ckptName), []byte(`{"gen":9,"segment":1,"offset":99999,"seq":2}`), 0o600)
		},
		"missing segment": func(t *testing.T, dir string) {
			os.WriteFile(filepath.Join(dir, ckptName), []byte(`{"gen":9,"segment":7,"offset":0,"seq":2}`), 0o600)
		},
		"symlink": func(t *testing.T, dir string) {
			target := filepath.Join(filepath.Dir(dir), "elsewhere")
			os.WriteFile(target, []byte(`{"gen":9,"segment":1,"offset":0,"seq":0}`), 0o600)
			os.Remove(filepath.Join(dir, ckptName))
			if err := os.Symlink(target, filepath.Join(dir, ckptName)); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := queueDir(t)
			cfg := testConfig(dir)
			q, _ := mustOpen(t, cfg)
			mustAppend(t, q, RoleBait, 0, 4)
			readAll(t, q)
			if err := q.Ack(2); err != nil {
				t.Fatal(err)
			}
			q.Close()
			mangle(t, dir)

			q2, rec := mustOpen(t, cfg)
			if !rec.Uncertain || rec.UncertainThrough != 4 || rec.Reason == "" {
				t.Fatalf("recovery = %+v, want uncertain through 4", rec)
			}
			// Unknown start: replay everything that survived, oldest first.
			wantPayloads(t, readAll(t, q2), 0, 4)
			if seqs := mustAppend(t, q2, RoleBait, 4, 5); seqs[0] != 5 {
				t.Fatalf("seq after uncertain recovery = %d, want 5", seqs[0])
			}
			// The replacement checkpoint is a regular file, never the link.
			if fi, err := os.Lstat(filepath.Join(dir, ckptName)); err != nil || !fi.Mode().IsRegular() {
				t.Fatalf("checkpoint after recovery: %v %v", fi, err)
			}
		})
	}
}

func TestQueueSymlinkedCheckpointUntouched(t *testing.T) {
	dir := queueDir(t)
	cfg := testConfig(dir)
	q, _ := mustOpen(t, cfg)
	q.Close()
	target := filepath.Join(filepath.Dir(dir), "victim")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, ckptName))
	if err := os.Symlink("../victim", filepath.Join(dir, ckptName)); err != nil {
		t.Fatal(err)
	}
	q2, _ := mustOpen(t, cfg)
	q2.Close()
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatalf("symlink target overwritten: %q", b)
	}
}

func TestQueueStaleTempRemoved(t *testing.T) {
	dir := queueDir(t)
	cfg := testConfig(dir)
	q, _ := mustOpen(t, cfg)
	q.Close()
	stale := filepath.Join(dir, ckptTmpPrefix+"deadbeef")
	if err := os.WriteFile(stale, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustOpen(t, cfg)
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale temp still present: %v", err)
	}
}

func TestQueueDetectsTamperOnRead(t *testing.T) {
	dir := queueDir(t)
	q, _ := mustOpen(t, testConfig(dir))
	mustAppend(t, q, RoleBait, 0, 2)
	seg := segFiles(t, dir, ".q")[0]
	f, err := os.OpenFile(seg, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteAt([]byte("X"), FrameHeader+1)
	f.Close()
	if _, err := q.Read(10, 1<<20); err == nil {
		t.Fatal("changed frame was delivered")
	}
	_, err = q.Append([]Item{{Role: RoleBait, Data: payload(9)}})
	if !errors.Is(err, ErrQueueBroken) {
		t.Fatalf("Append after a read failure = %v, want ErrQueueBroken", err)
	}
}

func TestQueueDirChecks(t *testing.T) {
	base := t.TempDir()
	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o770); err != nil {
		t.Fatal(err)
	}
	q, _ := mustOpen(t, testConfig(open))
	q.Close()
	if fi, err := os.Lstat(open); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("group-writable dir after open: %v %v", fi, err)
	}
	for _, mode := range []os.FileMode{0o750, 0o705, 0o777, 0o755} {
		dir := filepath.Join(base, fmt.Sprintf("m%03o", mode))
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		q, _ := mustOpen(t, testConfig(dir))
		q.Close()
		if fi, err := os.Lstat(dir); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("mode %04o dir after open: %v %v", mode, fi, err)
		}
	}
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenQueue(testConfig(link)); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("symlinked dir: %v", err)
	}
	created := filepath.Join(base, "new")
	q, _ = mustOpen(t, testConfig(created))
	q.Close()
	if fi, err := os.Lstat(created); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("created dir mode: %v %v", fi, err)
	}
}

func TestQueueConfigValidation(t *testing.T) {
	good := testConfig(queueDir(t))
	for name, mut := range map[string]func(*QueueConfig){
		"no dir":        func(c *QueueConfig) { c.Dir = "" },
		"tiny segment":  func(c *QueueConfig) { c.SegmentBytes = 1 },
		"tiny max":      func(c *QueueConfig) { c.MaxBytes = 1 },
		"zero payload":  func(c *QueueConfig) { c.MaxPayload = 0 },
		"bad role":      func(c *QueueConfig) { c.RoleBytes = map[Role]int64{9: 100} },
		"role over max": func(c *QueueConfig) { c.RoleBytes = map[Role]int64{RoleBait: c.MaxBytes + 1} },
	} {
		cfg := good
		mut(&cfg)
		if _, _, err := OpenQueue(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestQueueClosed(t *testing.T) {
	q, _ := mustOpen(t, testConfig(queueDir(t)))
	q.Close()
	if _, err := q.Append([]Item{{Role: RoleBait, Data: payload(0)}}); !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("Append after Close = %v", err)
	}
	if _, err := q.Read(1, 1); !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("Read after Close = %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
}
