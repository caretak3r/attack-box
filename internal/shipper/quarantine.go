package shipper

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
)

const QuarantineMaxBytes int64 = 64 << 20
const QuarantineMaxRecords = 4096

// Quarantine retains exact queue bytes rejected by the remote API. It has one
// owner, the queue drain. It never evicts evidence. Full or damaged storage
// stops the drain before acknowledgement. Operators archive records offline.
type Quarantine struct {
	mu       sync.Mutex
	root     *os.Root
	bytes    int64
	records  int
	maxBytes int64
}

type rejectedRecord struct {
	Version int    `json:"version"`
	Seq     uint64 `json:"queue_seq"`
	Role    Role   `json:"role"`
	Reason  string `json:"reason"`
	SHA256  string `json:"sha256"`
	Data    []byte `json:"data_base64"`
}

func OpenQuarantine(dir string) (*Quarantine, error) {
	root, err := openQueueDir(dir)
	if err != nil {
		return nil, err
	}
	q := &Quarantine{root: root, maxBytes: QuarantineMaxBytes}
	d, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	entries, err := d.ReadDir(QuarantineMaxRecords + 2)
	d.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		root.Close()
		return nil, err
	}
	for _, e := range entries {
		if e.Name() == ".pending" && e.Type().IsRegular() {
			if err := root.Remove(e.Name()); err != nil {
				root.Close()
				return nil, err
			}
			continue
		}
		info, err := e.Info()
		if err != nil || !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".json") || len(e.Name()) != 69 {
			root.Close()
			return nil, errors.New("quarantine: unexpected storage entry")
		}
		q.bytes += info.Size()
		q.records++
	}
	if q.bytes > q.maxBytes || q.records > QuarantineMaxRecords {
		root.Close()
		return nil, errors.New("quarantine: storage limit exceeded")
	}
	return q, nil
}

func (q *Quarantine) Close() error { return q.root.Close() }

func (q *Quarantine) Stats() (int, int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.records, q.bytes
}

func (q *Quarantine) syncDir() error {
	f, err := q.root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// Put is idempotent for a queue entry across crashes before queue checkpoint.
// Success means the file and its directory entry have both been synced.
func (q *Quarantine) Put(e Entry, reason string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(e.Data) > MaxData || len(reason) > 64 {
		return errors.New("quarantine: invalid record size")
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(e.Data))
	id := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d:%d:%s", e.Role, e.Seq, hash))))
	name := id + ".json"
	r := rejectedRecord{Version: 1, Seq: e.Seq, Role: e.Role, Reason: reason, SHA256: hash, Data: e.Data}
	if f, err := q.root.OpenFile(name, os.O_RDWR|syscall.O_NOFOLLOW, 0); err == nil {
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 12<<20 {
			return errors.New("quarantine: invalid existing record")
		}
		var old rejectedRecord
		if err := json.NewDecoder(io.LimitReader(f, 12<<20)).Decode(&old); err != nil {
			return err
		}
		if old.Version != 1 || old.Seq != e.Seq || old.Role != e.Role || old.SHA256 != hash || !bytes.Equal(old.Data, e.Data) {
			return errors.New("quarantine: existing record differs")
		}
		if err := f.Sync(); err != nil {
			return err
		}
		return q.syncDir()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if q.records >= QuarantineMaxRecords || q.bytes+int64(len(data)) > q.maxBytes {
		return errors.New("quarantine: full; queue retained; archive evidence before restart")
	}
	f, err := q.root.OpenFile(".pending", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer q.root.Remove(".pending")
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := q.root.Rename(".pending", name); err != nil {
		return err
	}
	if err := q.syncDir(); err != nil {
		return err
	}
	q.records++
	q.bytes += int64(len(data))
	return nil
}
