package telemetry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Envelope is the shipper evidence record on disk: UTC timestamp, producer
// role, queue sequence and the JSON-decoded record. At-least-once delivery:
// a crash between fsync and queue checkpoint may duplicate lines.
type Envelope struct {
	Ts     string `json:"ts"`
	Role   string `json:"role"`
	Seq    uint64 `json:"seq"`
	Record Record `json:"record"`
}

// EvidenceConfig configures the local evidence writer.
type EvidenceConfig struct {
	Dir           string
	RetentionDays int
	MaxBytes      int64
	Now           func() time.Time
	OnError       func(error)
}

// EvidenceLog writes evidence envelopes to day-stamped JSONL files. Files are
// mode 0600 in Dir, which must exist and be mode 0700. Writes fsync each batch;
// retention enforces day and size caps. One open file at a time, rolled over
// at UTC day change. The active file is never deleted by retention.
type EvidenceLog struct {
	cfg  EvidenceConfig
	mu   sync.Mutex
	file *os.File
	day  string
}

// NewEvidenceLog opens the writer. Dir must exist.
func NewEvidenceLog(cfg EvidenceConfig) (*EvidenceLog, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("evidencelog: Dir is required")
	}
	if cfg.RetentionDays <= 0 {
		cfg.RetentionDays = 30
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = 8 << 30
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	st, err := os.Stat(cfg.Dir)
	if err != nil {
		return nil, fmt.Errorf("evidencelog: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("evidencelog: %s is not a directory", cfg.Dir)
	}
	return &EvidenceLog{cfg: cfg}, nil
}

// EvidenceItem is one queued record for Write: the verified producer role, the
// queue sequence and the JSON record.
type EvidenceItem struct {
	Role string
	Seq  uint64
	Data []byte
}

// Write appends envelopes, fsync the file, then returns. A write or fsync
// error leaves the queue unacknowledged, so the drain will retry. Caller MUST
// checkpoint only after a successful Write.
func (e *EvidenceLog) Write(records []EvidenceItem) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.cfg.Now()
	day := now.UTC().Format("20060102")
	if day != e.day {
		if e.file != nil {
			e.file.Close()
		}
		if err := e.enforceRetention(day); err != nil && e.cfg.OnError != nil {
			e.cfg.OnError(err)
		}
		path := filepath.Join(e.cfg.Dir, fmt.Sprintf("events-%s.jsonl", day))
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			return fmt.Errorf("evidencelog: open %s: %w", path, err)
		}
		e.file = f
		e.day = day
	}
	ts := now.UTC().Format(time.RFC3339Nano)
	for _, r := range records {
		var rec Record
		if err := json.Unmarshal(r.Data, &rec); err != nil {
			return fmt.Errorf("evidencelog: decode seq %d: %w", r.Seq, err)
		}
		env := Envelope{Ts: ts, Role: r.Role, Seq: r.Seq, Record: rec}
		line, err := json.Marshal(env)
		if err != nil {
			return fmt.Errorf("evidencelog: encode seq %d: %w", r.Seq, err)
		}
		if _, err := e.file.Write(append(line, '\n')); err != nil {
			return fmt.Errorf("evidencelog: write: %w", err)
		}
	}
	if err := e.file.Sync(); err != nil {
		return fmt.Errorf("evidencelog: fsync: %w", err)
	}
	return nil
}

// Close syncs and closes the active file.
func (e *EvidenceLog) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file != nil {
		err := e.file.Close()
		e.file = nil
		e.day = ""
		return err
	}
	return nil
}

// enforceRetention deletes files older than RetentionDays UTC days, then
// deletes oldest first until total size is at most MaxBytes. The current
// day file (currentDay) is never deleted.
func (e *EvidenceLog) enforceRetention(currentDay string) error {
	entries, err := os.ReadDir(e.cfg.Dir)
	if err != nil {
		return err
	}
	cutoff := e.cfg.Now().AddDate(0, 0, -e.cfg.RetentionDays).UTC().Format("20060102")
	var files []struct {
		name string
		size int64
		day  string
	}
	for _, ent := range entries {
		name := ent.Name()
		var day string
		if _, err := fmt.Sscanf(name, "events-%8s.jsonl", &day); err != nil {
			continue
		}
		if day == currentDay {
			continue
		}
		if day < cutoff {
			os.Remove(filepath.Join(e.cfg.Dir, name))
			continue
		}
		info, err := ent.Info()
		if err != nil {
			continue
		}
		files = append(files, struct {
			name string
			size int64
			day  string
		}{name, info.Size(), day})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].day < files[j].day })
	var total int64
	for _, f := range files {
		total += f.size
	}
	for total > e.cfg.MaxBytes && len(files) > 0 {
		f := files[0]
		files = files[1:]
		os.Remove(filepath.Join(e.cfg.Dir, f.name))
		total -= f.size
	}
	return nil
}
