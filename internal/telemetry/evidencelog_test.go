package telemetry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEvidenceLogWrite(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	log, err := NewEvidenceLog(EvidenceConfig{
		Dir:           dir,
		RetentionDays: 30,
		MaxBytes:      8 << 30,
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	rec1 := Record{Event: &Event{Stream: "edge", Action: "request", Timestamp: now}}
	data1, _ := json.Marshal(rec1)
	rec2 := Record{Metric: &MetricRecord{Name: "test.counter", Kind: "count", Value: 1, At: now}}
	data2, _ := json.Marshal(rec2)

	records := []struct {
		Seq  uint64
		Data []byte
	}{
		{Seq: 1, Data: data1},
		{Seq: 2, Data: data2},
	}
	if err := log.Write("bait", records); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "events-20261128.jsonl")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, b := range content {
		if b == '\n' {
			lines++
		}
	}
	if lines != 2 {
		t.Errorf("got %d lines, want 2", lines)
	}
}

func TestEvidenceLogRollover(t *testing.T) {
	dir := t.TempDir()
	day1 := time.Date(2026, 11, 28, 23, 59, 0, 0, time.UTC)
	day2 := time.Date(2026, 11, 29, 0, 1, 0, 0, time.UTC)
	now := day1
	log, err := NewEvidenceLog(EvidenceConfig{
		Dir:           dir,
		RetentionDays: 30,
		MaxBytes:      8 << 30,
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	rec := Record{Event: &Event{Stream: "edge", Action: "request", Timestamp: day1}}
	data, _ := json.Marshal(rec)
	if err := log.Write("bait", []struct {
		Seq  uint64
		Data []byte
	}{{1, data}}); err != nil {
		t.Fatal(err)
	}

	now = day2
	if err := log.Write("bait", []struct {
		Seq  uint64
		Data []byte
	}{{2, data}}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(dir, "events-20261128.jsonl")); err != nil {
		t.Error("day 1 file missing")
	}
	if _, err := os.Stat(filepath.Join(dir, "events-20261129.jsonl")); err != nil {
		t.Error("day 2 file missing")
	}
}

func TestEvidenceLogRetentionByAge(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	old := now.AddDate(0, 0, -31)
	os.WriteFile(filepath.Join(dir, "events-"+old.Format("20060102")+".jsonl"), []byte("old\n"), 0600)

	log, err := NewEvidenceLog(EvidenceConfig{
		Dir:           dir,
		RetentionDays: 30,
		MaxBytes:      8 << 30,
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	rec := Record{Event: &Event{Stream: "edge", Action: "request", Timestamp: now}}
	data, _ := json.Marshal(rec)
	if err := log.Write("bait", []struct {
		Seq  uint64
		Data []byte
	}{{1, data}}); err != nil {
		t.Fatal(err)
	}

	oldPath := filepath.Join(dir, "events-"+old.Format("20060102")+".jsonl")
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Error("old file not deleted")
	}
}

func TestEvidenceLogRetentionBySize(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	old := now.AddDate(0, 0, -1)
	os.WriteFile(filepath.Join(dir, "events-"+old.Format("20060102")+".jsonl"), make([]byte, 1<<20), 0600)

	log, err := NewEvidenceLog(EvidenceConfig{
		Dir:           dir,
		RetentionDays: 30,
		MaxBytes:      500 << 10,
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	rec := Record{Event: &Event{Stream: "edge", Action: "request", Timestamp: now}}
	data, _ := json.Marshal(rec)
	if err := log.Write("bait", []struct {
		Seq  uint64
		Data []byte
	}{{1, data}}); err != nil {
		t.Fatal(err)
	}

	oldPath := filepath.Join(dir, "events-"+old.Format("20060102")+".jsonl")
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Error("oversized file not deleted")
	}
}

func TestEvidenceLogCheckpointAfterWrite(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	log, err := NewEvidenceLog(EvidenceConfig{
		Dir:           dir,
		RetentionDays: 30,
		MaxBytes:      8 << 30,
		Now:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	rec := Record{Event: &Event{Stream: "edge", Action: "request", Timestamp: now}}
	data, _ := json.Marshal(rec)
	if err := log.Write("bait", []struct {
		Seq  uint64
		Data []byte
	}{{1, data}}); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "events-20261128.jsonl")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) == 0 {
		t.Error("file empty after write")
	}
}
