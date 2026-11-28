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

	records := []EvidenceItem{
		{Role: "bait", Seq: 1, Data: data1},
		{Role: "runtime", Seq: 2, Data: data2},
	}
	if err := log.Write(records); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "events-20261128.jsonl")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var got []Envelope
	for dec := json.NewDecoder(f); dec.More(); {
		var env Envelope
		if err := dec.Decode(&env); err != nil {
			t.Fatal(err)
		}
		got = append(got, env)
	}
	if len(got) != 2 || got[0].Role != "bait" || got[0].Seq != 1 || got[0].Record.Event == nil ||
		got[1].Role != "runtime" || got[1].Seq != 2 || got[1].Record.Metric == nil {
		t.Fatalf("envelopes = %+v, want bait event seq 1 then runtime metric seq 2", got)
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
	if err := log.Write([]EvidenceItem{{"bait", 1, data}}); err != nil {
		t.Fatal(err)
	}

	now = day2
	if err := log.Write([]EvidenceItem{{"bait", 2, data}}); err != nil {
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
	if err := log.Write([]EvidenceItem{{"bait", 1, data}}); err != nil {
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
	if err := log.Write([]EvidenceItem{{"bait", 1, data}}); err != nil {
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
	if err := log.Write([]EvidenceItem{{"bait", 1, data}}); err != nil {
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
