package publicedge

import (
	"bufio"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCaptureRecordsRawTargetLocally(t *testing.T) {
	dir := t.TempDir()
	day := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	c, err := openCapture(dir, func() time.Time { return day })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := NewGateway(nil)
	g.Capture = c
	r := httptest.NewRequest("GET", "/.env?key=fixture-secret", nil)
	r.RemoteAddr = "[::ffff:203.0.113.9]:4242"
	r.Header.Set("User-Agent", "scanner/1.0\x1b[31m")
	g.ServeHTTP(httptest.NewRecorder(), r)

	f, err := os.Open(filepath.Join(dir, "capture-20261125.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	if st.Mode().Perm() != 0o600 {
		t.Errorf("capture mode = %v", st.Mode().Perm())
	}
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(line, "\x1b") {
		t.Fatal("control byte written raw")
	}
	var got captureRecord
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatal(err)
	}
	want := captureRecord{Time: "2026-11-25T12:00:00Z", Peer: "203.0.113.9", Method: "GET", Target: "/.env?key=fixture-secret", Host: "example.com",
		UserAgent: "scanner/1.0\x1b[31m", Route: "/unmatched", Status: 404, Probe: "env_file"}
	if got != want {
		t.Fatalf("record = %+v, want %+v", got, want)
	}
	if rec, drop := c.Counts(); rec != 1 || drop != 0 {
		t.Fatalf("counts = %d/%d", rec, drop)
	}
}

func TestCaptureBudgetAndRetention(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"capture-20261118.jsonl", "capture-20261119.jsonl", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 11, 25, 23, 59, 0, 0, time.UTC)
	c, err := openCapture(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, name := range []string{"capture-20261118.jsonl"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s survived retention", name)
		}
	}
	for _, name := range []string{"capture-20261119.jsonl", "notes.txt"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s removed: %v", name, err)
		}
	}

	r := httptest.NewRequest("GET", "/"+strings.Repeat("a", 4000), nil)
	c.size = CaptureDayLimit - 10
	c.Record(r, "/unmatched", 404, "other")
	if rec, drop := c.Counts(); rec != 0 || drop != 1 {
		t.Fatalf("over budget counts = %d/%d", rec, drop)
	}

	now = now.Add(2 * time.Minute)
	c.Record(r, "/unmatched", 404, "other")
	if rec, _ := c.Counts(); rec != 1 {
		t.Fatal("new day did not reset the budget")
	}
	data, err := os.ReadFile(filepath.Join(dir, "capture-20261126.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var got captureRecord
	if err := json.Unmarshal(data, &got); err != nil || len(got.Target) != captureTarget {
		t.Fatalf("target not clipped: %d %v", len(got.Target), err)
	}
	if _, err := os.Stat(filepath.Join(dir, "capture-20261119.jsonl")); !os.IsNotExist(err) {
		t.Error("rotation did not prune the oldest day")
	}
}

func TestOpenCaptureFailsWithoutDirectory(t *testing.T) {
	if _, err := OpenCapture(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing capture directory accepted")
	}
}
