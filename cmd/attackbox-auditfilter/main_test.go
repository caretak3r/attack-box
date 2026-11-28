package main

import (
	"attackbox/internal/hostevidence"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderAccountingAndOriginalBytes(t *testing.T) {
	lines := []string{"unparsed input", `type=USER_AUTH msg=audit(1.1:2): res=failed`}
	b, e := render(lines, "boot", "batch")
	if e != nil {
		t.Fatal(e)
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	var events []map[string]any
	for dec.More() {
		var row map[string]any
		if e = dec.Decode(&row); e != nil {
			t.Fatal(e)
		}
		events = append(events, row)
	}
	if len(events) != 3 || events[0]["message"] != "unparsed input\n" || events[2]["kept_rows"] != float64(2) {
		t.Fatal(events)
	}
}
func TestBatchCheckpointReplaysBeforeCommit(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "audit.log")
	os.WriteFile(source, []byte("first\nsecond\n"), 0600)
	path := filepath.Join(dir, "state")
	s, e := hostevidence.OpenState(path, "audit")
	if e != nil {
		t.Fatal(e)
	}
	r := hostevidence.FileReader{Path: source, State: s, Deliver: func(context.Context, string, []byte) error { return nil }, Commit: func(p hostevidence.Position) error { s.Position = p; return nil }}
	if _, e = r.Step(context.Background()); e != nil {
		t.Fatal(e)
	}
	r.Close()
	s.Close()
	s, e = hostevidence.OpenState(path, "audit")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if s.Position.Offset != 0 {
		t.Fatal("uncommitted data lost")
	}
	var got string
	r = hostevidence.FileReader{Path: source, State: s, Deliver: func(_ context.Context, _ string, b []byte) error { got = string(b); return nil }}
	defer r.Close()
	if _, e = r.Step(context.Background()); e != nil || got != "first\n" {
		t.Fatal(got, e)
	}
}
func TestOutputRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("unchanged"), 0600)
	os.Symlink(target, filepath.Join(dir, "events.jsonl"))
	o := output{dir: dir}
	if o.open() == nil {
		o.file.Close()
		t.Fatal("symlink accepted")
	}
}

func TestOutputRecoversUncommittedPartialTail(t *testing.T) {
	for _, original := range []string{"{\"ok\":1}\n{\"partial\":", "partial", "{\"ok\":1}\n"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "events.jsonl")
		if err := os.WriteFile(path, []byte(original), 0600); err != nil {
			t.Fatal(err)
		}
		o := output{dir: dir}
		if err := o.open(); err != nil {
			t.Fatal(err)
		}
		if err := o.write([]byte("{\"replayed\":true}\n")); err != nil {
			t.Fatal(err)
		}
		o.file.Close()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want := "{\"replayed\":true}\n"
		if strings.HasPrefix(original, "{\"ok\":1}\n") {
			want = "{\"ok\":1}\n" + want
		}
		if string(b) != want {
			t.Fatalf("got %q want %q", b, want)
		}
	}
}

func TestOutputRotationReportsRetiredBytes(t *testing.T) {
	dir := t.TempDir()
	o := output{dir: dir}
	if err := o.open(); err != nil {
		t.Fatal(err)
	}
	if err := o.file.Truncate(64 << 20); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl.3"), []byte("old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := o.write([]byte("{\"new\":true}\n")); err != nil {
		t.Fatal(err)
	}
	o.file.Close()
	b, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatal(string(b))
	}
	var marker map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &marker); err != nil {
		t.Fatal(err)
	}
	if marker["action"] != "audit_output_rotation" || marker["retired_local_bytes"] != float64(4) {
		t.Fatal(marker)
	}
	if lines[1] != "{\"new\":true}" {
		t.Fatal(lines[1])
	}
}
