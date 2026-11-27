package hostevidence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileReceiptFailureRestartAndRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "falco.jsonl")
	statePath := filepath.Join(dir, "state")
	if err := os.WriteFile(path, []byte("first\nsecond\npartial"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenState(statePath, "falco")
	if err != nil {
		t.Fatal(err)
	}
	var delivered []string
	fail := true
	deliver := func(_ context.Context, _ string, b []byte) error {
		if fail {
			return errors.New("receipt lost")
		}
		delivered = append(delivered, string(b))
		return nil
	}
	r := FileReader{Path: path, State: s, Deliver: deliver}
	if _, err := r.Step(context.Background()); err == nil {
		t.Fatal("expected missing receipt")
	}
	if s.Position.Offset != 0 {
		t.Fatal("advanced without receipt")
	}
	fail = false
	if ok, err := r.Step(context.Background()); !ok || err != nil {
		t.Fatal(ok, err)
	}
	r.Close()
	s.Close()
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err = OpenState(statePath, "falco")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r = FileReader{Path: path, State: s, Deliver: deliver}
	defer r.Close()
	if ok, err := r.Step(context.Background()); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if _, err := r.Step(context.Background()); err == nil {
		t.Fatal("incomplete rotated line must be explicit")
	}
	f, err := os.OpenFile(path+".1", os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("\n"))
	f.Close()
	for i := 0; i < 3; i++ {
		if _, err := r.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(delivered, "|") != "first\n|second\n|partial\n|new\n" {
		t.Fatal(delivered)
	}
}

func TestFileDetectsCopyTruncateAndMissingInode(t *testing.T) {
	for _, mode := range []string{"truncate", "rewrite", "missing"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "events")
			sp := filepath.Join(dir, "state")
			os.WriteFile(path, []byte("original\n"), 0o600)
			s, err := OpenState(sp, "falco")
			if err != nil {
				t.Fatal(err)
			}
			r := FileReader{Path: path, State: s, Deliver: func(context.Context, string, []byte) error { return nil }}
			if _, err := r.Step(context.Background()); err != nil {
				t.Fatal(err)
			}
			r.Close()
			s.Close()
			switch mode {
			case "truncate":
				os.WriteFile(path, []byte("x\n"), 0o600)
			case "rewrite":
				os.WriteFile(path, []byte("modified\nnew\n"), 0o600)
			case "missing":
				os.Rename(path, filepath.Join(dir, "unrelated"))
				os.WriteFile(path, []byte("next\n"), 0o600)
			}
			s, err = OpenState(sp, "falco")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			r = FileReader{Path: path, State: s, Deliver: func(context.Context, string, []byte) error { t.Fatal("gap silently skipped"); return nil }}
			defer r.Close()
			if _, err := r.Step(context.Background()); err == nil {
				t.Fatal("missing gap error")
			}
		})
	}
}

func TestFilePartialAndOversizeDoNotAdvance(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events")
	os.WriteFile(path, []byte("partial"), 0o600)
	s, err := OpenState(filepath.Join(dir, "state"), "falco")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := FileReader{Path: path, State: s, Deliver: func(context.Context, string, []byte) error { t.Fatal("invalid line sent"); return nil }}
	defer r.Close()
	if ok, err := r.Step(context.Background()); ok || err != nil {
		t.Fatal(ok, err)
	}
	os.WriteFile(path, []byte(strings.Repeat("x", MaxSourceRecord+1)+"\n"), 0o600)
	if _, err := r.Step(context.Background()); err == nil {
		t.Fatal("oversize accepted")
	}
	if s.Position.Offset != 0 {
		t.Fatal("advanced cursor")
	}
}

func TestStateRejectsCorruptionSymlinkAndSecondOwner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state")
	s, err := OpenState(path, "falco")
	if err != nil {
		t.Fatal(err)
	}
	if other, err := OpenState(path, "falco"); err == nil {
		other.Close()
		t.Fatal("second owner")
	}
	s.Close()
	os.WriteFile(filepath.Join(path, "cursor.json"), []byte("broken"), 0o600)
	if s, err := OpenState(path, "falco"); err == nil {
		s.Close()
		t.Fatal("corrupt state silently reset")
	}
	os.Symlink(path, filepath.Join(dir, "alias"))
	if s, err := OpenState(filepath.Join(dir, "alias"), "falco"); err == nil {
		s.Close()
		t.Fatal("followed state symlink")
	}
}

func TestNumericRotationDrainsEveryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	os.WriteFile(path, []byte("first\n"), 0600)
	s, e := OpenState(filepath.Join(dir, "state"), "audit")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var got []string
	r := FileReader{Path: path, State: s, NumericRotation: true, Deliver: func(_ context.Context, _ string, b []byte) error { got = append(got, string(b)); return nil }}
	defer r.Close()
	if _, e = r.Step(context.Background()); e != nil {
		t.Fatal(e)
	}
	os.Rename(path, path+".2")
	os.WriteFile(path+".1", []byte("middle\n"), 0600)
	os.WriteFile(path, []byte("last\n"), 0600)
	for i := 0; i < 5; i++ {
		if _, e = r.Step(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	if strings.Join(got, "") != "first\nmiddle\nlast\n" {
		t.Fatal(got)
	}
}
