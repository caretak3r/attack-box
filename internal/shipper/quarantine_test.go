package shipper

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestQuarantineRetainsExactBytesAcrossRestartAndReplay(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rejected")
	q, err := OpenQuarantine(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := Entry{Seq: 7, Role: RoleRuntime, Data: []byte{'{', 0, 0xff, '\n', '}'}}
	if err := q.Put(e, "http_400"); err != nil {
		t.Fatal(err)
	}
	count, size := q.Stats()
	if count != 1 || size == 0 {
		t.Fatalf("stats %d/%d", count, size)
	}
	q.Close()
	q, err = OpenQuarantine(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err := q.Put(e, "http_422"); err != nil {
		t.Fatal(err)
	}
	if n, b := q.Stats(); n != 1 || b != size {
		t.Fatalf("replay duplicated storage: %d/%d", n, b)
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 1 {
		t.Fatal(files)
	}
	info, _ := files[0].Info()
	if info.Mode().Perm() != 0o600 {
		t.Fatal(info.Mode())
	}
	data, _ := os.ReadFile(filepath.Join(dir, files[0].Name()))
	var r rejectedRecord
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.Data, e.Data) || r.Seq != e.Seq || r.Role != e.Role || r.Reason != "http_400" {
		t.Fatalf("evidence altered: %+v", r)
	}
}

func TestQuarantineCapacityNeverEvicts(t *testing.T) {
	q, err := OpenQuarantine(filepath.Join(t.TempDir(), "rejected"))
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	e := Entry{Seq: 1, Role: RoleBait, Data: []byte("evidence")}
	if err := q.Put(e, "http_400"); err != nil {
		t.Fatal(err)
	}
	_, size := q.Stats()
	q.maxBytes = size
	e.Seq++
	if err := q.Put(e, "http_400"); err == nil {
		t.Fatal("accepted beyond capacity")
	}
	e.Seq--
	if err := q.Put(e, "http_400"); err != nil {
		t.Fatal("replay at capacity:", err)
	}
	q.maxBytes = QuarantineMaxBytes
	q.records = QuarantineMaxRecords
	e.Seq++
	if err := q.Put(e, "http_400"); err == nil {
		t.Fatal("accepted beyond file count")
	}
}

func TestQuarantineRejectsSymlinkAndCorruptReplay(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(dir, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if q, err := OpenQuarantine(filepath.Join(dir, "link")); err == nil {
		q.Close()
		t.Fatal("followed directory symlink")
	}
	path := filepath.Join(dir, "rejected")
	q, err := OpenQuarantine(path)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	e := Entry{Seq: 1, Role: RoleBait, Data: []byte("evidence")}
	if err := q.Put(e, "http_400"); err != nil {
		t.Fatal(err)
	}
	files, _ := os.ReadDir(path)
	file := filepath.Join(path, files[0].Name())
	if err := os.WriteFile(file, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := q.Put(e, "http_400"); err == nil {
		t.Fatal("accepted corrupt prior receipt")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, file); err != nil {
		t.Fatal(err)
	}
	if err := q.Put(e, "http_400"); err == nil {
		t.Fatal("followed record symlink")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "untouched" {
		t.Fatal("modified external target")
	}
}

func TestQuarantineRemovesOnlyInterruptedTemporaryWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rejected")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".pending"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	q, err := OpenQuarantine(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if n, b := q.Stats(); n != 0 || b != 0 {
		t.Fatal(n, b)
	}
	if err := q.Put(Entry{Seq: 1, Role: RoleBait, Data: []byte("retry")}, "http_400"); err != nil {
		t.Fatal(err)
	}
}
