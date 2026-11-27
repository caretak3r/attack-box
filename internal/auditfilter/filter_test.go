package auditfilter

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func fixture() []string {
	return []string{
		`type=SYSCALL msg=audit(1700000000.123:42): arch=c000003e syscall=41 success=yes exit=4 a0=10 a1=80003 a2=0 items=0 ppid=1 pid=22 auid=4294967295 uid=0 euid=0 exe="/usr/bin/newrelic-infra" key="network_connect"`,
		`type=PROCTITLE msg=audit(1700000000.123:42): proctitle="/usr/bin/newrelic-infra"`,
	}
}
func TestOnlyVerifiedCompleteRoutine(t *testing.T) {
	rows, stats := Batch(fixture(), "boot", func(Record) bool { return true })
	if len(rows) != 0 || stats.SuppressedRows != 2 || stats.InputRows != 2 {
		t.Fatal(rows, stats)
	}
	for _, change := range []struct{ old, new string }{
		{"success=yes", "success=no"}, {"a0=10", "a0=2"}, {"a1=80003", "a1=80001"}, {"a2=0", "a2=9"}, {"auid=4294967295", "auid=0"}, {"uid=0", "uid=1"}, {"euid=0", "euid=1"}, {"items=0", "items=1"}, {"syscall=41", "syscall=42"}, {"arch=c000003e", "arch=40000003"}, {`key="network_connect"`, `key="exec"`}, {`exe="/usr/bin/newrelic-infra"`, `exe="/tmp/newrelic-infra"`}, {"pid=22", "pid=22 pid=23"},
	} {
		g := fixture()
		g[0] = strings.Replace(g[0], change.old, change.new, 1)
		_, s := Batch(g, "boot", func(Record) bool { return true })
		if s.KeptRows != 2 || s.SuppressedRows != 0 {
			t.Fatalf("lost %s: %+v", change.old, s)
		}
	}
	for _, g := range [][]string{fixture()[:1], fixture()[1:], append(fixture(), `type=PATH msg=audit(1700000000.123:42): item=0 name="/etc/passwd"`)} {
		_, s := Batch(g, "boot", func(Record) bool { return true })
		if s.KeptRows != len(g) {
			t.Fatal(s)
		}
	}
	_, s := Batch(fixture(), "boot", func(Record) bool { return false })
	if s.KeptRows != 2 {
		t.Fatal(s)
	}
}
func TestExactReconstructionUnknownAndChunks(t *testing.T) {
	lines := append(fixture(), "unknown "+strings.Repeat("λ", 8000))
	out, s := Batch(lines, "boot", nil)
	if s.KeptRows != 3 || s.SuppressedRows != 0 {
		t.Fatal(s)
	}
	var got strings.Builder
	for _, e := range out {
		if len([]rune(e.Message)) > 3500 {
			t.Fatal("large chunk")
		}
		got.WriteString(e.Message)
		if e.Boot != "boot" {
			t.Fatal(e)
		}
	}
	want := strings.Join(lines, "\n") + "\n"
	if got.String() != want {
		t.Fatal("evidence changed")
	}
	raw := strings.Join(fixture(), "\n") + "\n"
	if out[0].SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(raw))) {
		t.Fatal("wrong hash")
	}
}
func TestMalformedAndInterleavedRetained(t *testing.T) {
	a := fixture()
	b := []string{strings.ReplaceAll(a[0], ":42)", ":43)"), strings.ReplaceAll(a[1], ":42)", ":43)")}
	b[0] = strings.Replace(b[0], "success=yes", "success=no", 1)
	rows, s := Batch([]string{a[0], b[0], a[1], b[1]}, "boot", func(Record) bool { return true })
	if s.SuppressedRows != 2 || s.KeptRows != 2 || len(rows) != 1 || rows[0].EventID != "1700000000.123:43" {
		t.Fatal(s, rows)
	}
	for _, line := range []string{`type=SYSCALL msg=audit(1.1:2): exe="bad`, `type=SYSCALL msg=audit(1.1:2): uid=0 uid=1`, `type=SYSCALL msg=audit(1.1:2): bad key=x`} {
		if Parse(line).Valid {
			t.Fatal(line)
		}
	}
}
