package auditfilter

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func fixture() []string {
	return []string{
		`type=SYSCALL msg=audit(1700000000.123:42): arch=c000003e syscall=49 success=yes exit=0 items=0 ppid=1 pid=100 auid=4294967295 uid=0 euid=0 key="network_connect"`,
		`type=PROCTITLE msg=audit(1700000000.123:42): proctitle="attackbox"`,
	}
}

func TestExactReconstructionUnknownAndChunks(t *testing.T) {
	lines := append(fixture(), "unknown "+strings.Repeat("λ", 8000))
	out, s := Batch(lines, "boot")
	if s.KeptRows != 3 {
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
	rows, s := Batch([]string{a[0], b[0], a[1], b[1]}, "boot")
	if s.KeptRows != 4 || s.KeptEvents != 2 || len(rows) != 2 {
		t.Fatal(s, rows)
	}
	for _, line := range []string{`type=SYSCALL msg=audit(1.1:2): exe="bad`, `type=SYSCALL msg=audit(1.1:2): uid=0 uid=1`, `type=SYSCALL msg=audit(1.1:2): bad key=x`} {
		if Parse(line).Valid {
			t.Fatal(line)
		}
	}
}
