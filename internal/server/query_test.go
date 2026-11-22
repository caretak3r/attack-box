package server

import (
	"strconv"
	"strings"
	"testing"
)

func TestRedactQueryJudgesNamesLikeBodyKeys(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	for _, name := range []string{"pwd", "pass", "cookie", "jwt", "bearer", "Set-Cookie", "clientSecret", "x_api_key"} {
		got := r.srv.redactQuery(name + "=hunter2x&page=3")
		if strings.Contains(got, "hunter2x") || !strings.Contains(got, "page=3") {
			t.Errorf("%s: query logged as %q", name, got)
		}
	}
}

func TestRedactQueryBoundsParamsAndValues(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	var b strings.Builder
	for i := 0; i < 200; i++ {
		b.WriteString("p" + strconv.Itoa(1000+i) + "=1&")
	}
	got := r.srv.redactQuery(b.String())
	if !strings.Contains(got, "[truncated]") || strings.Contains(got, "p1100=") {
		t.Errorf("param cap: %q", got)
	}
	got = r.srv.redactQuery("q=" + strings.Repeat("a", 100000))
	if !strings.Contains(got, "[truncated]") || len(got) > maxQueryLen+len("[truncated]") {
		t.Errorf("value cap: %d bytes", len(got))
	}
}
