package responder

import (
	"strings"
	"testing"
	"time"
)

func TestStoreGetNotBlockedBySlowSession(t *testing.T) {
	r, _ := newTest(t)
	slow, _ := r.store.Get("slow")
	slow.mu.Lock()
	defer slow.mu.Unlock()
	go r.store.Get("slow")
	time.Sleep(20 * time.Millisecond)
	done := make(chan struct{})
	go func() { r.store.Get("other"); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Get for another source blocked on a busy session")
	}
}

func TestSanitizeBoundsInputBeforeScrub(t *testing.T) {
	longest := 0
	r := New(Config{Fingerprint: func(v string) string {
		longest = max(longest, len(v))
		return "hmac256:0123456789abcdef"
	}}, NewStore(StoreConfig{}))
	got := r.sanitize("password=" + strings.Repeat("x", 1<<20))
	if longest > 8<<10 {
		t.Errorf("scrub saw a %d byte value", longest)
	}
	if len(got) > maxDeclValue || strings.Contains(got, "xxxx") {
		t.Errorf("sanitized %q", got)
	}
}
