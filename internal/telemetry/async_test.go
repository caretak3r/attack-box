package telemetry

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// stallWriter blocks every Write until release is closed.
type stallWriter struct {
	release chan struct{}
	mu      sync.Mutex
	buf     bytes.Buffer
}

func (w *stallWriter) Write(p []byte) (int, error) {
	<-w.release
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

// syncRecorder is a recorder safe for concurrent use.
type syncRecorder struct {
	mu sync.Mutex
	r  recorder
}

func (s *syncRecorder) Emit(e Event) { s.mu.Lock(); s.r.Emit(e); s.mu.Unlock() }
func (s *syncRecorder) Count(n string, v float64, a map[string]string) {
	s.mu.Lock()
	s.r.Count(n, v, a)
	s.mu.Unlock()
}
func (s *syncRecorder) Gauge(n string, v float64, a map[string]string) {
	s.mu.Lock()
	s.r.Gauge(n, v, a)
	s.mu.Unlock()
}

func TestAsyncStalledLocalDoesNotBlockFanOut(t *testing.T) {
	w := &stallWriter{release: make(chan struct{})}
	local := NewAsync(NewJSONLog(w), 2)
	second := &syncRecorder{}
	m := Multi{local, second}

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				m.Emit(Event{Action: "x"})
				m.Count("attackbox.requests", 1, nil)
				m.Gauge("attackbox.sessions", 1, nil)
			}()
		}
		wg.Wait()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stalled local writer blocked the request path")
	}
	second.mu.Lock()
	ev, ms := len(second.r.events), len(second.r.counts)
	second.mu.Unlock()
	if ev != 8 || ms != 16 {
		t.Errorf("second sink got %d events, %d metrics", ev, ms)
	}
	// 24 items, queue of 2, one more held by the stalled writer.
	if d := local.Dropped(); d < 21 {
		t.Errorf("dropped = %d, want >= 21", d)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := local.Close(ctx); err == nil || !strings.Contains(err.Error(), "drain") {
		t.Errorf("Close on a stalled writer = %v", err)
	}
	close(w.release)
	if err := local.Close(context.Background()); err == nil || !strings.Contains(err.Error(), "dropped") {
		t.Errorf("Close after drops = %v", err)
	}
}

func TestAsyncDeliversInOrderAndOwnsMaps(t *testing.T) {
	var buf bytes.Buffer
	local := NewAsync(NewJSONLog(&buf), 0)
	attrs := map[string]any{"k": "first"}
	local.Emit(Event{Action: "a", Attrs: attrs})
	attrs["k"] = "mutated"
	labels := map[string]string{"persona": "vllm"}
	local.Count("attackbox.requests", 1, labels)
	labels["persona"] = "ollama"
	local.Gauge("attackbox.sessions", 2, nil)
	if err := local.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	ia, ic, ig := strings.Index(out, `"action":"a"`), strings.Index(out, `"type":"count"`), strings.Index(out, `"type":"gauge"`)
	if ia < 0 || ic < ia || ig < ic {
		t.Errorf("order wrong:\n%s", out)
	}
	if !strings.Contains(out, `"first"`) || strings.Contains(out, "mutated") || strings.Contains(out, "ollama") {
		t.Errorf("caller map mutation reached the log:\n%s", out)
	}
	local.Emit(Event{Action: "late"})
	if local.Dropped() != 1 || strings.Contains(buf.String(), "late") {
		t.Error("post-Close item not dropped")
	}
}
