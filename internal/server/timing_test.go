package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var testTiming = Timing{
	FirstToken:    300 * time.Millisecond,
	PerChunk:      100 * time.Millisecond,
	SentencePause: 50 * time.Millisecond,
	Jitter:        0.2,
	MaxTotal:      10 * time.Second,
}

// withTiming turns pacing on with a fixed jitter draw of 0.75, which scales
// every delay by 1+0.2*(2*0.75-1) = 1.1.
func withTiming(t Timing) func(*Config) {
	return func(c *Config) {
		c.Timing = t
		c.Rand = func() float64 { return 0.75 }
	}
}

// sseDeltas returns the content of each chat.completion.chunk delta.
func sseDeltas(t *testing.T, body string) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(body, "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok || data == "[DONE]" {
			continue
		}
		var ch struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &ch); err != nil {
			t.Fatalf("bad frame %q: %v", data, err)
		}
		if len(ch.Choices) == 1 && ch.Choices[0].Delta.Content != "" {
			out = append(out, ch.Choices[0].Delta.Content)
		}
	}
	return out
}

func ms(n float64) time.Duration { return time.Duration(n * float64(time.Millisecond)) }

// expected is the wait sequence testTiming gives for deltas at jitter 1.1.
func expected(deltas []string) []time.Duration {
	want := []time.Duration{ms(330)}
	for _, d := range deltas[:len(deltas)-1] {
		w := ms(110)
		if endsSentence(d) {
			w += ms(55)
		}
		want = append(want, w)
	}
	return want
}

func TestTimingStreamPacing(t *testing.T) {
	r := newRig(t, PersonaOpenAI, withTiming(testTiming))
	rec := r.do("POST", "/v1/chat/completions", `{"model":"qwen3:8b","stream":true,"messages":[{"role":"user","content":"hello there"}]}`)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	deltas := sseDeltas(t, rec.Body.String())
	if len(deltas) < 3 {
		t.Fatalf("want a multi-delta reply to pace, got %q", deltas)
	}
	sentences := 0
	for _, d := range deltas[:len(deltas)-1] {
		if endsSentence(d) {
			sentences++
		}
	}
	if sentences == 0 {
		t.Fatalf("reply has no inner sentence end; the sentence pause is untested: %q", deltas)
	}
	got, want := r.clk.recorded(), expected(deltas)
	if len(got) != len(want) {
		t.Fatalf("waits = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("wait %d = %v, want %v (all %v)", i, got[i], want[i], got)
		}
	}
	if e := r.sink.lastEdge(t); e.Attrs["stream_result"] != nil {
		t.Fatalf("completed stream logged stream_result %v", e.Attrs["stream_result"])
	}
}

// TestTimingNonStreamWaitsOnce checks that a whole reply waits once, for the
// same time its stream would take.
func TestTimingNonStreamWaitsOnce(t *testing.T) {
	r := newRig(t, PersonaOpenAI, withTiming(testTiming))
	rec := r.do("POST", "/v1/chat/completions", chatBody)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var body struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Choices) != 1 {
		t.Fatalf("body %s: %v", rec.Body, err)
	}
	var total time.Duration
	for _, w := range expected(wordChunks(body.Choices[0].Message.Content, wordsPerChunk)) {
		total += w
	}
	if got := r.clk.recorded(); len(got) != 1 || got[0] != total {
		t.Fatalf("waits = %v, want one wait of %v", got, total)
	}
}

// TestTimingBudget checks that MaxTotal bounds the summed delays of a reply.
func TestTimingBudget(t *testing.T) {
	tm := Timing{FirstToken: 300 * time.Millisecond, PerChunk: 100 * time.Millisecond, MaxTotal: 450 * time.Millisecond}
	r := newRig(t, PersonaOllama, withTiming(tm))
	rec := r.do("POST", "/api/chat", `{"model":"qwen3:8b","messages":[{"role":"user","content":"hello there"}]}`)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if n := strings.Count(rec.Body.String(), "\n"); n < 4 {
		t.Fatalf("want at least three deltas plus the final line, got %d lines", n)
	}
	var sum time.Duration
	got := r.clk.recorded()
	for _, w := range got {
		sum += w
	}
	// 300 first, 100 after delta one, then only the 50 left in the budget.
	want := []time.Duration{300 * time.Millisecond, 100 * time.Millisecond, 50 * time.Millisecond}
	if sum != tm.MaxTotal || len(got) < len(want) {
		t.Fatalf("waits = %v (sum %v), want sum %v", got, sum, tm.MaxTotal)
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("wait %d = %v, want %v", i, got[i], w)
		}
	}
}

// TestTimingCutBeforeFirstToken checks that a client that leaves during the
// first-token wait gets no response and is logged as client_closed.
func TestTimingCutBeforeFirstToken(t *testing.T) {
	r := newRig(t, PersonaOpenAI, withTiming(testTiming))
	r.clk.setGate(make(chan time.Time)) // waits never end on their own
	ctx, cancel := context.WithCancel(context.Background())
	req := request("POST", "/v1/chat/completions", `{"model":"qwen3:8b","stream":true,"messages":[{"role":"user","content":"hello there"}]}`).WithContext(ctx)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		r.h.ServeHTTP(rec, req)
		close(done)
	}()
	r.clk.waitEntered(t, 1)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not stop after the client left")
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("frames written after cut: %q", rec.Body.String())
	}
	if e := r.sink.lastEdge(t); e.Attrs["stream_result"] != "client_closed" {
		t.Fatalf("stream_result = %v", e.Attrs["stream_result"])
	}
}

// TestTimingOffByDefault checks that the zero Timing never waits.
func TestTimingOffByDefault(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	if rec := r.do("POST", "/v1/chat/completions", `{"model":"qwen3:8b","stream":true,"messages":[{"role":"user","content":"hello there"}]}`); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if got := r.clk.recorded(); len(got) != 0 {
		t.Fatalf("zero Timing waited %v", got)
	}
}

func TestTimingValidation(t *testing.T) {
	for name, tm := range map[string]Timing{
		"negative":  {PerChunk: -time.Millisecond},
		"jitter":    {PerChunk: time.Millisecond, Jitter: 0.6},
		"unbounded": {PerChunk: time.Millisecond, MaxTotal: 2 * time.Minute},
	} {
		if _, err := New(Config{Responder: newRig(t, PersonaOpenAI).srv.cfg.Responder, Timing: tm}); err == nil {
			t.Errorf("%s: New accepted %+v", name, tm)
		}
	}
	s, err := New(Config{Responder: newRig(t, PersonaOpenAI).srv.cfg.Responder, Timing: Timing{PerChunk: time.Millisecond}})
	if err != nil || s.cfg.Timing.MaxTotal != 12*time.Second {
		t.Fatalf("default budget: %v %v", s.cfg.Timing.MaxTotal, err)
	}
	if d := DefaultTiming(); d.FirstToken < 200*time.Millisecond || d.FirstToken > 500*time.Millisecond || d.Jitter != 0.2 {
		t.Fatalf("DefaultTiming outside the researched range: %+v", d)
	}
}

// TestPacerJitterBounds checks that any draw keeps each delay within
// base*(1±Jitter), clamps out-of-range draws and never overspends.
func TestPacerJitterBounds(t *testing.T) {
	for _, draw := range []float64{-1, 0, 0.5, 0.999, 2} {
		p := &pacer{t: Timing{Jitter: 0.2}, rnd: func() float64 { return draw }, budget: time.Hour}
		d := p.next(time.Second)
		if d < 800*time.Millisecond || d > 1200*time.Millisecond {
			t.Fatalf("draw %v: delay %v outside ±20%%", draw, d)
		}
	}
	p := &pacer{t: Timing{}, rnd: func() float64 { return 0 }, budget: 250 * time.Millisecond}
	if a, b, c := p.next(200*time.Millisecond), p.next(200*time.Millisecond), p.next(200*time.Millisecond); a+b+c != 250*time.Millisecond || c != 0 {
		t.Fatalf("budget spend = %v %v %v", a, b, c)
	}
	for in, want := range map[string]bool{"end. ": true, "why? ": true, `"go!" `: true, "on and on ": false, "is incomplete. Resubmit with ": true, "v1.2 build ": false, "e.g": false} {
		if endsSentence(in) != want {
			t.Errorf("endsSentence(%q) = %v", in, !want)
		}
	}
}
