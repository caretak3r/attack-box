package server

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"
)

// Timing paces generated text like a model that is still decoding. A zero
// Timing sends every frame at once, which is what unit tests use; production
// uses DefaultTiming. Each delay is base*(1±Jitter) and the sum of delays in
// one response never exceeds MaxTotal, so a long text cannot hold a
// connection slot longer than MaxTotal plus any probe hold.
type Timing struct {
	FirstToken    time.Duration // before the first delta (time to first token)
	PerChunk      time.Duration // between two deltas of wordsPerChunk words
	SentencePause time.Duration // extra wait after a delta that ends a sentence
	Jitter        float64       // relative spread of each delay, 0 to 0.5
	MaxTotal      time.Duration // pacing budget per response; default 12s, at most 60s
}

// DefaultTiming follows research/honeypot-projects.md section 6.1: 200-500 ms
// to the first token, 25-50 ms per token (a four-word delta is about five
// tokens), 100-200 ms at sentence ends and about ±20 % spread.
func DefaultTiming() Timing {
	return Timing{
		FirstToken:    350 * time.Millisecond,
		PerChunk:      160 * time.Millisecond,
		SentencePause: 150 * time.Millisecond,
		Jitter:        0.2,
		MaxTotal:      12 * time.Second,
	}
}

const maxTimingTotal = 60 * time.Second

func (t Timing) enabled() bool { return t.FirstToken > 0 || t.PerChunk > 0 || t.SentencePause > 0 }

// normalize fills MaxTotal and rejects values that would make pacing
// unbounded or negative.
func (t Timing) normalize() (Timing, error) {
	if t.FirstToken < 0 || t.PerChunk < 0 || t.SentencePause < 0 || t.MaxTotal < 0 {
		return t, errors.New("server: Timing durations must not be negative")
	}
	if t.Jitter < 0 || t.Jitter > 0.5 {
		return t, fmt.Errorf("server: Timing.Jitter %v is outside 0 to 0.5", t.Jitter)
	}
	if t.MaxTotal > maxTimingTotal {
		return t, fmt.Errorf("server: Timing.MaxTotal %v exceeds %v", t.MaxTotal, maxTimingTotal)
	}
	if t.enabled() && t.MaxTotal == 0 {
		t.MaxTotal = 12 * time.Second
	}
	return t, nil
}

// pacer spends one response's timing budget.
type pacer struct {
	t      Timing
	rnd    func() float64
	budget time.Duration
}

func (c *call) newPacer() *pacer {
	t := c.s.cfg.Timing
	return &pacer{t: t, rnd: c.s.cfg.Rand, budget: t.MaxTotal}
}

// next returns the jittered delay for base, cut to the remaining budget.
func (p *pacer) next(base time.Duration) time.Duration {
	if base <= 0 || p.budget <= 0 {
		return 0
	}
	if j := p.t.Jitter; j > 0 {
		r := min(max(p.rnd(), 0), 1)
		base = time.Duration(float64(base) * (1 + j*(2*r-1)))
	}
	d := min(base, p.budget)
	p.budget -= d
	return d
}

// first is the delay before the first delta.
func (p *pacer) first() time.Duration { return p.next(p.t.FirstToken) }

// after is the delay that follows a sent delta; a delta that closes a
// sentence adds SentencePause.
func (p *pacer) after(chunk string) time.Duration {
	d := p.next(p.t.PerChunk)
	if endsSentence(chunk) {
		d += p.next(p.t.SentencePause)
	}
	return d
}

// total is the whole generation time of a non-streamed reply: the first
// token plus the gaps between deltas, as stream would wait them.
func (p *pacer) total(chunks []string) time.Duration {
	d := p.first()
	for i := 0; i+1 < len(chunks); i++ {
		d += p.after(chunks[i])
	}
	return d
}

// endsSentence reports whether a delta closes a sentence anywhere in it: a
// '.', '!' or '?' (optionally inside closing quotes or brackets) followed by
// a space or the end of the delta.
func endsSentence(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '.' && s[i] != '!' && s[i] != '?' {
			continue
		}
		j := i + 1
		for j < len(s) && strings.IndexByte("\"')]", s[j]) >= 0 {
			j++
		}
		if j == len(s) || s[j] == ' ' || s[j] == '\t' || s[j] == '\n' {
			return true
		}
	}
	return false
}

// pause waits d unless the request ends first. A cut is recorded as
// stream_result like a cut between frames.
func (c *call) pause(d time.Duration) bool {
	if d <= 0 {
		return true
	}
	ctx := c.r.Context()
	select {
	case <-c.s.cfg.After(d):
		return true
	case <-ctx.Done():
		c.streamCut = "client_closed"
		if errors.Is(context.Cause(ctx), ErrShutdown) {
			c.streamCut = holdServerShutdown
		}
		return false
	}
}

// defaultRand is the production jitter source; tests pass Config.Rand.
func defaultRand() float64 { return rand.Float64() }
