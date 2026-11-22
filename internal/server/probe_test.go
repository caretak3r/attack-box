package server

import (
	"strings"
	"sync"
	"testing"
	"time"

	"attackbox/internal/responder"
	"attackbox/internal/telemetry"
)

// stepClock is a shared server and session-store clock that tests move forward.
type stepClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *stepClock) add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func lastProbe(t *testing.T, m *memSink) telemetry.Event {
	t.Helper()
	ev := m.stream(telemetry.StreamProbe)
	if len(ev) == 0 {
		t.Fatal("no probe event")
	}
	return ev[len(ev)-1]
}

func sum(cs []count) (total float64) {
	for _, c := range cs {
		total += c.value
	}
	return total
}

// TestProbeStream walks one session through registration and the retry gate
// and checks the probe records and the session/probe metrics they feed.
func TestProbeStream(t *testing.T) {
	clk := &stepClock{now: fixedNow}
	store := responder.NewStore(responder.StoreConfig{Now: clk.Now})
	r := newRig(t, PersonaOpenAI, func(c *Config) {
		c.Responder = responder.New(responder.Config{}, store)
		c.Now = clk.Now
	})
	r.store = store

	var reqBytes, respBytes int
	send := func(body string) int {
		rec := r.do("POST", "/v1/chat/completions", body)
		reqBytes += len(body)
		respBytes += rec.Body.Len()
		return rec.Code
	}

	send(chatBody)
	// The behavioral gate is drawn at session creation; pin it after the
	// first request so the session is created by the request, not the test.
	r.pin("retry")
	sess, _ := store.Get(r.srv.sessionKey("192.0.2.10", testUA, nil))
	p := lastProbe(t, r.sink)
	if p.Action != "decision" || p.ProbeID != "register-model" || p.SessionID != sess.ID || p.Status != 200 {
		t.Fatalf("first probe event = %+v", p)
	}
	if p.Attrs["nonce"] != sess.Nonce || p.Attrs["ticket"] != sess.Ticket || p.Attrs["behavior"] == "" ||
		p.Attrs["new_session"] != true || p.Attrs["session_age_ms"] != int64(0) {
		t.Fatalf("first probe attrs = %v", p.Attrs)
	}
	if _, ok := p.Attrs["followup"]; ok {
		t.Fatalf("first request scored as a follow-up: %v", p.Attrs)
	}
	edge := r.sink.lastEdge(t)
	for _, k := range []string{"declarations", "observations", "nonce"} {
		if _, ok := edge.Attrs[k]; ok {
			t.Fatalf("edge carries probe attr %q: %v", k, edge.Attrs)
		}
	}

	clk.add(2 * time.Second)
	send(strings.Replace(chatBody, `"model"`, `"metadata":{"client_model":"acme/coder-2.1"},"model"`, 1))
	p = lastProbe(t, r.sink)
	if p.Attrs["followup"] != "register-model" || p.Attrs["new_session"] != false || p.Attrs["session_age_ms"] != int64(2000) {
		t.Fatalf("second probe attrs = %v", p.Attrs)
	}
	decls, _ := p.Attrs["declarations"].([]responder.Declaration)
	if len(decls) != 1 || decls[0].Field != "client_model" || decls[0].Value != "acme/coder-2.1" {
		t.Fatalf("declarations = %+v", decls)
	}
	obs, _ := p.Attrs["observations"].([]responder.Observation)
	if len(obs) != 1 || obs[0].ProbeID != "register-model" || obs[0].DelayMS != 2000 || obs[0].Result["complied"] != "true" {
		t.Fatalf("observations = %+v", obs)
	}

	if code := send(chatBody); code != 429 {
		t.Fatalf("retry gate status %d", code)
	}
	p = lastProbe(t, r.sink)
	if p.ProbeID != "retry" || p.Attrs["probe_status"] != 429 || p.Attrs["retry_after"] != 1 || p.Result != "rate_limited" {
		t.Fatalf("retry probe event = %+v", p)
	}

	clk.add(1500 * time.Millisecond)
	send(chatBody)
	if p = lastProbe(t, r.sink); p.Attrs["followup"] != "retry" {
		t.Fatalf("retry follow-up attrs = %v", p.Attrs)
	}

	if s := r.sink.metric("attackbox.sessions", false); len(s) != 1 || s[0].attrs["persona"] != PersonaOpenAI {
		t.Fatalf("sessions = %v", s)
	}
	followups := map[string]int{}
	for _, c := range r.sink.metric("attackbox.probe_followups", false) {
		followups[c.attrs["probe_id"]]++
	}
	want := map[string]int{"register-model": 1, "register-harness": 1, "retry": 1}
	if len(followups) != len(want) {
		t.Fatalf("probe_followups = %v, want %v", followups, want)
	}
	for k, n := range want {
		if followups[k] != n {
			t.Fatalf("probe_followups = %v, want %v", followups, want)
		}
	}
	if g := r.sink.metric("attackbox.retry_delay_seconds", true); len(g) != 1 || g[0].value != 1.5 {
		t.Fatalf("retry_delay_seconds = %v", g)
	}
	ages := r.sink.metric("attackbox.session_duration_seconds", true)
	if len(ages) != 4 || ages[0].value != 0 || ages[len(ages)-1].value != 3.5 {
		t.Fatalf("session_duration_seconds = %v", ages)
	}
	if got := sum(r.sink.metric("attackbox.request_bytes", false)); got != float64(reqBytes) {
		t.Fatalf("request_bytes = %v, want %d", got, reqBytes)
	}
	if got := sum(r.sink.metric("attackbox.response_bytes", false)); got != float64(respBytes) {
		t.Fatalf("response_bytes = %v, want %d", got, respBytes)
	}
	if g := r.sink.metric("attackbox.stream_disconnect_seconds", true); len(g) != 0 {
		t.Fatalf("disconnect gauge without a disconnect: %v", g)
	}
}

// TestNoProbeEventWithoutProbe checks that plain routes write no probe record.
func TestNoProbeEventWithoutProbe(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	r.do("GET", "/v1/models", "")
	r.do("GET", "/nope", "")
	if ev := r.sink.stream(telemetry.StreamProbe); len(ev) != 0 {
		t.Fatalf("probe events for non-inference routes: %+v", ev)
	}
	if s := r.sink.metric("attackbox.sessions", false); len(s) != 0 {
		t.Fatalf("sessions counted without a decision: %v", s)
	}
}
