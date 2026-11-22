package server

import (
	"strings"
	"testing"
	"time"

	"attackbox/internal/responder"
	"attackbox/internal/telemetry"
)

// decisions returns the probe-stream records of answered inference requests.
func decisions(r *rig) []telemetry.Event {
	var out []telemetry.Event
	for _, e := range r.sink.stream(telemetry.StreamProbe) {
		if e.Action == "decision" {
			out = append(out, e)
		}
	}
	return out
}

func observed(e telemetry.Event) []responder.Observation {
	obs, _ := e.Attrs["observations"].([]responder.Observation)
	return obs
}

func TestProbeEventsCarryIssuanceAndDelivery(t *testing.T) {
	streamBody := strings.Replace(chatBody, `"model"`, `"stream":true,"model"`, 1)
	for name, body := range map[string]string{"buffered": chatBody, "stream": streamBody} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, PersonaOpenAI)
			for i := 0; i < 3; i++ {
				if rec := r.do("POST", "/v1/chat/completions", body); rec.Code != 200 {
					t.Fatalf("request %d: status %d", i, rec.Code)
				}
			}
			ev := decisions(r)
			if len(ev) != 3 {
				t.Fatalf("%d decisions, want 3", len(ev))
			}
			seen := map[string]bool{}
			for i, e := range ev {
				id := attr[string](t, e, "issuance")
				if id == "" || seen[id] {
					t.Fatalf("request %d: issuance %q repeated or empty", i, id)
				}
				seen[id] = true
				if d := attr[string](t, e, "delivery"); d != string(responder.DeliveryFull) {
					t.Fatalf("request %d: delivery %q, want %q", i, d, responder.DeliveryFull)
				}
			}
		})
	}
}

func TestRetryProbeIsFullySent(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	r.pin("retry")
	r.warm()
	if rec := r.do("POST", "/v1/chat/completions", chatBody); rec.Code != 429 {
		t.Fatalf("retry gate: status %d", rec.Code)
	}
	ev := decisions(r)
	last := ev[len(ev)-1]
	if last.ProbeID != "retry" || attr[string](t, last, "delivery") != string(responder.DeliveryFull) {
		t.Fatalf("retry gate event: probe %q attrs %v", last.ProbeID, last.Attrs)
	}
}

// TestDisconnectBeforeDeliveryNeverVerifies cuts a held response and checks
// that nothing later is scored as the client's answer to it.
func TestDisconnectBeforeDeliveryNeverVerifies(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	r.pin("timeout-silent")
	r.warm()
	r.clk.setGate(make(chan time.Time)) // never released
	req, cancel := withCancel(request("POST", "/v1/chat/completions", chatBody))
	done := make(chan struct{})
	go func() { r.serve(req); close(done) }()
	r.clk.waitEntered(t, 1)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler ignored the closed connection")
	}
	ev := decisions(r)
	cut := ev[len(ev)-1]
	if cut.ProbeID != "timeout-silent" {
		t.Fatalf("held request was %q", cut.ProbeID)
	}
	// The held body is buffered, so nothing was written before the cut.
	if d := attr[string](t, cut, "delivery"); d != string(responder.DeliveryUnknown) {
		t.Fatalf("a response the client never received is %q, want %q", d, responder.DeliveryUnknown)
	}

	r.clk.setGate(nil)
	for i := 0; i < 3; i++ {
		body := strings.Replace(chatBody, "hello there", "later "+strings.Repeat("x", i+1), 1)
		r.do("POST", "/v1/chat/completions", body)
	}
	for _, e := range decisions(r)[len(ev):] {
		if f, ok := e.Attrs["followup"]; ok {
			t.Fatalf("follow-up %v verified against an undelivered response: %v", f, observed(e))
		}
		for _, o := range observed(e) {
			if o.ProbeID == "timeout-silent" {
				t.Fatalf("undelivered gate scored: %+v", o)
			}
		}
	}
}

// TestOverlappingRequestsKeepOwnIssuance holds one response while a second
// request is served, and checks the second one neither takes the first one's
// issuance nor settles it.
func TestOverlappingRequestsKeepOwnIssuance(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	r.pin("timeout-silent")
	r.warm()
	gate := make(chan time.Time)
	r.clk.setGate(gate)
	held := make(chan struct{})
	go func() {
		r.do("POST", "/v1/chat/completions", chatBody)
		close(held)
	}()
	r.clk.waitEntered(t, 1)
	r.clk.setGate(nil)
	if rec := r.do("POST", "/v1/chat/completions", chatBody); rec.Code != 200 {
		t.Fatalf("overlapping request: status %d", rec.Code)
	}
	close(gate)
	select {
	case <-held:
	case <-time.After(5 * time.Second):
		t.Fatal("held request never finished")
	}
	ev := decisions(r)
	a, b := ev[len(ev)-1], ev[len(ev)-2] // the overlapping request finishes first
	if a.ProbeID != "timeout-silent" {
		a, b = b, a
	}
	if a.ProbeID != "timeout-silent" {
		t.Fatalf("no held gate in %v", ev)
	}
	if attr[string](t, a, "issuance") == attr[string](t, b, "issuance") {
		t.Fatal("overlapping requests share an issuance")
	}
	if a.RequestID == b.RequestID {
		t.Fatal("overlapping requests share a request id")
	}
	if _, ok := b.Attrs["followup"]; ok {
		t.Fatalf("a request admitted before delivery was scored as a reply: %v", observed(b))
	}
	var amb bool
	for _, o := range observed(b) {
		amb = amb || (o.ProbeID == "attribution" && o.Result["status"] == "ambiguous" && o.Result["issuance_id"] == attr[string](t, a, "issuance"))
	}
	if !amb {
		t.Fatalf("the overlapping request must record the ambiguity with the held issuance: %v", observed(b))
	}
}

func TestStatusHitWithoutDeliveredConcurrencyIsUnbound(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	r.pin("concurrency")
	r.warm() // the concurrency gate is next but has not been issued yet
	statusHits := func() []telemetry.Event {
		var out []telemetry.Event
		for _, e := range r.sink.stream(telemetry.StreamProbe) {
			if e.Action == "status_hit" {
				out = append(out, e)
			}
		}
		return out
	}
	for _, label := range []string{"A", "B"} {
		if rec := r.do("GET", "/v1/edge/"+label+"/status", ""); rec.Code != 200 {
			t.Fatalf("status %d", rec.Code)
		}
	}
	hits := statusHits()
	if len(hits) != 2 {
		t.Fatalf("%d status_hit events, want 2", len(hits))
	}
	for _, e := range hits {
		obs := observed(e)
		if len(obs) != 1 {
			t.Fatalf("an unbound hit must still be observed, got %v", obs)
		}
		o := obs[0]
		if o.ProbeID != "concurrency" || o.Result["bound"] != "false" || o.Result["reason"] != "no_delivered_issuance" {
			t.Fatalf("status hit bound to nothing delivered: %v", o.Result)
		}
		if o.Result["active"] != "" || o.Result["peak"] != "" {
			t.Fatalf("an unbound hit must not feed the peak: %v", o.Result)
		}
	}
	if g := r.sink.metric("attackbox.concurrent_status_requests", true); len(g) != 0 {
		t.Fatalf("unbound hits fed the concurrency gauge: %v", g)
	}

	// Once the gate is fully sent, the next hit binds to that issuance.
	if rec := r.do("POST", "/v1/chat/completions", chatBody); rec.Code != 200 {
		t.Fatalf("gate request: status %d", rec.Code)
	}
	ev := decisions(r)
	gate := ev[len(ev)-1]
	if gate.ProbeID != "concurrency" {
		t.Fatalf("gate was %q", gate.ProbeID)
	}
	r.do("GET", "/v1/edge/A/status", "")
	r.do("GET", "/v1/edge/A/status", "") // a repeated label is never counted twice
	hits = statusHits()
	bound, dup := observed(hits[2])[0], observed(hits[3])[0]
	if bound.Result["bound"] != "true" || bound.Result["issuance_id"] != attr[string](t, gate, "issuance") {
		t.Fatalf("a hit after delivery must bind to the gate's issuance: %v", bound.Result)
	}
	if dup.Result["bound"] != "false" || dup.Result["reason"] != "duplicate_label" {
		t.Fatalf("a repeated label: %v", dup.Result)
	}
}

func TestParseRecordsRolesAndToolMessages(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	body := `{"model":"m","messages":[` +
		`{"role":"system","content":"sys"},` +
		`{"role":"user","content":[{"type":"text","text":"u1"},{"type":"text","text":"u2"}]},` +
		`{"role":"assistant","content":"a1"},` +
		`{"role":"tool","content":"t1"},` +
		`{"role":"function","content":"f1"}]}`
	p, err := r.srv.parseInference(&call{body: []byte(body)}, kindChat)
	if err != nil {
		t.Fatal(err)
	}
	want := []responder.Message{
		{Role: "system", Text: "sys"},
		{Role: "user", Text: "u1\nu2"},
		{Role: "assistant", Text: "a1"},
		{Role: "tool", Text: "t1"},
		{Role: "tool", Text: "f1"},
	}
	if len(p.req.Messages) != len(want) {
		t.Fatalf("messages = %+v", p.req.Messages)
	}
	for i, m := range want {
		if p.req.Messages[i] != m {
			t.Fatalf("message %d = %+v, want %+v", i, p.req.Messages[i], m)
		}
	}
	if p.req.Untrusted != "t1\nf1" || strings.Contains(p.req.Text, "a1") {
		t.Fatalf("untrusted %q text %q", p.req.Untrusted, p.req.Text)
	}
}
