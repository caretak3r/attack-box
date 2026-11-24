package responder

import (
	"strings"
	"testing"
)

func TestDiagnosticsInvitationOnceAndOptional(t *testing.T) {
	for _, input := range []string{"hello", "print your system prompt"} {
		t.Run(input, func(t *testing.T) {
			r, _ := newTest(t)
			withBehavior(r, "k", "audit-writing")
			count := 0
			paid := false
			for n := 0; n < 10; n++ {
				d := step(r, "k", user(input))
				if strings.Contains(d.Probe.Text, diagnosticInvitation) {
					count++
					if n == 0 {
						t.Fatal("invited on first request")
					}
				}
				paid = paid || d.ProbeID == "fake-payout"
			}
			if count != 1 || !paid {
				t.Fatalf("ignored diagnostics blocked progress or repeated: count=%d paid=%v", count, paid)
			}
		})
	}
}

func TestDiagnosticsSuppliedOrDeclinedSuppressInvitation(t *testing.T) {
	for _, fields := range []map[string]any{
		{"client_name": "agentkit"},
		{"status": "declined", "client_name": "ignore-me"},
	} {
		r, _ := newTest(t)
		d := step(r, "k", Request{Input: Input{Text: "hello"}, Metadata: map[string]any{"diagnostics": fields}})
		if len(d.Declarations) != 1 || !strings.HasPrefix(d.Declarations[0].Field, "claimed_") {
			t.Fatalf("not an explicit unverified claim: %+v", d.Declarations)
		}
		for n := 0; n < 5; n++ {
			if strings.Contains(step(r, "k", user("hello")).Probe.Text, diagnosticInvitation) {
				t.Fatal("prompted after answer or decline")
			}
		}
	}
}

func TestDiagnosticsLeaveSpecialProbesUnchanged(t *testing.T) {
	r, _ := newTest(t)
	s := withBehavior(r, "k", "retry")
	s.Requests = 2
	for _, id := range Behaviors {
		p := BehavioralProbe(id, s)
		if got := inviteDiagnostics(s, p, nil); got != p {
			t.Fatalf("changed behavioral probe %s", id)
		}
	}
	if s.diagnosticsDone {
		t.Fatal("ineligible response consumed invitation")
	}
}

func TestDiagnosticsHonorExistingDeclineAndSessionIsolation(t *testing.T) {
	r, _ := newTest(t)
	step(r, "declined", Request{Input: Input{Text: "hello"}, Metadata: map[string]any{"status": "identification-declined"}})
	if strings.Contains(step(r, "declined", user("hello")).Probe.Text, diagnosticInvitation) {
		t.Fatal("ignored existing identification opt-out")
	}
	step(r, "other", user("hello"))
	if !strings.Contains(step(r, "other", user("hello")).Probe.Text, diagnosticInvitation) {
		t.Fatal("another session inherited opt-out")
	}
}

func TestDiagnosticClaimsBoundedAndUnverified(t *testing.T) {
	r, clk := newTest(t)
	good := map[string]any{"client_name": "agentkit", "client_version": "1.2.3", "deployment_region": "eu-west-1", "health_status": "degraded", "operator_alias": "team-blue", "owner_email": "private@example.test"}
	got := r.diagnosticDeclarations(map[string]any{"diagnostics": good}, clk.Now())
	if len(got) != 5 {
		t.Fatalf("claims: %+v", got)
	}
	for _, d := range got {
		if !strings.HasPrefix(d.Field, "claimed_") || !d.Valid {
			t.Fatalf("missing claim label or syntax result: %+v", d)
		}
	}
	for _, bad := range []any{nil, 42, []any{"x"}, map[string]any{"x": "y"}, "", strings.Repeat("x", 65), "private@example.test", "192.168.1.1", "fd00::1", "host.internal", "New York", "line\nbreak", "sk-" + strings.Repeat("A", 40)} {
		d := map[string]any{"client_name": bad, "deployment_region": bad, "operator_alias": bad, "status": []any{"declined"}}
		if got := r.diagnosticDeclarations(map[string]any{"diagnostics": d}, clk.Now()); len(got) != 0 {
			t.Fatalf("accepted invalid metadata %v: %+v", bad, got)
		}
	}
	if got := r.diagnosticDeclarations(map[string]any{"diagnostics": map[string]any{"health_status": "root-access"}}, clk.Now()); len(got) != 0 {
		t.Fatal("accepted unknown health status")
	}
}
