package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"attackbox/internal/telemetry"
	sdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestTracingRejectsClientAuthorityAndJoinsEvidence(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	p := sdk.NewTracerProvider(sdk.WithSpanProcessor(rec))
	defer p.Shutdown(context.Background())
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.FullEvidence = true; c.Tracer = p.Tracer("test") })
	req := httptest.NewRequest("POST", "/v1/chat/completions?password=top-secret", strings.NewReader(`{"model":"top-secret","messages":[{"role":"user","content":"top-secret"}]}`))
	req.Header.Set("traceparent", "00-11111111111111111111111111111111-2222222222222222-00")
	req.Header.Set("tracestate", "evil=top-secret")
	req.Header.Set("baggage", "password=top-secret")
	req.Header.Set("Authorization", "Bearer top-secret")
	tid, _ := trace.TraceIDFromHex("11111111111111111111111111111111")
	sid, _ := trace.SpanIDFromHex("2222222222222222")
	req = req.WithContext(trace.ContextWithRemoteSpanContext(req.Context(), trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, Remote: true})))
	w := httptest.NewRecorder()
	r.srv.Handler().ServeHTTP(w, req)
	var root sdk.ReadOnlySpan
	for _, s := range rec.Ended() {
		if s.Name() == "bait.request" {
			root = s
		}
		b, _ := json.Marshal(s.Attributes())
		if strings.Contains(string(b), "top-secret") {
			t.Fatal("span leaked sensitive request")
		}
	}
	if root == nil || root.Parent().IsValid() || root.SpanContext().TraceID() == tid || !root.SpanContext().IsSampled() {
		t.Fatal("attacker selected trace authority")
	}
	count := 0
	for _, e := range r.sink.stream(telemetry.StreamEdge) {
		if e.RequestID != "" {
			count++
			if e.Attrs["trace.id"] != root.SpanContext().TraceID().String() || e.Attrs["span.id"] != root.SpanContext().SpanID().String() {
				t.Fatalf("missing trace join: %s", e.Action)
			}
		}
	}
	if count < 4 {
		t.Fatal("missing evidence")
	}
}
func TestTracingUnknownMethodAndPathStayBounded(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	p := sdk.NewTracerProvider(sdk.WithSpanProcessor(rec))
	defer p.Shutdown(context.Background())
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.Tracer = p.Tracer("test") })
	req := httptest.NewRequest("SECRET", "/credential-in-path", nil)
	r.srv.Handler().ServeHTTP(httptest.NewRecorder(), req)
	for _, s := range rec.Ended() {
		b, _ := json.Marshal(s.Attributes())
		if strings.Contains(string(b), "credential-in-path") || strings.Contains(string(b), "SECRET") {
			t.Fatal(string(b))
		}
	}
}

func TestDisabledTracingDiscardsInheritedIdentity(t *testing.T) {
	r := newRig(t, PersonaOpenAI)
	tid, _ := trace.TraceIDFromHex("11111111111111111111111111111111")
	sid, _ := trace.SpanIDFromHex("2222222222222222")
	req := httptest.NewRequest("GET", "/v1/models", nil)
	req = req.WithContext(trace.ContextWithRemoteSpanContext(req.Context(), trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, Remote: true})))
	r.h.ServeHTTP(httptest.NewRecorder(), req)
	for _, e := range r.sink.stream(telemetry.StreamEdge) {
		if _, ok := e.Attrs["trace.id"]; ok {
			t.Fatal("disabled tracing retained inherited trace")
		}
	}
}
func TestHoldSpanRepresentsActualWait(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	p := sdk.NewTracerProvider(sdk.WithSpanProcessor(rec))
	defer p.Shutdown(context.Background())
	tr := p.Tracer("test")
	r := newRig(t, PersonaOpenAI, func(c *Config) {
		c.Tracer = tr
		c.After = func(time.Duration) <-chan time.Time { ch := make(chan time.Time, 1); ch <- time.Now(); return ch }
	})
	ctx, parent := tr.Start(context.Background(), "bait.request")
	c := &call{s: r.srv, r: httptest.NewRequest("GET", "/", nil).WithContext(ctx)}
	if !c.wait(time.Millisecond, time.Millisecond, nil) {
		t.Fatal("wait failed")
	}
	parent.End()
	for _, s := range rec.Ended() {
		if s.Name() == "bait.hold" {
			if s.Parent().SpanID() != parent.SpanContext().SpanID() {
				t.Fatal("wrong hold parent")
			}
			return
		}
	}
	t.Fatal("missing hold span")
}
