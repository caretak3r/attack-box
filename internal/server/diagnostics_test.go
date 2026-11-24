package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"attackbox/internal/responder"
	"attackbox/internal/telemetry"
	sdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestOptionalDiagnosticsResponseAndClaimsCaptured(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			spans := tracetest.NewSpanRecorder()
			provider := sdk.NewTracerProvider(sdk.WithSpanProcessor(spans))
			defer provider.Shutdown(context.Background())
			r := newRig(t, PersonaOpenAI, func(c *Config) { c.FullEvidence = true; c.Tracer = provider.Tracer("test") })
			r.do("POST", "/v1/chat/completions", chatBody)
			r.pin("audit-writing")
			body := fmt.Sprintf(`{"model":"qwen3:8b","stream":%t,"messages":[{"role":"user","content":"hello"}]}`, stream)
			w := r.do("POST", "/v1/chat/completions", body)
			text := w.Body.String()
			if stream {
				text = strings.Join(sseDeltas(t, text), "")
			}
			if w.Code != 200 || !strings.Contains(text, "Optional compatibility diagnostics") {
				t.Fatalf("missing invitation: %d %s", w.Code, w.Body)
			}
			probe := lastProbe(t, r.sink)
			only := &memSink{}
			for _, e := range r.sink.stream(telemetry.StreamEdge) {
				if e.RequestID == probe.RequestID {
					only.Emit(e)
				}
			}
			captured, manifest := evidenceBody(t, only, "response_body")
			if string(captured) != w.Body.String() || manifest.Attrs["evidence_complete"] != true ||
				manifest.Attrs["trace.id"] == nil || manifest.Attrs["trace.id"] != probe.Attrs["trace.id"] {
				t.Fatal("response capture incomplete or trace join missing")
			}
			found := false
			for _, s := range spans.Ended() {
				found = found || s.SpanContext().TraceID().String() == manifest.Attrs["trace.id"]
			}
			if !found {
				t.Fatal("capture trace does not exist")
			}
			w = r.do("POST", "/v1/chat/completions", `{"model":"qwen3:8b","messages":[{"role":"user","content":"hello again"}],"metadata":{"diagnostics":{"client_name":"agentkit","client_version":"1.2.3","deployment_region":"eu-west-1","health_status":"healthy","operator_alias":"team-blue"}}}`)
			probe = lastProbe(t, r.sink)
			claims, ok := probe.Attrs["declarations"].([]responder.Declaration)
			if w.Code != 200 || !ok || len(claims) != 5 || strings.Contains(w.Body.String(), "Optional compatibility diagnostics") {
				t.Fatalf("claims missing or invitation repeated: %+v", probe)
			}
			for _, claim := range claims {
				if !strings.HasPrefix(claim.Field, "claimed_") {
					t.Fatal("claim presented as verified")
				}
			}
			// Diagnostics must stay out of span labels and metric dimensions.
			for _, s := range spans.Ended() {
				b, _ := json.Marshal(s.Attributes())
				if strings.Contains(string(b), "team-blue") || strings.Contains(string(b), "eu-west-1") {
					t.Fatal("claim leaked into spans")
				}
			}
			for _, metric := range append(append([]count(nil), r.sink.counts...), r.sink.gauges...) {
				b, _ := json.Marshal(metric.attrs)
				if strings.Contains(string(b), "team-blue") || strings.Contains(string(b), "eu-west-1") {
					t.Fatal("claim leaked into metrics")
				}
			}
		})
	}
}
