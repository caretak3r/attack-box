package main

import (
	"context"
	"strings"
	"testing"

	"attackbox/internal/observability"
	"attackbox/internal/shipper"
	sdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestExportSpanIndependentAndNoEvidencePayload(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	p := sdk.NewTracerProvider(sdk.WithSpanProcessor(rec))
	defer p.Shutdown(context.Background())
	tr := p.Tracer("test")
	ctx, parent := tr.Start(context.Background(), "unrelated-request")
	ctx = observability.WithTracer(ctx, tr)
	e := &fakeEvidence{}
	n, blocked, err := deliver(ctx, e, []shipper.Entry{eventEntry(t, 1)}, 0)
	if n != 1 || blocked || err != nil {
		t.Fatal(n, blocked, err)
	}
	parent.End()
	for _, s := range rec.Ended() {
		if s.Name() != "shipper.export" {
			continue
		}
		if s.Parent().IsValid() || s.SpanContext().TraceID() == parent.SpanContext().TraceID() {
			t.Fatal("export span parented to unrelated request")
		}
		return
	}
	t.Fatal("missing export span")
}

func TestExportSpanErrorNeverLeaksCredentials(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	p := sdk.NewTracerProvider(sdk.WithSpanProcessor(rec))
	defer p.Shutdown(context.Background())
	tr := p.Tracer("test")
	ctx := observability.WithTracer(context.Background(), tr)
	e := &fakeEvidence{failNext: 1}
	n, blocked, err := deliver(ctx, e, []shipper.Entry{eventEntry(t, 1)}, 0)
	if n != 0 || !blocked || err != nil {
		t.Fatal(n, blocked, err)
	}
	for _, s := range rec.Ended() {
		if s.Name() != "shipper.export" {
			continue
		}
		if strings.Contains(s.Status().Description, "write") || strings.Contains(s.Status().Description, "failed") {
			t.Fatal("error leaked to span description")
		}
		return
	}
	t.Fatal("missing export span")
}
