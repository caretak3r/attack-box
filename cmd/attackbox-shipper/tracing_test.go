package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"attackbox/internal/observability"
	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
	sdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestBatchTraceIndependentAndNoEvidencePayload(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	p := sdk.NewTracerProvider(sdk.WithSpanProcessor(rec))
	defer p.Shutdown(context.Background())
	tr := p.Tracer("test")
	ctx, parent := tr.Start(context.Background(), "unrelated-request")
	ctx = observability.WithTracer(ctx, tr)
	var exported []telemetry.Record
	sink := &batchSink{ship: func(r []telemetry.Record) error { exported = r; return errors.New("credential=secret") }}
	n, blocked, err := deliverBatch(ctx, sink, []shipper.Entry{eventEntry(t, 1)}, 0)
	if n != 0 || !blocked || err != nil {
		t.Fatal(n, blocked, err)
	}
	parent.End()
	for _, s := range rec.Ended() {
		if s.Name() != "shipper.export" {
			continue
		}
		if len(exported) != 1 || exported[0].Event.Attrs["export.trace.id"] != s.SpanContext().TraceID().String() {
			t.Fatal("export log join missing")
		}
		if s.Parent().IsValid() || s.SpanContext().TraceID() == parent.SpanContext().TraceID() {
			t.Fatal("batch parented to unrelated request")
		}
		if strings.Contains(s.Status().Description, "secret") {
			t.Fatal("error leaked")
		}
		return
	}
	t.Fatal("missing export span")
}
