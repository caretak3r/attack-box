package observability

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	collector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type collectorServer struct {
	collector.UnimplementedTraceServiceServer
	requests chan *collector.ExportTraceServiceRequest
	headers  chan metadata.MD
}

func (c *collectorServer) Export(ctx context.Context, r *collector.ExportTraceServiceRequest) (*collector.ExportTraceServiceResponse, error) {
	c.requests <- r
	md, _ := metadata.FromIncomingContext(ctx)
	c.headers <- md
	return &collector.ExportTraceServiceResponse{}, nil
}
func TestUDSIdentityAndIgnoredEnvironment(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "abx-otel-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "otel.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	sink := &collectorServer{requests: make(chan *collector.ExportTraceServiceRequest, 10), headers: make(chan metadata.MD, 10)}
	collector.RegisterTraceServiceServer(srv, sink)
	go srv.Serve(ln)
	defer srv.Stop()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://192.0.2.2:4317")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=secret")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "authorization=secret")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "service.name=forged,evil=secret")
	t.Setenv("OTEL_TRACES_SAMPLER", "always_off")
	r, err := New(context.Background(), Config{Socket: socket, HostID: "host-1", InstanceID: "instance-1"}, "attackbox-bait", "test")
	if err != nil {
		t.Fatal(err)
	}
	_, span := r.Tracer.Start(context.Background(), "bait.request")
	span.End()
	func() {
		defer func() { _ = recover() }()
		_, sp := r.Tracer.Start(context.Background(), "bait.response")
		defer sp.End()
		panic("sensitive-panic-payload")
	}()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sink.requests:
		if len(got.ResourceSpans) != 1 {
			t.Fatal(got)
		}
		for _, scope := range got.ResourceSpans[0].ScopeSpans {
			for _, sp := range scope.Spans {
				if len(sp.Events) != 0 {
					t.Fatal("panic event exported")
				}
			}
		}
		attrs := got.ResourceSpans[0].Resource.Attributes
		values := map[string]string{}
		for _, a := range attrs {
			values[a.Key] = a.Value.GetStringValue()
		}
		if values["service.name"] != "attackbox-bait" || values["host.id"] != "host-1" || values["evil"] != "" {
			t.Fatal(values)
		}
	case <-time.After(time.Second):
		t.Fatal("no export")
	}
	if md := <-sink.headers; len(md.Get("authorization")) != 0 {
		t.Fatal("environment secret exported")
	}
	if r.Health()["otel_exported_spans_total"] != uint64(2) {
		t.Fatal(r.Health())
	}
}
func TestConfigDisabledAndInvalid(t *testing.T) {
	r, err := New(context.Background(), Config{}, "attackbox-bait", "test")
	if err != nil {
		t.Fatal(err)
	}
	ctx, span := r.Tracer.Start(context.Background(), "test")
	span.End()
	if trace.SpanContextFromContext(ctx).IsValid() || Correlate(ctx, nil) != nil {
		t.Fatal("disabled tracing made identity")
	}
	if r.Close() != nil {
		t.Fatal("disabled close")
	}
	for _, socket := range []string{"relative.sock", "http://remote:4317", "/tmp/a/../otel.sock", strings.Repeat("/a", 60)} {
		if (Config{Socket: socket, HostID: "host", InstanceID: "one"}).Validate() == nil {
			t.Fatalf("accepted %q", socket)
		}
	}
	if (Config{Socket: "/tmp/otel.sock"}).Validate() == nil {
		t.Fatal("accepted missing identity")
	}
}

type blockedExporter struct {
	entered chan struct{}
	once    sync.Once
}

func (e *blockedExporter) ExportSpans(ctx context.Context, _ []sdk.ReadOnlySpan) error {
	e.once.Do(func() { close(e.entered) })
	<-ctx.Done()
	return ctx.Err()
}
func (*blockedExporter) Shutdown(context.Context) error { return nil }
func TestOutageBoundedAndReportsLoss(t *testing.T) {
	e := &blockedExporter{entered: make(chan struct{})}
	p := newProcessor(e)
	provider := sdk.NewTracerProvider(sdk.WithSpanProcessor(p))
	tr := provider.Tracer("test")
	for i := 0; i < batchSize; i++ {
		_, s := tr.Start(context.Background(), "test")
		s.End()
	}
	<-e.entered
	started := time.Now()
	for i := 0; i < queueSize*2; i++ {
		_, s := tr.Start(context.Background(), "test")
		s.End()
	}
	if time.Since(started) > time.Second {
		t.Fatal("request path blocked")
	}
	if p.dropped.Load() == 0 || len(p.queue) > queueSize {
		t.Fatal("unbounded or unreported queue")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := provider.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if p.failed.Load() == 0 {
		t.Fatal("export failure not reported")
	}
	if len(p.queue) != 0 {
		t.Fatal("retained queue")
	}
}
func TestCorrelate(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	p := sdk.NewTracerProvider(sdk.WithSpanProcessor(rec))
	defer p.Shutdown(context.Background())
	ctx, s := p.Tracer("test").Start(context.Background(), "x")
	a := Correlate(ctx, map[string]any{"keep": true})
	s.End()
	if a["trace.id"] != s.SpanContext().TraceID().String() || a["span.id"] != s.SpanContext().SpanID().String() || a["keep"] != true {
		t.Fatal(a)
	}
}
func TestShutdownDeadline(t *testing.T) {
	e := &blockedExporter{entered: make(chan struct{})}
	p := newProcessor(e)
	provider := sdk.NewTracerProvider(sdk.WithSpanProcessor(p))
	_, s := provider.Tracer("test").Start(context.Background(), "x")
	s.End()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := provider.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown=%v", err)
	}
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
		t.Fatal("processor did not stop")
	}
}

func TestForceFlushDrainsPendingSnapshot(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	provider := sdk.NewTracerProvider(sdk.WithSpanProcessor(newProcessor(exporter)))
	defer provider.Shutdown(context.Background())
	for i := 0; i < 300; i++ {
		_, span := provider.Tracer("test").Start(context.Background(), "test")
		span.End()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := provider.ForceFlush(ctx); err != nil {
		t.Fatal(err)
	}
	if got := len(exporter.GetSpans()); got != 300 {
		t.Fatalf("flushed %d of 300", got)
	}
}
