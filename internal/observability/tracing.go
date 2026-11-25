// Package observability provides bounded, opt-in traces over a private Unix socket.
// Evidence remains on the independent durable log route.
package observability

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const queueSize = 1024
const batchSize = 128
const exportTimeout = 2 * time.Second

// Config values come only from trusted process configuration. Socket empty disables tracing.
type Config struct{ Socket, HostID, InstanceID, ContainerID, CampaignID string }

var identity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var publicService = regexp.MustCompile(`^attackbox-public-(80|443|1234|3000|4891|5000|6333|6334|8000|8001|8002|8080|8500|8501|11434|19530)$`)

func FromEnv(get func(string) string) (Config, error) {
	c := Config{get("ATTACKBOX_OTEL_SOCKET"), get("ATTACKBOX_HOST_ID"), get("ATTACKBOX_SERVICE_INSTANCE_ID"), get("ATTACKBOX_CONTAINER_ID"), get("ATTACKBOX_CAMPAIGN_ID")}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if c.Socket == "" {
		return nil
	}
	if !filepath.IsAbs(c.Socket) || filepath.Clean(c.Socket) != c.Socket || len(c.Socket) > 100 || strings.IndexFunc(c.Socket, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return errors.New("ATTACKBOX_OTEL_SOCKET must be a clean absolute Unix socket path up to 100 bytes")
	}
	for _, value := range []string{c.HostID, c.InstanceID} {
		if !identity.MatchString(value) {
			return errors.New("tracing requires valid ATTACKBOX_HOST_ID and ATTACKBOX_SERVICE_INSTANCE_ID (1-128 identifier characters)")
		}
	}
	for _, value := range []string{c.ContainerID, c.CampaignID} {
		if value != "" && !identity.MatchString(value) {
			return errors.New("invalid optional tracing identity")
		}
	}
	return nil
}

type Runtime struct {
	Tracer    trace.Tracer
	provider  *sdk.TracerProvider
	processor *processor
	conn      *grpc.ClientConn
}

func New(ctx context.Context, c Config, service, version string) (*Runtime, error) {
	r := &Runtime{Tracer: noop.NewTracerProvider().Tracer("attackbox")}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.Socket == "" {
		return r, nil
	}
	if service != "attackbox-bait" && service != "attackbox-shipper" && !publicService.MatchString(service) {
		return nil, errors.New("unsupported trace service")
	}
	// The dialer ignores all remote addresses. Supplying this connection and empty
	// headers prevents OTEL endpoint/header environment variables from adding egress or secrets.
	conn, err := grpc.NewClient("passthrough:///attackbox-otel", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", c.Socket)
	}))
	if err != nil {
		return nil, err
	}
	exp, err := otlptracegrpc.New(ctx, otlptracegrpc.WithGRPCConn(conn), otlptracegrpc.WithHeaders(map[string]string{}), otlptracegrpc.WithTimeout(exportTimeout), otlptracegrpc.WithRetry(otlptracegrpc.RetryConfig{Enabled: false}))
	if err != nil {
		conn.Close()
		return nil, err
	}
	attrs := []attribute.KeyValue{attribute.String("service.name", service), attribute.String("service.version", version), attribute.String("service.instance.id", c.InstanceID), attribute.String("host.id", c.HostID)}
	if c.ContainerID != "" {
		attrs = append(attrs, attribute.String("container.id", c.ContainerID))
	}
	if c.CampaignID != "" {
		attrs = append(attrs, attribute.String("campaign.id", c.CampaignID))
	}
	p := newProcessor(exp)
	p.resource = resource.NewSchemaless(attrs...)
	r.processor, r.conn = p, conn
	// Explicit options ignore global sampler/resource settings. A caller never
	// installs this provider globally or extracts attacker propagation headers.
	// The public service exports full credential values (up to 512 bytes); its Collector bounds every other attribute.
	valueLimit := 128
	if publicService.MatchString(service) {
		valueLimit = 512
	}
	r.provider = sdk.NewTracerProvider(sdk.WithoutPanicRecording(), sdk.WithSampler(sdk.AlwaysSample()), sdk.WithResource(resource.NewSchemaless(attrs...)), sdk.WithSpanLimits(sdk.SpanLimits{AttributeValueLengthLimit: valueLimit, AttributeCountLimit: 16, EventCountLimit: 4, LinkCountLimit: 0, AttributePerEventCountLimit: 4, AttributePerLinkCountLimit: 0}), sdk.WithSpanProcessor(p))
	r.Tracer = r.provider.Tracer("attackbox")
	return r, nil
}
func (r *Runtime) Close() error {
	if r == nil || r.provider == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := r.provider.Shutdown(ctx)
	return errors.Join(err, r.conn.Close())
}
func (r *Runtime) Health() map[string]any {
	attrs := map[string]any{"otel_enabled": r != nil && r.provider != nil, "go_goroutines": runtime.NumGoroutine()}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	attrs["go_heap_bytes"] = m.HeapAlloc
	if r != nil && r.processor != nil {
		p := r.processor
		attrs["otel_queue_spans"] = len(p.queue)
		attrs["otel_dropped_spans_total"] = p.dropped.Load()
		attrs["otel_export_failed_spans_total"] = p.failed.Load()
		attrs["otel_exported_spans_total"] = p.sent.Load()
		attrs["otel_last_export_unix_ms"] = p.last.Load()
	}
	return attrs
}
func Correlate(ctx context.Context, attrs map[string]any) map[string]any {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return attrs
	}
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs["trace.id"] = sc.TraceID().String()
	attrs["span.id"] = sc.SpanID().String()
	return attrs
}

// WithTracer carries the owned provider across internal calls without a global provider.
type tracerKey struct{}

func WithTracer(ctx context.Context, t trace.Tracer) context.Context {
	return context.WithValue(ctx, tracerKey{}, t)
}
func Tracer(ctx context.Context) trace.Tracer {
	if t, ok := ctx.Value(tracerKey{}).(trace.Tracer); ok {
		return t
	}
	return noop.NewTracerProvider().Tracer("attackbox")
}

// processor is a bounded, nonblocking SDK SpanProcessor. Overflow and failed
// exports are explicitly counted; request handlers never wait for the collector.
type resourceSpan struct {
	sdk.ReadOnlySpan
	trusted *resource.Resource
}

func (s resourceSpan) Resource() *resource.Resource { return s.trusted }

type flushRequest struct {
	ctx  context.Context
	done chan error
}

type processor struct {
	flushRequests         chan flushRequest
	shutdownCtx           context.Context
	resource              *resource.Resource
	exporter              sdk.SpanExporter
	queue                 chan sdk.ReadOnlySpan
	stop, done            chan struct{}
	mu                    sync.RWMutex
	closed                bool
	dropped, failed, sent atomic.Uint64
	last                  atomic.Int64
}

func newProcessor(e sdk.SpanExporter) *processor {
	p := &processor{flushRequests: make(chan flushRequest), exporter: e, queue: make(chan sdk.ReadOnlySpan, queueSize), stop: make(chan struct{}), done: make(chan struct{})}
	go p.run()
	return p
}
func (p *processor) OnStart(context.Context, sdk.ReadWriteSpan) {}
func (p *processor) OnEnd(s sdk.ReadOnlySpan) {
	if !s.SpanContext().IsSampled() {
		return
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		p.dropped.Add(1)
		return
	}
	select {
	case p.queue <- p.trustedSpan(s):
	default:
		p.dropped.Add(1)
	}
}
func (p *processor) ForceFlush(ctx context.Context) error {
	req := flushRequest{ctx: ctx, done: make(chan error, 1)}
	select {
	case p.flushRequests <- req:
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-req.done:
		return err
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (p *processor) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		p.shutdownCtx = ctx
		close(p.stop)
	}
	p.mu.Unlock()
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (p *processor) run() {
	defer close(p.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	batch := make([]sdk.ReadOnlySpan, 0, batchSize)
	flush := func(base context.Context) error {
		if len(batch) == 0 {
			return nil
		}
		ctx, cancel := context.WithTimeout(base, exportTimeout)
		err := p.exporter.ExportSpans(ctx, batch)
		cancel()
		if err != nil {
			p.failed.Add(uint64(len(batch)))
		} else {
			p.sent.Add(uint64(len(batch)))
			p.last.Store(time.Now().UnixMilli())
		}
		clear(batch)
		batch = batch[:0]
		return err
	}
	for {
		// Prefer stop over queued work so shutdown cannot export an unbounded
		// number of batches while the queue remains nonempty.
		select {
		case <-p.stop:
			goto shutdown
		default:
		}
		select {
		case s := <-p.queue:
			batch = append(batch, s)
			if len(batch) == batchSize {
				flush(context.Background())
			}
		case req := <-p.flushRequests:
			// Drain only the bounded snapshot pending when this request was
			// received. Later spans cannot make ForceFlush run forever.
			var flushErr error
			for n := len(p.queue); n > 0 && req.ctx.Err() == nil; n-- {
				batch = append(batch, <-p.queue)
				if len(batch) == batchSize {
					flushErr = errors.Join(flushErr, flush(req.ctx))
				}
			}
			flushErr = errors.Join(flushErr, flush(req.ctx), req.ctx.Err())
			req.done <- flushErr
		case <-ticker.C:
			flush(context.Background())
		case <-p.stop:
			goto shutdown
		}
	}
shutdown:
	// One final bounded batch; remaining queued spans are reported as drops.
	for len(batch) < batchSize {
		select {
		case s := <-p.queue:
			batch = append(batch, s)
		default:
			goto drained
		}
	}
drained:
	flush(p.shutdownCtx)
	p.dropped.Add(uint64(len(p.queue)))
	for len(p.queue) > 0 {
		<-p.queue
	}
	ctx, cancel := context.WithTimeout(p.shutdownCtx, exportTimeout)
	_ = p.exporter.Shutdown(ctx)
	cancel()
}

// SDK WithResource merges OTEL_RESOURCE_ATTRIBUTES. Replace the resource at
// export so generic environment attributes cannot carry secrets or identity.
func (p *processor) trustedSpan(s sdk.ReadOnlySpan) sdk.ReadOnlySpan {
	if p.resource == nil {
		return s
	}
	return resourceSpan{s, p.resource}
}
