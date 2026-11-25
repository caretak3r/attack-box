// Command attackbox-public serves the isolated cloud-gateway profile: HTTPS on port 8443 and plain HTTP on the plainPorts listeners.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"attackbox/internal/observability"
	"attackbox/internal/publicedge"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var version = "dev"

const internalPort = "8443"
const externalPort = 443

// A plain-HTTP public port p listens in the container on plainOffset+p, because the unprivileged user cannot bind port 80.
const plainOffset = 20000

var plainPorts = [...]int{80, 1234, 8000, 8080, 11434}

const requestRate = 1
const requestBurst = 4
const connectionLimit = 128
const connectionSpanRate = 1
const connectionSpanBurst = 16

type config struct {
	socket, host, campaign, cert, key, capture string
}

type app struct {
	listener    net.Listener
	plain       []net.Listener
	server      *http.Server
	tracing     *observability.Runtime
	limiter     rateLimit
	connLimiter rateLimit
	slots       chan struct{}
	capture     *publicedge.Capture
	accepted    atomic.Uint64
	limited     atomic.Uint64
	preHTTP     atomic.Uint64
	rejected    atomic.Uint64
	probe       func(remote string) bool
	tlsMu       sync.RWMutex
	tlsCert     *tls.Certificate
	certPath    string
	keyPath     string
	closeOnce   sync.Once
	closeErr    error
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(version)
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--healthcheck" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := healthcheck(ctx, os.Getenv("ATTACKBOX_PUBLIC_TLS_CERT"), "127.0.0.1:"+internalPort); err != nil {
			fmt.Fprintln(os.Stderr, "attackbox-public healthcheck:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: attackbox-public [--version|--healthcheck]")
		os.Exit(2)
	}
	cfg := config{socket: os.Getenv("ATTACKBOX_PUBLIC_OTEL_SOCKET"), host: os.Getenv("ATTACKBOX_HOST_ID"), campaign: os.Getenv("ATTACKBOX_CAMPAIGN_ID"), cert: os.Getenv("ATTACKBOX_PUBLIC_TLS_CERT"), key: os.Getenv("ATTACKBOX_PUBLIC_TLS_KEY"), capture: os.Getenv("ATTACKBOX_PUBLIC_CAPTURE_DIR")}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a, err := newApp(cfg, func() (net.Listener, error) {
		return net.Listen("tcp4", "0.0.0.0:"+internalPort)
	})
	for _, port := range plainPorts {
		if err != nil {
			break
		}
		var l net.Listener
		if l, err = net.Listen("tcp4", "0.0.0.0:"+strconv.Itoa(plainOffset+port)); err == nil {
			a.addPlain(port, l)
		}
	}
	if err == nil {
		err = a.run(ctx)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "attackbox-public:", err)
		os.Exit(1)
	}
}

func newApp(cfg config, listen func() (net.Listener, error)) (_ *app, err error) {
	if cfg.socket == "" || cfg.host == "" || cfg.cert == "" || cfg.key == "" {
		return nil, errors.New("collector socket, host identity, TLS certificate and TLS key are required")
	}
	probe, err := net.DialTimeout("unix", cfg.socket, 3*time.Second)
	if err != nil {
		return nil, errors.New("public collector socket is unavailable")
	}
	_ = probe.Close()

	pair, err := tls.LoadX509KeyPair(cfg.cert, cfg.key)
	if err != nil {
		return nil, fmt.Errorf("load public TLS identity: %w", err)
	}

	tracing, err := observability.New(context.Background(), observability.Config{Socket: cfg.socket, HostID: cfg.host, InstanceID: "attackbox-public-443", CampaignID: cfg.campaign}, "attackbox-public-443", version)
	if err != nil {
		return nil, fmt.Errorf("public tracing: %w", err)
	}

	now := time.Now()
	a := &app{tracing: tracing, limiter: newRateLimit(requestRate, requestBurst, now), connLimiter: newRateLimit(connectionSpanRate, connectionSpanBurst, now), slots: make(chan struct{}, connectionLimit), probe: loopbackPeer, tlsCert: &pair, certPath: cfg.cert, keyPath: cfg.key}
	defer func() {
		if err != nil {
			_ = a.close()
		}
	}()

	gateway := publicedge.NewGateway(tracing.Tracer)
	if cfg.capture != "" {
		if a.capture, err = publicedge.OpenCapture(cfg.capture); err != nil {
			return nil, fmt.Errorf("public capture: %w", err)
		}
		gateway.Capture = a.capture
	}
	listener, err := listen()
	if err != nil {
		return nil, fmt.Errorf("public listener: %w", err)
	}
	a.listener = &limitedListener{Listener: listener, slots: a.slots, rejected: &a.rejected, port: externalPort}

	// "h2" must be named here: if a plain listener's Serve reaches the server before ServeTLS, net/http sets up HTTP/2 only when the config asks for it, but ServeTLS offers h2 in ALPN anyway.
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: a.getCertificate, GetConfigForClient: a.noteSNI, NextProtos: []string{"h2", "http/1.1"}}
	a.server = &http.Server{
		Handler:           a.admit(gateway, publicedge.NewGateway(nil)),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8192,
		ErrorLog:          log.New(io.Discard, "", 0),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if lc := publicConn(c); lc != nil {
				return publicedge.WithPort(context.WithValue(ctx, connKey{}, lc), lc.port)
			}
			return ctx
		},
		ConnState: a.trackConn,
	}
	return a, nil
}

func (a *app) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	a.tlsMu.RLock()
	defer a.tlsMu.RUnlock()
	return a.tlsCert, nil
}

// noteSNI runs for every parsed ClientHello, including session resumption, where getCertificate is skipped.
func (a *app) noteSNI(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	if c, ok := hello.Conn.(*limitedConn); ok {
		cert, _ := a.getCertificate(hello)
		sni := sniOther
		if hello.ServerName == "" {
			sni = sniNone
		} else if cert.Leaf != nil && cert.Leaf.VerifyHostname(hello.ServerName) == nil {
			sni = sniMatch
		}
		c.sni.Store(sni)
	}
	return nil, nil
}

func (a *app) reloadCertificate() error {
	pair, err := tls.LoadX509KeyPair(a.certPath, a.keyPath)
	if err != nil {
		return err
	}
	a.tlsMu.Lock()
	a.tlsCert = &pair
	a.tlsMu.Unlock()
	return nil
}

// admit serves the in-container healthcheck untraced and outside the visitor rate limit.
func (a *app) admit(next, probe http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, _ := r.Context().Value(connKey{}).(*limitedConn); c != nil {
			c.served.Store(true)
		}
		if a.probe(r.RemoteAddr) {
			probe.ServeHTTP(w, r)
			return
		}
		now := time.Now()
		if !a.limiter.allow(now) {
			a.limited.Add(1)
			w.Header().Set("Retry-After", "1")
			http.Error(w, "busy", http.StatusTooManyRequests)
			return
		}
		a.accepted.Add(1)
		next.ServeHTTP(w, r)
	})
}

// loopbackPeer identifies the Docker healthcheck: DNAT and docker-proxy traffic never arrives from 127/8.
func loopbackPeer(remote string) bool {
	peer, err := netip.ParseAddrPort(remote)
	return err == nil && peer.Addr().Unmap().IsLoopback()
}

type rateLimit struct {
	mu     sync.Mutex
	tokens float64
	rate   float64
	burst  float64
	last   time.Time
}

func newRateLimit(rate, burst int, now time.Time) rateLimit {
	return rateLimit{tokens: float64(burst), rate: float64(rate), burst: float64(burst), last: now}
}

func (r *rateLimit) allow(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if elapsed := now.Sub(r.last).Seconds(); elapsed > 0 {
		r.tokens = min(r.burst, r.tokens+elapsed*r.rate)
		r.last = now
	}
	if r.tokens < 1 {
		return false
	}
	r.tokens--
	return true
}

type limitedListener struct {
	net.Listener
	slots    chan struct{}
	rejected *atomic.Uint64
	port     int // public port reported for this listener's connections
}

// addPlain serves l as plain HTTP for one public port; call it before run.
func (a *app) addPlain(port int, l net.Listener) {
	a.plain = append(a.plain, &limitedListener{Listener: l, slots: a.slots, rejected: &a.rejected, port: port})
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: conn, slots: l.slots, opened: time.Now(), port: l.port}, nil
		default:
			l.rejected.Add(1)
			_ = conn.Close()
		}
	}
}

const (
	sniUnknown uint32 = iota // no ClientHello was parsed
	sniNone
	sniMatch
	sniOther
)

var sniNames = [...]string{sniUnknown: "unknown", sniNone: "none", sniMatch: "match", sniOther: "other"}

type connKey struct{}

type limitedConn struct {
	net.Conn
	slots  chan struct{}
	port   int
	once   sync.Once
	opened time.Time
	first  atomic.Int32  // first received byte + 1; 0 until data arrives
	sni    atomic.Uint32 // set once a ClientHello is parsed
	served atomic.Bool   // a request reached the handler
}

func (c *limitedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.first.Load() == 0 {
		c.first.CompareAndSwap(0, int32(p[0])+1)
	}
	return n, err
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.slots })
	return err
}

func publicConn(c net.Conn) *limitedConn {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	lc, _ := c.(*limitedConn)
	return lc
}

// trackConn records connections that close before any request reaches the handler.
func (a *app) trackConn(conn net.Conn, state http.ConnState) {
	c := publicConn(conn)
	if state != http.StateClosed || c == nil || c.served.Load() || a.probe(c.RemoteAddr().String()) {
		return
	}
	a.preHTTP.Add(1)
	if !a.connLimiter.allow(time.Now()) {
		return
	}
	outcome := "no_request"
	switch first := c.first.Load(); {
	case first == 0:
		outcome = "no_data"
	case c.port != externalPort:
		// plain listener: bytes arrived but no request reached the handler
	case first != 0x16+1:
		outcome = "not_tls"
	default:
		if tc, ok := conn.(*tls.Conn); !ok || !tc.ConnectionState().HandshakeComplete {
			outcome = "tls_failed"
		}
	}
	attrs := []attribute.KeyValue{attribute.Int("server.port", c.port), attribute.String("attackbox.connection.outcome", outcome)}
	if addr := publicedge.ClientAddress(c.RemoteAddr().String()); addr != "" {
		attrs = append(attrs, attribute.String("client.address", addr))
	}
	attrs = append(attrs, attribute.String("attackbox.tls.sni", sniNames[c.sni.Load()]))
	_, span := a.tracing.Tracer.Start(context.Background(), "public.connection", trace.WithNewRoot(), trace.WithTimestamp(c.opened), trace.WithAttributes(attrs...))
	span.End()
}

func (a *app) emitHealth() {
	_, span := a.tracing.Tracer.Start(context.Background(), "public.health", trace.WithNewRoot())
	stats := a.tracing.Health()
	recorded, dropped := a.capture.Counts()
	span.SetAttributes(attribute.Int("server.port", externalPort), attribute.Int64("attackbox.accepted_requests", int64(a.accepted.Load())), attribute.Int64("attackbox.rate_limited_requests", int64(a.limited.Load())), attribute.Int64("attackbox.pre_http_connections", int64(a.preHTTP.Load())), attribute.Int64("attackbox.rejected_connections", int64(a.rejected.Load())), attribute.Int64("attackbox.captured_requests", int64(recorded)), attribute.Int64("attackbox.capture_dropped", int64(dropped)), attribute.Int64("attackbox.otel_dropped_spans_total", int64(stats["otel_dropped_spans_total"].(uint64))), attribute.Int64("attackbox.otel_export_failed_spans_total", int64(stats["otel_export_failed_spans_total"].(uint64))))
	span.End()
}

func (a *app) run(ctx context.Context) error {
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)

	result := make(chan error, 1+len(a.plain))
	serve := func(f func() error) {
		go func() {
			err := f()
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			result <- err
		}()
	}
	serve(func() error { return a.server.ServeTLS(a.listener, "", "") })
	for _, l := range a.plain {
		serve(func() error { return a.server.Serve(l) })
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	var serveErr error
	for {
		select {
		case <-ctx.Done():
			return errors.Join(serveErr, a.close())
		case err := <-result:
			if err == nil {
				err = errors.New("public listener stopped")
			}
			serveErr = err
			return errors.Join(serveErr, a.close())
		case <-ticker.C:
			a.emitHealth()
		case <-sighup:
			_ = a.reloadCertificate()
		}
	}
}

func (a *app) close() error {
	a.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if a.server != nil {
			if err := a.server.Shutdown(ctx); err != nil {
				_ = a.server.Close()
			}
		}
		if a.listener != nil {
			_ = a.listener.Close()
		}
		for _, l := range a.plain {
			_ = l.Close()
		}
		if a.tracing != nil {
			a.closeErr = a.tracing.Close()
		}
		_ = a.capture.Close()
	})
	return a.closeErr
}
