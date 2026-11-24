// Command attackbox-public serves the isolated cloud-gateway HTTPS profile on port 8443.
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
	"os"
	"os/signal"
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
const requestRate = 1
const requestBurst = 4
const connectionLimit = 128

type config struct {
	socket, host, campaign, cert, key string
}

type app struct {
	listener  net.Listener
	server    *http.Server
	tracing   *observability.Runtime
	limiter   rateLimit
	slots     chan struct{}
	accepted  atomic.Uint64
	limited   atomic.Uint64
	tlsMu     sync.RWMutex
	tlsCert   *tls.Certificate
	certPath  string
	keyPath   string
	closeOnce sync.Once
	closeErr  error
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(version)
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--healthcheck" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := healthcheck(ctx, os.Getenv("ATTACKBOX_PUBLIC_TLS_CERT")); err != nil {
			fmt.Fprintln(os.Stderr, "attackbox-public healthcheck:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: attackbox-public [--version|--healthcheck]")
		os.Exit(2)
	}
	cfg := config{socket: os.Getenv("ATTACKBOX_PUBLIC_OTEL_SOCKET"), host: os.Getenv("ATTACKBOX_HOST_ID"), campaign: os.Getenv("ATTACKBOX_CAMPAIGN_ID"), cert: os.Getenv("ATTACKBOX_PUBLIC_TLS_CERT"), key: os.Getenv("ATTACKBOX_PUBLIC_TLS_KEY")}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a, err := newApp(cfg, func() (net.Listener, error) {
		return net.Listen("tcp4", "0.0.0.0:"+internalPort)
	})
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

	a := &app{tracing: tracing, limiter: newRateLimit(requestRate, requestBurst, time.Now()), slots: make(chan struct{}, connectionLimit), tlsCert: &pair, certPath: cfg.cert, keyPath: cfg.key}
	defer func() {
		if err != nil {
			_ = a.close()
		}
	}()

	gateway := publicedge.NewGateway(tracing.Tracer)
	listener, err := listen()
	if err != nil {
		return nil, fmt.Errorf("public listener: %w", err)
	}
	a.listener = &limitedListener{Listener: listener, slots: a.slots}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: a.getCertificate}
	a.server = &http.Server{
		Handler:           a.admit(gateway),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8192,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	return a, nil
}

func (a *app) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	a.tlsMu.RLock()
	defer a.tlsMu.RUnlock()
	return a.tlsCert, nil
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

func (a *app) admit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	slots chan struct{}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: conn, slots: l.slots}, nil
		default:
			_ = conn.Close()
		}
	}
}

type limitedConn struct {
	net.Conn
	slots chan struct{}
	once  sync.Once
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.slots })
	return err
}

func (a *app) emitHealth() {
	_, span := a.tracing.Tracer.Start(context.Background(), "public.health", trace.WithNewRoot())
	stats := a.tracing.Health()
	span.SetAttributes(attribute.Int("server.port", externalPort), attribute.Int64("attackbox.accepted_requests", int64(a.accepted.Load())), attribute.Int64("attackbox.rate_limited_requests", int64(a.limited.Load())), attribute.Int64("attackbox.otel_dropped_spans_total", int64(stats["otel_dropped_spans_total"].(uint64))), attribute.Int64("attackbox.otel_export_failed_spans_total", int64(stats["otel_export_failed_spans_total"].(uint64))))
	span.End()
}

func (a *app) run(ctx context.Context) error {
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)

	result := make(chan error, 1)
	go func() {
		err := a.server.ServeTLS(a.listener, "", "")
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		result <- err
	}()

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
		if a.tracing != nil {
			a.closeErr = a.tracing.Close()
		}
	})
	return a.closeErr
}
