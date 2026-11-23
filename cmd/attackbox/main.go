// Command attackbox runs the bait inference API. It serves the generic
// OpenAI-compatible, vLLM and Ollama personas on separate listeners, answers
// from local templates, writes JSON lines to stdout and, unless deliberately
// disabled, ships the same events to New Relic.
//
// Configuration is read from ATTACKBOX_* environment variables; see the
// "Process entry point" section of implementation_plan.md. Flags:
//
//	-version        print the version and exit
//	-check-config   validate the environment and exit
//	-healthcheck U  GET a loopback URL and exit 0 on HTTP 200 (container probe)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"attackbox/internal/responder"
	"attackbox/internal/server"
	"attackbox/internal/telemetry"
)

// version is set at release build time with -ldflags '-X main.version=...'.
var version = "dev"

func main() {
	os.Exit(cli(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func cli(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attackbox", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print the version and exit")
	check := fs.Bool("check-config", false, "validate the environment and exit")
	health := fs.String("healthcheck", "", "GET this loopback URL and exit 0 on HTTP 200")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "attackbox: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	switch {
	case *showVersion:
		fmt.Fprintln(stdout, version)
		return 0
	case *health != "":
		if err := healthcheck(*health); err != nil {
			fmt.Fprintln(stderr, "attackbox: healthcheck:", err)
			return 1
		}
		return 0
	}
	cfg, err := loadConfig(getenv)
	if err != nil {
		fmt.Fprintln(stderr, "attackbox: configuration error:\n"+err.Error())
		return 2
	}
	if *check {
		mode := "enabled"
		switch {
		case cfg.nrDisabled:
			mode = "disabled"
		case cfg.spoolSocket != "":
			mode = "off (host shipper), spool " + cfg.spoolSocket
		}
		fmt.Fprintf(stdout, "configuration ok: %d listener(s), new relic %s\n", len(cfg.listeners), mode)
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a, err := newApp(cfg, stdout)
	if err != nil {
		fmt.Fprintln(stderr, "attackbox:", err)
		return 1
	}
	if err := a.run(ctx); err != nil {
		fmt.Fprintln(stderr, "attackbox:", err)
		return 1
	}
	return 0
}

// healthcheck probes the local listener. It refuses non-loopback targets so
// the binary cannot be used to make outbound requests.
func healthcheck(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return errors.New("want an http:// loopback URL")
	}
	if u.User != nil {
		return errors.New("credentials in the healthcheck URL are not allowed")
	}
	switch u.Hostname() {
	case "127.0.0.1", "::1", "localhost":
	default:
		return errors.New("only loopback hosts are allowed")
	}
	c := &http.Client{
		Timeout:       3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := c.Get(u.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// app is one running process: the listeners, their servers and the sinks.
type app struct {
	cfg       config
	local     *telemetry.Async    // JSONLog behind a bounded queue, off the request path
	nr        *telemetry.NewRelic // direct mode only
	spool     *telemetry.Spool    // spool mode only: the host shipper owns egress
	sink      telemetry.Sink
	servers   []*http.Server
	listeners []net.Listener
	personas  []string
	handlerMu sync.Mutex
	handlers  sync.WaitGroup
	closing   bool
}

// newApp binds every listener before it returns, so a port conflict fails
// startup instead of leaving a partial service.
func newApp(cfg config, logOut io.Writer) (*app, error) {
	a := &app{cfg: cfg, local: telemetry.NewAsync(telemetry.NewJSONLog(logOut), 0)}
	a.sink = a.local
	if cfg.nrKey != "" {
		nr, err := telemetry.NewNewRelic(telemetry.NRConfig{
			LicenseKey: cfg.nrKey,
			LogURL:     cfg.nrLogURL,
			MetricURL:  cfg.nrMetricURL,
			Common:     map[string]any{"service.name": "attackbox", "instance": cfg.instance},
			// Delivery failures go to the local log only, never back into
			// the queue that is failing.
			OnError: func(err error) {
				a.local.Emit(telemetry.Event{Stream: telemetry.StreamRuntime, Action: "newrelic_error", Result: "error", Attrs: map[string]any{"error": err.Error()}})
			},
		})
		if err != nil {
			a.closeLocal()
			return nil, err
		}
		a.nr = nr
		a.sink = telemetry.Multi{a.local, nr}
	}
	if cfg.spoolSocket != "" {
		sp, err := telemetry.NewSpool(telemetry.SpoolConfig{
			Socket:       cfg.spoolSocket,
			QueueSize:    cfg.spoolQueue,
			WriteTimeout: cfg.spoolTimeout,
			// As for New Relic: failures go to the local log only.
			OnError: func(err error) {
				a.local.Emit(telemetry.Event{Stream: telemetry.StreamRuntime, Action: "spool_error", Result: "error", Attrs: map[string]any{"error": err.Error()}})
			},
		})
		if err != nil {
			return nil, errors.Join(err, a.closeLocal())
		}
		a.spool = sp
		a.sink = telemetry.Multi{a.local, sp}
	}

	redactor := telemetry.NewRedactor(cfg.derive("redact"))
	resp := responder.New(responder.Config{Fingerprint: redactor.Fingerprint},
		responder.NewStore(responder.StoreConfig{MaxSessions: cfg.maxSessions}))
	sessionKey, embedSeed := cfg.derive("session"), cfg.derive("embed")
	var timing server.Timing
	if cfg.timing {
		timing = server.DefaultTiming()
	}
	for _, l := range cfg.listeners {
		s, err := server.New(server.Config{
			Persona:           l.persona,
			Models:            cfg.models,
			Responder:         resp,
			Sink:              a.sink,
			Redactor:          redactor,
			SessionKey:        sessionKey,
			EmbedSeed:         embedSeed,
			MaxBodyBytes:      cfg.maxBody,
			MaxLogBody:        cfg.maxLogBody,
			MaxConcurrent:     cfg.maxInFlight,
			MaxPerSource:      cfg.maxPerSource,
			MaxStreamDuration: cfg.maxStream,
			HoldSilent:        cfg.holdSilent,
			IdleInterval:      cfg.idleInterval,
			TrustedProxies:    cfg.trustedProxies,
			Timing:            timing,
		})
		if err == nil {
			var ln net.Listener
			ln, err = net.Listen("tcp", l.addr)
			if err == nil {
				a.listeners = append(a.listeners, ln)
				a.personas = append(a.personas, l.persona)
				a.servers = append(a.servers, &http.Server{
					Handler:           a.trackHandler(s.Handler()),
					ReadHeaderTimeout: cfg.readHeaderTimeout,
					ReadTimeout:       cfg.readTimeout,
					// Holds and streams last up to maxStream; allow headroom.
					WriteTimeout:   cfg.maxStream + 30*time.Second,
					IdleTimeout:    cfg.idleTimeout,
					MaxHeaderBytes: 32 << 10,
				})
			}
		}
		if err != nil {
			a.closeListeners()
			bindErr := fmt.Errorf("%s listener %s: %w", l.persona, l.addr, err)
			var remoteErr error
			ctx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
			if a.nr != nil {
				if err := a.nr.Close(ctx); err != nil {
					remoteErr = fmt.Errorf("new relic close: %w", err)
				}
			}
			if a.spool != nil {
				if err := a.spool.Close(ctx); err != nil {
					remoteErr = fmt.Errorf("spool close: %w", err)
				}
			}
			cancel()
			return nil, errors.Join(bindErr, remoteErr, a.closeLocal())
		}
	}
	return a, nil
}

// closeLocal drains the local log within the shutdown grace period.
func (a *app) closeLocal() error {
	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.shutdownTimeout)
	defer cancel()
	return a.local.Close(ctx)
}

func (a *app) closeListeners() {
	for _, ln := range a.listeners {
		_ = ln.Close()
	}
}

// addrs returns the bound address of each listener, keyed by persona.
func (a *app) addrs() map[string]string {
	m := make(map[string]string, len(a.listeners))
	for i, ln := range a.listeners {
		m[a.personas[i]] = ln.Addr().String()
	}
	return m
}

// Close can return before active handlers finish their final evidence. Gate
// new handlers and join existing ones before closing any telemetry sink.
func (a *app) trackHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.handlerMu.Lock()
		if a.closing {
			a.handlerMu.Unlock()
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		a.handlers.Add(1)
		a.handlerMu.Unlock()
		defer a.handlers.Done()
		next.ServeHTTP(w, r)
	})
}

// run serves until ctx ends or a listener fails, then shuts down: listeners
// stop, in-flight requests get shutdownTimeout, and New Relic is flushed.
// It returns an error if a listener failed or New Relic lost events.
func (a *app) run(ctx context.Context) error {
	a.runtime("start", "ok", map[string]any{"version": version, "listeners": a.addrs(), "newrelic": a.nr != nil, "spool": a.spool != nil})
	// Request contexts derive from base. When the grace period ends it is
	// cancelled with server.ErrShutdown, so cut holds are logged as
	// server_shutdown rather than client_closed.
	base, cut := context.WithCancelCause(context.Background())
	defer cut(nil)
	errc := make(chan error, len(a.servers))
	for i, srv := range a.servers {
		srv.BaseContext = func(net.Listener) context.Context { return base }
		go func(srv *http.Server, ln net.Listener, persona string) {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s listener: %w", persona, err)
			}
		}(srv, a.listeners[i], a.personas[i])
	}
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errc:
	}

	// Emitted before the drain so New Relic has the whole flush window for
	// it; the local "stopped" event below is the authoritative final record.
	reason := "signal"
	if serveErr != nil {
		reason = "listener_error"
	}
	a.runtime("stop", "ok", map[string]any{"reason": reason, "grace_ms": a.cfg.shutdownTimeout.Milliseconds()})
	a.handlerMu.Lock()
	a.closing = true
	a.handlerMu.Unlock()

	shutCtx, cancel := context.WithTimeout(context.Background(), a.cfg.shutdownTimeout)
	defer cancel()
	var wg sync.WaitGroup
	for _, srv := range a.servers {
		wg.Add(1)
		go func(srv *http.Server) {
			defer wg.Done()
			if err := srv.Shutdown(shutCtx); err != nil {
				cut(server.ErrShutdown) // holds outlived the grace period
				_ = srv.Close()
			}
		}(srv)
	}
	wg.Wait()
	finished := make(chan struct{})
	go func() { a.handlers.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(max(time.Second, a.cfg.shutdownTimeout)):
		serveErr = errors.Join(serveErr, errors.New("handlers did not finish evidence before shutdown deadline"))
	}

	attrs := map[string]any{}
	var nrErr error
	if a.nr != nil {
		flushCtx, cancelFlush := context.WithTimeout(context.Background(), a.cfg.shutdownTimeout)
		nrErr = a.nr.Close(flushCtx)
		cancelFlush()
		st := a.nr.Stats()
		attrs = map[string]any{"nr_sent": st.Sent, "nr_dropped": st.Dropped, "nr_lost": st.Lost, "nr_errors": st.Errors, "nr_retries": st.Retries}
		if nrErr == nil {
			nrErr = lossError(st)
		}
	}
	var spErr error
	if a.spool != nil {
		// The host shipper gets a stopped record with the spool counters as
		// they stand before the drain; the local record below carries the
		// final ones and stays authoritative.
		a.spool.Emit(a.stopped(serveErr, nil, attrs))
		flushCtx, cancelFlush := context.WithTimeout(context.Background(), a.cfg.shutdownTimeout)
		spErr = a.spool.Close(flushCtx)
		cancelFlush()
	}
	stopped := a.stopped(serveErr, errors.Join(nrErr, spErr), attrs)
	// Written locally only: the remote sink is closed at this point.
	a.local.Emit(stopped)
	return errors.Join(serveErr, nrErr, spErr, a.closeLocal())
}

// stopped builds the final runtime record. attrs holds the New Relic
// counters, if any; spool and local counters are read now.
func (a *app) stopped(serveErr, remoteErr error, nrAttrs map[string]any) telemetry.Event {
	attrs := make(map[string]any, len(nrAttrs)+6)
	for k, v := range nrAttrs {
		attrs[k] = v
	}
	loss := false
	if a.spool != nil {
		st := a.spool.Stats()
		attrs["spool_written"], attrs["spool_dropped"], attrs["spool_lost"], attrs["spool_errors"], attrs["spool_resent"] = st.Written, st.Dropped, st.Lost, st.Errors, st.Resent
		loss = st.Dropped > 0 || st.Lost > 0
	}
	localDropped := a.local.Dropped()
	attrs["local_dropped"] = localDropped
	result := "ok"
	if serveErr != nil || remoteErr != nil || loss || localDropped > 0 {
		result = "error"
	}
	return telemetry.Event{Stream: telemetry.StreamRuntime, Action: "stopped", Result: result, Attrs: attrs}
}

// lossError reports events New Relic never accepted, or nil if none.
func lossError(st telemetry.Stats) error {
	if st.Lost == 0 && st.Dropped == 0 {
		return nil
	}
	msg := fmt.Sprintf("new relic: %d lost, %d dropped", st.Lost, st.Dropped)
	if st.LastError != "" {
		msg += "; last error: " + st.LastError
	}
	return errors.New(msg)
}

func (a *app) runtime(action, result string, attrs map[string]any) {
	a.sink.Emit(telemetry.Event{Stream: telemetry.StreamRuntime, Action: action, Result: result, Attrs: attrs})
}
