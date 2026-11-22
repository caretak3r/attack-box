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
		fmt.Fprintf(stdout, "configuration ok: %d listener(s), new relic %s\n", len(cfg.listeners), map[bool]string{true: "disabled", false: "enabled"}[cfg.nrDisabled])
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
	local     *telemetry.JSONLog
	nr        *telemetry.NewRelic
	sink      telemetry.Sink
	servers   []*http.Server
	listeners []net.Listener
	personas  []string
}

// newApp binds every listener before it returns, so a port conflict fails
// startup instead of leaving a partial service.
func newApp(cfg config, logOut io.Writer) (*app, error) {
	a := &app{cfg: cfg, local: telemetry.NewJSONLog(logOut)}
	a.sink = a.local
	if !cfg.nrDisabled {
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
			return nil, err
		}
		a.nr = nr
		a.sink = telemetry.Multi{a.local, nr}
	}

	resp := responder.New(responder.Config{}, responder.NewStore(responder.StoreConfig{MaxSessions: cfg.maxSessions}))
	sessionKey, embedSeed := cfg.derive("session"), cfg.derive("embed")
	redactor := telemetry.NewRedactor(cfg.derive("redact"))
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
			MaxConcurrent:     cfg.maxInFlight,
			MaxPerSource:      cfg.maxPerSource,
			MaxStreamDuration: cfg.maxStream,
			HoldSilent:        cfg.holdSilent,
			IdleInterval:      cfg.idleInterval,
			TrustedProxies:    cfg.trustedProxies,
		})
		if err == nil {
			var ln net.Listener
			ln, err = net.Listen("tcp", l.addr)
			if err == nil {
				a.listeners = append(a.listeners, ln)
				a.personas = append(a.personas, l.persona)
				a.servers = append(a.servers, &http.Server{
					Handler:           s.Handler(),
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
			if a.nr != nil {
				ctx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
				_ = a.nr.Close(ctx)
				cancel()
			}
			return nil, fmt.Errorf("%s listener %s: %w", l.persona, l.addr, err)
		}
	}
	return a, nil
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

// run serves until ctx ends or a listener fails, then shuts down: listeners
// stop, in-flight requests get shutdownTimeout, and New Relic is flushed.
// It returns an error if a listener failed or New Relic lost events.
func (a *app) run(ctx context.Context) error {
	a.runtime("start", "ok", map[string]any{"version": version, "listeners": a.addrs(), "newrelic": a.nr != nil})
	errc := make(chan error, len(a.servers))
	for i, srv := range a.servers {
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

	shutCtx, cancel := context.WithTimeout(context.Background(), a.cfg.shutdownTimeout)
	defer cancel()
	var wg sync.WaitGroup
	for _, srv := range a.servers {
		wg.Add(1)
		go func(srv *http.Server) {
			defer wg.Done()
			if err := srv.Shutdown(shutCtx); err != nil {
				_ = srv.Close() // holds outlived the grace period
			}
		}(srv)
	}
	wg.Wait()

	attrs := map[string]any{}
	var nrErr error
	a.runtime("stop", "ok", nil)
	if a.nr != nil {
		flushCtx, cancelFlush := context.WithTimeout(context.Background(), a.cfg.shutdownTimeout)
		nrErr = a.nr.Close(flushCtx)
		cancelFlush()
		st := a.nr.Stats()
		attrs = map[string]any{"nr_sent": st.Sent, "nr_dropped": st.Dropped, "nr_lost": st.Lost, "nr_errors": st.Errors}
		if nrErr == nil && (st.Lost > 0 || st.Dropped > 0) {
			nrErr = fmt.Errorf("new relic: %d lost, %d dropped; last error: %s", st.Lost, st.Dropped, st.LastError)
		}
	}
	result := "ok"
	if serveErr != nil || nrErr != nil {
		result = "error"
	}
	// Written locally only: New Relic is closed at this point.
	a.local.Emit(telemetry.Event{Stream: telemetry.StreamRuntime, Action: "stopped", Result: result, Attrs: attrs})
	return errors.Join(serveErr, nrErr)
}

func (a *app) runtime(action, result string, attrs map[string]any) {
	a.sink.Emit(telemetry.Event{Stream: telemetry.StreamRuntime, Action: action, Result: result, Attrs: attrs})
}
