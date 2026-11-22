// Package server is the public HTTP surface of the bait service. It speaks
// three local-inference dialects (generic OpenAI-compatible, vLLM and
// Ollama), answers every inference request from responder templates, and logs
// every request. It never calls a model, never makes an outbound request and
// never acts on request content.
package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"attackbox/internal/responder"
	"attackbox/internal/telemetry"
)

// Config configures one Server. Zero values take defaults.
type Config struct {
	Persona string // "openai" (default), "vllm" or "ollama"
	Version string // release string on /version and /api/version

	Models []string // served model names; default qwen3:8b, gpt-oss:20b, llama3.1:8b

	Responder *responder.Responder // required
	Sink      telemetry.Sink       // default: discard
	Redactor  *telemetry.Redactor  // default: keyed from SessionKey

	// SessionKey keys the session HMAC; EmbedSeed keys the embedding
	// vectors. Both default to random values, which only holds for one
	// process. Share them across Servers that must agree.
	SessionKey []byte
	EmbedSeed  []byte

	MaxBodyBytes      int64         // request body cap; default 1 MiB
	MaxMessages       int           // messages, input items and prompts per request; default 1024
	MaxTools          int           // tools per request; default 128
	MaxConcurrent     int           // in-flight requests, all sources; default 256
	MaxPerSource      int           // in-flight requests per source; default 8
	MaxStreamDuration time.Duration // longest hold; default 180s
	MaxLogBody        int           // request and response body bytes kept per log event; default 128 KiB
	HoldSilent        time.Duration // hold length of the timeout gates; default 150s
	IdleInterval      time.Duration // keepalive spacing in the idle hold; default 45s
	StatusHold        time.Duration // hold of /v1/edge/{A-D}/status; default 200ms

	// TrustedProxies lists peers whose X-Forwarded-For is believed.
	TrustedProxies []netip.Prefix

	// Timing paces inference replies; the zero value sends at once.
	Timing Timing

	Now   func() time.Time                     // default time.Now
	After func(time.Duration) <-chan time.Time // default time.After
	Rand  func() float64                       // timing jitter in [0,1); default math/rand/v2
}

// Server is one persona's HTTP handler.
type Server struct {
	cfg     Config
	persona string
	routes  []route
	openapi []byte
	sem     chan struct{}
	started time.Time

	mu     sync.Mutex
	perSrc map[string]int
}

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	if cfg.Responder == nil {
		return nil, errors.New("server: Responder is required")
	}
	switch cfg.Persona {
	case "":
		cfg.Persona = PersonaOpenAI
	case PersonaOpenAI, PersonaVLLM, PersonaOllama:
	default:
		return nil, fmt.Errorf("server: unknown persona %q", cfg.Persona)
	}
	if cfg.Version == "" {
		cfg.Version = defaultVersions[cfg.Persona]
	}
	if len(cfg.Models) == 0 {
		cfg.Models = append([]string(nil), defaultModels...)
	}
	if len(cfg.SessionKey) == 0 {
		cfg.SessionKey = randBytes(32)
	}
	if len(cfg.EmbedSeed) == 0 {
		cfg.EmbedSeed = randBytes(32)
	}
	if cfg.Redactor == nil {
		m := hmac.New(sha256.New, cfg.SessionKey)
		m.Write([]byte("redactor"))
		cfg.Redactor = telemetry.NewRedactor(m.Sum(nil))
	}
	if cfg.Sink == nil {
		cfg.Sink = telemetry.Multi{}
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if cfg.MaxMessages <= 0 {
		cfg.MaxMessages = 1024
	}
	if cfg.MaxTools <= 0 {
		cfg.MaxTools = 128
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 256
	}
	if cfg.MaxPerSource <= 0 {
		cfg.MaxPerSource = 8
	}
	if cfg.MaxStreamDuration <= 0 {
		cfg.MaxStreamDuration = 180 * time.Second
	}
	if cfg.MaxLogBody <= 0 {
		cfg.MaxLogBody = 128 << 10
	}
	if cfg.HoldSilent <= 0 {
		cfg.HoldSilent = 150 * time.Second
	}
	if cfg.IdleInterval <= 0 {
		cfg.IdleInterval = 45 * time.Second
	}
	if cfg.StatusHold <= 0 {
		cfg.StatusHold = 200 * time.Millisecond
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.After == nil {
		cfg.After = time.After
	}
	if cfg.Rand == nil {
		cfg.Rand = defaultRand
	}
	var err error
	if cfg.Timing, err = cfg.Timing.normalize(); err != nil {
		return nil, err
	}
	s := &Server{
		cfg:     cfg,
		persona: cfg.Persona,
		sem:     make(chan struct{}, cfg.MaxConcurrent),
		started: cfg.Now(),
		perSrc:  make(map[string]int),
	}
	s.routes = s.buildRoutes()
	s.openapi = s.buildOpenAPI()
	return s, nil
}

// Handler returns the HTTP handler. Wrap it in an http.Server that sets
// ReadHeaderTimeout and ReadTimeout; the handler bounds body size, not read
// time. Once the body is read the handler clears the read deadline, so
// ReadTimeout never cuts a hold short, and it sets its own write deadline.
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serve) }

// call is the state of one request.
type call struct {
	s     *Server
	w     *recorder
	r     *http.Request
	id    string
	start time.Time
	src   string
	ua    string
	key   string
	style errStyle
	rc    *http.ResponseController

	panicked  bool
	panicInfo string

	body      []byte
	tooLarge  bool
	endpoint  string
	params    map[string]string
	sessionID string

	model      string
	streaming  bool
	tools      int
	parallel   *bool
	dec        *responder.Decision
	adm        uint64              // admission tick, taken when the request arrived
	iss        *responder.Issuance // the probe response this call is sending; nil otherwise
	probeText  string
	obs        []responder.Observation
	holdResult string
	holdMS     int64
	streamCut  string // why frame emission stopped early, if it did
	noFlush    bool   // the writer cannot flush, so acceptance is unconfirmed
	termFailed bool   // the closing stream frame failed after the content was sent
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	rid := randHex(16)
	c := &call{s: s, r: r, id: rid[:16], start: s.cfg.Now(), w: &recorder{ResponseWriter: w, keep: s.logRawLimit()}}
	c.adm = s.cfg.Responder.Admit() // before any read: a probe delivered after this is not this request's
	c.rc = http.NewResponseController(w)
	c.src = s.source(r)
	c.ua = r.UserAgent()
	c.key = s.sessionKey(c.src, c.ua, r.Header)
	c.style = s.styleFor(r.URL.Path)
	c.endpoint = "/unmatched"
	s.personaHeaders(c, rid)
	defer s.finish(c)
	defer c.recoverPanic()
	defer c.finalize()
	c.extendWriteDeadline()

	release, ok := s.acquire(c.src)
	if !ok {
		c.w.Header().Set("Retry-After", "1")
		msg := "Rate limit reached for requests"
		if c.style == styleOllama {
			msg = "server busy, please try again.  maximum pending requests exceeded"
		}
		c.fail(http.StatusTooManyRequests, msg, "", "rate_limit_exceeded")
		return
	}
	defer release()

	c.readBody(w)
	// No read-deadline reset here: net/http clears the connection's read
	// deadline itself once the body hits EOF (startBackgroundRead), so a hold
	// outlives ReadTimeout. TestReadTimeoutDoesNotCutHold pins that down.
	c.extendWriteDeadline()
	h, allowed := s.lookup(c)
	switch {
	case h == nil && len(allowed) == 0:
		s.notFound(c)
	case h == nil:
		s.methodNotAllowed(c, allowed)
	case c.tooLarge:
		c.fail(http.StatusRequestEntityTooLarge, "Request body too large", "", "")
	default:
		h(c)
	}
}

// extendWriteDeadline gives the response the longest hold, the pacing budget
// and slack. Without it a client that stops reading pins the connection and
// its slot.
func (c *call) extendWriteDeadline() {
	_ = c.rc.SetWriteDeadline(time.Now().Add(c.s.cfg.MaxStreamDuration + c.s.cfg.Timing.MaxTotal + 15*time.Second))
}

// finalize settles the delivery state of the issuance on every handler exit,
// so a response nothing was written for never stays "selected".
func (c *call) finalize() {
	if c.dec != nil {
		c.dec.Issuance.Finalize()
	}
}

// recoverPanic turns a handler panic into the persona's 500. The request is
// logged with panic=true rather than as a client that left.
func (c *call) recoverPanic() {
	v := recover()
	if v == nil {
		return
	}
	if v == http.ErrAbortHandler {
		panic(v)
	}
	c.panicked = true
	c.panicInfo = truncRunes(cleanEcho(fmt.Sprint(v), 256), 256)
	c.iss.Unknown() // the 500 below is not the probe response
	c.iss = nil
	if c.w.status != 0 {
		return
	}
	msg := "Internal Server Error"
	if c.style == styleOpenAI {
		msg = "The server had an error while processing your request. Sorry about that!"
	}
	c.fail(http.StatusInternalServerError, msg, "", "")
}

// personaHeaders sets the headers every response of the persona carries. rid
// is the full 32-hex request id; the log keeps its first half.
func (s *Server) personaHeaders(c *call, rid string) {
	h := c.w.Header()
	switch s.persona {
	case PersonaOpenAI:
		// api.openai.com echoes a request id; vLLM sends none by default.
		h.Set("X-Request-Id", "req_"+rid)
	case PersonaVLLM:
		h.Set("Server", "uvicorn")
	}
}

// readBody reads the request body up to MaxBodyBytes. On overflow the first
// MaxBodyBytes are kept for the log and tooLarge is set.
func (c *call) readBody(w http.ResponseWriter) {
	if c.r.Body == nil || c.r.Body == http.NoBody {
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, c.r.Body, c.s.cfg.MaxBodyBytes))
	c.body = b
	var mbe *http.MaxBytesError
	c.tooLarge = errors.As(err, &mbe)
}

// acquire takes a global and a per-source slot.
func (s *Server) acquire(src string) (func(), bool) {
	select {
	case s.sem <- struct{}{}:
	default:
		return nil, false
	}
	s.mu.Lock()
	if s.perSrc[src] >= s.cfg.MaxPerSource {
		s.mu.Unlock()
		<-s.sem
		return nil, false
	}
	s.perSrc[src]++
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		if s.perSrc[src]--; s.perSrc[src] <= 0 {
			delete(s.perSrc, src)
		}
		s.mu.Unlock()
		<-s.sem
	}, true
}

// source returns the client address. X-Forwarded-For counts only when the
// peer is a trusted proxy; then the right-most untrusted entry wins.
func (s *Server) source(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return truncRunes(cleanEcho(host, 64), 64)
	}
	peer = peer.Unmap().WithZone("")
	if !s.trusted(peer) {
		return peer.String()
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		a = a.Unmap().WithZone("")
		if !s.trusted(a) {
			return a.String()
		}
	}
	return peer.String()
}

func (s *Server) trusted(a netip.Addr) bool {
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// sessionKey is HMAC-SHA256(SessionKey, src NUL user-agent NUL credential
// fingerprint). The source address alone never identifies a session. The
// credential is Authorization; X-Api-Key counts only when Authorization is
// absent or empty, so a client that sends both is keyed by Authorization alone.
func (s *Server) sessionKey(src, ua string, h http.Header) string {
	cred := h.Get("Authorization")
	if cred == "" {
		cred = h.Get("X-Api-Key")
	}
	m := hmac.New(sha256.New, s.cfg.SessionKey)
	m.Write([]byte(src))
	m.Write([]byte{0})
	m.Write([]byte(ua))
	m.Write([]byte{0})
	m.Write([]byte(s.cfg.Redactor.Fingerprint(cred)))
	return hex.EncodeToString(m.Sum(nil))
}

// recorder keeps the status and size of a response and its first keep bytes
// for the log. Capture is bounded: a long stream costs at most keep bytes.
type recorder struct {
	http.ResponseWriter
	status int
	n      int64
	keep   int
	head   []byte
}

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 && code >= 200 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(p)
	if room := r.keep - len(r.head); room > 0 && n > 0 {
		r.head = append(r.head, p[:min(n, room)]...)
	}
	r.n += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach the real writer.
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// wait blocks for total, in steps of at most every when idle is set. idle runs
// after each step that does not end the wait and reports whether the client is
// still writable. It returns false when the client left. The outcome goes to
// the request log.
func (c *call) wait(total, every time.Duration, idle func() bool) bool {
	s := c.s
	began := s.cfg.Now()
	ctx := c.r.Context()
	result := "completed"
	for remaining := total; remaining > 0; {
		step := remaining
		if idle != nil && step > every {
			step = every
		}
		timer := s.cfg.After(step)
		select {
		case <-timer:
		case <-ctx.Done():
			// Both can be ready at once and select picks at random. A hold
			// that ran its full duration is complete, whatever came after.
			if step < remaining || !ready(timer) {
				result = "client_closed"
				if errors.Is(context.Cause(ctx), ErrShutdown) {
					result = holdServerShutdown
				}
			}
		}
		if result != "completed" {
			break
		}
		remaining -= step
		if remaining > 0 && idle != nil && !idle() {
			result = "client_closed"
			break
		}
	}
	c.holdResult = result
	c.holdMS = s.cfg.Now().Sub(began).Milliseconds()
	if result != "completed" {
		c.iss.Cut() // a hold the client left is a delivery fact, not a reply
	}
	return result == "completed"
}

// ready reports whether ch has a value or is closed, without blocking.
func ready(ch <-chan time.Time) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// ErrShutdown is the cancel cause the process puts on the http.Server base
// context when the shutdown grace period ends. Holds cut by it are logged as
// server_shutdown, not client_closed, so telemetry does not blame the client.
var ErrShutdown = errors.New("server shutdown")

const holdServerShutdown = "server_shutdown"

// holdFor carries out a probe hold mode before or inside a response.
func (c *call) holdFor(mode string, idle func() bool) bool {
	if mode == responder.HoldNone {
		return true
	}
	total := min(c.s.cfg.HoldSilent, c.s.cfg.MaxStreamDuration)
	if mode != responder.HoldIdle {
		idle = nil
	}
	return c.wait(total, c.s.cfg.IdleInterval, idle)
}
