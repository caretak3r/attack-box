// Package server is the public HTTP surface of the bait service. It speaks
// three local-inference dialects (generic OpenAI-compatible, vLLM and
// Ollama), answers every inference request from responder templates, and logs
// every request. It never calls a model, never makes an outbound request and
// never acts on request content.
package server

import (
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
	MaxMessages       int           // messages, input items and prompts per request; default 256
	MaxTools          int           // tools per request; default 64
	MaxConcurrent     int           // in-flight requests, all sources; default 256
	MaxPerSource      int           // in-flight requests per source; default 8
	MaxStreamDuration time.Duration // longest hold; default 180s
	MaxLogBody        int           // request body bytes kept in a log event; default 128 KiB
	HoldSilent        time.Duration // hold length of the timeout gates; default 150s
	IdleInterval      time.Duration // keepalive spacing in the idle hold; default 45s
	StatusHold        time.Duration // hold of /v1/edge/{A-D}/status; default 200ms

	// TrustedProxies lists peers whose X-Forwarded-For is believed.
	TrustedProxies []netip.Prefix

	Now   func() time.Time                     // default time.Now
	After func(time.Duration) <-chan time.Time // default time.After
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
		cfg.MaxMessages = 256
	}
	if cfg.MaxTools <= 0 {
		cfg.MaxTools = 64
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
// time.
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
	probeText  string
	obs        []responder.Observation
	holdResult string
	holdMS     int64
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	c := &call{s: s, r: r, id: randHex(8), start: s.cfg.Now(), w: &recorder{ResponseWriter: w}}
	c.src = s.source(r)
	c.ua = r.UserAgent()
	c.key = s.sessionKey(c.src, c.ua, r.Header)
	c.style = s.styleFor(r.URL.Path)
	c.endpoint = "/unmatched"
	s.personaHeaders(c)
	defer s.finish(c)

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

// personaHeaders sets the headers every response of the persona carries.
func (s *Server) personaHeaders(c *call) {
	h := c.w.Header()
	switch s.persona {
	case PersonaOpenAI:
		// api.openai.com echoes a request id; vLLM sends none by default.
		h.Set("X-Request-Id", c.id)
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
// fingerprint). The source address alone never identifies a session.
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

// recorder keeps the status and size of a response.
type recorder struct {
	http.ResponseWriter
	status int
	n      int64
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
		select {
		case <-s.cfg.After(step):
		case <-ctx.Done():
			result = "client_closed"
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
	return result == "completed"
}

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
