package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"attackbox/internal/telemetry"
)

// minSecret is the shortest accepted secret file, in bytes.
const minSecret = 32

// Upper bounds for the resource settings. A larger value is an operator
// error that would let one host exhaust memory, not a tuning choice.
const (
	maxSessionsCap  = 100_000
	maxBodyCap      = 16 << 20
	maxLogBodyCap   = 1 << 20
	maxInFlightCap  = 10_000
	maxPerSourceCap = 1_000
	maxDurationCap  = time.Hour
)

// listener is one persona bound to one address.
type listener struct {
	persona string
	addr    string
}

// config is the process configuration, read from ATTACKBOX_* variables.
type config struct {
	listeners []listener

	models         []string
	trustedProxies []netip.Prefix
	instance       string

	// secret derives the session, embedding and redaction keys. It comes
	// from ATTACKBOX_SECRET_FILE; without it, keys are random per process.
	secret     []byte
	secretFile string

	nrDisabled  bool
	nrKey       string
	nrLogURL    string
	nrMetricURL string

	maxSessions  int
	maxBody      int64
	maxLogBody   int
	maxPerSource int
	maxInFlight  int
	holdSilent   time.Duration
	idleInterval time.Duration
	maxStream    time.Duration
	timing       bool // realistic response pacing; ATTACKBOX_TIMING, default true

	readHeaderTimeout time.Duration
	readTimeout       time.Duration
	idleTimeout       time.Duration
	shutdownTimeout   time.Duration
}

// loadConfig reads and validates the configuration. getenv is os.Getenv in
// production and a map lookup in tests.
func loadConfig(getenv func(string) string) (config, error) {
	var errs []error
	env := func(name, def string) string {
		if v := strings.TrimSpace(getenv("ATTACKBOX_" + name)); v != "" {
			return v
		}
		return def
	}
	dur := func(name string, def time.Duration) time.Duration {
		v := env(name, "")
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 || d > maxDurationCap {
			errs = append(errs, fmt.Errorf("ATTACKBOX_%s: want a positive duration up to %v such as 30s, got %q", name, maxDurationCap, v))
			return def
		}
		return d
	}
	num := func(name string, def, limit int) int {
		v := env(name, "")
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > limit {
			errs = append(errs, fmt.Errorf("ATTACKBOX_%s: want an integer from 1 to %d, got %q", name, limit, v))
			return def
		}
		return n
	}
	flag := func(name string, def bool) bool {
		switch strings.ToLower(env(name, strconv.FormatBool(def))) {
		case "1", "true", "yes":
			return true
		case "0", "false", "no":
			return false
		}
		errs = append(errs, fmt.Errorf("ATTACKBOX_%s: want true or false", name))
		return def
	}

	c := config{
		instance:          env("INSTANCE", "attackbox"),
		secretFile:        env("SECRET_FILE", ""),
		nrDisabled:        flag("NR_DISABLED", false),
		nrKey:             strings.TrimSpace(getenv("ATTACKBOX_NR_LICENSE_KEY")),
		nrLogURL:          env("NR_LOG_URL", ""),
		nrMetricURL:       env("NR_METRIC_URL", ""),
		maxSessions:       num("MAX_SESSIONS", 10000, maxSessionsCap),
		maxBody:           int64(num("MAX_BODY_BYTES", 1<<20, maxBodyCap)),
		maxLogBody:        num("MAX_LOG_BODY", 128<<10, maxLogBodyCap),
		maxPerSource:      num("MAX_PER_SOURCE", 8, maxPerSourceCap),
		maxInFlight:       num("MAX_IN_FLIGHT", 256, maxInFlightCap),
		holdSilent:        dur("HOLD_SILENT", 150*time.Second),
		idleInterval:      dur("IDLE_INTERVAL", 45*time.Second),
		maxStream:         dur("MAX_STREAM", 180*time.Second),
		timing:            flag("TIMING", true),
		readHeaderTimeout: dur("READ_HEADER_TIMEOUT", 10*time.Second),
		readTimeout:       dur("READ_TIMEOUT", 30*time.Second),
		idleTimeout:       dur("IDLE_TIMEOUT", 60*time.Second),
		shutdownTimeout:   dur("SHUTDOWN_TIMEOUT", 15*time.Second),
	}
	if !validLabel(c.instance) {
		errs = append(errs, errors.New("ATTACKBOX_INSTANCE: use 1-64 characters from [A-Za-z0-9._-]"))
	}
	if c.holdSilent > c.maxStream {
		errs = append(errs, errors.New("ATTACKBOX_HOLD_SILENT must not exceed ATTACKBOX_MAX_STREAM"))
	}
	if c.maxPerSource > c.maxInFlight {
		errs = append(errs, errors.New("ATTACKBOX_MAX_PER_SOURCE must not exceed ATTACKBOX_MAX_IN_FLIGHT"))
	}

	var used []boundAddr
	for _, l := range []struct{ persona, name, def string }{
		{"openai", "OPENAI_ADDR", "127.0.0.1:8080"},
		{"vllm", "VLLM_ADDR", "off"},
		{"ollama", "OLLAMA_ADDR", "off"},
	} {
		a := env(l.name, l.def)
		if strings.EqualFold(a, "off") {
			continue
		}
		host, port, err := splitAddr(a)
		if err != nil {
			errs = append(errs, fmt.Errorf("ATTACKBOX_%s: %v", l.name, err))
			continue
		}
		if other := conflict(used, host, port); other != "" {
			errs = append(errs, fmt.Errorf("ATTACKBOX_%s: address %s is already used by %s", l.name, a, other))
			continue
		}
		used = append(used, boundAddr{host, port, l.persona})
		c.listeners = append(c.listeners, listener{l.persona, a})
	}
	if len(c.listeners) == 0 {
		errs = append(errs, errors.New("no listener enabled: set ATTACKBOX_OPENAI_ADDR, ATTACKBOX_VLLM_ADDR or ATTACKBOX_OLLAMA_ADDR"))
	}

	for _, m := range splitList(env("MODELS", "")) {
		if len(m) > 128 || strings.ContainsFunc(m, func(r rune) bool { return r < 0x21 || r == 0x7f }) {
			errs = append(errs, fmt.Errorf("ATTACKBOX_MODELS: invalid model name %q", m))
			continue
		}
		c.models = append(c.models, m)
	}
	for _, p := range splitList(env("TRUSTED_PROXIES", "")) {
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			addr, aerr := netip.ParseAddr(p)
			if aerr != nil {
				errs = append(errs, fmt.Errorf("ATTACKBOX_TRUSTED_PROXIES: %q is not an IP or CIDR", p))
				continue
			}
			pfx = netip.PrefixFrom(addr, addr.BitLen())
		}
		c.trustedProxies = append(c.trustedProxies, pfx.Masked())
	}

	switch {
	case c.nrDisabled && c.nrKey != "":
		errs = append(errs, errors.New("ATTACKBOX_NR_DISABLED=true conflicts with ATTACKBOX_NR_LICENSE_KEY; unset one"))
	case !c.nrDisabled && c.nrKey == "":
		errs = append(errs, errors.New("ATTACKBOX_NR_LICENSE_KEY is required; set ATTACKBOX_NR_DISABLED=true to log locally only"))
	}
	if !c.nrDisabled && c.nrKey != "" {
		if err := telemetry.ValidLicenseKey(c.nrKey); err != nil {
			errs = append(errs, fmt.Errorf("ATTACKBOX_NR_LICENSE_KEY: %v", err))
		}
	}

	if c.secretFile != "" {
		b, err := readSecret(c.secretFile)
		if err != nil {
			errs = append(errs, fmt.Errorf("ATTACKBOX_SECRET_FILE: %w", err))
		}
		c.secret = b
	}
	if err := errors.Join(errs...); err != nil {
		return config{}, err
	}
	if c.secret == nil {
		c.secret = make([]byte, minSecret)
		if _, err := rand.Read(c.secret); err != nil {
			return config{}, err
		}
	}
	return c, nil
}

// readSecret reads a key file that only its owner can read. A group- or
// world-readable key would let any local process forge session IDs and
// reverse redaction fingerprints.
func readSecret(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("mode %#o is readable by group or others; use 0600 or 0400", perm)
	}
	if info.Size() > 4096 {
		return nil, fmt.Errorf("file is %d bytes; at most 4096 are allowed", info.Size())
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return nil, err
	}
	if len(b) < minSecret {
		return nil, fmt.Errorf("need at least %d bytes, got %d", minSecret, len(b))
	}
	return b, nil
}

// derive returns a purpose-specific key so no two uses share key material.
func (c config) derive(purpose string) []byte {
	m := hmac.New(sha256.New, c.secret)
	m.Write([]byte("attackbox/" + purpose))
	return m.Sum(nil)
}

func splitList(v string) []string {
	var out []string
	for _, f := range strings.Split(v, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// wildcard reports hosts that bind every interface.
func wildcard(host string) bool {
	return host == "" || host == "0.0.0.0" || host == "::"
}

type boundAddr struct {
	host    string
	port    int
	persona string
}

// conflict returns the persona already bound to port on an overlapping host.
// Port 0 picks a free port, so it never conflicts.
func conflict(used []boundAddr, host string, port int) string {
	if port == 0 {
		return ""
	}
	for _, u := range used {
		if u.port == port && (u.host == host || wildcard(u.host) || wildcard(host)) {
			return u.persona
		}
	}
	return ""
}

func splitAddr(a string) (host string, port int, err error) {
	i := strings.LastIndexByte(a, ':')
	if i < 0 {
		return "", 0, fmt.Errorf("%q: want host:port or :port", a)
	}
	host = strings.Trim(a[:i], "[]")
	port, err = strconv.Atoi(a[i+1:])
	if err != nil || port < 0 || port > 65535 {
		return "", 0, fmt.Errorf("%q: invalid port", a)
	}
	if host != "" && host != "localhost" {
		if _, perr := netip.ParseAddr(host); perr != nil {
			return "", 0, fmt.Errorf("%q: host must be an IP address", a)
		}
	}
	return host, port, nil
}

func validLabel(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
