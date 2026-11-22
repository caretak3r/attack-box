package telemetry

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

const (
	redacted       = "[redacted]"
	maxHeaders     = 64
	maxNameLen     = 128
	infoValueLimit = 512
	miscValueLimit = 256
	canaryPrefix   = "sk-local-"
)

var credHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "x-api-key": true,
	"api-key": true, "cookie": true, "set-cookie": true, "openai-api-key": true,
	"x-goog-api-key": true, "x-auth-token": true,
}

var credFragments = []string{"token", "secret", "password", "session", "key"}

var infoHeaders = map[string]bool{
	"user-agent": true, "openai-organization": true, "openai-project": true,
	"x-request-id": true, "content-type": true, "accept": true,
	"accept-encoding": true, "content-length": true, "origin": true,
	"referer": true, "host": true, "x-forwarded-for": true, "x-real-ip": true,
}

var (
	bearerRe = regexp.MustCompile(`(?i)bearer\s+([A-Za-z0-9._~+/=-]{8,})`)
	skRe     = regexp.MustCompile(`sk-[A-Za-z0-9_-]{16,}`)
	cookieRe = regexp.MustCompile(`(?i)\b((?:set-)?cookie)\s*:[ \t]*([^\r\n]+)`)
)

// Redactor strips credentials from headers and text. Credentials are replaced
// by keyed fingerprints so reuse stays correlatable without storing the value.
type Redactor struct{ key []byte }

func NewRedactor(key []byte) *Redactor {
	return &Redactor{key: append([]byte(nil), key...)}
}

// Fingerprint is "hmac256:" plus the first 16 hex chars of HMAC-SHA256(key, v).
func (r *Redactor) Fingerprint(v string) string {
	if v == "" {
		return ""
	}
	m := hmac.New(sha256.New, r.key)
	m.Write([]byte(v))
	return "hmac256:" + hex.EncodeToString(m.Sum(nil))[:16]
}

func isCredHeader(lower string) bool {
	if credHeaders[lower] {
		return true
	}
	for _, f := range credFragments {
		if strings.Contains(lower, f) {
			return true
		}
	}
	return false
}

// Headers returns the log-safe header map and the fingerprints of credential
// headers, both keyed by canonical header name. At most 64 headers are kept,
// in name order.
func (r *Redactor) Headers(h http.Header) (safe map[string]string, credFingerprints map[string]string) {
	safe = map[string]string{}
	credFingerprints = map[string]string{}

	merged := make(map[string][]string, len(h))
	for name, vals := range h {
		name = http.CanonicalHeaderKey(truncate(name, maxNameLen))
		merged[name] = append(merged[name], vals...)
	}
	names := make([]string, 0, len(merged))
	for n := range merged {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) > maxHeaders {
		names = names[:maxHeaders]
	}

	for _, name := range names {
		val := strings.Join(merged[name], ", ")
		lower := strings.ToLower(name)
		switch {
		case lower == "authorization" || lower == "proxy-authorization":
			scheme, token := splitScheme(val)
			safe[name] = redacted
			if scheme != "" {
				safe[name] = scheme + " " + redacted
			}
			credFingerprints[name] = r.Fingerprint(token)
		case isCredHeader(lower):
			safe[name] = redacted
			credFingerprints[name] = r.Fingerprint(val)
		case infoHeaders[lower] || strings.HasPrefix(lower, "x-stainless-"):
			safe[name] = truncate(val, infoValueLimit)
		default:
			safe[name] = truncate(val, miscValueLimit)
		}
	}
	return safe, credFingerprints
}

// splitScheme splits "Bearer abc" into a letters-only scheme and the credential.
// Without a scheme the whole value is the credential.
func splitScheme(v string) (scheme, token string) {
	v = strings.TrimSpace(v)
	i := strings.IndexAny(v, " \t")
	if i <= 0 || i > 32 {
		return "", v
	}
	for _, c := range v[:i] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return "", v
		}
	}
	return v[:i], strings.TrimSpace(v[i:])
}

// Text scrubs credentials that show up inside bodies: bearer tokens, sk- API
// keys and Cookie/Set-Cookie lines. Each becomes a fingerprint. Keys starting
// with sk-local- are decoy canaries and stay visible so their reuse is
// detectable. This is pattern matching, not a guarantee: unusual secret
// shapes pass through.
func (r *Redactor) Text(s string) string {
	s = bearerRe.ReplaceAllStringFunc(s, func(m string) string {
		tok := bearerRe.FindStringSubmatch(m)[1]
		return "Bearer [redacted:" + r.Fingerprint(tok) + "]"
	})
	s = cookieRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := cookieRe.FindStringSubmatch(m)
		return sub[1] + ": [redacted:" + r.Fingerprint(sub[2]) + "]"
	})
	return skRe.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasPrefix(m, canaryPrefix) {
			return m
		}
		return "[redacted:" + r.Fingerprint(m) + "]"
	})
}

// truncate cuts s to at most n runes.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}
