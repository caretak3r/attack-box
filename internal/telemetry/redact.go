package telemetry

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"

	"attackbox/internal/secret"
)

const (
	redacted       = "[redacted]"
	maxHeaders     = 64
	maxNameLen     = 128
	infoValueLimit = 512
	miscValueLimit = 256
)

var credHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "x-api-key": true,
	"api-key": true, "cookie": true, "set-cookie": true, "openai-api-key": true,
	"x-goog-api-key": true, "x-auth-token": true,
}

var credFragments = []string{"token", "secret", "password", "passwd", "session", "key", "auth", "credential", "cookie"}

var infoHeaders = map[string]bool{
	"user-agent": true, "openai-organization": true, "openai-project": true,
	"x-request-id": true, "content-type": true, "accept": true,
	"accept-encoding": true, "content-length": true, "origin": true,
	"referer": true, "host": true, "x-forwarded-for": true, "x-real-ip": true,
}

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
	if credHeaders[lower] || secret.IsCredentialName(lower) {
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
			safe[name] = truncate(r.Text(val), infoValueLimit)
		default:
			safe[name] = truncate(r.Text(val), miscValueLimit)
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

// Text scrubs credentials inside bodies and free-form values with
// secret.Scrub; each becomes a keyed fingerprint. Decoy canaries stay visible
// so their reuse is detectable.
func (r *Redactor) Text(s string) string { return secret.Scrub(s, r.Fingerprint) }

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
