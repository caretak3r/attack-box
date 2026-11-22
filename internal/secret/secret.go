// Package secret finds credential-shaped values in free text so logs and
// session state never keep them. It is pattern matching: it catches the
// common shapes (JSON and form fields, Bearer/Basic, sk- keys, cookies, URL
// userinfo) and fails toward redaction for credential-named fields. Decoy
// canary shapes stay visible so their reuse is detectable.
package secret

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"strings"
)

// Fingerprinter maps a secret to a correlatable fingerprint. nil gives a
// plain "[redacted]" marker.
type Fingerprinter func(string) string

// credWords are matched against the last segment of a field name, so
// "client_secret" and "X-Refresh-Token" match but "max_tokens" does not.
var credWords = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "passphrase": true, "pass": true,
	"secret": true, "token": true, "apikey": true, "auth": true, "authorization": true,
	"authentication": true, "cookie": true, "credential": true, "credentials": true,
	"sessionid": true, "bearer": true, "jwt": true, "signature": true, "sig": true,
}

// credPairs are two-segment suffixes such as api_key or session_id.
var credPairs = map[string]bool{
	"api key": true, "access key": true, "private key": true, "secret key": true,
	"session id": true, "license key": true, "ingest key": true, "client secret": true,
	"set cookie": true, "auth token": true, "id token": true,
}

// IsCredentialName reports whether a header, JSON key or form field name
// names a credential.
func IsCredentialName(name string) bool {
	parts := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == ' '
	})
	n := len(parts)
	if n == 0 {
		return false
	}
	if credWords[parts[n-1]] {
		return true
	}
	return n >= 2 && credPairs[parts[n-2]+" "+parts[n-1]]
}

var canaryRe = regexp.MustCompile(`^(?:sk-local-[0-9a-f]{36}|dpl-[0-9a-f]{20}|tk_[0-9a-f]{12}\.[0-9a-f]{32})$`)

// IsCanary reports whether v has the exact shape of a decoy canary.
func IsCanary(v string) bool { return canaryRe.MatchString(v) }

const fieldName = `([A-Za-z][A-Za-z0-9_.-]{0,63})`

var (
	// "name": "value" and its escaped form inside a JSON string.
	jsonFieldRe    = regexp.MustCompile(`"` + fieldName + `"(\s*:\s*)"((?:[^"\\]|\\.)*)"`)
	escapedFieldRe = regexp.MustCompile(`\\"` + fieldName + `\\"(\s*:\s*)\\"((?:[^"\\]|\\[^"])*)\\"`)
	// name=value or name: value in forms, queries, env files and YAML.
	kvRe       = regexp.MustCompile(`\b` + fieldName + `([ \t]*[=:][ \t]*)([^\s"'&,;<>?#]+)`)
	bearerRe   = regexp.MustCompile(`(?i)\b(bearer)[ \t]+([A-Za-z0-9._~+/=-]+)`)
	basicRe    = regexp.MustCompile(`(?i)\b(basic)[ \t]+([A-Za-z0-9+/]{4,}={0,2})`)
	skRe       = regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{8,}`)
	authLineRe = regexp.MustCompile(`(?i)\b((?:proxy-)?authori[sz]ation)[ \t]*:[ \t]*(?:(bearer|basic|digest|token|negotiate|ntlm)[ \t]+)?([^\s"']+)`)
	cookieRe   = regexp.MustCompile(`(?i)\b((?:set-)?cookie)[ \t]*:[ \t]*([^\r\n]+)`)
	userinfoRe = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]{0,31}://)([^/\s:@"'<>]{1,256}):([^/\s@"'<>]{1,256})@`)
)

// isBasicCredential reports whether v decodes to "user:password", so prose
// such as "basic idea" is left alone.
func isBasicCredential(v string) bool {
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(v)
	}
	return err == nil && bytes.IndexByte(b, ':') > 0
}

var authSchemes = map[string]bool{
	"bearer": true, "basic": true, "digest": true, "token": true, "negotiate": true, "ntlm": true,
}

// proseWords are not secrets when they follow "bearer" or "token".
var proseWords = map[string]bool{
	"token": true, "tokens": true, "auth": true, "authentication": true, "authorization": true,
	"header": true, "headers": true, "scheme": true, "credential": true, "credentials": true,
	"string": true, "value": true, "the": true, "a": true, "an": true, "and": true, "or": true,
	"is": true, "in": true, "to": true, "for": true, "of": true, "with": true, "from": true,
}

// Scrub replaces credentials in s with "[redacted]" or "[redacted:<fp>]".
func Scrub(s string, fp Fingerprinter) string {
	mark := func(v string) string {
		if fp == nil {
			return "[redacted]"
		}
		return "[redacted:" + fp(v) + "]"
	}
	keep := func(v string) bool {
		return v == "" || IsCanary(v) || strings.HasPrefix(v, "[redacted")
	}
	field := func(re *regexp.Regexp, open, close string) func(string) string {
		return func(m string) string {
			sub := re.FindStringSubmatch(m)
			if !IsCredentialName(sub[1]) || keep(sub[3]) {
				return m
			}
			return open + sub[1] + close + sub[2] + open + mark(sub[3]) + close
		}
	}
	s = jsonFieldRe.ReplaceAllStringFunc(s, field(jsonFieldRe, `"`, `"`))
	s = escapedFieldRe.ReplaceAllStringFunc(s, field(escapedFieldRe, `\"`, `\"`))
	s = cookieRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := cookieRe.FindStringSubmatch(m)
		return sub[1] + ": " + mark(sub[2])
	})
	s = authLineRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := authLineRe.FindStringSubmatch(m)
		if keep(sub[3]) {
			return m
		}
		scheme := ""
		if sub[2] != "" {
			scheme = sub[2] + " "
		}
		return sub[1] + ": " + scheme + mark(sub[3])
	})
	s = kvRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := kvRe.FindStringSubmatch(m)
		if !IsCredentialName(sub[1]) || keep(sub[3]) || authSchemes[strings.ToLower(sub[3])] {
			return m
		}
		return sub[1] + sub[2] + mark(sub[3])
	})
	s = bearerRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := bearerRe.FindStringSubmatch(m)
		if proseWords[strings.ToLower(sub[2])] || keep(sub[2]) {
			return m
		}
		return sub[1] + " " + mark(sub[2])
	})
	s = basicRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := basicRe.FindStringSubmatch(m)
		if !isBasicCredential(sub[2]) {
			return m
		}
		return sub[1] + " " + mark(sub[2])
	})
	s = userinfoRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := userinfoRe.FindStringSubmatch(m)
		if keep(sub[3]) {
			return m
		}
		return sub[1] + sub[2] + ":" + mark(sub[3]) + "@"
	})
	return skRe.ReplaceAllStringFunc(s, func(m string) string {
		if keep(m) || strings.HasPrefix(m, "sk-local-") {
			return m
		}
		return mark(m)
	})
}
