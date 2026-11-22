// Package secret finds credential-shaped values in free text so logs and
// session state never keep them. It is pattern matching, not a proof: it
// catches JSON fields (any value type, escaped names, one level of JSON
// nested in a string), form/query/env/YAML pairs (bare or quoted),
// Authorization lines, Bearer/Basic values, sk- keys, cookies, URL userinfo
// passwords and PEM private-key blocks. Exact decoy canary shapes stay
// visible so their reuse is detectable. Free-text secrets with no name, scheme
// or known shape are not detected; the dedicated New Relic account is the
// remaining blast-radius control.
package secret

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Fingerprinter maps a secret to a correlatable fingerprint. Output that is
// not "hmac256:" plus 16 lowercase hex chars is discarded and the plain
// "[redacted]" marker is used, so a callback can never re-emit a secret.
type Fingerprinter func(string) string

var (
	fpRe     = regexp.MustCompile(`^hmac256:[0-9a-f]{16}$`)
	markerRe = regexp.MustCompile(`^\[redacted(?::hmac256:[0-9a-f]{16})?\]`)
)

// IsMarker reports whether v is exactly one redaction marker. A value that
// only starts with a marker is not a marker.
func IsMarker(v string) bool {
	m := markerRe.FindStringIndex(v)
	return m != nil && m[1] == len(v)
}

// credWords are matched against the last segment of a field name, so
// "client_secret", "accessToken" and "X-Refresh-Token" match but
// "max_tokens" does not.
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

var uEscRe = regexp.MustCompile(`\\u[0-9A-Fa-f]{4}`)

// canonicalName undoes JSON \u escapes (at any nesting level) and
// percent-encoding in a field name. Only the name is decoded; payload bytes
// are never rewritten.
func canonicalName(name string) string {
	if !strings.ContainsAny(name, `\%+`) {
		return name
	}
	for strings.Contains(name, `\\`) {
		name = strings.ReplaceAll(name, `\\`, `\`)
	}
	name = uEscRe.ReplaceAllStringFunc(name, func(m string) string {
		r, _ := strconv.ParseUint(m[2:], 16, 32)
		return string(rune(r))
	})
	if u, err := url.QueryUnescape(name); err == nil {
		name = u
	}
	return name
}

// nameParts lowercases a name and splits it on punctuation and camelCase
// boundaries: "XApiKey" -> x api key, "clientSecret" -> client secret.
func nameParts(name string) []string {
	rs := []rune(name)
	var parts []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			parts = append(parts, string(cur))
			cur = cur[:0]
		}
	}
	for i, r := range rs {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush()
			continue
		}
		if unicode.IsUpper(r) && i > 0 {
			p := rs[i-1]
			if unicode.IsLower(p) || unicode.IsDigit(p) ||
				(unicode.IsUpper(p) && i+1 < len(rs) && unicode.IsLower(rs[i+1])) {
				flush()
			}
		}
		cur = append(cur, unicode.ToLower(r))
	}
	flush()
	return parts
}

// IsCredentialName reports whether a header, JSON key or form field name
// names a credential.
func IsCredentialName(name string) bool {
	parts := nameParts(canonicalName(name))
	n := len(parts)
	if n == 0 {
		return false
	}
	if credWords[parts[n-1]] {
		return true
	}
	return n >= 2 && credPairs[parts[n-2]+" "+parts[n-1]]
}

var (
	canaryRe    = regexp.MustCompile(`^(?:sk-local-[0-9a-f]{36}|dpl-[0-9a-f]{20}|tk_[0-9a-f]{12}\.[0-9a-f]{32})$`)
	jwtCanaryRe = regexp.MustCompile(`^eyJhbGciOiJIUzI1NiJ9\.([A-Za-z0-9_-]{31})\.[A-Za-z0-9_-]{32}$`)
	jwtSubRe    = regexp.MustCompile(`^\{"sub":"edge-[0-9a-f]{8}"\}$`)
)

// IsCanary reports whether v has the exact shape of a decoy canary issued by
// the responder: sk-local-, dpl-, tk_ token.secret or the edge-* JWT.
func IsCanary(v string) bool {
	if canaryRe.MatchString(v) {
		return true
	}
	m := jwtCanaryRe.FindStringSubmatch(v)
	if m == nil {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(m[1])
	return err == nil && jwtSubRe.Match(b)
}

func keep(v string) bool { return v == "" || IsCanary(v) || IsMarker(v) }

// nameClass is a field name: plain characters, percent escapes, or JSON \u
// escapes at up to three nesting levels.
const nameClass = `(?:[A-Za-z0-9_.+-]|%[0-9A-Fa-f]{2}|\\{1,3}u[0-9A-Fa-f]{4}){1,64}`

// bareValue stops at whitespace, quotes and JSON string escapes such as \n,
// so a value inside a JSON string never swallows the closing quote.
const bareValue = `(?:[^\s"'\\&,;<>?#]|\\[^"nrt])+`

var (
	jsonKeyRe = regexp.MustCompile(`"(` + nameClass + `)"\s*:\s*`)
	schemaRe  = regexp.MustCompile(`"type"\s*:\s*"(?:string|number|integer|boolean|object|array|null)"`)
	// \"name\": \"value\" or a number, one JSON level down inside a string.
	escapedFieldRe = regexp.MustCompile(`\\"(` + nameClass + `)\\"(\s*:\s*)(?:\\"((?:\\\\(?:\\.|[^\\"])|\\[^\\"]|[^\\"])*)\\"|(-?[0-9][0-9.eE+-]*))`)
	// name=value or name: value in forms, queries, env files and YAML.
	kvRe       = regexp.MustCompile(`(^|\\[nrt]|[^A-Za-z0-9_.+%\\-])(` + nameClass + `)([ \t]*[=:][ \t]*)("(?:[^"\\\n]|\\.)*"|\\"(?:[^"\\]|\\[^"])*\\"|'[^'\n]*'|` + bareValue + `)`)
	pemRe      = regexp.MustCompile(`-----BEGIN ([A-Z0-9 ]{0,40}PRIVATE KEY)-----((?:[^"\\]|\\[^"])*?)(-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|\\"|"|$)`)
	bearerRe   = regexp.MustCompile(`(?i)\b(bearer)[ \t]+([A-Za-z0-9._~+/=-]+)`)
	basicRe    = regexp.MustCompile(`(?i)\b(basic)[ \t]+([A-Za-z0-9+/]{4,}={0,2})`)
	skRe       = regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{8,}`)
	authLineRe = regexp.MustCompile(`(?i)\b((?:proxy-)?authori[sz]ation)[ \t]*:[ \t]*(?:(bearer|basic|digest|token|negotiate|ntlm)[ \t]+)?(` + `(?:[^\s"'\\]|\\[^"nrt])+)`)
	cookieRe   = regexp.MustCompile(`(?i)\b((?:set-)?cookie)[ \t]*:[ \t]*((?:[^\r\n"\\]|\\[^"nrt])+)`)
	userinfoRe = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]{0,31}://)([^/\s:@"'<>\\]*):((?:[^/\s@"'<>\\]|\\[^"nrt])+)@`)
)

// isBasicCredential reports whether v decodes to "user:password" (the user
// may be empty), so prose such as "basic idea" is left alone.
func isBasicCredential(v string) bool {
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(v)
	}
	return err == nil && bytes.IndexByte(b, ':') >= 0
}

var authSchemes = map[string]bool{
	"bearer": true, "basic": true, "digest": true, "token": true, "negotiate": true, "ntlm": true,
}

// ownPass names have dedicated passes that keep cookie names and auth
// schemes; the generic name=value pass must not re-redact their output.
var ownPass = map[string]bool{
	"cookie": true, "set-cookie": true, "authorization": true, "authorisation": true,
	"proxy-authorization": true, "proxy-authorisation": true,
}

// proseWords are not secrets when they follow "bearer".
var proseWords = map[string]bool{
	"token": true, "tokens": true, "auth": true, "authentication": true, "authorization": true,
	"header": true, "headers": true, "scheme": true, "credential": true, "credentials": true,
	"string": true, "value": true, "the": true, "a": true, "an": true, "and": true, "or": true,
	"is": true, "in": true, "to": true, "for": true, "of": true, "with": true, "from": true,
}

// tokenLike separates "Bearer x9.q" from prose such as "bearer bonds": a
// free-text bearer value must contain a digit or token punctuation, or be at
// least 16 characters. Authorization lines are redacted regardless.
func tokenLike(v string) bool {
	return len(v) >= 16 || strings.ContainsAny(v, "0123456789._~+/=-")
}

// Scrub replaces credentials in s with "[redacted]" or
// "[redacted:hmac256:<hex>]". Nonsecret bytes, including JSON keys, siblings,
// whitespace and escapes, are kept unchanged. Fingerprints cover the
// credential after JSON unescaping, quote removal and auth-scheme removal, so
// the same token sent as a header and as a JSON field correlates.
func Scrub(s string, fp Fingerprinter) string {
	mark := func(v string) string {
		if fp != nil {
			if f := fp(v); fpRe.MatchString(f) {
				return "[redacted:" + f + "]"
			}
		}
		return "[redacted]"
	}
	s = scrubJSON(s, mark)
	s = replaceSub(escapedFieldRe, s, func(sub []string) string {
		m := sub[0]
		if !IsCredentialName(sub[1]) {
			return m
		}
		head := `\"` + sub[1] + `\"` + sub[2]
		if sub[4] != "" {
			return head + `\"` + mark(sub[4]) + `\"`
		}
		v := unquote(unquote(sub[3]))
		if keep(v) || keep(sub[3]) {
			return m
		}
		return head + `\"` + mark(v) + `\"`
	})
	s = replaceSub(pemRe, s, func(sub []string) string {
		m := sub[0]
		if keep(sub[2]) {
			return m
		}
		return "-----BEGIN " + sub[1] + "-----" + mark(sub[2]) + sub[3]
	})
	s = replaceSub(authLineRe, s, func(sub []string) string {
		m := sub[0]
		if keep(sub[3]) {
			return m
		}
		return m[:len(m)-len(sub[3])] + mark(sub[3])
	})
	s = replaceSub(kvRe, s, func(sub []string) string {
		m := sub[0]
		v, open, close := sub[4], "", ""
		switch {
		case strings.HasPrefix(v, `\"`):
			open, close = `\"`, `\"`
		case v[0] == '"' || v[0] == '\'':
			open, close = v[:1], v[:1]
		}
		inner := v[len(open) : len(v)-len(close)]
		if !IsCredentialName(sub[2]) || ownPass[strings.ToLower(sub[2])] || keep(inner) || authSchemes[strings.ToLower(inner)] {
			return m
		}
		return sub[1] + sub[2] + sub[3] + open + mark(inner) + close
	})
	s = replaceSub(cookieRe, s, func(sub []string) string {
		m := sub[0]
		return m[:len(m)-len(sub[2])] + scrubCookie(sub[2], mark)
	})
	s = replaceSub(bearerRe, s, func(sub []string) string {
		m := sub[0]
		if proseWords[strings.ToLower(sub[2])] || keep(sub[2]) || !tokenLike(sub[2]) {
			return m
		}
		return sub[1] + " " + mark(sub[2])
	})
	s = replaceSub(basicRe, s, func(sub []string) string {
		m := sub[0]
		if !isBasicCredential(sub[2]) {
			return m
		}
		return sub[1] + " " + mark(sub[2])
	})
	s = replaceSub(userinfoRe, s, func(sub []string) string {
		m := sub[0]
		if keep(sub[3]) {
			return m
		}
		return sub[1] + sub[2] + ":" + mark(sub[3]) + "@"
	})
	return skRe.ReplaceAllStringFunc(s, func(m string) string {
		if keep(m) {
			return m
		}
		return mark(m)
	})
}

// scrubCookie redacts every cookie value but keeps names, separators, exact
// canaries and existing markers.
func scrubCookie(v string, mark func(string) string) string {
	parts := strings.Split(v, ";")
	for i, p := range parts {
		body := strings.TrimSpace(p)
		if body == "" {
			continue
		}
		lead := strings.Index(p, body)
		eq := strings.IndexByte(body, '=')
		switch {
		case eq < 0 && !keep(body):
			body = mark(body)
		case eq >= 0 && !keep(body[eq+1:]):
			body = body[:eq+1] + mark(body[eq+1:])
		}
		parts[i] = p[:lead] + body + p[lead+len(strings.TrimSpace(p)):]
	}
	return strings.Join(parts, ";")
}

// unquote decodes JSON string escapes; on error it returns v unchanged.
func unquote(v string) string {
	if !strings.ContainsRune(v, '\\') {
		return v
	}
	var out string
	if json.Unmarshal([]byte(`"`+v+`"`), &out) != nil {
		return v
	}
	return out
}

type edit struct {
	start, end int
	repl       string
}

// scrubJSON finds "name": value pairs and, for credential names, replaces the
// whole value span: strings, numbers, bare words, and every string or number
// leaf of an array or object (keys stay). An object that looks like a JSON
// Schema property ("type":"string") is a tool definition, not a secret, so
// only credential-named fields inside it are redacted. Replacements are JSON
// strings, so valid JSON stays valid.
func scrubJSON(s string, mark func(string) string) string {
	if strings.IndexByte(s, '"') < 0 {
		return s
	}
	var edits []edit
	for pos := 0; pos < len(s); {
		loc := jsonKeyRe.FindStringSubmatchIndex(s[pos:])
		if loc == nil {
			break
		}
		cred := IsCredentialName(s[pos+loc[2] : pos+loc[3]])
		v := pos + loc[1]
		pos = v
		if v >= len(s) {
			break
		}
		switch c := s[v]; {
		case c == '"':
			end, closed := stringEnd(s, v)
			if cred {
				if e, ok := stringEdit(s, v, end, closed, mark); ok {
					edits = append(edits, e)
				}
				pos = end
			} else if closed && valueFollows(s, end) {
				pos = end
			} else {
				// Not a well-formed value: the quote may belong to a later
				// key, so rescan from inside rather than skip past it.
				pos = v + 1
			}
		case c == '-' || isDigit(c):
			end := numberEnd(s, v)
			if cred {
				edits = append(edits, edit{v, end, `"` + mark(s[v:end]) + `"`})
			}
			pos = end
		case c == '[' && markerRe.MatchString(s[v:]) || c != '{' && c != '[':
			if cred {
				end := bareEnd(s, v)
				if w := s[v:end]; w != "true" && w != "false" && w != "null" && !keep(w) {
					edits = append(edits, edit{v, end, mark(w)})
				}
				pos = end
			}
		case cred:
			end := skipBalanced(s, v)
			if c == '[' || !schemaRe.MatchString(s[v:end]) {
				edits = leafEdits(s, v, end, mark, edits)
				pos = end
			}
		}
	}
	return applyEdits(s, edits)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// stringEnd returns the index after the closing quote of the string starting
// at s[i] == '"', or len(s) and false when the string is unterminated.
func stringEnd(s string, i int) (int, bool) {
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '"':
			return j + 1, true
		}
	}
	return len(s), false
}

func numberEnd(s string, i int) int {
	j := i + 1
	for j < len(s) && strings.IndexByte("0123456789.eE+-", s[j]) >= 0 {
		j++
	}
	return j
}

// bareEnd ends a non-JSON value at whitespace or a JSON delimiter. A leading
// marker is skipped first so "[redacted]x" is judged as one word.
func bareEnd(s string, i int) int {
	if m := markerRe.FindStringIndex(s[i:]); m != nil {
		i += m[1]
	}
	for i < len(s) && strings.IndexByte(" \t\r\n,}]\"\\", s[i]) < 0 {
		i++
	}
	return i
}

// skipBalanced returns the index after the bracket that closes s[i], or
// len(s) if the input is truncated.
func skipBalanced(s string, i int) int {
	depth := 0
	for j := i; j < len(s); j++ {
		switch s[j] {
		case '"':
			end, _ := stringEnd(s, j)
			j = end - 1
		case '{', '[':
			depth++
		case '}', ']':
			if depth--; depth == 0 {
				return j + 1
			}
		}
	}
	return len(s)
}

func stringEdit(s string, i, end int, closed bool, mark func(string) string) (edit, bool) {
	raw, tail := s[i+1:end], ""
	if closed {
		raw, tail = s[i+1:end-1], `"`
	}
	v := unquote(raw)
	if keep(v) || keep(raw) {
		return edit{}, false
	}
	return edit{i, end, `"` + mark(v) + tail}, true
}

// leafEdits redacts every string and number in s[start:end] that is not an
// object key.
func leafEdits(s string, start, end int, mark func(string) string, edits []edit) []edit {
	for j := start; j < end; {
		switch c := s[j]; {
		case c == '"':
			k, closed := stringEnd(s, j)
			n := k
			for n < len(s) && strings.IndexByte(" \t\r\n", s[n]) >= 0 {
				n++
			}
			if n >= len(s) || s[n] != ':' {
				if e, ok := stringEdit(s, j, k, closed, mark); ok {
					edits = append(edits, e)
				}
			}
			j = k
		case c == '-' || isDigit(c):
			k := numberEnd(s, j)
			edits = append(edits, edit{j, k, `"` + mark(s[j:k]) + `"`})
			j = k
		default:
			j++
		}
	}
	return edits
}

func applyEdits(s string, edits []edit) string {
	if len(edits) == 0 {
		return s
	}
	slices.SortFunc(edits, func(a, b edit) int { return a.start - b.start })
	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for _, e := range edits {
		if e.start < last {
			continue
		}
		b.WriteString(s[last:e.start])
		b.WriteString(e.repl)
		last = e.end
	}
	b.WriteString(s[last:])
	return b.String()
}

// replaceSub is ReplaceAllStringFunc with the submatches from the original
// context, so each pass runs the regex once instead of once more per hit.
func replaceSub(re *regexp.Regexp, s string, f func(sub []string) string) string {
	locs := re.FindAllStringSubmatchIndex(s, -1)
	if locs == nil {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	sub := make([]string, re.NumSubexp()+1)
	last := 0
	for _, loc := range locs {
		for i := range sub {
			sub[i] = ""
			if loc[2*i] >= 0 {
				sub[i] = s[loc[2*i]:loc[2*i+1]]
			}
		}
		b.WriteString(s[last:loc[0]])
		b.WriteString(f(sub))
		last = loc[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// valueFollows reports whether s[i:] can continue after a JSON value.
func valueFollows(s string, i int) bool {
	for ; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\r', '\n':
		case ',', '}', ']', ':':
			return true
		default:
			return false
		}
	}
	return true
}
