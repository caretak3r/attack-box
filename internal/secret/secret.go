// Package secret finds credential-shaped values in free text so logs and
// session state never keep them. It is pattern matching, not a proof: it
// catches JSON fields (any value type, escaped names, one level of JSON
// nested in a string), form/query/env/YAML pairs (bare or quoted),
// Authorization lines, Bearer/Basic values, sk- keys, cookies, URL userinfo
// passwords (also network-path //user:pass@), PEM private-key blocks,
// folded header lines, Digest auth-params and quoted cookies. Exact decoy
// canary shapes stay visible so their reuse is detectable.
//
// Known limits, by design:
//   - Free-text secrets with no name, scheme or known shape are not detected.
//   - Names are matched as ASCII after JSON \u and percent decoding; raw
//     non-ASCII names and confusables (Cyrillic or fullwidth letters) are not
//     recognized.
//   - A credential-named object is exempt only if it is a complete JSON Schema
//     made of structural keywords; its description/title strings are prose
//     and are kept.
//   - Unquoted form/YAML true, false, null, none, nil and ~ are kept, as JSON
//     literals are.
//   - "Bearer" and "BEARER" always mark a credential; lowercase "bearer"
//     needs a token-like value so prose survives.
//   - Fingerprints cover the JSON-unescaped value without its auth scheme;
//     there is no percent-decoding, so encoded and raw forms of one secret
//     get different fingerprints.
//
// Local evidence stays on the host; the Mac pulls it over SSH.
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
	"cookies": true,
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

// nameClass is a field name: plain characters, percent escapes, JSON \u
// escapes at up to three nesting levels, or bracket segments as in
// user[password].
const nameElem = `[A-Za-z0-9_.+\[\]-]|%[0-9A-Fa-f]{2}|\\{1,3}u[0-9A-Fa-f]{4}`
const nameClass = `(?:` + nameElem + `){1,64}`

// jsonNameClass also allows spaces, as in {"api key": ...}; JSON quotes
// delimit the name, so a space cannot merge two words of prose.
const jsonNameClass = `(?:` + nameElem + `| ){1,64}`

// kvValue is a quoted (plain or JSON-escaped) or bare form/env/YAML value.
const kvValue = `("(?:[^"\\\n]|\\.)*"|\\"(?:[^"\\]|\\[^"])*\\"|'[^'\n]*'|` + bareValue + `)`

// fold is header whitespace, including obsolete line folding (a line break
// followed by a space or tab), raw or JSON-escaped.
const fold = `(?:[ \t]|\r?\n[ \t]|(?:\\r)?\\n[ \t])`

// authParams is an auth-param list such as Digest username="u", response="r".
const authParam = `[A-Za-z0-9_-]+=(?:"[^"\r\n]*"|\\"(?:[^"\\]|\\[^"])*?\\"|[^\s,"'\\]+)`
const authParams = authParam + `(?:[ \t]*,` + fold + `*` + authParam + `)*`

// bareValue stops at whitespace, quotes and JSON string escapes such as \n,
// so a value inside a JSON string never swallows the closing quote.
const bareValue = `(?:[^\s"'\\&,;<>?#]|\\[^"nrt])+`

var (
	jsonKeyRe = regexp.MustCompile(`"(` + jsonNameClass + `)"\s*:\s*`)
	schemaRe  = regexp.MustCompile(`"type"\s*:\s*"(?:string|number|integer|boolean|object|array|null)"`)
	// \"name\": \"value\" or a number, one JSON level down inside a string.
	escapedFieldRe = regexp.MustCompile(`\\"(` + nameClass + `)\\"(\s*:\s*)(?:\\"((?:\\\\(?:\\.|[^\\"])|\\[^\\"]|[^\\"])*)\\"|(-?[0-9][0-9.eE+-]*))`)
	// name=value or name: value in forms, queries, env files and YAML.
	kvRe = regexp.MustCompile(`(^|\\[nrt]|[^A-Za-z0-9_.+%\\-])(` + nameClass + `)([ \t]*[=:][ \t]*)` + kvValue)
	// Two-word names such as "api key: v" or "session id = v".
	spacedKVRe = regexp.MustCompile(`(?i)(^|\\[nrt]|[^A-Za-z0-9_.+%\\-])((?:api|access|private|secret|session|license|ingest|client|auth|id)[ \t]+(?:key|id|secret|token))([ \t]*[=:][ \t]*)` + kvValue)
	pemRe      = regexp.MustCompile(`-----BEGIN ([A-Z0-9 ]{0,40}PRIVATE KEY)-----((?:[^"\\]|\\[^"])*?)(-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|\\"|"|$)`)
	bearerRe   = regexp.MustCompile(`(?i)\b(bearer)[ \t]+([A-Za-z0-9._~+/=-]+)`)
	basicRe    = regexp.MustCompile(`(?i)\b(basic)[ \t]+([A-Za-z0-9+/]{4,}={0,2})`)
	skRe       = regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{8,}`)
	// A key glued to a word character ("xsk-...", "key_sk-..."). Words such as
	// "risk-assessment" match the shape, so gluedSK also checks the body.
	gluedSKRe  = regexp.MustCompile(`([A-Za-z0-9_])(sk-[A-Za-z0-9_-]{8,})`)
	alnumRunRe = regexp.MustCompile(`[A-Za-z0-9]{10,}`)
	authLineRe = regexp.MustCompile(`(?i)\b((?:proxy-)?authori[sz]ation)[ \t]*[:=]` + fold + `*(?:(bearer|basic|digest|token|negotiate|ntlm|hoba|mutual|vapid|scram-sha-1|scram-sha-256|aws4-hmac-sha256)` + fold + `+)?(` + authParams + `|(?:[^\s"'\\]|\\[^"nrt])+)`)
	cookieRe   = regexp.MustCompile(`(?i)\b((?:set-)?cookie)[ \t]*[:=][ \t]*((?:="[^"\r\n\\;]*"|=\\"[^"\\\r\n;]*\\"|[^\r\n"\\]|\\[^"nrt]|\r?\n[ \t]|\\r\\n[ \t]|\\n[ \t])+)`)
	userinfoRe = regexp.MustCompile(`(?i)((?:\b[a-z][a-z0-9+.-]*:)?//)([^/\s:@"'<>\\]*):((?:[^/\s@"'<>\\]|\\[^"nrt])+)@`)
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
	s, _ = ScrubCount(s, fp)
	return s
}

// RedactionVersion names the redaction behavior of Scrub. Raise it, and the
// digest in its pin test, when a rule changes what the scrubber writes.
const RedactionVersion = 1

// ScrubCount is Scrub plus the number of replacements it made, literal
// "[redacted]" markers included. Marker text that the input already held is
// not counted: only a credential that the scrubber replaced is.
func ScrubCount(s string, fp Fingerprinter) (string, int) {
	n := 0
	mark := func(v string) string {
		n++
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
	kv := func(sub []string) string {
		m := sub[0]
		v, open, close := sub[4], "", ""
		switch {
		case strings.HasPrefix(v, `\"`):
			open, close = `\"`, `\"`
		case v[0] == '"' || v[0] == '\'':
			open, close = v[:1], v[:1]
		}
		inner := v[len(open) : len(v)-len(close)]
		if !IsCredentialName(sub[2]) || ownPass[strings.ToLower(sub[2])] || keep(inner) || authSchemes[strings.ToLower(inner)] ||
			open == "" && literals[inner] {
			return m
		}
		return sub[1] + sub[2] + sub[3] + open + mark(inner) + close
	}
	s = replaceSub(kvRe, s, kv)
	s = replaceSub(spacedKVRe, s, kv)
	s = replaceSub(cookieRe, s, func(sub []string) string {
		m := sub[0]
		return m[:len(m)-len(sub[2])] + scrubCookie(sub[2], strings.EqualFold(sub[1], "set-cookie"), mark)
	})
	s = replaceSub(bearerRe, s, func(sub []string) string {
		m := sub[0]
		if keep(sub[2]) {
			return m
		}
		// "Bearer"/"BEARER" is the HTTP scheme spelling; lowercase "bearer"
		// is usually prose ("bearer bonds") and needs a token-like value.
		if sub[1] != "Bearer" && sub[1] != "BEARER" && (proseWords[strings.ToLower(sub[2])] || !tokenLike(sub[2])) {
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
	s = skRe.ReplaceAllStringFunc(s, func(m string) string {
		if keep(m) {
			return m
		}
		return mark(m)
	})
	s = replaceSub(gluedSKRe, s, func(sub []string) string {
		if keep(sub[2]) || !looksLikeKey(sub[2]) {
			return sub[0]
		}
		return sub[1] + mark(sub[2])
	})
	return s, n
}

// looksLikeKey tells a random key body from a hyphenated word that happens to
// follow "sk-": a key has a digit and a long unbroken alphanumeric run.
func looksLikeKey(k string) bool {
	return strings.ContainsAny(k, "0123456789") && alnumRunRe.MatchString(k)
}

// literals are unquoted form/YAML values that carry no secret, matching the
// JSON true/false/null preservation.
var literals = map[string]bool{
	"true": true, "false": true, "null": true, "True": true, "False": true, "TRUE": true, "FALSE": true,
	"Null": true, "NULL": true, "none": true, "None": true, "nil": true, "~": true,
}

// cookieAttrs are Set-Cookie attributes; they are not secret.
var cookieAttrs = map[string]bool{
	"path": true, "domain": true, "expires": true, "max-age": true, "samesite": true,
	"secure": true, "httponly": true, "partitioned": true, "priority": true,
}

// scrubCookie redacts every cookie value but keeps names, separators,
// DQUOTE wrappers, exact canaries and existing markers. For Set-Cookie only
// the first pair is a cookie; the rest are attributes and stay visible.
func scrubCookie(v string, set bool, mark func(string) string) string {
	parts := strings.Split(v, ";")
	for i, p := range parts {
		// Offsets come from trimming, not strings.Index: the trimmed body can
		// also occur inside the leading whitespace bytes (U+2000 is E2 80 80,
		// body "\x80"), and a split rune makes the next pass disagree.
		trimmed := strings.TrimLeftFunc(p, unicode.IsSpace)
		lead := len(p) - len(trimmed)
		body := strings.TrimRightFunc(trimmed, unicode.IsSpace)
		end := lead + len(body)
		if body == "" {
			continue
		}
		eq := strings.IndexByte(body, '=')
		name := body
		if eq >= 0 {
			name = body[:eq]
		}
		switch {
		case set && i > 0 && cookieAttrs[strings.ToLower(strings.TrimSpace(name))]:
		case eq < 0 && !keep(body):
			body = mark(body)
		case eq >= 0:
			val, q := body[eq+1:], ""
			switch {
			case len(val) >= 4 && strings.HasPrefix(val, `\"`) && strings.HasSuffix(val, `\"`):
				q = `\"`
			case len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"':
				q = `"`
			}
			if inner := val[len(q) : len(val)-len(q)]; !keep(inner) {
				body = body[:eq+1] + q + mark(inner) + q
			}
		}
		parts[i] = p[:lead] + body + p[end:]
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
			if c == '{' && isSchemaSpan(s[v:end]) {
				// A validated schema holds only names, types and prose, so
				// nothing inside it needs scanning.
				pos = end
				break
			}
			edits = leafEdits(s, v, end, mark, edits)
			pos = end
		}
	}
	return applyEdits(s, edits)
}

// isSchemaSpan reports whether span is a complete JSON Schema object built
// only from structural keywords. Value-carrying keywords (default, const,
// enum, examples) or any other key, such as "value", disqualify it, so
// {"password":{"type":"string","value":"x"}} is redacted.
func isSchemaSpan(span string) bool {
	if !schemaRe.MatchString(span) {
		return false
	}
	var v any
	if json.Unmarshal([]byte(span), &v) != nil {
		return false
	}
	return isSchema(v)
}

func isSchema(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	for k, x := range m {
		var good bool
		switch k {
		case "type":
			good = isString(x) || allOf(x, isString)
		case "description", "title", "format", "pattern", "$ref", "$id", "$schema", "$comment",
			"contentMediaType", "contentEncoding":
			good = isString(x)
		case "minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems", "multipleOf",
			"minProperties", "maxProperties":
			_, good = x.(float64)
		case "exclusiveMinimum", "exclusiveMaximum":
			_, num := x.(float64)
			_, b := x.(bool)
			good = num || b
		case "nullable", "readOnly", "writeOnly", "deprecated", "uniqueItems":
			_, good = x.(bool)
		case "required":
			good = allOf(x, isString)
		case "properties", "patternProperties", "$defs", "definitions":
			if mm, ok := x.(map[string]any); ok {
				good = true
				for _, s := range mm {
					good = good && isSchema(s)
				}
			}
		case "items":
			good = isSchema(x) || allOf(x, isSchema)
		case "additionalProperties", "additionalItems":
			_, b := x.(bool)
			good = b || isSchema(x)
		case "anyOf", "oneOf", "allOf":
			good = allOf(x, isSchema)
		case "not":
			good = isSchema(x)
		}
		if !good {
			return false
		}
	}
	return true
}

func isString(v any) bool { _, ok := v.(string); return ok }

func allOf(v any, f func(any) bool) bool {
	a, ok := v.([]any)
	if !ok {
		return false
	}
	for _, x := range a {
		if !f(x) {
			return false
		}
	}
	return true
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
	// "Bearer abc" keeps its scheme and fingerprints only the credential,
	// as the header-line pass does.
	if sp := strings.IndexByte(v, ' '); sp > 0 && authSchemes[strings.ToLower(v[:sp])] {
		if rest := strings.TrimLeft(v[sp:], " "); rest != "" {
			if keep(rest) {
				return edit{}, false
			}
			return edit{i, end, `"` + v[:len(v)-len(rest)] + mark(rest) + tail}, true
		}
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
