package secret

import (
	"encoding/json"
	"strings"
	"testing"
)

// Exact-output regressions for research/secret-rereview.md.
func TestScrubRereviewExact(t *testing.T) {
	long := strings.Repeat("a", 40)
	cases := []struct{ name, in, want string }{
		// 1: schema exemption needs a real schema.
		{"1 value in schema", `{"password":{"type":"string","value":"hunter2"}}`, `{"password":{"type":"[redacted]","value":"[redacted]"}}`},
		{"1 default in schema", `{"password":{"type":"string","default":"hunter2"},"n":1}`, `{"password":{"type":"[redacted]","default":"[redacted]"},"n":1}`},
		{"1 nested schema value", `{"token":{"type":"object","properties":{"v":{"type":"string","const":"hunter2"}}}}`, `{"token":{"type":"[redacted]","properties":{"v":{"type":"[redacted]","const":"[redacted]"}}}}`},
		{"1 truncated schema", `{"password":{"type":"string","x":"hunter2"`, `{"password":{"type":"[redacted]","x":"[redacted]"`},
		{"1 real schema kept", `{"password":{"type":"string","description":"login","minLength":8}}`, `{"password":{"type":"string","description":"login","minLength":8}}`},
		// 2: obsolete header folding.
		{"2 folded bearer", "Authorization: Bearer\r\n  abc\r\nX: 1", "Authorization: Bearer\r\n  [redacted]\r\nX: 1"},
		{"2 folded after colon", "Authorization:\r\n Basic dXNlcjpwYXNz", "Authorization:\r\n Basic [redacted]"},
		{"2 folded escaped", `{"raw":"Authorization: Bearer\r\n abc"}`, `{"raw":"Authorization: Bearer\r\n [redacted]"}`},
		{"2 folded cookie", "Cookie: a=b\r\n c=d\r\nX: 1", "Cookie: a=[redacted]\r\nX: 1"},
		// 3: name grammar.
		{"3 json spaced", `{"api key":"k9z"}`, `{"api key":"[redacted]"}`},
		{"3 yaml spaced", "api key: k9z\nmodel: m", "api key: [redacted]\nmodel: m"},
		{"3 spaced session", "Session ID = s-91", "Session ID = [redacted]"},
		{"3 bracket form", "user[name]=bob&user[password]=pw1", "user[name]=bob&user[password]=[redacted]"},
		{"3 bracket encoded", "user%5Bpassword%5D=pw1", "user%5Bpassword%5D=[redacted]"},
		{"3 cookies", `{"cookies":"a=b"}`, `{"cookies":"[redacted]"}`},
		// 4: standalone Bearer.
		{"4 bearer abc", "send Bearer abc now", "send Bearer [redacted] now"},
		{"4 bearer token", "Bearer token", "Bearer [redacted]"},
		{"4 upper", "BEARER abc", "BEARER [redacted]"},
		// 5: userinfo.
		{"5 network path", "//user:pa55@example.test/", "//user:[redacted]@example.test/"},
		{"5 referer path", "Referer: //u:pw-1@h.test/x", "Referer: //u:[redacted]@h.test/x"},
		{"5 long scheme", long + "://u:pw-2@h.test/", long + "://u:[redacted]@h.test/"},
		// 6: cookie quoting and attributes.
		{"6 quoted cookie", `Cookie: session="hunter2"; theme=dark`, `Cookie: session="[redacted]"; theme=[redacted]`},
		{"6 quoted in json", `{"h":"Cookie: session=\"hunter2\"","n":1}`, `{"h":"Cookie: session=\"[redacted]\"","n":1}`},
		{"6 set-cookie attrs", "Set-Cookie: sid=abc; Path=/; Domain=h.test; Max-Age=60; SameSite=Lax; HttpOnly; Secure",
			"Set-Cookie: sid=[redacted]; Path=/; Domain=h.test; Max-Age=60; SameSite=Lax; HttpOnly; Secure"},
		{"6 cookie named path", "Cookie: Path=abc", "Cookie: Path=[redacted]"},
		// 7: JSON auth values keep the scheme.
		{"7 json bearer", `{"Authorization":"Bearer abc"}`, `{"Authorization":"Bearer [redacted]"}`},
		{"7 json basic", `{"auth":"Basic dXNlcjpwYXNz"}`, `{"auth":"Basic [redacted]"}`},
		{"7 json scheme only", `{"auth":"Bearer"}`, `{"auth":"[redacted]"}`},
		// 8: Digest auth-params.
		{"8 digest", `Authorization: Digest username="u", response="abc123"` + "\r\nX: 1", "Authorization: Digest [redacted]\r\nX: 1"},
		{"8 digest json", `{"Authorization":"Digest username=\"u\", response=\"abc123\""}`, `{"Authorization":"Digest [redacted]"}`},
		{"8 digest escaped line", `{"raw":"Authorization: Digest username=\"u\", response=\"abc123\""}`, `{"raw":"Authorization: Digest [redacted]"}`},
		// 9: boolean/null telemetry matches JSON.
		{"9 form literals", "auth=true&token=null&secret=False", "auth=true&token=null&secret=False"},
		{"9 yaml literal", "password: ~\ntoken: none", "password: ~\ntoken: none"},
		{"9 quoted literal", `token="null"`, `token="[redacted]"`},
	}
	for _, c := range cases {
		got := Scrub(c.in, nil)
		if got != c.want {
			t.Errorf("%s: %q\n got %q\nwant %q", c.name, c.in, got, c.want)
		}
		if again := Scrub(got, nil); again != got {
			t.Errorf("%s: not idempotent: %q -> %q", c.name, got, again)
		}
		if json.Valid([]byte(c.in)) && !json.Valid([]byte(got)) {
			t.Errorf("%s: valid JSON became invalid: %q", c.name, got)
		}
	}
}

// The JSON and header forms of one bearer token share a fingerprint.
func TestScrubBearerFingerprintParity(t *testing.T) {
	want := "Bearer [redacted:" + fp("abc9") + "]"
	for _, in := range []string{`{"Authorization":"Bearer abc9"}`, "Authorization: Bearer abc9", "Bearer abc9"} {
		if out := Scrub(in, fp); !strings.Contains(out, want) {
			t.Errorf("%q -> %q, want %q", in, out, want)
		}
	}
}

// FuzzScrub corpus 8783b3da9bc4b3bc: the cookie body "\x80" also occurs
// inside the leading U+2000 (E2 80 80). Locating it with strings.Index split
// the rune, so a second pass re-fingerprinted the whole suffix.
func TestScrubCookieUnicodeSpaceInvalidUTF8(t *testing.T) {
	in := "Cookie: \x80"
	want := "Cookie: [redacted:" + fp("\x80") + "]"
	once := Scrub(in, fp)
	if once != want {
		t.Fatalf("got %q, want %q", once, want)
	}
	if twice := Scrub(once, fp); twice != once {
		t.Fatalf("not idempotent: %q -> %q", once, twice)
	}
	if !strings.HasPrefix(once, "Cookie: ") {
		t.Fatalf("leading U+2000 split: %q", once)
	}
}
