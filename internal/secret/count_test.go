package secret

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"unicode"
)

// countCase is one input of the fixed corpus and the number of replacements
// the scrubber must report for it.
type countCase struct {
	name string
	in   string
	want int
}

// countCorpus covers every rule that writes a marker, and inputs that hold
// marker text with no credential in it.
var countCorpus = []countCase{
	// no credential
	{"empty", "", 0},
	{"prose", "hello world, nothing to see", 0},
	{"json no credential", `{"model":"x","n":1}`, 0},
	{"json literals", `{"password":null,"token":true,"secret":false}`, 0},
	{"bare marker", "[redacted]", 0},
	{"bare fp marker", "[redacted:hmac256:0123456789abcdef]", 0},
	{"marker in json value", `{"password":"[redacted]"}`, 0},
	{"marker in bearer", "Authorization: Bearer [redacted]", 0},
	{"marker in fp bearer", "Authorization: Bearer [redacted:hmac256:0123456789abcdef]", 0},
	{"marker in form", "access_token=[redacted]", 0},
	{"marker in cookie", "Cookie: sid=[redacted]", 0},
	{"marker in non-credential field", `{"note":"[redacted]","other":"[redacted:hmac256:0123456789abcdef]"}`, 0},
	{"canary kept", "token=" + canaries()[0], 0},

	// one credential, one rule each
	{"json string", `{"password":"hunter2"}`, 1},
	{"json number", `{"password":12,"n":3}`, 1},
	{"json bare word", `{"password": hunter2 }`, 1},
	{"json escaped string", `{"content":"{\"password\":\"p4ss\"}"}`, 1},
	{"json scheme value", `{"Authorization":"Bearer abc"}`, 1},
	{"json schema value", `{"password":{"type":"string","default":"hunter2"},"n":1}`, 2},
	{"escaped field", `{"raw":"{\"token\":\"a-b9\"}"}`, 1},
	{"pem", "-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\nok", 1},
	{"auth line bearer", "Authorization: Bearer abc", 1},
	{"auth line basic", "Authorization: Basic dXNlcjpwYXNz", 1},
	{"auth line digest", `Authorization: Digest username="u", response="abc123"` + "\r\nX: 1", 1},
	{"form field", "access_token=qq9&model=m", 1},
	{"quoted form field", `token="hunter2"`, 1},
	{"spaced field", "api key: k9z\nmodel: m", 1},
	{"bracket field", "user[name]=bob&user[password]=pw1", 1},
	{"cookie header", "Cookie: sid=zz9", 1},
	{"set-cookie header", "Set-Cookie: sid=abc; Path=/; HttpOnly", 1},
	{"free bearer", "send Bearer abc now", 1},
	{"free basic", "Basic dXNlcjpwYXNz", 1},
	{"userinfo", "https://user:pa55@example.test/x", 1},
	{"sk key", "use sk-proj-abcdefgh1234 now", 1},
	{"glued sk key", "Bearersk-Ab3dEf9hJk2mNp7", 1},

	// more than one credential
	{"two json", `{"password":"hunter2","api_key":"k-123"}`, 2},
	{"json and bearer", `{"password":"hunter2"} Bearer tok123`, 2},
	{"two cookies", "Cookie: a=1; theme=dark\nnext: line", 2},
	{"array leaves", `{"api_key":["a",{"x":2}],"ok":"y"}`, 2},
	{"object leaves", `{"credentials":{"user":"u","password":"p"},"k":1}`, 2},
	{"form pair", "password=hunter2&token=abc9", 2},
	{"mixed rules", "Authorization: Bearer abc\n" + `{"password":"hunter2"}` + "\nuse sk-proj-abcdefgh1234", 3},
	{"credential beside marker", `{"password":"hunter2","token":"[redacted]"}`, 1},
	{"marker prefix then credential", `{"password":"[redacted]hunter2"}`, 1},
}

// fuzzSeedInputs rebuilds the inputs that FuzzScrub derives from its seeds.
func fuzzSeedInputs() []string {
	var out []string
	for _, s := range [][2]string{
		{`{"model":"x"} Bearer abc sk-abcdefgh12 https://a:b@c/`, "hunter2x9"},
		{"Cookie: a=b\n", "s3cretValue"},
	} {
		noise, sec := s[0], strings.Map(func(r rune) rune {
			if r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
				return r
			}
			return -1
		}, s[1])
		out = append(out, strings.TrimRight(noise, `\`)+"\n"+
			`{"password":"`+sec+`","note":"x"}`+"\n"+
			"token="+canaries()[0]+"\n"+
			"Authorization: Bearer "+sec+"\n")
	}
	return out
}

func TestScrubCountMatchesScrub(t *testing.T) {
	inputs := fuzzSeedInputs()
	for _, c := range countCorpus {
		inputs = append(inputs, c.in)
	}
	for _, in := range inputs {
		for name, f := range map[string]Fingerprinter{"fp": fp, "nil": nil} {
			text, _ := ScrubCount(in, f)
			if want := Scrub(in, f); text != want {
				t.Errorf("%s: ScrubCount text %q, Scrub %q (input %q)", name, text, want, in)
			}
		}
	}
}

func TestScrubCountValues(t *testing.T) {
	for _, c := range countCorpus {
		t.Run(c.name, func(t *testing.T) {
			_, n := ScrubCount(c.in, fp)
			if n != c.want {
				t.Errorf("count = %d, want %d for %q", n, c.want, c.in)
			}
			// The literal marker and the fingerprint marker count the same.
			if _, plain := ScrubCount(c.in, nil); plain != c.want {
				t.Errorf("count without fingerprinter = %d, want %d", plain, c.want)
			}
		})
	}
}

// A count that equals the markers in the output would count client text.
func TestScrubCountIgnoresInputMarkers(t *testing.T) {
	in := strings.Repeat("[redacted] [redacted:hmac256:0123456789abcdef] ", 5)
	out, n := ScrubCount(in, fp)
	if n != 0 || out != in {
		t.Errorf("marker text only: count %d, text changed %v", n, out != in)
	}
	out, n = ScrubCount(in+`{"password":"hunter2"}`, fp)
	if n != 1 || strings.Contains(out, "hunter2") {
		t.Errorf("one credential among markers: count %d, out %q", n, out)
	}
}

// redactionDigests maps RedactionVersion to the digest of redactionDigest.
var redactionDigests = map[int]string{
	1: "879812b0f2648434112abbbe30dedf108457bdd0803b5b2b2cfb400ea8a3d0a4",
}

// redactionPinCorpus is the input of the redaction pin. It is private to the
// pin and written out in full: adding a fuzz seed or a count case elsewhere
// must not change the digest. Change it only together with a version change.
var redactionPinCorpus = []string{
	`{"model":"x"} Bearer abc sk-abcdefgh12 https://a:b@c/` + "\n" +
		`{"password":"hunter2x9","note":"x"}` + "\n" +
		"token=sk-local-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\n" +
		"Authorization: Bearer hunter2x9\n",
	"Cookie: a=b\n\n" +
		`{"password":"s3cretValue","note":"x"}` + "\n" +
		"token=sk-local-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\n" +
		"Authorization: Bearer s3cretValue\n",
	"",
	"hello world, nothing to see",
	`{"model":"x","n":1}`,
	`{"password":null,"token":true,"secret":false}`,
	"[redacted]",
	"[redacted:hmac256:0123456789abcdef]",
	`{"password":"[redacted]"}`,
	"Authorization: Bearer [redacted]",
	"Authorization: Bearer [redacted:hmac256:0123456789abcdef]",
	"access_token=[redacted]",
	"Cookie: sid=[redacted]",
	`{"note":"[redacted]","other":"[redacted:hmac256:0123456789abcdef]"}`,
	"token=sk-local-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
	`{"password":"hunter2"}`,
	`{"password":12,"n":3}`,
	`{"password": hunter2 }`,
	`{"content":"{\"password\":\"p4ss\"}"}`,
	`{"Authorization":"Bearer abc"}`,
	`{"password":{"type":"string","default":"hunter2"},"n":1}`,
	`{"raw":"{\"token\":\"a-b9\"}"}`,
	"-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\nok",
	"Authorization: Bearer abc",
	"Authorization: Basic dXNlcjpwYXNz",
	`Authorization: Digest username="u", response="abc123"` + "\r\nX: 1",
	"access_token=qq9&model=m",
	`token="hunter2"`,
	"api key: k9z\nmodel: m",
	"user[name]=bob&user[password]=pw1",
	"Cookie: sid=zz9",
	"Set-Cookie: sid=abc; Path=/; HttpOnly",
	"send Bearer abc now",
	"Basic dXNlcjpwYXNz",
	"https://user:pa55@example.test/x",
	"use sk-proj-abcdefgh1234 now",
	"Bearersk-Ab3dEf9hJk2mNp7",
	`{"password":"hunter2","api_key":"k-123"}`,
	`{"password":"hunter2"} Bearer tok123`,
	"Cookie: a=1; theme=dark\nnext: line",
	`{"api_key":["a",{"x":2}],"ok":"y"}`,
	`{"credentials":{"user":"u","password":"p"},"k":1}`,
	"password=hunter2&token=abc9",
	"Authorization: Bearer abc\n" + `{"password":"hunter2"}` + "\nuse sk-proj-abcdefgh1234",
	`{"password":"hunter2","token":"[redacted]"}`,
	`{"password":"[redacted]hunter2"}`,
}

// redactionDigest hashes the scrubber output and count for the pin corpus,
// with a fingerprinter and without one.
func redactionDigest() string {
	h := sha256.New()
	for _, in := range redactionPinCorpus {
		for _, f := range []Fingerprinter{fp, nil} {
			out, n := ScrubCount(in, f)
			fmt.Fprintf(h, "%q -> %q %d\n", in, out, n)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestRedactionVersionPin(t *testing.T) {
	want, ok := redactionDigests[RedactionVersion]
	if !ok {
		t.Fatalf("RedactionVersion %d has no digest in redactionDigests; add it", RedactionVersion)
	}
	if got := redactionDigest(); got != want {
		t.Fatalf("a redaction rule changed what the scrubber writes, and RedactionVersion is still %d.\n"+
			"Raise RedactionVersion and add this digest for the new number:\n\t%d: %q,\n(old digest %q)",
			RedactionVersion, RedactionVersion+1, got, want)
	}
}
