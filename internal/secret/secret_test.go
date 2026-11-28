package secret

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"unicode"
)

func fp(v string) string {
	h := sha256.Sum256([]byte(v))
	return "hmac256:" + hex.EncodeToString(h[:])[:16]
}

func TestScrubRedactsCredentialShapes(t *testing.T) {
	cases := map[string]struct{ in, secret string }{
		"json password":     {`{"password":"hunter2"}`, "hunter2"},
		"json spaced":       {`{"access_token" : "abc.def"}`, "abc.def"},
		"json api_key":      {`{"api_key":"k-123"}`, "k-123"},
		"json client":       {`{"client_secret":"cs-9"}`, "cs-9"},
		"json cookie":       {`{"cookie":"sid=zz9"}`, "sid=zz9"},
		"json escaped":      {`{"content":"{\"password\":\"p4ss\"}"}`, "p4ss"},
		"json escaped char": {`{"token":"a\"b-q7"}`, `b-q7`},
		"short bearer":      {"Authorization: Bearer abc", "abc"},
		"bearer jwt":        {"bearer eyJ0.eyJ1.sig", "eyJ0.eyJ1.sig"},
		"basic":             {"Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"},
		"sk key":            {"use sk-proj-abcdefgh1234", "sk-proj-abcdefgh1234"},
		"sk glued word":     {"use xsk-proj-abcdefgh1234", "sk-proj-abcdefgh1234"},
		"sk glued key_":     {"openai_key_sk-Ab3dEf9hJk2mNp", "sk-Ab3dEf9hJk2mNp"},
		"sk glued Bearer":   {"Bearersk-ant-api03-Zx81Qw44Lm09", "sk-ant-api03-Zx81Qw44Lm09"},
		"sk glued after sk": {"task-sk-abcdefgh1234", "sk-abcdefgh1234"},
		"cookie line":       {"Cookie: a=b7; c=d8", "b7"},
		"cookie second":     {"Cookie: a=b7; c=d8", "d8"},
		"form":              {"user=x&password=pw1&x=1", "pw1"},
		"query":             {"https://h.test/cb?access_token=qq9&x=1", "qq9"},
		"env":               {"AWS_SECRET_ACCESS_KEY=AKIAxyz\n", "AKIAxyz"},
		"yaml":              {"db_password: s3cr", "s3cr"},
		"userinfo":          {"postgres://admin:pa55@db.test/x", "pa55"},
		"x-api-key alias":   {`{"X-Api-Key":"zz-1"}`, "zz-1"},
		"license key":       {"NEW_RELIC_LICENSE_KEY=abcd1234", "abcd1234"},
		// research/secret-review.md findings.
		"1 marker prefix json":   {`{"password":"[redacted]hunter2"}`, "hunter2"},
		"1 marker prefix form":   {"access_token=[redacted]qq9", "qq9"},
		"1 marker prefix auth":   {"Authorization: Bearer [redacted]x9z", "x9z"},
		"1 marker prefix bare":   {`"password": [redacted]hunter2`, "hunter2"},
		"1 fake fp marker":       {`{"password":"[redacted:hunter2]"}`, "hunter2"},
		"2 camel access":         {`{"accessToken":"at-77"}`, "at-77"},
		"2 camel client":         {`{"clientSecret":"cs-77"}`, "cs-77"},
		"2 camel refresh":        {`{"refreshToken":"rt-77"}`, "rt-77"},
		"2 camel acronym":        {`{"APIKey":"ak-77"}`, "ak-77"},
		"2 escaped name":         {`{"password":"pw-77"}`, "pw-77"},
		"2 nested escaped name":  {`{"c":"{\"pass\\u0077ord\":\"pw-78\"}"}`, "pw-78"},
		"2 encoded form name":    {"x=1&access%5Ftoken=qq-77", "qq-77"},
		"2 encoded first char":   {"%70assword=pw-79", "pw-79"},
		"2 camel form":           {"clientSecret=cs-79", "cs-79"},
		"3 json number":          {`{"password":918273}`, "918273"},
		"3 json array":           {`{"password":["aa-1","bb-2"]}`, "bb-2"},
		"3 json array number":    {`{"token":[4417, 9921]}`, "9921"},
		"3 json object":          {`{"token":{"value":"vv-1"}}`, "vv-1"},
		"3 nested array object":  {`{"credentials":[{"user":"u","v":"vv-2"}]}`, "vv-2"},
		"3 escaped number":       {`{"c":"{\"pin_token\":55443}"}`, "55443"},
		"3 truncated":            {`{"password":"hunter2-trunc`, "hunter2-trunc"},
		"4 env double quoted":    {`DB_PASSWORD="hunter 2"`, "hunter 2"},
		"4 yaml single quoted":   {"password: 'a b c'", "a b c"},
		"4 escaped quoted":       {`{"c":"token: \"tq-1\""}`, "tq-1"},
		"4 after escaped nl":     {`{"c":"a=1\npassword=pw-80"}`, "pw-80"},
		"4 pem":                  {"-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----\nnext", "MIIEow"},
		"4 pem in json":          {`{"c":"-----BEGIN PRIVATE KEY-----\nMIIEpq\n-----END PRIVATE KEY-----"}`, "MIIEpq"},
		"4 pem truncated":        {"-----BEGIN EC PRIVATE KEY-----\nMHcCAQ", "MHcCAQ"},
		"5 sk-local not exact":   {"use sk-local-abcdefgh1234", "sk-local-abcdefgh1234"},
		"5 canary with suffix":   {"token=dpl-" + strings.Repeat("0f", 10) + "x", "dpl-"},
		"6 cookie canary prefix": {"Cookie: s=[redacted]zz9", "zz9"},
		"8 conventional bearer":  {"Authorization: Bearer abcdef", "abcdef"},
		"8 proxy auth":           {"Proxy-Authorization: Basic Zm9vOmJhcg==", "Zm9vOmJhcg=="},
		"8 empty user basic":     {"curl -H 'X: Basic OnBhc3MxMjM='", "OnBhc3MxMjM="},
		"9 empty username":       {"https://:pw-81@h.test/", "pw-81"},
		"9 long password":        {"https://u:" + strings.Repeat("p", 2000) + "@h.test/", strings.Repeat("p", 300)},
		// Fuzz findings.
		"quote desync newline":   {"\"0\":\"\n{\"password\":\"q90zz7w\"}", "q90zz7w"},
		"quote desync same line": {`{"note":"abc {"password":"hunter2x9"}`, "hunter2x9"},
		"cookie name in value":   {"Cookie:0 0Cookie:=", "Cookie:0"},
	}
	for name, c := range cases {
		for _, f := range []Fingerprinter{nil, fp} {
			out := Scrub(c.in, f)
			if strings.Contains(out, c.secret) || !strings.Contains(out, "[redacted") {
				t.Errorf("%s: %q -> %q", name, c.in, out)
			}
			if again := Scrub(out, f); again != out {
				t.Errorf("%s: not idempotent: %q -> %q", name, out, again)
			}
		}
	}
}

// Nonsecret telemetry must survive byte-for-byte.
func TestScrubKeepsBenignText(t *testing.T) {
	for _, in := range []string{
		`{"model":"gpt-4o","max_tokens":64,"stream":true}`,
		"send the bearer token in the header",
		"we sold bearer bonds",
		"a basic idea about tokens",
		`{"prompt_cache_key":"abc"}`,
		"task-force sk-short",
		"risk-assessment and task-management-tool notes",
		"see the disk-usage-report-2024 and risk-factor-2024-annual-summary",
		"https://example.test/path?q=1",
		"https://example.test/search?q=token+usage&page=2#top",
		`{"tools":[{"type":"function","function":{"name":"run","parameters":{"type":"object","properties":{"argv":{"type":"array","items":{"type":"string"}},"cwd":{"type":"string"},"password":{"type":"string","description":"login password"}},"required":["argv"]}}}],"parallel_tool_calls":true}`,
		"{\n  \"metadata\" : {\"client\": \"claude-code/1.2\", \"operator\":\"alias-7\"},\n\t\"note\":\"identification-declined\"\n}",
		`{"messages":[{"role":"user","content":"café \"quoted\" \\ back"}],"temperature":0.2}`,
		"R​éG-0A1B2C3D4E5F6071",
		"line=001 marker=M001-0A1B2C3D4E5F6071 status=ok\nline=002 marker=M002-0A1B2C3D4E5F6071 status=ok",
		`{"token_count":12,"auth_mode":"none","password_hint":"ask admin"}`,
		`{"auth":true,"token":null,"secret":false}`,
		"Authorization header docs",
	} {
		for _, f := range []Fingerprinter{nil, fp} {
			if out := Scrub(in, f); out != in {
				t.Errorf("%q -> %q", in, out)
			}
		}
	}
}

// Redaction keeps every byte outside the credential value.
func TestScrubExactJSON(t *testing.T) {
	cases := map[string]string{
		`{"a" : 1, "password" : "x9" ,"b":[1,2]}`:                         `{"a" : 1, "password" : "[redacted]" ,"b":[1,2]}`,
		`{"password":12,"n":3}`:                                           `{"password":"[redacted]","n":3}`,
		`{"credentials":{"user":"u","password":"p"},"k":1}`:               `{"credentials":{"user":"[redacted]","password":"[redacted]"},"k":1}`,
		`{"api_key":["a",{"x":2}],"ok":"y"}`:                              `{"api_key":["[redacted]",{"x":"[redacted]"}],"ok":"y"}`,
		`{"c":"{\"password\":\"p4ss\",\"n\":1}"}`:                         `{"c":"{\"password\":\"[redacted]\",\"n\":1}"}`,
		"Cookie: a=1; theme=dark\nnext: line":                             "Cookie: a=[redacted]; theme=[redacted]\nnext: line",
		`{"h":"Cookie: sid=9","x":2}`:                                     `{"h":"Cookie: sid=[redacted]","x":2}`,
		"-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\nok": "-----BEGIN PRIVATE KEY-----[redacted]-----END PRIVATE KEY-----\nok",
	}
	for in, want := range cases {
		out := Scrub(in, nil)
		if out != want {
			t.Errorf("%q\n got %q\nwant %q", in, out, want)
		}
		if json.Valid([]byte(in)) && !json.Valid([]byte(out)) {
			t.Errorf("valid JSON became invalid: %q", out)
		}
	}
}

// A key glued to a word keeps the word and loses only the key.
func TestScrubGluedSKKeepsPrefix(t *testing.T) {
	cases := map[string]string{
		"use xsk-proj-abcdefgh1234 now": "use x[redacted] now",
		"Bearersk-Ab3dEf9hJk2mNp7":      "Bearer[redacted]",
		"task-sk-abcdefgh1234 ok":       "task-[redacted] ok",
		"a sk-abcdefgh1234 b":           "a [redacted] b",
	}
	for in, want := range cases {
		if out := Scrub(in, nil); out != want {
			t.Errorf("%q\n got %q\nwant %q", in, out, want)
		}
	}
}

func canaries() []string {
	jwt := "eyJhbGciOiJIUzI1NiJ9." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"edge-0a1b2c3d"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(make([]byte, 24))
	return []string{
		"sk-local-" + strings.Repeat("a1", 18),
		"dpl-" + strings.Repeat("0f", 10),
		"tk_" + strings.Repeat("ab", 6) + "." + strings.Repeat("cd", 16),
		jwt,
	}
}

func TestScrubKeepsCanaries(t *testing.T) {
	for _, c := range canaries() {
		if !IsCanary(c) {
			t.Fatalf("%q not a canary", c)
		}
		for _, in := range []string{
			`{"password":"` + c + `"}`, `{"token":["` + c + `"]}`, "token=" + c, "Bearer " + c,
			"Authorization: Bearer " + c, "https://u:" + c + "@h.test/", "Cookie: s=" + c + "; t=" + c,
			`{"c":"{\"token\":\"` + c + `\"}"}`, "TOKEN='" + c + "'", "use " + c + " now",
		} {
			out := Scrub(in, fp)
			if out != in {
				t.Errorf("canary changed: %q -> %q", in, out)
			}
		}
	}
	for _, bad := range []string{
		"sk-local-" + strings.Repeat("a1", 18) + "x",
		"sk-local-" + strings.Repeat("A1", 18),
		"eyJhbGciOiJIUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"root-0a1b2c3d"}`)) + "." + strings.Repeat("A", 32),
	} {
		if IsCanary(bad) {
			t.Errorf("loose canary match %q", bad)
		}
	}
}

func TestScrubFingerprintContract(t *testing.T) {
	out := Scrub(`{"password":"hunter2"} Bearer tok123`, fp)
	if !strings.Contains(out, "[redacted:"+fp("hunter2")+"]") || !strings.Contains(out, "Bearer [redacted:"+fp("tok123")+"]") {
		t.Fatalf("got %q", out)
	}
	// Header, JSON and escaped forms of one token correlate.
	for _, in := range []string{"Authorization: Bearer tq\"9", `{"token":"tq\"9"}`, `{"c":"{\"token\":\"tq\\\"9\"}"}`} {
		if out := Scrub(in, fp); in != "Authorization: Bearer tq\"9" && !strings.Contains(out, fp(`tq"9`)) {
			t.Errorf("%q -> %q, want fingerprint of decoded value", in, out)
		}
	}
	// A callback that echoes its input or breaks JSON is ignored.
	for _, bad := range []Fingerprinter{
		func(v string) string { return v },
		func(string) string { return `x"}` },
		func(string) string { return "hmac256:ZZZZ" },
	} {
		out := Scrub(`{"password":"hunter2","n":1}`, bad)
		if out != `{"password":"[redacted]","n":1}` {
			t.Errorf("bad fingerprinter output leaked: %q", out)
		}
	}
}

func TestIsCredentialName(t *testing.T) {
	for _, n := range []string{"Authorization", "X-Auth", "X-Authorization", "Authentication", "X-Credential",
		"api_key", "X-Refresh-Token", "client_secret", "session-id", "password", "LICENSE_KEY",
		"accessToken", "clientSecret", "APIKey", "XApiKey", `password`, "access%5Ftoken", "api+key"} {
		if !IsCredentialName(n) {
			t.Errorf("%q should be a credential name", n)
		}
	}
	for _, n := range []string{"max_tokens", "maxTokens", "model", "prompt_cache_key", "promptCacheKey", "key",
		"user-agent", "Referer", "author", "authorId", "", "token_count"} {
		if IsCredentialName(n) {
			t.Errorf("%q should not be a credential name", n)
		}
	}
}

func TestIsMarker(t *testing.T) {
	for v, want := range map[string]bool{
		"[redacted]": true, "[redacted:" + fp("x") + "]": true,
		"[redacted]x": false, "[redacted:abc]": false, "[redacted": false, "": false,
	} {
		if IsMarker(v) != want {
			t.Errorf("IsMarker(%q) != %v", v, want)
		}
	}
}

// The oracle: a credential in a known shape never survives, canaries always
// survive, and scrubbing is idempotent, whatever surrounds them.
func FuzzScrub(f *testing.F) {
	f.Add(`{"model":"x"} Bearer abc sk-abcdefgh12 https://a:b@c/`, "hunter2x9")
	f.Add("Cookie: a=b\n", "s3cretValue")
	f.Fuzz(func(t *testing.T, noise, sec string) {
		sec = strings.Map(func(r rune) rune {
			if r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
				return r
			}
			return -1
		}, sec)
		if len(sec) < 8 || !strings.ContainsAny(sec, "0123456789") {
			sec = "q9" + sec + "zz7w"
		}
		if strings.Contains(noise, sec) {
			t.Skip()
		}
		canary := canaries()[0]
		in := strings.TrimRight(noise, `\`) + "\n" +
			`{"password":"` + sec + `","note":"x"}` + "\n" +
			"token=" + canary + "\n" +
			"Authorization: Bearer " + sec + "\n"
		once := Scrub(in, fp)
		if strings.Contains(once, sec) {
			t.Errorf("secret survived: %q", once)
		}
		if !strings.Contains(once, "token="+canary) {
			t.Errorf("canary lost: %q", once)
		}
		if twice := Scrub(once, fp); twice != once {
			t.Errorf("not idempotent: %q -> %q", once, twice)
		}
	})
}
