package secret

import (
	"strings"
	"testing"
)

func fp(v string) string { return "fp(" + v + ")" }

func TestScrubRedactsCredentialShapes(t *testing.T) {
	cases := map[string]struct{ in, secret string }{
		"json password":     {`{"password":"hunter2"}`, "hunter2"},
		"json spaced":       {`{"access_token" : "abc.def"}`, "abc.def"},
		"json api_key":      {`{"api_key":"k-123"}`, "k-123"},
		"json client":       {`{"client_secret":"cs-9"}`, "cs-9"},
		"json cookie":       {`{"cookie":"sid=zz9"}`, "sid=zz9"},
		"json escaped":      {`{"content":"{\"password\":\"p4ss\"}"}`, "p4ss"},
		"json escaped char": {`{"token":"a\"b-q7"}`, `a\"b-q7`},
		"short bearer":      {"Authorization: Bearer abc", "abc"},
		"bearer jwt":        {"bearer eyJ0.eyJ1.sig", "eyJ0.eyJ1.sig"},
		"basic":             {"Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"},
		"sk key":            {"use sk-proj-abcdefgh1234", "sk-proj-abcdefgh1234"},
		"cookie line":       {"Cookie: a=b; c=d", "a=b; c=d"},
		"form":              {"user=x&password=pw1&x=1", "pw1"},
		"query":             {"https://h.test/cb?access_token=qq9&x=1", "qq9"},
		"env":               {"AWS_SECRET_ACCESS_KEY=AKIAxyz\n", "AKIAxyz"},
		"yaml":              {"db_password: s3cr", "s3cr"},
		"userinfo":          {"postgres://admin:pa55@db.test/x", "pa55"},
		"x-api-key alias":   {`{"X-Api-Key":"zz-1"}`, "zz-1"},
		"license key":       {"NEW_RELIC_LICENSE_KEY=abcd1234", "abcd1234"},
	}
	for name, c := range cases {
		out := Scrub(c.in, nil)
		if strings.Contains(out, c.secret) || !strings.Contains(out, "[redacted]") {
			t.Errorf("%s: %q -> %q", name, c.in, out)
		}
	}
}

func TestScrubKeepsBenignText(t *testing.T) {
	for _, in := range []string{
		`{"model":"gpt-4o","max_tokens":64,"stream":true}`,
		"send the bearer token in the header",
		"a basic idea about tokens",
		`{"prompt_cache_key":"abc"}`,
		"task-force sk-short",
		"https://example.test/path?q=1",
	} {
		if out := Scrub(in, nil); out != in {
			t.Errorf("%q -> %q", in, out)
		}
	}
}

func TestScrubKeepsCanaries(t *testing.T) {
	canaries := []string{
		"sk-local-" + strings.Repeat("a1", 18),
		"dpl-" + strings.Repeat("0f", 10),
		"tk_" + strings.Repeat("ab", 6) + "." + strings.Repeat("cd", 16),
	}
	for _, c := range canaries {
		if !IsCanary(c) {
			t.Fatalf("%q not a canary", c)
		}
		for _, in := range []string{`{"password":"` + c + `"}`, "token=" + c, "Bearer " + c, "https://u:" + c + "@h.test/"} {
			if out := Scrub(in, nil); !strings.Contains(out, c) {
				t.Errorf("canary lost: %q -> %q", in, out)
			}
		}
	}
	if IsCanary("sk-local-" + strings.Repeat("a1", 18) + "x") {
		t.Error("loose canary match")
	}
}

func TestScrubFingerprintsAndIdempotent(t *testing.T) {
	out := Scrub(`{"password":"hunter2"} Bearer tok123`, fp)
	if !strings.Contains(out, "[redacted:fp(hunter2)]") || !strings.Contains(out, "Bearer [redacted:fp(tok123)]") {
		t.Fatalf("got %q", out)
	}
	if again := Scrub(out, fp); again != out {
		t.Errorf("not idempotent: %q -> %q", out, again)
	}
}

func TestIsCredentialName(t *testing.T) {
	for _, n := range []string{"Authorization", "X-Auth", "X-Authorization", "Authentication", "X-Credential",
		"api_key", "X-Refresh-Token", "client_secret", "session-id", "password", "NR_LICENSE_KEY"} {
		if !IsCredentialName(n) {
			t.Errorf("%q should be a credential name", n)
		}
	}
	for _, n := range []string{"max_tokens", "model", "prompt_cache_key", "key", "user-agent", "Referer", "author", ""} {
		if IsCredentialName(n) {
			t.Errorf("%q should not be a credential name", n)
		}
	}
}

func FuzzScrubIdempotent(f *testing.F) {
	f.Add(`{"password":"x"} Bearer abc sk-abcdefgh12 https://a:b@c/`)
	f.Fuzz(func(t *testing.T, s string) {
		once := Scrub(s, nil)
		if twice := Scrub(once, nil); twice != once {
			t.Errorf("not idempotent: %q -> %q -> %q", s, once, twice)
		}
	})
}
