package telemetry

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestHeadersRedactsCredentials(t *testing.T) {
	r := NewRedactor([]byte("k1"))
	const tok = "sk-proj-SuperSecretTokenValue123456"
	const cookie = "sessid=abcdef123456; other=zzz"
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	h.Set("Cookie", cookie)
	h.Set("X-Api-Key", tok)
	h.Set("X-My-Token", "mytokenvalue")
	h.Set("X-Custom-Secret", "hush")
	h.Set("User-Agent", "OpenAI/Python 1.2")
	h.Set("X-Stainless-Lang", "python")
	h.Set("X-Odd", strings.Repeat("v", 400))
	h.Add("X-Forwarded-For", "1.1.1.1")
	h.Add("X-Forwarded-For", "2.2.2.2")

	safe, fps := r.Headers(h)
	out, _ := json.Marshal([]any{safe, fps})
	for _, secret := range []string{tok, "sessid=abcdef", "mytokenvalue", "hush"} {
		if strings.Contains(string(out), secret) {
			t.Errorf("%q leaked: %s", secret, out)
		}
	}
	if safe["Authorization"] != "Bearer [redacted]" {
		t.Errorf("Authorization = %q", safe["Authorization"])
	}
	for _, n := range []string{"Cookie", "X-Api-Key", "X-My-Token", "X-Custom-Secret"} {
		if safe[n] != "[redacted]" || fps[n] == "" {
			t.Errorf("%s: safe=%q fp=%q", n, safe[n], fps[n])
		}
	}
	if safe["X-Stainless-Lang"] != "python" || safe["User-Agent"] != "OpenAI/Python 1.2" {
		t.Errorf("informational headers lost: %v", safe)
	}
	if safe["X-Forwarded-For"] != "1.1.1.1, 2.2.2.2" {
		t.Errorf("multi-value = %q", safe["X-Forwarded-For"])
	}
	if len(safe["X-Odd"]) != 256 {
		t.Errorf("X-Odd len = %d", len(safe["X-Odd"]))
	}
	if fps["Authorization"] != r.Fingerprint(tok) {
		t.Error("Authorization fingerprint must cover the token only")
	}
}

func TestHeadersBareAuthorization(t *testing.T) {
	r := NewRedactor([]byte("k"))
	h := http.Header{"Authorization": {"sk-abcdefghijklmnopqrstuv"}}
	safe, _ := r.Headers(h)
	if safe["Authorization"] != "[redacted]" {
		t.Errorf("got %q", safe["Authorization"])
	}
}

func TestHeadersCap(t *testing.T) {
	h := http.Header{}
	for i := 0; i < 200; i++ {
		h.Set("X-H"+strings.Repeat("a", i%5)+string(rune('a'+i%26))+string(rune('a'+i/26)), "v")
	}
	safe, _ := NewRedactor(nil).Headers(h)
	if len(safe) != 64 {
		t.Errorf("kept %d headers", len(safe))
	}
}

func TestFingerprint(t *testing.T) {
	a, b := NewRedactor([]byte("one")), NewRedactor([]byte("two"))
	fp := a.Fingerprint("secret")
	if fp != a.Fingerprint("secret") {
		t.Error("not stable")
	}
	if fp == b.Fingerprint("secret") {
		t.Error("not keyed")
	}
	if !strings.HasPrefix(fp, "hmac256:") || len(fp) != len("hmac256:")+16 {
		t.Errorf("shape = %q", fp)
	}
	if a.Fingerprint("") != "" {
		t.Error("empty input must give empty fingerprint")
	}
}

func TestText(t *testing.T) {
	r := NewRedactor([]byte("k"))
	const real = "sk-proj-abcdefghijklmnop1234"
	const canary = "sk-local-0123456789abcdefghij"
	in := "curl -H 'Authorization: Bearer eyJhbGciOi.payload.sig' key=" + real +
		" canary=" + canary + "\nCookie: sid=topsecretcookie\nshort sk-abc"
	out := r.Text(in)
	for _, leak := range []string{"eyJhbGciOi", real, "topsecretcookie"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q leaked: %s", leak, out)
		}
	}
	if !strings.Contains(out, canary) {
		t.Errorf("canary scrubbed: %s", out)
	}
	if !strings.Contains(out, "Bearer [redacted:"+r.Fingerprint("eyJhbGciOi.payload.sig")+"]") {
		t.Errorf("bearer fingerprint missing: %s", out)
	}
	if !strings.Contains(out, "[redacted:"+r.Fingerprint(real)+"]") {
		t.Errorf("sk fingerprint missing: %s", out)
	}
	if !strings.Contains(out, "short sk-abc") {
		t.Errorf("short key altered: %s", out)
	}
}

func TestHeadersCredentialAliasesAndReferer(t *testing.T) {
	r := NewRedactor([]byte("k"))
	h := http.Header{}
	for _, n := range []string{"X-Authorization", "Authentication", "X-Auth", "X-Credential", "X-Client-Secret"} {
		h.Set(n, "alias-secret-"+n)
	}
	h.Set("Referer", "https://u:refpass@example.test/cb?access_token=reftok&page=2")
	h.Set("X-Note", `{"password":"notepass"}`)
	safe, fps := r.Headers(h)
	out, _ := json.Marshal(safe)
	for _, leak := range []string{"alias-secret", "refpass", "reftok", "notepass"} {
		if strings.Contains(string(out), leak) {
			t.Errorf("%q leaked: %s", leak, out)
		}
	}
	for _, n := range []string{"X-Authorization", "Authentication", "X-Auth", "X-Credential", "X-Client-Secret"} {
		if safe[n] != "[redacted]" || fps[n] == "" {
			t.Errorf("%s: safe=%q fp=%q", n, safe[n], fps[n])
		}
	}
	if !strings.Contains(safe["Referer"], "example.test/cb?access_token=[redacted:") || !strings.Contains(safe["Referer"], "page=2") {
		t.Errorf("Referer = %q", safe["Referer"])
	}
}

func TestTextStructuredCredentials(t *testing.T) {
	r := NewRedactor([]byte("k"))
	in := `{"messages":[{"role":"user","content":"login {\"password\":\"hunter2\"}"}],"api_key":"abc","x":"Basic dXNlcjpwYXNz"}`
	out := r.Text(in)
	for _, leak := range []string{"hunter2", `"abc"`, "dXNlcjpwYXNz"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q leaked: %s", leak, out)
		}
	}
	if !strings.Contains(out, `"api_key":"[redacted:`+r.Fingerprint("abc")+`]"`) {
		t.Errorf("api_key fingerprint missing: %s", out)
	}
}
