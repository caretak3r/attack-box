package secret

import (
	"strings"
	"testing"
	"time"
)

// Adversarial inputs must scale linearly. Comparing n against 4n keeps the
// check independent of machine speed and -race overhead: quadratic would be
// ~16x, linear ~4x.
func TestScrubAdversarialLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	gen := map[string]func(n int) string{
		"keys":        func(n int) string { return strings.Repeat(`"a":`, n/4) },
		"credkeys":    func(n int) string { return strings.Repeat(`"token":1,`, n/10) },
		"brackets":    func(n int) string { return `{"token":` + strings.Repeat("[", n) },
		"strings":     func(n int) string { return strings.Repeat(`"x" `, n/4) },
		"quotes":      func(n int) string { return strings.Repeat(`"`, n) },
		"backslash":   func(n int) string { return strings.Repeat(`\`, n) },
		"kv":          func(n int) string { return strings.Repeat("password=", n/9) },
		"cookie":      func(n int) string { return "Cookie: " + strings.Repeat("a=b;", n/4) },
		"pem":         func(n int) string { return strings.Repeat("-----BEGIN PRIVATE KEY-----", n/27) },
		"markers":     func(n int) string { return `"password":` + strings.Repeat("[redacted]", n/10) },
		"escaped":     func(n int) string { return strings.Repeat(`\"token\":\"`, n/11) },
		"unicodename": func(n int) string { return `"` + strings.Repeat(`a`, n/6) },
		"schemanest": func(n int) string {
			return strings.Repeat(`{"token":{"type":"object","properties":{"p":`, n/44) + strings.Repeat("}}}", n/44)
		},
		"schemaflat":  func(n int) string { return strings.Repeat(`"token":{"type":"string"},`, n/26) },
		"fold":        func(n int) string { return "Authorization:" + strings.Repeat("\r\n ", n/5) },
		"digest":      func(n int) string { return "Authorization: Digest " + strings.Repeat(`a="b", `, n/7) },
		"cookiequote": func(n int) string { return "Cookie: " + strings.Repeat(`a="b";`, n/6) },
		"spacedkv":    func(n int) string { return strings.Repeat("api key api key: ", n/16) },
		"netpath":     func(n int) string { return strings.Repeat("//a:", n/4) },
		"brackets kv": func(n int) string { return strings.Repeat("a[", n/2) },
	}
	// The race detector slows the regex engine ~20x; smaller inputs keep
	// the default gate fast while still exposing a quadratic path.
	n := 16 << 10
	if raceEnabled {
		n = 4 << 10
	}
	best := func(in string) time.Duration {
		d := time.Duration(1 << 62)
		for i := 0; i < 3; i++ {
			s := time.Now()
			Scrub(in, fp)
			d = min(d, time.Since(s))
		}
		return d
	}
	for name, g := range gen {
		small, large := best(g(n)), best(g(4*n))
		ratio := float64(large) / float64(max(small, time.Microsecond))
		t.Logf("%s: %v -> %v (x%.1f)", name, small, large, ratio)
		if ratio > 10 && large > 20*time.Millisecond {
			t.Errorf("%s: superlinear, %v at n vs %v at 4n", name, small, large)
		}
	}
}
