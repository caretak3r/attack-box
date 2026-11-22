package secret

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func benchFP(v string) string {
	h := sha256.Sum256([]byte(v))
	return "hmac256:" + hex.EncodeToString(h[:])[:16]
}

// Benchmark hot path: credential scrubbing in production logs

func BenchmarkScrubSmallBenign(b *testing.B) {
	text := `{"status":"ok","count":42}`
	b.ResetTimer()
	for b.Loop() {
		_ = Scrub(text, benchFP)
	}
}

func BenchmarkScrubTypicalLog(b *testing.B) {
	text := `{"timestamp":"2024-11-22T10:30:00Z","level":"info","msg":"request handled","duration_ms":125,"path":"/api/models","status":200}`
	b.ResetTimer()
	for b.Loop() {
		_ = Scrub(text, benchFP)
	}
}

func BenchmarkScrubWithCredential(b *testing.B) {
	text := `{"api_key":"sk-1234567890abcdef","timestamp":"2024-11-22T10:30:00Z","status":"authenticated"}`
	b.ResetTimer()
	for b.Loop() {
		_ = Scrub(text, benchFP)
	}
}

func BenchmarkScrubAuthHeader(b *testing.B) {
	text := `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`
	b.ResetTimer()
	for b.Loop() {
		_ = Scrub(text, benchFP)
	}
}

func BenchmarkScrubCookie(b *testing.B) {
	text := `Cookie: sessionid=abc123def456; token=xyz789uvw012; path=/`
	b.ResetTimer()
	for b.Loop() {
		_ = Scrub(text, benchFP)
	}
}

func BenchmarkScrubFormData(b *testing.B) {
	text := `username=alice&password=secret123&remember=true`
	b.ResetTimer()
	for b.Loop() {
		_ = Scrub(text, benchFP)
	}
}

func BenchmarkScrubNestedJSON(b *testing.B) {
	text := `{"user":{"name":"alice","credentials":{"api_key":"sk-abc123","refresh_token":"rt_xyz789"}},"timestamp":"2024-11-22T10:30:00Z"}`
	b.ResetTimer()
	for b.Loop() {
		_ = Scrub(text, benchFP)
	}
}

func BenchmarkScrubLargeLog(b *testing.B) {
	// Simulate 1KB log with multiple credential patterns
	var sb strings.Builder
	sb.WriteString(`{"timestamp":"2024-11-22T10:30:00Z","request":{`)
	sb.WriteString(`"headers":{"Authorization":"Bearer tok_1234567890abcdef","User-Agent":"curl/7.68.0"},`)
	sb.WriteString(`"body":{"username":"alice","password":"pass123","data":[`)
	for i := 0; i < 10; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"id":`)
		sb.WriteString(string(rune('0' + i)))
		sb.WriteString(`,"value":"item_`)
		sb.WriteString(string(rune('0' + i)))
		sb.WriteString(`"}`)
	}
	sb.WriteString(`],"metadata":{"api_key":"sk-9876543210fedcba"}}}}`)
	text := sb.String()

	b.ResetTimer()
	for b.Loop() {
		_ = Scrub(text, benchFP)
	}
}

func BenchmarkScrubAdversarialBrackets(b *testing.B) {
	// From adv_test.go: deeply nested brackets
	text := strings.Repeat(`user[`, 500) + "password" + strings.Repeat(`]`, 500) + "=secret123"
	b.ResetTimer()
	for b.Loop() {
		_ = Scrub(text, benchFP)
	}
}

func BenchmarkScrubAdversarialCookie(b *testing.B) {
	// From adv_test.go: many cookie pairs
	var sb strings.Builder
	sb.WriteString("Cookie: ")
	for i := 0; i < 200; i++ {
		if i > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString("token")
		sb.WriteString(string(rune('0' + (i % 10))))
		sb.WriteString("=val")
		sb.WriteString(string(rune('0' + (i % 10))))
	}
	text := sb.String()

	b.ResetTimer()
	for b.Loop() {
		_ = Scrub(text, benchFP)
	}
}

func BenchmarkScrubNoFingerprint(b *testing.B) {
	text := `{"api_key":"sk-1234567890abcdef","timestamp":"2024-11-22T10:30:00Z"}`
	b.ResetTimer()
	for b.Loop() {
		_ = Scrub(text, nil)
	}
}

func BenchmarkIsCredentialName(b *testing.B) {
	names := []string{
		"api_key",
		"password",
		"access_token",
		"client_secret",
		"refresh_token",
		"count",
		"status",
		"timestamp",
	}

	b.ResetTimer()
	for b.Loop() {
		for _, name := range names {
			_ = IsCredentialName(name)
		}
	}
}
