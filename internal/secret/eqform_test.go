package secret

import (
	"strings"
	"testing"
)

func TestScrubEqualsFormAuthAndCookie(t *testing.T) {
	cases := map[string]struct{ in, secret string }{
		"authorization bearer": {"curl -d authorization=Bearer abcdef123456 x", "abcdef123456"},
		"authorization basic":  {"authorization=Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"},
		"authorization bare":   {"authorization=tok-9f8e7d", "tok-9f8e7d"},
		"proxy authorization":  {"proxy-authorization=Bearer zz991", "zz991"},
		"spaced":               {"authorization = Bearer zz992", "zz992"},
		"cookie":               {"cookie=session=s3ss10n; other=0th3r", "s3ss10n"},
		"cookie second":        {"cookie=session=s3ss10n; other=0th3r", "0th3r"},
		"set-cookie":           {"set-cookie=sid=abc777; Path=/", "abc777"},
		"after text":           {"hdr dump: cookie=a=b8c9 end", "b8c9"},
	}
	for name, c := range cases {
		if got := Scrub(c.in, fp); strings.Contains(got, c.secret) {
			t.Errorf("%s: %q leaks %q", name, got, c.secret)
		}
	}
	if got := Scrub("cookie=session=s3ss10n; Path=/", fp); !strings.Contains(got, "session=") {
		t.Errorf("cookie name dropped: %q", got)
	}
}
