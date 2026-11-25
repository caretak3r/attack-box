package publicedge

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCaptureRecordsRawTargetLocally(t *testing.T) {
	dir := t.TempDir()
	day := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	c, err := openCapture(dir, func() time.Time { return day })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := NewGateway(nil)
	g.Capture = c
	r := httptest.NewRequest("GET", "/.env?key=fixture-secret", nil)
	r.RemoteAddr = "[::ffff:203.0.113.9]:4242"
	r.Header.Set("User-Agent", "scanner/1.0\x1b[31m")
	g.ServeHTTP(httptest.NewRecorder(), r)

	f, err := os.Open(filepath.Join(dir, "capture-20261125.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	if st.Mode().Perm() != 0o600 {
		t.Errorf("capture mode = %v", st.Mode().Perm())
	}
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(line, "\x1b") {
		t.Fatal("control byte written raw")
	}
	var got captureRecord
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatal(err)
	}
	want := captureRecord{Time: "2026-11-25T12:00:00Z", Peer: "203.0.113.9", Method: "GET", Target: "/.env?key=fixture-secret", Host: "example.com",
		UserAgent: "scanner/1.0\x1b[31m", Route: "/unmatched", Status: 404, Probe: "env_file", Port: 443, Proto: "HTTP/1.1"}
	if got.Time != want.Time || got.Peer != want.Peer || got.Method != want.Method || got.Target != want.Target ||
		got.Host != want.Host || got.UserAgent != want.UserAgent || got.Route != want.Route ||
		got.Status != want.Status || got.Probe != want.Probe || got.Port != want.Port || got.Proto != want.Proto {
		t.Fatalf("record = %+v, want %+v", got, want)
	}
	if len(got.Headers) == 0 {
		t.Fatal("expected headers, got none")
	}
	if rec, drop := c.Counts(); rec != 1 || drop != 0 {
		t.Fatalf("counts = %d/%d", rec, drop)
	}
}

func TestCaptureBudgetAndRetention(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"capture-20261118.jsonl", "capture-20261119.jsonl", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 11, 25, 23, 59, 0, 0, time.UTC)
	c, err := openCapture(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, name := range []string{"capture-20261118.jsonl"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s survived retention", name)
		}
	}
	for _, name := range []string{"capture-20261119.jsonl", "notes.txt"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s removed: %v", name, err)
		}
	}

	r := httptest.NewRequest("GET", "/"+strings.Repeat("a", 4000), nil)
	c.size = CaptureDayLimit - 10
	c.Record(r, "/unmatched", 404, "other", nil)
	if rec, drop := c.Counts(); rec != 0 || drop != 1 {
		t.Fatalf("over budget counts = %d/%d", rec, drop)
	}

	now = now.Add(2 * time.Minute)
	c.Record(r, "/unmatched", 404, "other", nil)
	if rec, _ := c.Counts(); rec != 1 {
		t.Fatal("new day did not reset the budget")
	}
	data, err := os.ReadFile(filepath.Join(dir, "capture-20261126.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var got captureRecord
	if err := json.Unmarshal(data, &got); err != nil || len(got.Target) != captureTarget {
		t.Fatalf("target not clipped: %d %v", len(got.Target), err)
	}
	if _, err := os.Stat(filepath.Join(dir, "capture-20261119.jsonl")); !os.IsNotExist(err) {
		t.Error("rotation did not prune the oldest day")
	}
}

func TestOpenCaptureFailsWithoutDirectory(t *testing.T) {
	if _, err := OpenCapture(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing capture directory accepted")
	}
}

func TestCaptureBodyAndHeaders(t *testing.T) {
	dir := t.TempDir()
	day := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	c, err := openCapture(dir, func() time.Time { return day })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := NewGateway(nil)
	g.Capture = c

	body := `{"messages":[{"role":"user","content":"test"}]}`
	r := httptest.NewRequest("POST", "/unmatched", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Custom", "value")
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, r)

	if rec.Code != 404 {
		t.Fatalf("expected 404, got %d", rec.Code)
	}

	f, err := os.Open(filepath.Join(dir, "capture-20261125.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var got captureRecord
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatal(err)
	}

	if got.Body != body {
		t.Errorf("body = %q, want %q", got.Body, body)
	}
	if got.BodyBytes != len(body) {
		t.Errorf("body_bytes = %d, want %d", got.BodyBytes, len(body))
	}
	h := sha256.Sum256([]byte(body))
	wantHash := hex.EncodeToString(h[:])
	if got.BodySHA256 != wantHash {
		t.Errorf("body_sha256 = %q, want %q", got.BodySHA256, wantHash)
	}
	if got.BodyTruncated {
		t.Error("body_truncated should be false for small body")
	}
	if len(got.Headers) == 0 {
		t.Fatal("expected headers")
	}
	foundContentType := false
	for _, h := range got.Headers {
		if h[0] == "Content-Type" && h[1] == "application/json" {
			foundContentType = true
		}
	}
	if !foundContentType {
		t.Error("Content-Type header not found")
	}
}

func TestCaptureLargeBodyTruncation(t *testing.T) {
	dir := t.TempDir()
	day := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	c, err := openCapture(dir, func() time.Time { return day })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := NewGateway(nil)
	g.Capture = c

	// A chunked body larger than the request limit is the only body that reaches the capture cut.
	body := strings.Repeat("a", gatewayBodyLimit+5000)
	r := httptest.NewRequest("POST", "/unmatched", strings.NewReader(body))
	r.ContentLength = -1
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, r)

	f, err := os.Open(filepath.Join(dir, "capture-20261125.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var got captureRecord
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatal(err)
	}

	if len(got.Body) != captureBodyLimit || got.BodyBytes != captureBodyLimit {
		t.Errorf("body length = %d, body_bytes = %d, want %d", len(got.Body), got.BodyBytes, captureBodyLimit)
	}
	h := sha256.Sum256([]byte(body[:captureBodyLimit]))
	if got.BodySHA256 != hex.EncodeToString(h[:]) {
		t.Errorf("body_sha256 mismatch")
	}
	if !got.BodyTruncated {
		t.Error("body_truncated should be true for large body")
	}
}

// The operator keeps credentials as sent: headers and bodies are not redacted.
func TestCaptureKeepsCredentialsAsSent(t *testing.T) {
	dir := t.TempDir()
	day := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	c, err := openCapture(dir, func() time.Time { return day })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := NewGateway(nil)
	g.Capture = c

	// Fixtures are built here so that no credential-shaped literal exists in the source.
	key, other := "sk-proj-"+strings.Repeat("a1", 12), "sk-ant-"+strings.Repeat("b2", 12)
	r := httptest.NewRequest("POST", "/unmatched", strings.NewReader(`{"api_key":"`+other+`"}`))
	r.Header.Set("Authorization", "Bearer "+key)
	g.ServeHTTP(httptest.NewRecorder(), r)

	raw, err := os.ReadFile(filepath.Join(dir, "capture-20261125.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var got captureRecord
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Body != `{"api_key":"`+other+`"}` || len(got.Headers) != 1 || got.Headers[0] != [2]string{"Authorization", "Bearer " + key} {
		t.Fatalf("record = %+v", got)
	}
}

func TestCaptureWithMatchedRoute(t *testing.T) {
	dir := t.TempDir()
	day := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	c, err := openCapture(dir, func() time.Time { return day })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := NewGateway(nil)
	g.Capture = c

	body := `{"model":"local-instruct-8b","messages":[{"role":"user","content":"test"}]}`
	r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, r)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	f, err := os.Open(filepath.Join(dir, "capture-20261125.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var got captureRecord
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatal(err)
	}

	if got.Route != "/v1/chat/completions" {
		t.Errorf("route = %q, want /v1/chat/completions", got.Route)
	}
	if got.BodyBytes != len(body) {
		t.Errorf("body_bytes = %d, want %d", got.BodyBytes, len(body))
	}
	if got.Body == "" {
		t.Error("expected body for matched route")
	}
}

func TestGatewayWithoutCaptureDoesNotReadUnusedBody(t *testing.T) {
	body := strings.NewReader("unused body")
	NewGateway(nil).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/unmatched", body))
	if body.Len() != len("unused body") {
		t.Fatalf("the gateway read %d body bytes without a capture", len("unused body")-body.Len())
	}
}

func TestCaptureKeepsBodyThatNoHandlerReads(t *testing.T) {
	dir := t.TempDir()
	c, err := OpenCapture(dir)
	if err != nil {
		t.Fatal(err)
	}
	g := NewGateway(nil)
	g.Capture = c
	w := httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest("GET", "/v1/models", strings.NewReader("probe-body")))
	_ = c.Close()
	files, _ := filepath.Glob(filepath.Join(dir, "capture-*.jsonl"))
	if len(files) != 1 {
		t.Fatalf("capture files = %v", files)
	}
	raw, _ := os.ReadFile(files[0])
	var rec captureRecord
	if err := json.Unmarshal(raw, &rec); err != nil || w.Code != 200 || rec.Body != "probe-body" || rec.BodyBytes != 10 || rec.BodyTruncated {
		t.Fatalf("status=%d record=%+v err=%v", w.Code, rec, err)
	}
}
