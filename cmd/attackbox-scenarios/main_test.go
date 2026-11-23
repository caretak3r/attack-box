package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"attackbox/internal/responder"
	"attackbox/internal/server"
	"attackbox/internal/telemetry"
)

type capture struct {
	sync.Mutex
	events []telemetry.Event
}

func (s *capture) Emit(e telemetry.Event)                 { s.Lock(); defer s.Unlock(); s.events = append(s.events, e) }
func (*capture) Count(string, float64, map[string]string) {}
func (*capture) Gauge(string, float64, map[string]string) {}
func (s *capture) snapshot() []telemetry.Event {
	s.Lock()
	defer s.Unlock()
	return append([]telemetry.Event(nil), s.events...)
}

func rebuild(t *testing.T, events []telemetry.Event, id, kind string) ([]byte, telemetry.Event) {
	t.Helper()
	var body []byte
	var manifest telemetry.Event
	segments := 0
	for _, e := range events {
		if e.RequestID != id || e.Action != "capture" {
			continue
		}
		if e.Attrs["evidence_kind"] == "manifest" && e.Attrs["evidence_target"] == kind {
			manifest = e
		}
		if e.Attrs["evidence_kind"] != kind {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(e.Body, "base64:"))
		if err != nil || e.Attrs["evidence_offset"] != int64(len(body)) || e.Attrs["evidence_segment"] != segments || e.Attrs["evidence_sha256"] != digest(b) {
			t.Fatalf("invalid %s segment: %+v %v", kind, e.Attrs, err)
		}
		body = append(body, b...)
		segments++
	}
	if manifest.Attrs["evidence_bytes"] != int64(len(body)) || manifest.Attrs["evidence_sha256"] != digest(body) || manifest.Attrs["evidence_segments"] != segments {
		t.Fatalf("invalid %s manifest: %+v", kind, manifest)
	}
	return body, manifest
}

func TestScenariosRealServerEvidence(t *testing.T) {
	sink := &capture{}
	app, err := server.New(server.Config{Responder: responder.New(responder.Config{}, responder.NewStore(responder.StoreConfig{})), Sink: sink, FullEvidence: true, HoldSilent: time.Millisecond, IdleInterval: time.Millisecond, MaxStreamDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{}, len(cases()))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { app.Handler().ServeHTTP(w, r); done <- struct{}{} }))
	defer srv.Close()
	manifest := filepath.Join(t.TempDir(), "manifest.jsonl")
	if code := run([]string{"-target", srv.URL, "-output", manifest, "-run-id", "local-evidence-check"}, os.Stderr); code != 0 {
		t.Fatalf("scenario CLI exit %d", code)
	}
	f, err := os.Open(manifest)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	var results []result
	for _, s := range cases() {
		var r result
		if err := decoder.Decode(&r); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("handler did not finish")
		}
		if !r.ResponseVerified || r.LoggingVerified {
			t.Fatalf("%s: %+v", s.name, r)
		}
		events := sink.snapshot()
		body, m := rebuild(t, events, r.LogRequestID, "request_body")
		expected := s.body
		if s.name == "oversized" {
			expected = expected[:1<<20]
			if m.Attrs["evidence_complete"] != false || m.Attrs["evidence_reason"] != "body_limit" {
				t.Fatal("oversized evidence was not marked incomplete")
			}
		} else if m.Attrs["evidence_complete"] != true {
			t.Fatal("request evidence incomplete")
		}
		if string(body) != expected {
			t.Fatalf("%s request bytes changed", s.name)
		}
		response, m := rebuild(t, events, r.LogRequestID, "response_body")
		if digest(response) != r.ResponseSHA256 || len(response) != r.ResponseBytes || m.Attrs["evidence_complete"] != true {
			t.Fatalf("%s response bytes changed or incomplete", s.name)
		}
		metadata, _ := rebuild(t, events, r.LogRequestID, "request_metadata")
		var meta struct {
			URI     []byte              `json:"request_uri"`
			Headers map[string][][]byte `json:"headers"`
		}
		if json.Unmarshal(metadata, &meta) != nil || string(meta.URI) != s.path || len(meta.Headers["X-Attackbox-Research-Run"]) != 1 || string(meta.Headers["X-Attackbox-Research-Run"][0]) != r.RunID {
			t.Fatalf("%s marker or URI lost", s.name)
		}
		if s.fakeAuth && string(meta.Headers["Authorization"][0]) != "Bearer TEST_ONLY_INVALID_CREDENTIAL_42" {
			t.Fatal("fake credential not preserved in raw metadata")
		}
		found := false
		for _, e := range events {
			if e.RequestID == r.LogRequestID && e.Action != "capture" && e.UserAgent == r.Marker {
				found = true
			}
		}
		if !found {
			t.Fatal("readable research marker absent from normal logs")
		}
		results = append(results, r)
	}
	// Optional artifacts are local candidate evidence, never New Relic receipts.
	if dir := os.Getenv("ATTACKBOX_SCENARIO_TEST_REPORT_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		save := func(name string, values any) {
			f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if err = json.NewEncoder(f).Encode(values); err != nil {
				t.Fatal(err)
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
		}
		save("results.json", results)
		save("local-events.json", sink.snapshot())
	}
}

func TestLoopbackOnlyAndNoProxy(t *testing.T) {
	for _, raw := range []string{"https://example.com", "https://localhost:8443", "http://192.0.2.1", "http://127.0.0.1@evil.test", "http://127.0.0.1/path", "http://127.0.0.1?x=1", "http://127.0.0.1#x", "file:///tmp/x", "http://[::1%25lo0]:123"} {
		if _, _, err := localClient(raw, false); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	var proxy atomic.Int32
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxy.Add(1) }))
	defer p.Close()
	t.Setenv("HTTP_PROXY", p.URL)
	t.Setenv("HTTPS_PROXY", p.URL)
	t.Setenv("ALL_PROXY", p.URL)
	c, _, err := localClient("http://127.0.0.1:1234", false)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseIdleConnections()
	tr := c.Transport.(*http.Transport)
	if tr.Proxy != nil || tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("proxy or insecure TLS default enabled")
	}
	if _, err = tr.DialContext(context.Background(), "tcp", "192.0.2.1:80"); err == nil {
		t.Fatal("alternate dial accepted")
	}
	if _, _, err = localClient("http://127.0.0.1", true); err == nil {
		t.Fatal("self-signed accepted for HTTP")
	}
	if proxy.Load() != 0 {
		t.Fatal("proxy used")
	}
}

func TestRedirectAndResponseBounds(t *testing.T) {
	var followed atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1) }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	defer redirect.Close()
	c, base, _ := localClient(redirect.URL, false)
	defer c.CloseIdleConnections()
	r := execute(context.Background(), c, base, "test", cases()[0])
	if r.Error == "" || r.ResponseVerified || followed.Load() != 0 {
		t.Fatalf("redirect followed: %+v", r)
	}
	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-Id", "req_"+strings.Repeat("a", 32))
		io.WriteString(w, strings.Repeat("X", maxResponse+100))
	}))
	defer huge.Close()
	c2, base2, _ := localClient(huge.URL, false)
	defer c2.CloseIdleConnections()
	r = execute(context.Background(), c2, base2, "test", cases()[0])
	if r.ResponseComplete || r.ResponseVerified || r.ResponseBytes != maxResponse+1 || r.Error == "" {
		t.Fatalf("response limit failed: %+v", r)
	}
	s := cases()[0]
	s.body = strings.Repeat("X", maxRequest+1)
	if r = execute(context.Background(), c2, base2, "test", s); r.Error == "" || r.Status != 0 {
		t.Fatal("request limit failed")
	}
}

func TestSelfSignedAndManifestSafety(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-Id", "req_"+strings.Repeat("b", 32))
		io.WriteString(w, `{"data":[{"id":"test"}]}`)
	}))
	defer srv.Close()
	c, base, _ := localClient(srv.URL, true)
	defer c.CloseIdleConnections()
	if r := execute(context.Background(), c, base, "tls", cases()[0]); !r.ResponseVerified {
		t.Fatalf("loopback self-signed: %+v", r)
	}
	path := filepath.Join(t.TempDir(), "manifest.jsonl")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if run([]string{"-output", path, "-target", srv.URL, "-self-signed"}, io.Discard) != 1 {
		t.Fatal("existing manifest accepted")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "keep" {
		t.Fatal("manifest overwritten")
	}
	if run([]string{"-output", path, "-run-id", "bad\nlabel"}, io.Discard) != 2 {
		t.Fatal("invalid run label accepted")
	}
}

func TestSSERejectsPartialOrMalformedFrames(t *testing.T) {
	for _, body := range []string{"data: [DONE]\n\n", "data: broken\n\ndata: [DONE]\n\n", "data: {}\n\n", "data: [DONE]\n\ndata: [DONE]\n\n"} {
		if validSSE([]byte(body)) {
			t.Fatalf("accepted malformed SSE %q", body)
		}
	}
	if !validSSE([]byte("data: {\"choices\":[]}\n\ndata: [DONE]\n\n")) {
		t.Fatal("valid JSON frame rejected")
	}
}
