package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	collector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
)

type traceSink struct {
	collector.UnimplementedTraceServiceServer
	requests chan *collector.ExportTraceServiceRequest
}

func (s *traceSink) Export(_ context.Context, r *collector.ExportTraceServiceRequest) (*collector.ExportTraceServiceResponse, error) {
	s.requests <- r
	return &collector.ExportTraceServiceResponse{}, nil
}

func publicTestConfig(t *testing.T) (config, *x509.CertPool, *traceSink, string) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "attackbox-public-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parsed)
	socket := filepath.Join(dir, "otel.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	sink := &traceSink{requests: make(chan *collector.ExportTraceServiceRequest, 128)}
	collector.RegisterTraceServiceServer(server, sink)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	return config{socket: socket, host: "test-host", campaign: "test-campaign", cert: certPath, key: keyPath}, roots, sink, dir
}

func TestGatewayHTTPSAndTracing(t *testing.T) {
	cfg, roots, sink, _ := publicTestConfig(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	a, err := newApp(cfg, func() (net.Listener, error) {
		return net.Listen("tcp4", addr)
	})
	if err != nil {
		t.Fatal(err)
	}
	a.probe = func(string) bool { return false } // test clients share the healthcheck's loopback peer

	ctx, stop := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() {
		defer close(finished)
		finished <- a.run(ctx)
	}()
	defer func() {
		stop()
		if err := <-finished; err != nil {
			t.Fatal(err)
		}
	}()

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}}}
	defer client.CloseIdleConnections()

	for _, tc := range []struct {
		method, path, body, marker string
	}{
		{"GET", "/v1/models", "", `"local-instruct-8b"`},
		{"POST", "/v1/chat/completions", `{"model":"local-instruct-8b","messages":[{"role":"user","content":"test"}]}`, `"chatcmpl-`},
		{"POST", "/v1/completions", `{"model":"local-instruct-8b","prompt":"test"}`, `"cmpl-`},
		{"POST", "/openai/deployments/local-instruct-8b/chat/completions", `{"messages":[{"role":"user","content":"test"}]}`, `"chatcmpl-`},
	} {
		req, err := http.NewRequestWithContext(ctx, tc.method, "https://"+addr+tc.path, strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body), tc.marker) {
			t.Fatalf("%s %s: got status %d, body %q", tc.method, tc.path, resp.StatusCode, body)
		}
	}

	a.emitHealth()
	stop()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timeout")
	}

	seen := make(map[string]bool)
	health := false
	for len(sink.requests) > 0 {
		req := <-sink.requests
		for _, r := range req.ResourceSpans {
			for _, s := range r.ScopeSpans {
				for _, span := range s.Spans {
					if span.Name == "public.health" {
						health = true
						continue
					}
					if span.Name == "public.request" {
						var route, persona string
						for _, attr := range span.Attributes {
							if attr.Key == "http.route" {
								route = attr.Value.GetStringValue()
							}
							if attr.Key == "attackbox.persona" {
								persona = attr.Value.GetStringValue()
							}
						}
						if persona != "cloud-gateway" {
							t.Errorf("unexpected persona %q", persona)
						}
						seen[route] = true
					}
				}
			}
		}
	}
	if !health {
		t.Error("missing health span")
	}
	expected := []string{"/v1/models", "/v1/chat/completions", "/v1/completions", "/openai/deployments/{deployment}/chat/completions"}
	for _, route := range expected {
		if !seen[route] {
			t.Errorf("missing route %q", route)
		}
	}
}

func TestPreHTTPConnectionSpans(t *testing.T) {
	cfg, roots, sink, _ := publicTestConfig(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	a, err := newApp(cfg, func() (net.Listener, error) { return listener, nil })
	if err != nil {
		t.Fatal(err)
	}
	a.probe = func(string) bool { return false }
	ctx, stop := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- a.run(ctx) }()
	running := true
	defer func() {
		if running {
			stop()
			<-finished
		}
	}()

	dial := func() net.Conn {
		conn, err := net.DialTimeout("tcp4", addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		return conn
	}
	_ = dial().Close()
	plain := dial()
	_, _ = io.WriteString(plain, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	_, _ = io.Copy(io.Discard, plain)
	_ = plain.Close()
	untrusted := tls.Client(dial(), &tls.Config{ServerName: "scanner.invalid", MinVersion: tls.VersionTLS12})
	if untrusted.Handshake() == nil {
		t.Fatal("untrusted handshake succeeded")
	}
	_ = untrusted.Close()
	idle := tls.Client(dial(), &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	if err := idle.Handshake(); err != nil {
		t.Fatal(err)
	}
	_ = idle.Close()
	for deadline := time.Now().Add(5 * time.Second); a.preHTTP.Load() < 4 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if got := a.preHTTP.Load(); got != 4 || a.accepted.Load() != 0 {
		t.Fatalf("pre-HTTP connections = %d, accepted requests = %d", got, a.accepted.Load())
	}
	stop()
	running = false
	if err := <-finished; err != nil {
		t.Fatal(err)
	}

	got := make(map[string]string)
	for len(sink.requests) > 0 {
		for _, r := range (<-sink.requests).ResourceSpans {
			for _, s := range r.ScopeSpans {
				for _, span := range s.Spans {
					if span.Name != "public.connection" {
						continue
					}
					var outcome, sni string
					for _, attr := range span.Attributes {
						switch attr.Key {
						case "attackbox.connection.outcome":
							outcome = attr.Value.GetStringValue()
						case "attackbox.tls.sni":
							sni = attr.Value.GetStringValue()
						case "client.address":
							t.Error("loopback connection acquired an internet client address")
						}
					}
					got[outcome] = sni
				}
			}
		}
	}
	want := map[string]string{"no_data": "", "not_tls": "", "tls_failed": "other", "no_request": "match"}
	if len(got) != len(want) {
		t.Fatalf("connection outcomes = %v, want %v", got, want)
	}
	for outcome, sni := range want {
		if s, ok := got[outcome]; !ok || s != sni {
			t.Errorf("outcome %s: sni %q, want %q (all: %v)", outcome, s, sni, got)
		}
	}
}

func TestRateLimitBoundsAndRefills(t *testing.T) {
	now := time.Unix(1000, 0)
	r := newRateLimit(1, 2, now)
	if !r.allow(now) || !r.allow(now) || r.allow(now) {
		t.Fatal("rate limit burst incorrect")
	}
	now = now.Add(time.Second)
	if !r.allow(now) || r.allow(now) {
		t.Fatal("rate limit refill incorrect")
	}
}

func TestConnectionReleaseIsIdempotent(t *testing.T) {
	slots := make(chan struct{}, 1)
	conn := &limitedConn{Conn: mockConn{}, slots: slots}
	slots <- struct{}{}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if len(slots) != 0 {
		t.Fatal("slot not released exactly once")
	}
}

func TestStartupRequiresTrustedPrerequisites(t *testing.T) {
	cfg, _, _, dir := publicTestConfig(t)
	cfg.socket = "/nonexistent.sock"
	if _, err := newApp(cfg, func() (net.Listener, error) { return nil, nil }); err == nil {
		t.Fatal("server admitted a missing collector socket")
	}
	cfg.socket = filepath.Join(dir, "otel.sock")
	cfg.cert = "/nonexistent"
	if _, err := newApp(cfg, func() (net.Listener, error) { return nil, nil }); err == nil {
		t.Fatal("server admitted a missing certificate")
	}
}

func TestNonGatewayRouteRejected(t *testing.T) {
	cfg, roots, _, _ := publicTestConfig(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	a, err := newApp(cfg, func() (net.Listener, error) {
		return net.Listen("tcp4", addr)
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, stop := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- a.run(ctx) }()
	defer func() {
		stop()
		_ = <-finished
	}()

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}}}
	defer client.CloseIdleConnections()

	for _, path := range []string{"/api/version", "/health", "/collections", "/v2/models/score"} {
		req, err := http.NewRequestWithContext(ctx, "GET", "https://"+addr+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("GET %s: expected 404, got %d", path, resp.StatusCode)
		}
	}
}

func TestSIGHUPReloadsCertificate(t *testing.T) {
	cfg, roots, _, dir := publicTestConfig(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	a, err := newApp(cfg, func() (net.Listener, error) {
		return net.Listen("tcp4", addr)
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, stop := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- a.run(ctx) }()
	defer func() {
		stop()
		_ = <-finished
	}()

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}}}
	defer client.CloseIdleConnections()

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+addr+"/v1/models", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("initial request failed")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	newCert := filepath.Join(dir, "cert-new.pem")
	newKey := filepath.Join(dir, "key-new.pem")
	if err := os.WriteFile(newCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newKey, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(newCert, cfg.cert); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(newKey, cfg.key); err != nil {
		t.Fatal(err)
	}

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	newRoots := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(der)
	newRoots.AddCert(parsed)
	newClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: newRoots, ServerName: "localhost", MinVersion: tls.VersionTLS12}}}
	defer newClient.CloseIdleConnections()

	req, _ = http.NewRequestWithContext(ctx, "GET", "https://"+addr+"/v1/models", nil)
	resp, err = newClient.Do(req)
	if err != nil {
		t.Fatal("reload failed:", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal("request after reload failed")
	}
}

type mockConn struct{}

func (mockConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (mockConn) Write([]byte) (int, error)        { return 0, io.EOF }
func (mockConn) Close() error                     { return nil }
func (mockConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (mockConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (mockConn) SetDeadline(time.Time) error      { return nil }
func (mockConn) SetReadDeadline(time.Time) error  { return nil }
func (mockConn) SetWriteDeadline(time.Time) error { return nil }
