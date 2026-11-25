package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	collector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

// The real pinned collector is optional for ordinary offline test runs.
func TestGatewayThroughPublicCollector(t *testing.T) {
	binary := os.Getenv("ATTACKBOX_TEST_COLLECTOR")
	if binary == "" {
		t.Skip("set ATTACKBOX_TEST_COLLECTOR to the verified native Collector")
	}
	cfg, roots, _, dir := publicTestConfig(t)
	cfg.socket = filepath.Join(dir, "public-collector.sock")
	got := make(chan *collector.ExportTraceServiceRequest, 128)
	const privateMarker = "fixture-private-marker"
	const forgedPeer = "203.0.113.29"
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/traces" || r.Header.Get("Content-Type") != "application/x-protobuf" || r.Header.Get("Api-Key") == "" {
			http.Error(w, "invalid collector request", http.StatusBadRequest)
			return
		}
		body := r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			var err error
			body, err = gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, "gzip error", http.StatusBadRequest)
				return
			}
			defer body.Close()
		}
		data, err := io.ReadAll(body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		if bytes.Contains(data, []byte(privateMarker)) || bytes.Contains(data, []byte(forgedPeer)) {
			t.Error("public export contains private request data or an address from a forwarding header")
		}
		var req collector.ExportTraceServiceRequest
		if err := proto.Unmarshal(data, &req); err != nil {
			http.Error(w, "proto error", http.StatusBadRequest)
			return
		}
		got <- &req
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	defer mock.Close()
	if err := os.WriteFile(filepath.Join(dir, "newrelic_license_key"), []byte("validation-only"), 0600); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile("../../deploy/public-otel/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	collectorConfig := strings.ReplaceAll(string(original), "/run/attackbox-public-otel/otlp.sock", cfg.socket)
	collectorConfig = strings.ReplaceAll(collectorConfig, "https://otlp.nr-data.net:443", mock.URL)
	collectorConfig = strings.ReplaceAll(collectorConfig, "127.0.0.1:13134", "127.0.0.1:0")
	collectorConfig = strings.ReplaceAll(collectorConfig, "port: 8889", "port: 0")
	path := filepath.Join(dir, "public-config.yaml")
	if err := os.WriteFile(path, []byte(collectorConfig), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--config="+path)
	cmd.Env = append(os.Environ(), "CREDENTIALS_DIRECTORY="+dir, "ATTACKBOX_HOST_ID=test-host", "ATTACKBOX_HOST_NAME=test-name", "ATTACKBOX_CAMPAIGN_ID=test-campaign", "ATTACKBOX_PUBLIC_RELEASE_VERSION=test-release")
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("collector logs:\n%s", logs.String())
		}
	}()
	for range 100 {
		if conn, err := net.DialTimeout("unix", cfg.socket, 100*time.Millisecond); err == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	defer listener.Close()
	a, err := newApp(cfg, func() (net.Listener, error) { return listener, nil })
	if err != nil {
		t.Fatal(err)
	}

	serverCtx, stop := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- a.run(serverCtx) }()
	running := true
	defer func() {
		if running {
			stop()
			select {
			case err := <-finished:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(5 * time.Second):
				t.Error("shutdown timeout")
			}
		}
	}()

	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}}}
	defer client.CloseIdleConnections()

	const chatPayload = `{"model":"local-instruct-8b","stream":true,"messages":[{"role":"user","content":"` + privateMarker + `"}]}`
	for _, tc := range []struct {
		method, path, body string
	}{
		{"GET", "/v1/models", ""},
		{"POST", "/v1/chat/completions", chatPayload},
		{"POST", "/v1/completions", `{"model":"local-instruct-8b","prompt":"test"}`},
		{"POST", "/openai/deployments/local-instruct-8b/chat/completions", `{"messages":[{"role":"user","content":"test"}]}`},
	} {
		req, err := http.NewRequestWithContext(serverCtx, tc.method, "https://"+addr+tc.path+"?token="+privateMarker, strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json; fixture="+privateMarker)
		req.Header.Set("Authorization", "Bearer "+privateMarker)
		req.Header.Set("Cookie", "session="+privateMarker)
		req.Header.Set("Forwarded", "for="+forgedPeer)
		req.Header.Set("X-Forwarded-For", forgedPeer)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s %s: status %d", tc.method, tc.path, resp.StatusCode)
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
	running = false

	seen := make(map[string]bool)
	health := false
	expected := []string{"/v1/models", "/v1/chat/completions", "/v1/completions", "/openai/deployments/{deployment}/chat/completions"}
	for !health || len(seen) < len(expected) {
		var req *collector.ExportTraceServiceRequest
		select {
		case req = <-got:
		case <-ctx.Done():
			t.Fatalf("collector deadline: health=%t routes=%v", health, seen)
		}
		for _, r := range req.ResourceSpans {
			for _, s := range r.ScopeSpans {
				for _, span := range s.Spans {
					if span.Name == "public.health" {
						health = true
						var port int64
						for _, attr := range span.Attributes {
							if attr.Key == "server.port" {
								port = attr.Value.GetIntValue()
							}
						}
						if port != externalPort {
							t.Errorf("health span: expected port %d, got %d", externalPort, port)
						}
						continue
					}
					if span.Name == "public.request" {
						var route, persona, contentType, model string
						var port int64
						var stream bool
						size := int64(-1)
						for _, attr := range span.Attributes {
							switch attr.Key {
							case "http.route":
								route = attr.Value.GetStringValue()
							case "attackbox.persona":
								persona = attr.Value.GetStringValue()
							case "server.port":
								port = attr.Value.GetIntValue()
							case "client.address":
								t.Error("loopback traffic acquired an internet client address")
							case "attackbox.request.content_type":
								contentType = attr.Value.GetStringValue()
							case "gen_ai.request.model":
								model = attr.Value.GetStringValue()
							case "attackbox.request.stream":
								stream = attr.Value.GetBoolValue()
							case "http.request.body.size":
								size = attr.Value.GetIntValue()
							}
						}
						if persona != "cloud-gateway" {
							t.Errorf("request span: unexpected persona %q", persona)
						}
						if port != externalPort {
							t.Errorf("request span: expected port %d, got %d", externalPort, port)
						}
						if route == "/v1/chat/completions" && (size != int64(len(chatPayload)) || contentType != "application/json" || model != "local-instruct-8b" || !stream) {
							t.Error("chat span lost structured request fields on its way to the exporter")
						}
						seen[route] = true
					}
				}
			}
		}
	}
	for _, route := range expected {
		if !seen[route] {
			t.Errorf("missing route %q", route)
		}
	}
}
