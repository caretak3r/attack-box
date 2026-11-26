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
	cfg.capture = filepath.Join(dir, "capture")
	if err := os.Mkdir(cfg.capture, 0o700); err != nil {
		t.Fatal(err)
	}
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
	a.probe = func(string) bool { return false }         // test clients share the healthcheck's loopback peer
	a.limiter = newRateLimit(requestRate, 9, time.Now()) // eight requests follow without a pause
	plainAddr := make(map[int]string)
	for _, port := range []int{8000, 9999} { // 9999 is outside the Collector's port allowlist
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		plainAddr[port] = l.Addr().String()
		a.addPlain(port, l)
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
	// Longer than the 128-byte cap on other spans: the full value must survive the Collector.
	credential := "sk-ant-" + strings.Repeat("k0", 80)
	for _, tc := range []struct {
		method, path, body string
		port               int
	}{
		{"GET", "/v1/models", "", externalPort},
		{"POST", "/v1/chat/completions", chatPayload, externalPort},
		{"POST", "/v1/api/completions", `{"model":"local-instruct-8b","prompt":"test"}`, externalPort},
		{"POST", "/openai/deployments/local-instruct-8b/chat/completions", `{"messages":[{"role":"user","content":"test"}]}`, externalPort},
		{"GET", "/api/tags", "", 8000},
		{"GET", "/health", "", 8000}, // port persona path: its route label must pass the Collector
		{"GET", "/.env", "", 8000},   // env-file answer: its route label and its fake key must pass the Collector
		{"GET", "/v1/models", "", 9999},
	} {
		base := "https://" + addr
		if tc.port != externalPort {
			base = "http://" + plainAddr[tc.port]
		}
		req, err := http.NewRequestWithContext(serverCtx, tc.method, base+tc.path+"?q="+privateMarker, strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json; fixture="+privateMarker)
		req.Header.Set("Authorization", "Bearer "+credential)
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
	plain, err := net.DialTimeout("tcp4", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = plain.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(plain, "GET /?token="+privateMarker+" HTTP/1.1\r\nHost: x\r\n\r\n")
	_, _ = io.Copy(io.Discard, plain)
	_ = plain.Close()
	for deadline := time.Now().Add(5 * time.Second); a.preHTTP.Load() < 1 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
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
	health, connection := false, false
	expected := []string{"/v1/models", "/v1/chat/completions", "/v1/api/completions", "/openai/deployments/{deployment}/chat/completions", "/api/tags", "/health", "/.env"}
	for !health || !connection || len(seen) < len(expected) {
		var req *collector.ExportTraceServiceRequest
		select {
		case req = <-got:
		case <-ctx.Done():
			t.Fatalf("collector deadline: health=%t connection=%t routes=%v", health, connection, seen)
		}
		for _, r := range req.ResourceSpans {
			for _, s := range r.ScopeSpans {
				for _, span := range s.Spans {
					if span.Name == "public.health" {
						health = true
						var port, preHTTP, captured int64
						for _, attr := range span.Attributes {
							switch attr.Key {
							case "server.port":
								port = attr.Value.GetIntValue()
							case "attackbox.pre_http_connections":
								preHTTP = attr.Value.GetIntValue()
							case "attackbox.captured_requests":
								captured = attr.Value.GetIntValue()
							}
						}
						if port != externalPort || preHTTP != 1 || captured != 8 {
							t.Errorf("health span: port %d, pre-HTTP connections %d, captured %d", port, preHTTP, captured)
						}
						continue
					}
					if span.Name == "public.connection" {
						connection = true
						var outcome string
						for _, attr := range span.Attributes {
							if attr.Key == "attackbox.connection.outcome" {
								outcome = attr.Value.GetStringValue()
							}
						}
						if outcome != "not_tls" {
							t.Errorf("connection span outcome %q, want not_tls", outcome)
						}
						continue
					}
					if span.Name == "public.request" {
						var route, persona, contentType, model, credSource, credType, credValue, canary string
						var port int64
						var stream bool
						size, queryParams := int64(-1), int64(-1)
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
							case "attackbox.request.query_params":
								queryParams = attr.Value.GetIntValue()
							case "attackbox.credential.source":
								credSource = attr.Value.GetStringValue()
							case "attackbox.credential.type":
								credType = attr.Value.GetStringValue()
							case "attackbox.credential.value":
								credValue = attr.Value.GetStringValue()
							case "attackbox.canary.key":
								canary = attr.Value.GetStringValue()
							}
						}
						if persona != "cloud-gateway" {
							t.Errorf("request span: unexpected persona %q", persona)
						}
						wantPort := int64(externalPort)
						if route == "/api/tags" || route == "/health" || route == "/.env" {
							wantPort = 8000
						}
						if port != wantPort || queryParams != 1 {
							t.Errorf("request span: port %d, query params %d", port, queryParams)
						}
						if credSource != "authorization" || credType != "anthropic" || credValue != credential {
							t.Errorf("request span credential: source %q type %q value length %d", credSource, credType, len(credValue))
						}
						if (route == "/.env") != (len(canary) == 51) {
							t.Errorf("request span %s: fake key length %d", route, len(canary))
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
	raw, err := os.ReadFile(filepath.Join(cfg.capture, "capture-"+time.Now().UTC().Format("20060102")+".jsonl"))
	if err != nil || bytes.Count(raw, []byte("\n")) != 8 || !bytes.Contains(raw, []byte(`"port":8000`)) || !bytes.Contains(raw, []byte(`"port":9999`)) || !bytes.Contains(raw, []byte(`"/v1/api/completions?q=`+privateMarker+`"`)) || !bytes.Contains(raw, []byte(`"Bearer `+credential+`"`)) {
		t.Fatalf("local capture missing raw targets: %v\n%s", err, raw)
	}
}
