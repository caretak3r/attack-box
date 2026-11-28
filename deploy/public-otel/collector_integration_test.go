package publicotel_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	collector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	common "go.opentelemetry.io/proto/otlp/common/v1"
	resource "go.opentelemetry.io/proto/otlp/resource/v1"
	trace "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestPublicCollectorSanitizesAndBindsIdentity(t *testing.T) {
	binary := os.Getenv("ATTACKBOX_TEST_COLLECTOR")
	if binary == "" {
		t.Skip("set ATTACKBOX_TEST_COLLECTOR to the verified native Collector")
	}
	dir, err := os.MkdirTemp("/tmp", "abx-public-otel-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	original, err := os.ReadFile("config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.ReplaceAll(string(original), "/run/attackbox-public-otel", dir)
	cfg = strings.ReplaceAll(cfg, "127.0.0.1:13134", "127.0.0.1:0")
	cfg = strings.ReplaceAll(cfg, "port: 8889", "port: 0")
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--config="+path)
	cmd.Env = append(os.Environ(), "STATE_DIRECTORY="+dir, "ATTACKBOX_HOST_ID=trusted-host", "ATTACKBOX_HOST_NAME=trusted-name", "ATTACKBOX_CAMPAIGN_ID=trusted-campaign", "ATTACKBOX_PUBLIC_RELEASE_VERSION=test-release")
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_ = cmd.Wait()
		if t.Failed() {
			t.Log(logs.String())
		}
	}()
	socket := filepath.Join(dir, "otlp.sock")
	for range 100 {
		if st, err := os.Stat(socket); err == nil && st.Mode()&os.ModeSocket != 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	conn, err := grpc.NewClient("passthrough:///collector", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	str := func(k, v string) *common.KeyValue {
		return &common.KeyValue{Key: k, Value: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: v}}}
	}
	num := func(k string, v int64) *common.KeyValue {
		return &common.KeyValue{Key: k, Value: &common.AnyValue{Value: &common.AnyValue_IntValue{IntValue: v}}}
	}
	now := uint64(time.Now().UnixNano())
	span := func(name string, id byte, attrs ...*common.KeyValue) *trace.Span {
		return &trace.Span{Name: name, TraceId: bytes.Repeat([]byte{id}, 16), SpanId: bytes.Repeat([]byte{id}, 8), StartTimeUnixNano: now, EndTimeUnixNano: now + 1000, Kind: trace.Span_SPAN_KIND_CLIENT, TraceState: "private-marker", Status: &trace.Status{Message: "private-marker"}, Attributes: attrs, Events: []*trace.Span_Event{{Name: "private-marker", TimeUnixNano: now}}}
	}
	contentType := str("attackbox.request.content_type", "application/json")
	queryParams := num("attackbox.request.query_params", 2)
	goodHTTP := span("public.request", 1, num("server.port", 443), str("attackbox.persona", "cloud-gateway"), str("http.route", "/v1/completions"), str("http.request.method", "POST"), num("http.response.status_code", 200), contentType, queryParams, str("client.address", "192.0.2.1"), str("request.body", "private-marker"))
	goodFamily := span("public.request", 40, num("server.port", 443), str("attackbox.persona", "cloud-gateway"), str("http.route", "/litellm/anthropic/v1/messages"), str("http.request.method", "POST"), num("http.response.status_code", 200), contentType, queryParams, str("client.address", "192.0.2.1"))
	goodProbe := span("public.request", 41, num("server.port", 443), str("attackbox.persona", "cloud-gateway"), str("http.route", "/unmatched"), str("http.request.method", "GET"), num("http.response.status_code", 404), contentType, num("attackbox.request.query_params", 0), str("attackbox.probe.class", "env_file"), str("client.address", "192.0.2.1"))
	badFamily := span("public.request", 42, num("server.port", 443), str("attackbox.persona", "cloud-gateway"), str("http.route", "/v1/private-marker/models"), str("http.request.method", "GET"), num("http.response.status_code", 200), contentType, queryParams)
	noQuery := span("public.request", 43, num("server.port", 443), str("attackbox.persona", "cloud-gateway"), str("http.route", "/v1/models"), str("http.request.method", "GET"), num("http.response.status_code", 200), contentType)
	badCapture := span("public.health", 44, num("server.port", 443), str("attackbox.captured_requests", "private-marker"))
	badRoute := span("public.request", 2, num("server.port", 443), str("attackbox.persona", "cloud-gateway"), str("http.route", "/private-marker"), str("http.request.method", "GET"), num("http.response.status_code", 200), contentType)
	badPort := span("public.request", 3, num("server.port", 80), str("attackbox.persona", "cloud-gateway"), str("http.route", "/v1/models"), str("http.request.method", "GET"), num("http.response.status_code", 200), contentType)
	badAddress := span("public.request", 4, num("server.port", 443), str("attackbox.persona", "cloud-gateway"), str("http.route", "/v1/models"), str("http.request.method", "GET"), num("http.response.status_code", 200), contentType, str("client.address", "private-marker"))
	health := span("public.health", 5, num("server.port", 443), num("attackbox.accepted_requests", 1), num("attackbox.rate_limited_requests", 0), num("attackbox.pre_http_connections", 3), num("attackbox.rejected_connections", 0), num("attackbox.captured_requests", 1), num("attackbox.capture_dropped", 0), num("attackbox.otel_dropped_spans_total", 0), num("attackbox.otel_export_failed_spans_total", 0), contentType, str("client.address", "198.51.100.2"))
	goodConn := span("public.connection", 30, num("server.port", 443), str("client.address", "192.0.2.7"), str("attackbox.connection.outcome", "tls_failed"), str("attackbox.tls.sni", "other"), str("request.body", "private-marker"))
	badOutcome := span("public.connection", 31, num("server.port", 443), str("attackbox.connection.outcome", "private-marker"))
	noOutcome := span("public.connection", 32, num("server.port", 443))
	badSNI := span("public.connection", 33, num("server.port", 443), str("attackbox.connection.outcome", "no_request"), str("attackbox.tls.sni", "private-marker"))
	badCounter := span("public.health", 34, num("server.port", 443), str("attackbox.pre_http_connections", "private-marker"))
	goodRPC := span("public.rpc", 6, num("server.port", 6334), str("attackbox.persona", "qdrant-grpc"), str("rpc.system", "grpc"), str("rpc.service", "qdrant.Collections"), str("rpc.method", "List"), num("rpc.grpc.status_code", 0), str("client.address", "2001:db8::1"))
	badPersona := span("public.request", 7, num("server.port", 443), str("attackbox.persona", "mlflow"), str("http.route", "/v1/models"), str("http.request.method", "GET"), num("http.response.status_code", 200), contentType)
	badRPCPort := span("public.rpc", 8, num("server.port", 443), str("attackbox.persona", "qdrant-grpc"), str("rpc.system", "grpc"), str("rpc.service", "qdrant.Collections"), str("rpc.method", "List"), num("rpc.grpc.status_code", 0))
	badRPCService := span("public.rpc", 9, num("server.port", 6334), str("attackbox.persona", "qdrant-grpc"), str("rpc.system", "grpc"), str("rpc.service", "tensorflow.serving.ModelService"), str("rpc.method", "GetModelStatus"), num("rpc.grpc.status_code", 0))
	resourceSpan := func(service string, spans ...*trace.Span) *trace.ResourceSpans {
		return &trace.ResourceSpans{SchemaUrl: "private-marker", Resource: &resource.Resource{Attributes: []*common.KeyValue{str("service.name", service), str("secret", "private-marker")}}, ScopeSpans: []*trace.ScopeSpans{{SchemaUrl: "private-marker", Scope: &common.InstrumentationScope{Name: "private-marker", Attributes: []*common.KeyValue{str("secret", "private-marker")}}, Spans: spans}}}
	}
	public := []*trace.Span{goodHTTP, badRoute, badPort, badAddress, health, badPersona, badRPCPort, goodConn, badOutcome, noOutcome, badSNI, badCounter, goodFamily, goodProbe, badFamily, noQuery, badCapture}
	for i, invalid := range []*common.KeyValue{
		str("client.address", "203.0.113.256"), str("client.address", "192.000.2.1"), str("client.address", "2001:db8::1"),
		str("client.address", "172.19.0.1"), str("client.address", "100.127.0.1"), str("client.address", "127.0.0.1"),
		str("client.address", "0.1.2.3"), str("client.address", "240.0.0.1"), num("client.address", 1),
		str("attackbox.request.content_type", "application/json; token=private-marker"), num("http.request.body.size", -1),
		str("http.request.body.size", "private-marker"), str("gen_ai.request.model", "private-marker"), str("attackbox.request.stream", "true"),
		num("attackbox.request.query_params", -1), num("attackbox.request.query_params", 65), str("attackbox.request.query_params", "private-marker"),
		str("attackbox.probe.class", "private-marker"), num("attackbox.probe.class", 1), str("attackbox.canary.key", "private-marker"),
		str("attackbox.mcp.method", "private-marker"),
	} {
		s := span("public.request", byte(60+i), num("server.port", 443), str("attackbox.persona", "cloud-gateway"), str("http.route", "/v1/models"), str("http.request.method", "GET"), num("http.response.status_code", 200), invalid)
		for _, base := range []*common.KeyValue{contentType, queryParams} {
			if invalid.Key != base.Key {
				s.Attributes = append(s.Attributes, base)
			}
		}
		public = append(public, s)
	}
	input := &collector.ExportTraceServiceRequest{ResourceSpans: []*trace.ResourceSpans{
		resourceSpan("attackbox-public-443", public...),
		resourceSpan("attackbox-public-6334", goodRPC, badRPCService),
	}}
	if _, err := collector.NewTraceServiceClient(conn).Export(ctx, input); err != nil {
		t.Fatal(err)
	}
	tracesFile := filepath.Join(dir, "traces.jsonl")
	var result *collector.ExportTraceServiceRequest
	for range 200 {
		if st, err := os.Stat(tracesFile); err == nil && st.Size() > 0 {
			data, err := os.ReadFile(tracesFile)
			if err != nil {
				t.Fatal(err)
			}
			scanner := bufio.NewScanner(bytes.NewReader(data))
			for scanner.Scan() {
				line := scanner.Bytes()
				if len(line) == 0 {
					continue
				}
				// OTLP/JSON encodes trace/span IDs as hex; protojson expects base64
				line = bytes.ReplaceAll(line, []byte(`"traceId":"`), []byte(`"traceId":"__HEX__`))
				line = bytes.ReplaceAll(line, []byte(`"spanId":"`), []byte(`"spanId":"__HEX__`))
				line = bytes.ReplaceAll(line, []byte(`"parentSpanId":"`), []byte(`"parentSpanId":"__HEX__`))
				hexPrefix := []byte(`"__HEX__`)
				for {
					idx := bytes.Index(line, hexPrefix)
					if idx < 0 {
						break
					}
					start := idx + len(hexPrefix)
					end := start
					for end < len(line) && line[end] != '"' {
						end++
					}
					hexStr := line[start:end]
					decoded, _ := hex.DecodeString(string(hexStr))
					b64 := base64.StdEncoding.EncodeToString(decoded)
					line = append(line[:idx], append([]byte(`"`+b64), line[end:]...)...)
				}
				result = &collector.ExportTraceServiceRequest{}
				if err := protojson.Unmarshal(line, result); err != nil {
					t.Fatalf("invalid OTLP JSON: %v", err)
				}
				break
			}
			if result != nil {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if result == nil {
		t.Fatal("no OTLP export before timeout")
	}
	wire, err := proto.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte("private-marker")) || bytes.Contains(wire, []byte("198.51.100.2")) || bytes.Contains(wire, []byte("2001:db8::1")) {
		t.Fatal("unapproved request or health data reached the exporter")
	}
	seen := make(map[byte]bool)
	for _, rs := range result.ResourceSpans {
		attrs := make(map[string]string)
		for _, a := range rs.Resource.Attributes {
			attrs[a.Key] = a.Value.GetStringValue()
		}
		if attrs["host.id"] != "trusted-host" || attrs["service.instance.id"] != attrs["service.name"] || attrs["service.version"] != "test-release" {
			t.Fatalf("invalid trusted identity: %v", attrs)
		}
		for _, ss := range rs.ScopeSpans {
			for _, s := range ss.Spans {
				if len(s.SpanId) != 8 || len(s.Events) != 0 || len(s.Links) != 0 || s.TraceState != "" || s.Status.GetMessage() != "" {
					t.Fatal("untrusted trace metadata survived")
				}
				seen[s.SpanId[0]] = true
				if s.Name == "public.request" {
					var peer string
					for _, field := range s.Attributes {
						if field.Key == "client.address" {
							peer = field.Value.GetStringValue()
						}
					}
					if peer != "192.0.2.1" {
						t.Error("exporter lost the approved request peer")
					}
				}
				if s.Name == "public.health" {
					for _, field := range s.Attributes {
						switch field.Key {
						case "server.port", "attackbox.accepted_requests", "attackbox.rate_limited_requests", "attackbox.pre_http_connections", "attackbox.rejected_connections", "attackbox.captured_requests", "attackbox.capture_dropped", "attackbox.otel_dropped_spans_total", "attackbox.otel_export_failed_spans_total":
						default:
							t.Errorf("request data on health span: %s", field.Key)
						}
					}
				}
				if s.Name == "public.connection" {
					fields := make(map[string]string)
					for _, field := range s.Attributes {
						switch field.Key {
						case "server.port", "client.address", "attackbox.connection.outcome", "attackbox.tls.sni":
							fields[field.Key] = field.Value.GetStringValue()
						default:
							t.Errorf("unapproved field on connection span: %s", field.Key)
						}
					}
					if fields["client.address"] != "192.0.2.7" || fields["attackbox.connection.outcome"] != "tls_failed" || fields["attackbox.tls.sni"] != "other" {
						t.Errorf("exporter lost approved connection fields: %v", fields)
					}
				}
				if (s.Name == "public.request" || s.Name == "public.rpc") && s.Kind != trace.Span_SPAN_KIND_SERVER {
					t.Fatal("server span kind not normalized")
				}
			}
		}
	}
	if len(seen) != 5 || !seen[1] || !seen[5] || !seen[30] || !seen[40] || !seen[41] {
		t.Fatalf("wrong accepted spans: %v", seen)
	}
}
