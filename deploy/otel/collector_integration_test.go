package otel_test

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

// Run with ATTACKBOX_TEST_COLLECTOR pointing to the checksum-verified native binary.
// This test uses private Unix sockets and a loopback mock. No New Relic key or network.
func TestCollectorUnixTrustBoundary(t *testing.T) {
	binary := os.Getenv("ATTACKBOX_TEST_COLLECTOR")
	if binary == "" {
		t.Skip("set ATTACKBOX_TEST_COLLECTOR to verified native Collector")
	}
	dir, err := os.MkdirTemp("/tmp", "abx-otel-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	for _, role := range []string{"bait", "shipper"} {
		if err := os.Mkdir(filepath.Join(dir, role), 0700); err != nil {
			t.Fatal(err)
		}
	}
	source, err := os.ReadFile("config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	config := strings.ReplaceAll(string(source), "/run/attackbox-otel", dir)
	config = strings.ReplaceAll(config, "127.0.0.1:13133", "127.0.0.1:0")
	config = strings.ReplaceAll(config, "port: 8888", "port: 0")
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "--config="+path)
	cmd.Env = append(os.Environ(), "STATE_DIRECTORY="+dir, "ATTACKBOX_HOST_ID=trusted-host", "ATTACKBOX_HOST_NAME=trusted-name", "ATTACKBOX_CAMPAIGN_ID=trusted-campaign", "ATTACKBOX_BAIT_INSTANCE_ID=trusted-bait", "ATTACKBOX_SHIPPER_INSTANCE_ID=trusted-shipper", "ATTACKBOX_MONITOR_INSTANCE_ID=trusted-monitor", "ATTACKBOX_OTEL_INSTANCE_ID=trusted-otel", "ATTACKBOX_BAIT_CONTAINER_ID=trusted-container", "ATTACKBOX_RELEASE_VERSION=test")
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
	sock := filepath.Join(dir, "bait", "otlp.sock")
	for range 100 {
		if st, err := os.Stat(sock); err == nil && st.Mode()&os.ModeSocket != 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	conn, err := grpc.NewClient("passthrough:///collector", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	str := func(k, v string) *common.KeyValue {
		return &common.KeyValue{Key: k, Value: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: v}}}
	}
	now := uint64(time.Now().UnixNano())
	span := &trace.Span{Name: "bait.request", TraceId: bytes.Repeat([]byte{1}, 16), SpanId: bytes.Repeat([]byte{2}, 8), StartTimeUnixNano: now, EndTimeUnixNano: now + 1000, Kind: trace.Span_SPAN_KIND_CLIENT, TraceState: "untrusted-secret", Status: &trace.Status{Message: "untrusted-secret"}, Attributes: []*common.KeyValue{str("http.request.method", "GET"), str("http.route", "/v1/models"), str("attackbox.request_id", "0123456789abcdef"), str("payload", "untrusted-secret")}, Events: []*trace.Span_Event{{Name: "untrusted-secret", TimeUnixNano: now}}}
	wrong := proto.Clone(span).(*trace.Span)
	wrong.Name = "shipper.export"
	invalid := proto.Clone(span).(*trace.Span)
	invalid.Attributes = append(invalid.Attributes, str("attackbox.persona", "untrusted-secret"))
	input := &collector.ExportTraceServiceRequest{
		ResourceSpans: []*trace.ResourceSpans{{
			SchemaUrl: "untrusted-secret",
			Resource: &resource.Resource{Attributes: []*common.KeyValue{
				str("service.name", "spoofed-shipper"), str("host.id", "spoofed-host"), str("secret", "untrusted-secret"),
			}},
			ScopeSpans: []*trace.ScopeSpans{{
				SchemaUrl: "untrusted-secret",
				Scope:     &common.InstrumentationScope{Name: "untrusted-secret", Attributes: []*common.KeyValue{str("secret", "untrusted-secret")}},
				Spans:     []*trace.Span{span, wrong, invalid},
			}},
		}},
	}
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
					t.Fatal(err)
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
		t.Fatal("no trace export before timeout")
	}
	wire, _ := proto.Marshal(result)
	if bytes.Contains(wire, []byte("untrusted-secret")) || bytes.Contains(wire, []byte("spoofed")) {
		t.Fatal("untrusted metadata escaped")
	}
	count := 0
	for _, rs := range result.ResourceSpans {
		attrs := map[string]string{}
		for _, a := range rs.Resource.Attributes {
			attrs[a.Key] = a.Value.GetStringValue()
		}
		if attrs["service.name"] != "attackbox-bait" || attrs["host.id"] != "trusted-host" || attrs["service.instance.id"] != "trusted-bait" || attrs["tags.sensor_id"] != "trusted-host" {
			t.Fatalf("identity not normalized: %v", attrs)
		}
		for _, ss := range rs.ScopeSpans {
			for _, s := range ss.Spans {
				count++
				if s.Name != "bait.request" || s.Kind != trace.Span_SPAN_KIND_SERVER || len(s.Events) != 0 || len(s.Links) != 0 {
					t.Fatalf("unexpected span: %v", s)
				}
			}
		}
	}
	if count != 1 {
		t.Fatalf("want one accepted span, got %d", count)
	}
}
