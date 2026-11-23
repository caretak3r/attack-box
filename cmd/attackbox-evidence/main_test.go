package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"attackbox/internal/responder"
	"attackbox/internal/server"
	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
)

func fixture(data []byte) []map[string]any {
	var rows []map[string]any
	parts := 0
	for offset := 0; offset < len(data); parts++ {
		end := min(offset+11, len(data))
		b := data[offset:end]
		body := "base64:" + base64.StdEncoding.EncodeToString(b)
		count := (len(body) + 8) / 9
		for i := 0; i < count; i++ {
			rows = append(rows, map[string]any{
				"source": "bait", "stream": "edge", "action": "capture", "request_id": "req-1",
				"evidence_version": 1, "evidence_encoding": "base64", "evidence_scope": "application",
				"record_id": fmt.Sprintf("bait-boot-%d", parts+1), "body_sha256": digest([]byte(body)),
				"chunk_index": i, "chunk_count": count, "body_chunk": body[i*9 : min((i+1)*9, len(body))],
				"evidence_kind": "request_body", "evidence_segment": parts, "evidence_offset": offset,
				"evidence_bytes": len(b), "evidence_sha256": digest(b),
			})
		}
		offset = end
	}
	return append(rows, map[string]any{
		"source": "bait", "stream": "edge", "action": "capture", "request_id": "req-1",
		"evidence_version": 1, "evidence_encoding": "base64", "evidence_scope": "application",
		"record_id": "bait-boot-manifest", "body_sha256": digest(nil), "chunk_index": 0, "chunk_count": 1,
		"evidence_kind": "manifest", "evidence_target": "request_body", "evidence_bytes": len(data),
		"evidence_segments": parts, "evidence_sha256": digest(data), "evidence_complete": true,
		"evidence_reason": "complete",
	})
}

func encode(t *testing.T, rows []map[string]any, array bool) []byte {
	t.Helper()
	if array {
		b, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var b bytes.Buffer
	for _, row := range rows {
		if err := json.NewEncoder(&b).Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	return b.Bytes()
}

func TestReconstructBinaryReplayAndFormats(t *testing.T) {
	want := append([]byte("héllo 世界\n"), 0, 0xff, 0xfe, 0x1b, 0x7f)
	for _, array := range []bool{false, true} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("array=%t/nested=%t", array, nested), func(t *testing.T) {
				rows := fixture(want)
				rows = append(rows, rows...)
				for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
					rows[i], rows[j] = rows[j], rows[i]
				}
				if nested {
					for i, row := range rows {
						rows[i] = map[string]any{"attributes": row}
					}
				}
				got, err := reconstruct(bytes.NewReader(encode(t, rows, array)), "req-1", "request_body")
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("binary mismatch: %x", got)
				}
			})
		}
	}
}

func TestEmptyCapture(t *testing.T) {
	got, err := reconstruct(bytes.NewReader(encode(t, fixture(nil), true)), "req-1", "request_body")
	if err != nil || len(got) != 0 {
		t.Fatalf("empty: len=%d err=%v", len(got), err)
	}
}

func TestRejectUnsupportedCaptureSchema(t *testing.T) {
	cases := []struct {
		name, key string
		value     any
	}{
		{"missing_version", "evidence_version", nil},
		{"old_version", "evidence_version", 0},
		{"future_version", "evidence_version", 2},
		{"string_version", "evidence_version", "1"},
		{"fractional_version", "evidence_version", 1.5},
		{"exponent_version", "evidence_version", json.Number("1e0")},
		{"missing_encoding", "evidence_encoding", nil},
		{"wrong_encoding", "evidence_encoding", "hex"},
		{"missing_scope", "evidence_scope", nil},
		{"wrong_scope", "evidence_scope", "wire"},
	}
	for _, tc := range cases {
		for _, target := range []string{"segment", "manifest", "all"} {
			t.Run(tc.name+"/"+target, func(t *testing.T) {
				rows := fixture([]byte("capture"))
				for i, row := range rows {
					if target == "segment" && i != 0 || target == "manifest" && i != len(rows)-1 {
						continue
					}
					if tc.value == nil {
						delete(row, tc.key)
					} else {
						row[tc.key] = tc.value
					}
				}
				_, err := reconstruct(bytes.NewReader(encode(t, rows, true)), "req-1", "request_body")
				if err == nil || !strings.Contains(err.Error(), "capture schema") {
					t.Fatalf("expected schema rejection, got %v", err)
				}
			})
		}
	}
}

func TestRejectDamagedEvidence(t *testing.T) {
	cases := map[string]func([]map[string]any) []map[string]any{
		"missing_chunk":    func(r []map[string]any) []map[string]any { return r[1:] },
		"missing_manifest": func(r []map[string]any) []map[string]any { return r[:len(r)-1] },
		"incomplete":       func(r []map[string]any) []map[string]any { r[len(r)-1]["evidence_complete"] = false; return r },
		"string_complete":  func(r []map[string]any) []map[string]any { r[len(r)-1]["evidence_complete"] = "true"; return r },
		"record_hash": func(r []map[string]any) []map[string]any {
			for _, v := range r {
				if v["evidence_kind"] != "manifest" {
					v["body_sha256"] = strings.Repeat("0", 64)
				}
			}
			return r
		},
		"segment_hash": func(r []map[string]any) []map[string]any {
			for _, v := range r {
				if v["evidence_kind"] != "manifest" {
					v["evidence_sha256"] = strings.Repeat("0", 64)
				}
			}
			return r
		},
		"whole_hash": func(r []map[string]any) []map[string]any {
			r[len(r)-1]["evidence_sha256"] = strings.Repeat("0", 64)
			return r
		},
		"negative_index":   func(r []map[string]any) []map[string]any { r[0]["chunk_index"] = -1; return r },
		"fractional_index": func(r []map[string]any) []map[string]any { r[0]["chunk_index"] = 0.5; return r },
		"exponent_index":   func(r []map[string]any) []map[string]any { r[0]["chunk_index"] = json.Number("0e0"); return r },
		"huge_count": func(r []map[string]any) []map[string]any {
			r[0]["chunk_count"] = json.Number("9007199254740993")
			return r
		},
		"conflicting_chunk": func(r []map[string]any) []map[string]any {
			c := copyRow(r[0])
			c["body_chunk"] = "different"
			return append(r, c)
		},
		"conflicting_metadata": func(r []map[string]any) []map[string]any { r[0]["evidence_offset"] = 1; return r },
		"overlap": func(r []map[string]any) []map[string]any {
			for _, v := range r {
				if v["evidence_segment"] == 1 {
					v["evidence_offset"] = 0
				}
			}
			return r
		},
		"gap": func(r []map[string]any) []map[string]any {
			for _, v := range r {
				if v["evidence_segment"] == 1 {
					v["evidence_offset"] = 12
				}
			}
			return r
		},
		"missing_body_chunk":      func(r []map[string]any) []map[string]any { delete(r[0], "body_chunk"); return r },
		"manifest_nonstring_body": func(r []map[string]any) []map[string]any { r[len(r)-1]["body_chunk"] = 42; return r },
		"manifest_null_body":      func(r []map[string]any) []map[string]any { r[len(r)-1]["body_chunk"] = nil; return r },
		"excessive_bytes":         func(r []map[string]any) []map[string]any { r[len(r)-1]["evidence_bytes"] = maxBody + 1; return r },
		"wrong_source": func(r []map[string]any) []map[string]any {
			for _, v := range r {
				v["source"] = "runtime"
			}
			return r
		},
		"conflicting_manifest": func(r []map[string]any) []map[string]any {
			c := copyRow(r[len(r)-1])
			c["record_id"] = "other-manifest"
			c["evidence_bytes"] = 1
			return append(r, c)
		},
		"nested_conflict": func(r []map[string]any) []map[string]any {
			r[0]["attributes"] = map[string]any{"source": "runtime"}
			return r
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rows := mutate(fixture([]byte("a capture with multiple segments")))
			if _, err := reconstruct(bytes.NewReader(encode(t, rows, true)), "req-1", "request_body"); err == nil {
				t.Fatal("accepted damaged evidence")
			}
		})
	}
}

func copyRow(m map[string]any) map[string]any {
	n := map[string]any{}
	for k, v := range m {
		n[k] = v
	}
	return n
}

func TestLogicalReplay(t *testing.T) {
	want := []byte("identical data")
	rows := fixture(want)
	for _, r := range append([]map[string]any(nil), rows...) {
		c := copyRow(r)
		c["record_id"] = "replay-" + r["record_id"].(string)
		rows = append(rows, c)
	}
	got, err := reconstruct(bytes.NewReader(encode(t, rows, false)), "req-1", "request_body")
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("logical replay: %v", err)
	}
	conflict := fixture([]byte("different data"))
	for _, r := range conflict[:len(conflict)-1] {
		r["record_id"] = "conflict-" + r["record_id"].(string)
		rows = append(rows, r)
	}
	if _, err := reconstruct(bytes.NewReader(encode(t, rows, false)), "req-1", "request_body"); err == nil {
		t.Fatal("accepted conflicting logical replay")
	}
}

func TestInputValidation(t *testing.T) {
	for _, raw := range []string{"", "[", "[] {}", "{} trailing", `{"source":"bait","source":"runtime"}`, `{"attributes":{"a":1,"a":2}}`, `{"x":"` + strings.Repeat("x", maxRecord) + `"}`} {
		if _, err := reconstruct(strings.NewReader(raw), "req-1", "request_body"); err == nil {
			t.Fatal("accepted invalid export")
		}
	}
	if _, err := reconstruct(ioZeros{maxInput + 1}, "req-1", "request_body"); err == nil {
		t.Fatal("accepted oversized input")
	}
}

// LimitReader in reconstruct stops this otherwise endless source.
type ioZeros struct{ ignored int }

func (ioZeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestCLIExclusiveOutputAndPermissions(t *testing.T) {
	want := []byte("hostile\x1b[2Jpayload\x00\xff")
	input := encode(t, fixture(want), true)
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.bin")
	args := []string{"-request-id", "req-1", "-kind", "request_body", "-output", path}
	var stderr bytes.Buffer
	if code := run(args, bytes.NewReader(input), &stderr); code != 0 {
		t.Fatalf("exit=%d: %s", code, &stderr)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("output: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v", err)
	}
	if bytes.Contains(stderr.Bytes(), want) || bytes.Contains(stderr.Bytes(), []byte{0x1b}) {
		t.Fatal("payload printed")
	}
	if code := run(args, bytes.NewReader(input), &stderr); code != 1 {
		t.Fatal("overwrote existing output")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, want) {
		t.Fatal("existing file changed")
	}
	badPath := filepath.Join(dir, "incomplete.bin")
	args[len(args)-1] = badPath
	rows := fixture(want)
	rows[len(rows)-1]["evidence_complete"] = false
	if code := run(args, bytes.NewReader(encode(t, rows, false)), &stderr); code != 1 {
		t.Fatal("accepted incomplete capture")
	}
	if _, err := os.Stat(badPath); !os.IsNotExist(err) {
		t.Fatal("created output before verification")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	args[len(args)-1] = link
	if code := run(args, bytes.NewReader(input), &stderr); code != 1 {
		t.Fatal("followed output symlink")
	}
}

func TestCLIInputFileKindsAndUsage(t *testing.T) {
	for _, kind := range []string{"request_body", "response_body", "request_metadata", "response_metadata", "request_trailers"} {
		dir := t.TempDir()
		rows := fixture([]byte("fixture"))
		for _, r := range rows {
			if r["evidence_kind"] == "manifest" {
				r["evidence_target"] = kind
			} else {
				r["evidence_kind"] = kind
			}
		}
		input := filepath.Join(dir, "export.ndjson")
		if err := os.WriteFile(input, encode(t, rows, false), 0600); err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		if code := run([]string{"-input", input, "-output", filepath.Join(dir, "result"), "-request-id", "req-1", "-kind", kind}, nil, &stderr); code != 0 {
			t.Fatalf("%s: %s", kind, &stderr)
		}
	}
	for _, args := range [][]string{nil, {"-request-id", "id", "-kind", "bad", "-output", "file"}, {"-request-id", "id", "-kind", "request_body", "-output", "-"}} {
		var stderr bytes.Buffer
		if code := run(args, strings.NewReader(""), &stderr); code != 2 {
			t.Fatalf("usage exit %d", code)
		}
	}
}

type collectSink struct{ events []telemetry.Event }

func (s *collectSink) Emit(e telemetry.Event)                 { s.events = append(s.events, e) }
func (*collectSink) Count(string, float64, map[string]string) {}
func (*collectSink) Gauge(string, float64, map[string]string) {}

func TestEvidenceServerAdmissionExportCLI(t *testing.T) {
	sink := &collectSink{}
	srv, err := server.New(server.Config{
		Responder: responder.New(responder.Config{}, responder.NewStore(responder.StoreConfig{})),
		Sink:      sink, FullEvidence: true, MaxLogBody: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Repeat([]byte("credential=sk-live-secret\x00世界\n"), 8000), 0xff, 0xfe)
	if len(want) <= 128<<10 {
		t.Fatal("fixture must exceed legacy capture size")
	}
	req := httptest.NewRequest("POST", "/unmatched?token=keep-this-credential", bytes.NewReader(want))
	req.Header.Set("Authorization", "Bearer keep-this-credential")
	req.Header.Set("X-Binary", string([]byte{0xff, 0, 'x'}))
	req.Trailer = http.Header{"X-Trailer": []string{"keep-trailer-secret"}}
	response := httptest.NewRecorder()
	srv.Handler().ServeHTTP(response, req)
	var records []telemetry.Record
	requestID := ""
	for _, event := range sink.events {
		if event.Action != "capture" {
			continue
		}
		requestID = event.RequestID
		raw, err := json.Marshal(telemetry.Record{V: telemetry.SchemaVersion, ID: fmt.Sprintf("0123456789abcdef-%d", len(records)+1), Event: &event})
		if err != nil {
			t.Fatal(err)
		}
		admitted, err := shipper.Admit(shipper.RoleBait, raw, time.Now())
		if err != nil {
			t.Fatalf("capture rejected at admission: %v", err)
		}
		records = append(records, admitted.Record)
	}
	if len(records) == 0 || requestID == "" {
		t.Fatal("server emitted no capture")
	}
	var mu sync.Mutex
	var rows []map[string]any
	posts := 0
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		z, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		defer z.Close()
		var payload []struct {
			Common struct {
				Attributes map[string]any `json:"attributes"`
			} `json:"common"`
			Logs []map[string]any `json:"logs"`
		}
		if err := json.NewDecoder(z).Decode(&payload); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		posts++
		for _, envelope := range payload {
			for _, log := range envelope.Logs {
				flat := copyRow(envelope.Common.Attributes)
				for k, v := range log {
					if k != "attributes" {
						flat[k] = v
					}
				}
				attrs, ok := log["attributes"].(map[string]any)
				if !ok {
					t.Error("missing log attributes")
					continue
				}
				for k, v := range attrs {
					flat[k] = v
				}
				rows = append(rows, flat)
			}
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer endpoint.Close()
	nr, err := telemetry.NewNewRelic(telemetry.NRConfig{
		LicenseKey: strings.Repeat("a", 40), LogURL: endpoint.URL + "/log/v1", MetricURL: endpoint.URL + "/metric/v1",
		HeartbeatInterval: -1, FlushInterval: time.Hour, Backoff: []time.Duration{}, MaxPayloadBytes: 64 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := nr.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	for i := 0; i < len(records); i += telemetry.MaxShipRecords {
		if err := nr.ShipRecords(records[i:min(i+telemetry.MaxShipRecords, len(records))]); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	if posts < 2 {
		t.Error("fixture did not exercise byte-bounded multi-POST export")
	}
	export := encode(t, rows, false)
	mu.Unlock()
	reassemble := func(kind string) []byte {
		t.Helper()
		path := filepath.Join(t.TempDir(), kind+".bin")
		var stderr bytes.Buffer
		code := run([]string{"-request-id", requestID, "-kind", kind, "-output", path}, bytes.NewReader(export), &stderr)
		if code != 0 {
			t.Fatalf("%s reconstruction failed: %s", kind, &stderr)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if got := reassemble("request_body"); !bytes.Equal(got, want) {
		t.Fatal("request bytes changed through admission/export/CLI")
	}
	if got := reassemble("response_body"); !bytes.Equal(got, response.Body.Bytes()) {
		t.Fatal("response bytes changed through admission/export/CLI")
	}
	var metadata struct {
		URI     []byte              `json:"request_uri"`
		Headers map[string][][]byte `json:"headers"`
	}
	if err := json.Unmarshal(reassemble("request_metadata"), &metadata); err != nil {
		t.Fatal(err)
	}
	if string(metadata.URI) != req.RequestURI || !bytes.Equal(metadata.Headers["Authorization"][0], []byte(req.Header.Get("Authorization"))) || !bytes.Equal(metadata.Headers["X-Binary"][0], []byte(req.Header.Get("X-Binary"))) {
		t.Fatal("request metadata was redacted or changed")
	}
	var reply struct {
		Status int `json:"status"`
	}
	if err := json.Unmarshal(reassemble("response_metadata"), &reply); err != nil || reply.Status != response.Code {
		t.Fatalf("response metadata: %v", err)
	}
	var trailers map[string][][]byte
	if err := json.Unmarshal(reassemble("request_trailers"), &trailers); err != nil || string(trailers["X-Trailer"][0]) != "keep-trailer-secret" {
		t.Fatalf("trailer metadata: %v", err)
	}
}
