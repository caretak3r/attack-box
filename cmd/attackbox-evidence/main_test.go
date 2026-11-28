package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"attackbox/internal/responder"
	"attackbox/internal/server"
	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
)

type collectSink struct{ events []telemetry.Event }

func (s *collectSink) Emit(e telemetry.Event)                 { s.events = append(s.events, e) }
func (*collectSink) Count(string, float64, map[string]string) {}
func (*collectSink) Gauge(string, float64, map[string]string) {}

// fixture generates real envelopes via bait → shipper → evidencelog path
func fixture(t *testing.T, data []byte, kind string) []byte {
	t.Helper()
	sink := &collectSink{}
	srv, err := server.New(server.Config{
		Responder: responder.New(responder.Config{}, responder.NewStore(responder.StoreConfig{})),
		Sink:      sink, FullEvidence: true, MaxLogBody: 12 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	var req *http.Request
	var response *httptest.ResponseRecorder

	switch kind {
	case "request_body":
		req = httptest.NewRequest("POST", "/unmatched", bytes.NewReader(data))
		response = httptest.NewRecorder()
		srv.Handler().ServeHTTP(response, req)
	case "response_body":
		req = httptest.NewRequest("GET", "/unmatched", nil)
		response = httptest.NewRecorder()
		srv.Handler().ServeHTTP(response, req)
		if _, err := response.Body.Write(data); err != nil {
			t.Fatal(err)
		}
	case "request_metadata", "response_metadata", "request_trailers":
		req = httptest.NewRequest("POST", "/unmatched?token=secret", bytes.NewReader([]byte("body")))
		req.Header.Set("Authorization", "Bearer secret")
		if kind == "request_trailers" {
			req.Trailer = http.Header{"X-Trailer": []string{"trailer-value"}}
		}
		response = httptest.NewRecorder()
		srv.Handler().ServeHTTP(response, req)
	default:
		t.Fatalf("unknown kind: %s", kind)
	}

	var buf bytes.Buffer
	requestID := ""
	for _, event := range sink.events {
		if event.Action != "capture" {
			continue
		}
		requestID = event.RequestID
		raw, err := json.Marshal(telemetry.Record{V: telemetry.SchemaVersion, ID: fmt.Sprintf("0123456789abcdef-%d", len(buf.Bytes())/100+1), Event: &event})
		if err != nil {
			t.Fatal(err)
		}
		admitted, err := shipper.Admit(shipper.RoleBait, raw, event.Timestamp)
		if err != nil {
			t.Fatalf("admission rejected: %v", err)
		}
		var rec telemetry.Record
		if err := json.Unmarshal(admitted.Data, &rec); err != nil {
			t.Fatal(err)
		}
		env := telemetry.Envelope{Ts: time.Now().UTC().Format(time.RFC3339Nano), Role: "bait", Seq: uint64(len(buf.Bytes())/100 + 1), Record: rec}
		line, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(append(line, '\n'))
	}
	if requestID == "" {
		t.Fatal("no capture events emitted")
	}
	// Store the request ID for the first line so tests can extract it
	t.Setenv("FIXTURE_REQUEST_ID", requestID)
	return buf.Bytes()
}

func TestReconstructBinaryReplayAndFormats(t *testing.T) {
	want := append([]byte("héllo 世界\n"), 0, 0xff, 0xfe, 0x1b, 0x7f)
	jsonl := fixture(t, want, "request_body")
	reqID := os.Getenv("FIXTURE_REQUEST_ID")

	path := filepath.Join(t.TempDir(), "out.bin")
	var stderr bytes.Buffer
	code := run([]string{"-request-id", reqID, "-kind", "request_body", "-output", path}, bytes.NewReader(jsonl), &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, &stderr)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("binary mismatch: %x", got)
	}
}

func TestEmptyCapture(t *testing.T) {
	jsonl := fixture(t, nil, "request_body")
	reqID := os.Getenv("FIXTURE_REQUEST_ID")

	path := filepath.Join(t.TempDir(), "out.bin")
	var stderr bytes.Buffer
	code := run([]string{"-request-id", reqID, "-kind", "request_body", "-output", path}, bytes.NewReader(jsonl), &stderr)
	if code != 0 {
		t.Fatal(code, stderr.String())
	}
	got, err := os.ReadFile(path)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty: len=%d err=%v", len(got), err)
	}
}

func TestRejectDamagedEvidence(t *testing.T) {
	damageEnvelope := func(jsonl []byte, mutate func(*telemetry.Envelope) bool) []byte {
		lines := bytes.Split(bytes.TrimSpace(jsonl), []byte("\n"))
		var out bytes.Buffer
		for _, line := range lines {
			var env telemetry.Envelope
			if err := json.Unmarshal(line, &env); err != nil {
				out.Write(append(line, '\n'))
				continue
			}
			if mutate(&env) {
				line, _ = json.Marshal(env)
			}
			out.Write(append(line, '\n'))
		}
		return out.Bytes()
	}

	runCLI := func(t *testing.T, input []byte, reqID string) int {
		t.Helper()
		path := filepath.Join(t.TempDir(), "out.bin")
		var stderr bytes.Buffer
		return run([]string{"-request-id", reqID, "-kind", "request_body", "-output", path}, bytes.NewReader(input), &stderr)
	}

	t.Run("missing_manifest", func(t *testing.T) {
		jsonl := fixture(t, []byte("data"), "request_body")
		reqID := os.Getenv("FIXTURE_REQUEST_ID")
		// Filter to only request_body events, then remove the manifest
		lines := bytes.Split(bytes.TrimSpace(jsonl), []byte("\n"))
		var filtered [][]byte
		for _, line := range lines {
			var env telemetry.Envelope
			if json.Unmarshal(line, &env) != nil || env.Record.Event == nil {
				continue
			}
			kind := env.Record.Event.Attrs["evidence_kind"]
			target := env.Record.Event.Attrs["evidence_target"]
			if kind == "request_body" || (kind == "manifest" && target == "request_body") {
				filtered = append(filtered, line)
			}
		}
		// Remove manifest (last filtered line)
		if len(filtered) < 2 {
			t.Fatal("fixture should generate at least segment+manifest for request_body")
		}
		damaged := bytes.Join(filtered[:len(filtered)-1], []byte("\n"))
		if runCLI(t, damaged, reqID) == 0 {
			t.Fatal("accepted missing manifest")
		}
	})

	t.Run("duplicate_manifest", func(t *testing.T) {
		jsonl := fixture(t, []byte("data"), "request_body")
		reqID := os.Getenv("FIXTURE_REQUEST_ID")
		damaged := damageEnvelope(jsonl, func(env *telemetry.Envelope) bool {
			if env.Record.Event != nil && env.Record.Event.Attrs["evidence_kind"] == "manifest" {
				env.Record.ID = "duplicate-manifest-id"
				return true
			}
			return false
		})
		if runCLI(t, append(jsonl, damaged...), reqID) == 0 {
			t.Fatal("accepted duplicate manifest")
		}
	})

	t.Run("incomplete", func(t *testing.T) {
		jsonl := fixture(t, []byte("data"), "request_body")
		reqID := os.Getenv("FIXTURE_REQUEST_ID")
		damaged := damageEnvelope(jsonl, func(env *telemetry.Envelope) bool {
			if env.Record.Event != nil && env.Record.Event.Attrs["evidence_kind"] == "manifest" {
				env.Record.Event.Attrs["evidence_complete"] = false
				return true
			}
			return false
		})
		if runCLI(t, damaged, reqID) == 0 {
			t.Fatal("accepted incomplete manifest")
		}
	})

	t.Run("incomplete_no_reason", func(t *testing.T) {
		jsonl := fixture(t, []byte("data"), "request_body")
		reqID := os.Getenv("FIXTURE_REQUEST_ID")
		damaged := damageEnvelope(jsonl, func(env *telemetry.Envelope) bool {
			if env.Record.Event != nil && env.Record.Event.Attrs["evidence_kind"] == "manifest" {
				env.Record.Event.Attrs["evidence_complete"] = false
				env.Record.Event.Attrs["evidence_reason"] = ""
				return true
			}
			return false
		})
		if runCLI(t, damaged, reqID) == 0 {
			t.Fatal("accepted incomplete manifest without reason")
		}
	})

	t.Run("complete_missing", func(t *testing.T) {
		jsonl := fixture(t, []byte("data"), "request_body")
		reqID := os.Getenv("FIXTURE_REQUEST_ID")
		damaged := damageEnvelope(jsonl, func(env *telemetry.Envelope) bool {
			if env.Record.Event != nil && env.Record.Event.Attrs["evidence_kind"] == "manifest" {
				delete(env.Record.Event.Attrs, "evidence_complete")
				return true
			}
			return false
		})
		if runCLI(t, damaged, reqID) == 0 {
			t.Fatal("accepted manifest missing evidence_complete")
		}
	})

	t.Run("segment_hash_mismatch", func(t *testing.T) {
		jsonl := fixture(t, []byte("data"), "request_body")
		reqID := os.Getenv("FIXTURE_REQUEST_ID")
		damaged := damageEnvelope(jsonl, func(env *telemetry.Envelope) bool {
			if env.Record.Event != nil && env.Record.Event.Attrs["evidence_kind"] != "manifest" {
				env.Record.Event.Attrs["evidence_sha256"] = strings.Repeat("0", 64)
				return true
			}
			return false
		})
		if runCLI(t, damaged, reqID) == 0 {
			t.Fatal("accepted segment hash mismatch")
		}
	})

	t.Run("data_length_mismatch", func(t *testing.T) {
		jsonl := fixture(t, []byte("data"), "request_body")
		reqID := os.Getenv("FIXTURE_REQUEST_ID")
		damaged := damageEnvelope(jsonl, func(env *telemetry.Envelope) bool {
			if env.Record.Event != nil && env.Record.Event.Attrs["evidence_kind"] != "manifest" {
				env.Record.Event.Attrs["evidence_bytes"] = float64(999)
				return true
			}
			return false
		})
		if runCLI(t, damaged, reqID) == 0 {
			t.Fatal("accepted data length mismatch")
		}
	})

	t.Run("data_not_base64", func(t *testing.T) {
		jsonl := fixture(t, []byte("data"), "request_body")
		reqID := os.Getenv("FIXTURE_REQUEST_ID")
		damaged := damageEnvelope(jsonl, func(env *telemetry.Envelope) bool {
			if env.Record.Event != nil && env.Record.Event.Attrs["evidence_kind"] != "manifest" {
				env.Record.Event.Body = "base64:invalid!@#"
				return true
			}
			return false
		})
		if runCLI(t, damaged, reqID) == 0 {
			t.Fatal("accepted invalid base64")
		}
	})

	t.Run("total_bytes_mismatch", func(t *testing.T) {
		jsonl := fixture(t, []byte("data"), "request_body")
		reqID := os.Getenv("FIXTURE_REQUEST_ID")
		damaged := damageEnvelope(jsonl, func(env *telemetry.Envelope) bool {
			if env.Record.Event != nil && env.Record.Event.Attrs["evidence_kind"] == "manifest" {
				env.Record.Event.Attrs["evidence_bytes"] = float64(999)
				return true
			}
			return false
		})
		if runCLI(t, damaged, reqID) == 0 {
			t.Fatal("accepted total bytes mismatch")
		}
	})

	t.Run("sha256_mismatch", func(t *testing.T) {
		jsonl := fixture(t, []byte("data"), "request_body")
		reqID := os.Getenv("FIXTURE_REQUEST_ID")
		damaged := damageEnvelope(jsonl, func(env *telemetry.Envelope) bool {
			if env.Record.Event != nil && env.Record.Event.Attrs["evidence_kind"] == "manifest" {
				env.Record.Event.Attrs["evidence_sha256"] = strings.Repeat("0", 64)
				return true
			}
			return false
		})
		if runCLI(t, damaged, reqID) == 0 {
			t.Fatal("accepted sha256 mismatch")
		}
	})

	t.Run("data_offset_mismatch", func(t *testing.T) {
		jsonl := fixture(t, bytes.Repeat([]byte("x"), 20000), "request_body")
		reqID := os.Getenv("FIXTURE_REQUEST_ID")
		damaged := damageEnvelope(jsonl, func(env *telemetry.Envelope) bool {
			if env.Record.Event != nil {
				if seg, ok := env.Record.Event.Attrs["evidence_segment"].(float64); ok && seg == 1 {
					env.Record.Event.Attrs["evidence_offset"] = float64(999)
					return true
				}
			}
			return false
		})
		if runCLI(t, damaged, reqID) == 0 {
			t.Fatal("accepted offset mismatch")
		}
	})

	t.Run("overlap", func(t *testing.T) {
		jsonl := fixture(t, bytes.Repeat([]byte("x"), 20000), "request_body")
		reqID := os.Getenv("FIXTURE_REQUEST_ID")
		damaged := damageEnvelope(jsonl, func(env *telemetry.Envelope) bool {
			if env.Record.Event != nil {
				if seg, ok := env.Record.Event.Attrs["evidence_segment"].(float64); ok && seg == 1 {
					env.Record.Event.Attrs["evidence_offset"] = float64(0)
					return true
				}
			}
			return false
		})
		if runCLI(t, damaged, reqID) == 0 {
			t.Fatal("accepted overlapping segments")
		}
	})

	t.Run("gap", func(t *testing.T) {
		jsonl := fixture(t, bytes.Repeat([]byte("x"), 20000), "request_body")
		reqID := os.Getenv("FIXTURE_REQUEST_ID")
		damaged := damageEnvelope(jsonl, func(env *telemetry.Envelope) bool {
			if env.Record.Event != nil {
				if seg, ok := env.Record.Event.Attrs["evidence_segment"].(float64); ok && seg == 1 {
					env.Record.Event.Attrs["evidence_offset"] = float64(99999)
					return true
				}
			}
			return false
		})
		if runCLI(t, damaged, reqID) == 0 {
			t.Fatal("accepted gap in segments")
		}
	})
}

func TestCLIExclusiveOutputAndPermissions(t *testing.T) {
	want := []byte("hostile\x1b[2Jpayload\x00\xff")
	jsonl := fixture(t, want, "request_body")
	reqID := os.Getenv("FIXTURE_REQUEST_ID")

	dir := t.TempDir()
	path := filepath.Join(dir, "capture.bin")
	args := []string{"-request-id", reqID, "-kind", "request_body", "-output", path}
	var stderr bytes.Buffer
	if code := run(args, bytes.NewReader(jsonl), &stderr); code != 0 {
		t.Fatalf("exit=%d: %s", code, &stderr)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("output: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v %o", err, info.Mode().Perm())
	}
	if bytes.Contains(stderr.Bytes(), want) || bytes.Contains(stderr.Bytes(), []byte{0x1b}) {
		t.Fatal("payload printed")
	}
	if code := run(args, bytes.NewReader(jsonl), &stderr); code != 1 {
		t.Fatal("overwrote existing output")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(after, want) {
		t.Fatal("existing file changed")
	}
}

func TestCLIInputFileKindsAndUsage(t *testing.T) {
	for _, kind := range []string{"request_body", "response_body", "request_metadata", "response_metadata", "request_trailers"} {
		t.Run(kind, func(t *testing.T) {
			var data []byte
			if kind == "request_body" || kind == "response_body" {
				data = []byte("test data")
			}
			jsonl := fixture(t, data, kind)
			reqID := os.Getenv("FIXTURE_REQUEST_ID")

			dir := t.TempDir()
			input := filepath.Join(dir, "export.jsonl")
			if err := os.WriteFile(input, jsonl, 0600); err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			if code := run([]string{"-input", input, "-output", filepath.Join(dir, "result"), "-request-id", reqID, "-kind", kind}, nil, &stderr); code != 0 {
				t.Fatalf("%s: %s", kind, &stderr)
			}
		})
	}
	for _, args := range [][]string{nil, {"-request-id", "id", "-kind", "bad", "-output", "file"}, {"-request-id", "id", "-kind", "request_body", "-output", "-"}} {
		var stderr bytes.Buffer
		if code := run(args, strings.NewReader(""), &stderr); code != 2 {
			t.Fatalf("usage exit %d", code)
		}
	}
}

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

	evidenceDir := t.TempDir()
	log, err := telemetry.NewEvidenceLog(telemetry.EvidenceConfig{
		Dir: evidenceDir,
		Now: func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	var records []telemetry.EvidenceItem
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
		admitted, err := shipper.Admit(shipper.RoleBait, raw, event.Timestamp)
		if err != nil {
			t.Fatalf("capture rejected at admission: %v", err)
		}
		records = append(records, telemetry.EvidenceItem{Role: "bait", Seq: uint64(len(records) + 1), Data: admitted.Data})
	}
	if len(records) == 0 || requestID == "" {
		t.Fatal("server emitted no capture")
	}

	if err := log.Write(records); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	files, err := os.ReadDir(evidenceDir)
	if err != nil || len(files) == 0 {
		t.Fatalf("no evidence files: %v", err)
	}
	evidencePath := filepath.Join(evidenceDir, files[0].Name())

	reassemble := func(kind string) []byte {
		t.Helper()
		path := filepath.Join(t.TempDir(), kind+".bin")
		var stderr bytes.Buffer
		code := run([]string{"-input", evidencePath, "-request-id", requestID, "-kind", kind, "-output", path}, nil, &stderr)
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
