package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"attackbox/internal/telemetry"
)

func evidenceBody(t *testing.T, sink *memSink, kind string) ([]byte, telemetry.Event) {
	t.Helper()
	var b []byte
	var manifest telemetry.Event
	segments := 0
	for _, e := range sink.stream(telemetry.StreamEdge) {
		if e.Action != "capture" {
			continue
		}
		if e.Attrs["evidence_kind"] == "manifest" && e.Attrs["evidence_target"] == kind {
			manifest = e
		}
		if e.Attrs["evidence_kind"] != kind {
			continue
		}
		part, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(e.Body, "base64:"))
		if err != nil || e.Attrs["evidence_offset"] != int64(len(b)) || e.Attrs["evidence_segment"] != segments {
			t.Fatalf("invalid segment: %v, %v", e.Attrs, err)
		}
		if len(part) > evidenceSegmentBytes {
			t.Fatal("unbounded segment")
		}
		sum := sha256.Sum256(part)
		if e.Attrs["evidence_sha256"] != hex.EncodeToString(sum[:]) {
			t.Fatal("segment hash mismatch")
		}
		b = append(b, part...)
		segments++
	}
	sum := sha256.Sum256(b)
	if manifest.Attrs["evidence_sha256"] != hex.EncodeToString(sum[:]) ||
		manifest.Attrs["evidence_segments"] != segments || manifest.Attrs["evidence_bytes"] != int64(len(b)) {
		t.Fatalf("manifest mismatch: %+v", manifest)
	}
	return b, manifest
}

func TestEvidencePreservesCapturedBytesAndCredentials(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.FullEvidence = true; c.MaxLogBody = 8 })
	body := append([]byte(strings.Repeat("binary\x00💣", 20000)), 0xff, 0xfe)
	req := httptest.NewRequest("POST", "/unknown?token=unredacted-secret", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer unredacted-secret")
	req.Header.Set("X-Odd", string([]byte{0xff, 'x'}))
	r.srv.Handler().ServeHTTP(httptest.NewRecorder(), req)
	got, manifest := evidenceBody(t, r.sink, "request_body")
	if !bytes.Equal(got, body) || manifest.Attrs["evidence_complete"] != true {
		t.Fatal("raw request changed or incomplete")
	}
	meta, _ := evidenceBody(t, r.sink, "request_metadata")
	var decoded struct {
		URI     []byte              `json:"request_uri"`
		Headers map[string][][]byte `json:"headers"`
	}
	if err := json.Unmarshal(meta, &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded.URI) != req.RequestURI || string(decoded.Headers["Authorization"][0]) != "Bearer unredacted-secret" ||
		!bytes.Equal(decoded.Headers["X-Odd"][0], []byte{0xff, 'x'}) {
		t.Fatal("metadata changed")
	}
}

func TestEvidenceBodyLimitIsExplicit(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.FullEvidence = true; c.MaxBodyBytes = 32 })
	r.do("POST", "/v1/chat/completions", strings.Repeat("x", 100))
	b, m := evidenceBody(t, r.sink, "request_body")
	if len(b) != 32 || m.Attrs["evidence_complete"] != false || m.Attrs["evidence_reason"] != "body_limit" {
		t.Fatalf("incorrect limit manifest: %v", m.Attrs)
	}
	_, trailer := evidenceBody(t, r.sink, "request_trailers")
	if trailer.Attrs["evidence_complete"] != false {
		t.Fatal("unread trailers called complete")
	}
}

type brokenBody struct{ sent bool }

func (b *brokenBody) Read(p []byte) (int, error) {
	if b.sent {
		return 0, io.ErrUnexpectedEOF
	}
	b.sent = true
	return copy(p, "partial"), io.ErrUnexpectedEOF
}
func (*brokenBody) Close() error { return nil }

func TestEvidenceReadFailureIsExplicit(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.FullEvidence = true })
	req := httptest.NewRequest("POST", "/v1/chat/completions", &brokenBody{})
	r.srv.Handler().ServeHTTP(httptest.NewRecorder(), req)
	b, m := evidenceBody(t, r.sink, "request_body")
	if string(b) != "partial" || m.Attrs["evidence_complete"] != false || m.Attrs["evidence_reason"] != "read_error" {
		t.Fatalf("read error hidden: %v", m.Attrs)
	}
}

func TestEvidenceResponseStreamsBeforeFinish(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.FullEvidence = true })
	request := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	c := &call{s: r.srv, r: request, id: "live", src: "192.0.2.1", w: &recorder{ResponseWriter: w}}
	c.startEvidence()
	payload := bytes.Repeat([]byte{0xff, 0, 'x'}, 9000)
	_, _ = c.w.Write(payload)
	// A response segment exists before finish/end; no full-response buffer.
	found := false
	for _, e := range r.sink.stream(telemetry.StreamEdge) {
		if e.Attrs["evidence_kind"] == "response_body" {
			found = true
		}
		if e.Attrs["evidence_target"] == "response_body" {
			t.Fatal("premature manifest")
		}
	}
	if !found {
		t.Fatal("response held until completion")
	}
	c.endEvidence()
	got, m := evidenceBody(t, r.sink, "response_body")
	if !bytes.Equal(got, payload) || m.Attrs["evidence_complete"] != true {
		t.Fatal("response changed")
	}
}

func TestEvidenceUnreadBusyBodyIsIncomplete(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.FullEvidence = true })
	c := &call{s: r.srv, r: httptest.NewRequest("POST", "/", strings.NewReader("unread")), id: "busy",
		w: &recorder{ResponseWriter: httptest.NewRecorder()}}
	c.startEvidence()
	c.w.WriteHeader(http.StatusTooManyRequests)
	c.endEvidence()
	b, m := evidenceBody(t, r.sink, "request_body")
	if len(b) != 0 || m.Attrs["evidence_complete"] != false {
		t.Fatal("unread body called complete")
	}
}

func TestEvidenceFragmentedInputIsCoalesced(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.FullEvidence = true })
	c := &call{s: r.srv, r: httptest.NewRequest("POST", "/", nil), id: "fragments"}
	w := newEvidenceWriter(c, "request_body")
	for i := 0; i < 32768; i++ {
		_, _ = w.Write([]byte{'x'})
	}
	w.end(true, "eof")
	body, m := evidenceBody(t, r.sink, "request_body")
	if len(body) != 32768 || m.Attrs["evidence_segments"].(int) > 8 {
		t.Fatalf("fragment amplification: %v", m.Attrs)
	}
}

func TestEvidenceSmallLiveWriteFlushesWithoutFinish(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.FullEvidence = true })
	c := &call{s: r.srv, r: httptest.NewRequest("GET", "/", nil), id: "live"}
	w := newEvidenceWriter(c, "response_body")
	defer w.end(true, "writer_accepted")
	_, _ = w.Write([]byte("live-prefix"))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range r.sink.stream(telemetry.StreamEdge) {
			if e.Attrs["evidence_kind"] == "response_body" {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("small write waited for response completion")
}

func TestEvidenceAbortAfterPrefixIsIncomplete(t *testing.T) {
	r := newRig(t, PersonaOpenAI, func(c *Config) { c.FullEvidence = true })
	r.srv.routes = append(r.srv.routes, newRoute("GET", "/abort", "", func(c *call) {
		_, _ = c.w.Write([]byte("partial"))
		panic(http.ErrAbortHandler)
	}))
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Fatal("abort not propagated")
			}
		}()
		r.do("GET", "/abort", "")
	}()
	b, m := evidenceBody(t, r.sink, "response_body")
	if string(b) != "partial" || m.Attrs["evidence_complete"] != false {
		t.Fatal("aborted response called complete")
	}
}
