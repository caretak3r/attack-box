package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"net/http"
	"sync"
	"time"

	"attackbox/internal/telemetry"
)

// Evidence is an additional, unredacted application-layer capture. Base64
// preserves arbitrary bytes through UTF-8 JSON transport. It is not a packet
// capture: net/http has already parsed headers and decoded transfer framing.
// A segment is deliberately small enough for the bounded spool and admission
// path.
const evidenceSegmentBytes = 12 << 10
const evidenceFlushInterval = 250 * time.Millisecond

type evidenceWriter struct {
	c        *call
	kind     string
	hash     hash.Hash
	bytes    int64
	segments int
	ended    bool
	mu       sync.Mutex
	buffer   []byte
	timer    *time.Timer
}

func newEvidenceWriter(c *call, kind string) *evidenceWriter {
	return &evidenceWriter{c: c, kind: kind, hash: sha256.New()}
}

func (w *evidenceWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ended {
		return 0, io.ErrClosedPipe
	}
	n := len(b)
	for len(b) > 0 {
		next := min(len(b), evidenceSegmentBytes-len(w.buffer))
		w.buffer = append(w.buffer, b[:next]...)
		b = b[next:]
		if len(w.buffer) == evidenceSegmentBytes {
			w.flush()
		}
	}
	if len(w.buffer) > 0 && w.timer == nil {
		w.timer = time.AfterFunc(evidenceFlushInterval, func() {
			w.mu.Lock()
			defer w.mu.Unlock()
			if !w.ended {
				w.flush()
			}
		})
	}
	return n, nil
}

// Called with mu held. Coalescing bounds telemetry amplification when a
// client fragments a body into one-byte reads. The timer bounds live latency.
func (w *evidenceWriter) flush() {
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
	if len(w.buffer) == 0 {
		return
	}
	sum := sha256.Sum256(w.buffer)
	w.c.evidenceEvent(w.kind, "base64:"+base64.StdEncoding.EncodeToString(w.buffer), map[string]any{
		"evidence_segment": w.segments, "evidence_offset": w.bytes,
		"evidence_bytes": len(w.buffer), "evidence_sha256": hex.EncodeToString(sum[:]),
	})
	_, _ = w.hash.Write(w.buffer)
	w.bytes += int64(len(w.buffer))
	w.segments++
	w.buffer = w.buffer[:0]
}

func (w *evidenceWriter) end(complete bool, reason string) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.ended {
		return
	}
	w.flush()
	w.ended = true
	w.c.evidenceEvent("manifest", "", map[string]any{
		"evidence_target":   w.kind,
		"evidence_bytes":    w.bytes,
		"evidence_segments": w.segments,
		"evidence_sha256":   hex.EncodeToString(w.hash.Sum(nil)),
		"evidence_complete": complete,
		"evidence_reason":   reason,
	})
}

func (c *call) evidenceEvent(kind, body string, attrs map[string]any) {
	attrs["evidence_version"] = 1
	attrs["evidence_kind"] = kind
	attrs["evidence_encoding"] = "base64"
	attrs["evidence_scope"] = "application"
	c.emit(telemetry.Event{
		Timestamp: c.s.cfg.Now(), Stream: telemetry.StreamEdge, Action: "capture",
		RequestID: c.id, SessionID: c.sessionID, SrcIP: c.src,
		Persona: c.s.persona, Attrs: attrs, Body: body,
	})
}

// Byte slices preserve even invalid UTF-8 in parsed header values. Header
// names and order reflect net/http's representation, not the original wire.
func evidenceHeaders(h http.Header) map[string][][]byte {
	out := make(map[string][][]byte, len(h))
	for k, values := range h {
		for _, v := range values {
			out[k] = append(out[k], []byte(v))
		}
	}
	return out
}

func (c *call) evidenceMetadata(kind string, value any) {
	c.evidenceMetadataState(kind, value, true, "captured")
}

func (c *call) evidenceMetadataState(kind string, value any, complete bool, reason string) {
	b, err := json.Marshal(value)
	if err != nil {
		// Only fixed structs/maps of byte slices and scalars are passed here.
		newEvidenceWriter(c, kind).end(false, "metadata_encode_error")
		return
	}
	w := newEvidenceWriter(c, kind)
	_, _ = w.Write(b)
	w.end(complete, reason)
}

func (c *call) startEvidence() {
	if !c.s.cfg.FullEvidence {
		return
	}
	c.requestEvidence = newEvidenceWriter(c, "request_body")
	c.responseEvidence = newEvidenceWriter(c, "response_body")
	c.evidenceMetadata("request_metadata", map[string]any{
		"method": []byte(c.r.Method), "request_uri": []byte(c.r.RequestURI),
		"host": []byte(c.r.Host), "protocol": c.r.Proto,
		"headers": evidenceHeaders(c.r.Header), "content_length": c.r.ContentLength,
		"transfer_encoding": c.r.TransferEncoding, "remote_addr": c.r.RemoteAddr,
	})
	c.w.onHeader = func(status int) {
		c.evidenceMetadata("response_metadata", map[string]any{
			"status": status, "headers": evidenceHeaders(c.w.Header()),
		})
	}
	c.w.onWrite = func(b []byte, err error) {
		_, _ = c.responseEvidence.Write(b)
		if err != nil {
			c.responseWriteFailed = true
		}
	}
}

func (c *call) endRequestEvidence(complete bool, reason string) {
	if c.requestEvidence == nil {
		return
	}
	c.requestEvidence.end(complete, reason)
	c.evidenceMetadataState("request_trailers", evidenceHeaders(c.r.Trailer), complete, reason)
	// A held response can last minutes. Make the readable request available
	// as soon as reading ends; the independent base64 capture retains all
	// captured bytes, including values removed from this contextual preview.
	body, cut := c.s.logBody(c.body, int64(len(c.body)))
	c.emit(telemetry.Event{
		Timestamp: c.s.cfg.Now(), Stream: telemetry.StreamEdge, Action: "request_received",
		RequestID: c.id, SrcIP: c.src, Persona: c.s.persona,
		Resource: truncRunes(c.s.cfg.Redactor.Text(c.r.URL.Path), maxResourceLen),
		Body:     body, Attrs: map[string]any{
			"direction": "request_start", "body_truncated": cut,
			"body_bytes": len(c.body), "request_complete": complete, "capture_reason": reason,
		},
	})
}

func (c *call) endEvidence() {
	if c.requestEvidence == nil {
		return
	}
	// A rejected request may never enter readBody. Do not call an unread
	// body empty or complete. EOF on a known empty request is an exception.
	if !c.requestEvidence.ended {
		empty := c.r.Body == nil || c.r.Body == http.NoBody
		c.requestEvidence.end(empty, "body_not_read")
	}
	complete := !c.responseWriteFailed && !c.panicked && !c.termFailed && !c.disconnected(c.w.status) &&
		c.r.Context().Err() == nil &&
		c.holdResult != holdServerShutdown && c.streamCut != holdServerShutdown
	reason := "writer_accepted"
	if !complete {
		reason = "response_interrupted"
	}
	c.responseEvidence.end(complete, reason)
}
