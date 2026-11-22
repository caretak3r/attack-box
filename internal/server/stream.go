package server

import (
	"errors"
	"net/http"
	"time"
)

// wordsPerChunk is how many words one streamed delta carries.
const wordsPerChunk = 4

// format renders one response envelope, whole or as stream frames.
type format interface {
	contentType() string // stream content type
	start() [][]byte     // frames before the first delta
	delta(text string) []byte
	idle() []byte // keepalive frame for the idle hold
	finish(text string) [][]byte
	full(text string) any // non-streaming body
}

// stream writes text as stream frames. The probe text goes out first, then
// the hold (if any) runs, then the stream ends normally.
func (c *call) stream(f format, text, hold string) {
	w := c.w
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(c.s.cfg.MaxStreamDuration + 15*time.Second))
	h := w.Header()
	h.Set("Content-Type", f.contentType())
	h.Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	emit := func(frames ...[]byte) bool {
		for _, fr := range frames {
			if len(fr) == 0 {
				continue
			}
			if _, err := w.Write(fr); err != nil {
				return false
			}
		}
		err := rc.Flush()
		return err == nil || errors.Is(err, http.ErrNotSupported)
	}

	if !emit(f.start()...) {
		return
	}
	for _, chunk := range wordChunks(text, wordsPerChunk) {
		if !emit(f.delta(chunk)) {
			return
		}
	}
	if !c.holdFor(hold, func() bool { return emit(f.idle()) }) {
		return
	}
	emit(f.finish(text)...)
}

// sseData frames one JSON payload as a data-only server-sent event.
func sseData(v any) []byte {
	b := marshal(v)
	b = b[:len(b)-1] // Encode appends a newline
	out := make([]byte, 0, len(b)+8)
	out = append(out, "data: "...)
	out = append(out, b...)
	return append(out, '\n', '\n')
}

// sseEvent frames one JSON payload as a named server-sent event.
func sseEvent(name string, v any) []byte {
	b := marshal(v)
	b = b[:len(b)-1]
	out := make([]byte, 0, len(b)+len(name)+16)
	out = append(out, "event: "...)
	out = append(out, name...)
	out = append(out, "\ndata: "...)
	out = append(out, b...)
	return append(out, '\n', '\n')
}

var (
	sseKeepAlive = []byte(": keep-alive\n\n")
	sseDone      = []byte("data: [DONE]\n\n")
)

const sseContentType = "text/event-stream; charset=utf-8"

// ndjson frames one JSON payload as a line.
func ndjson(v any) []byte { return marshal(v) }
