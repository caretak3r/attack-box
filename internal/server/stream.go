package server

import (
	"context"
	"errors"
	"net/http"
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

// stream writes text as stream frames, paced by Config.Timing. The probe
// text goes out first, then
// the hold (if any) runs, then the stream ends normally. Every frame write
// checks the request context first, so a client that leaves or a server
// shutdown stops emission at the next frame; the cut is logged as
// stream_result.
func (c *call) stream(f format, text, hold string) {
	// Headers go out with the first token, as from a server still decoding.
	p := c.newPacer()
	if !c.pause(p.first()) {
		return
	}
	w := c.w
	rc := c.rc // the write deadline was set in serve
	h := w.Header()
	h.Set("Content-Type", f.contentType())
	h.Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	ctx := c.r.Context()
	emit := func(frames ...[]byte) bool {
		if ctx.Err() != nil {
			c.streamCut = "client_closed"
			if errors.Is(context.Cause(ctx), ErrShutdown) {
				c.streamCut = holdServerShutdown
			}
			return false
		}
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
	chunks := wordChunks(text, wordsPerChunk)
	for i, chunk := range chunks {
		if !emit(f.delta(chunk)) {
			return
		}
		if i+1 < len(chunks) && !c.pause(p.after(chunk)) {
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
