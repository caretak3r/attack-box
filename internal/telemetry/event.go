package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
	"unicode/utf8"
)

// MaxChunk is the largest body chunk in runes. New Relic keeps only the first
// 4,094 characters of a string attribute, so chunks stay under that.
const MaxChunk = 3500

// Stream names.
const (
	StreamEdge       = "edge"
	StreamTranscript = "transcript"
	StreamProbe      = "probe"
	StreamEgress     = "egress"
	StreamRuntime    = "runtime"
	StreamHeartbeat  = "heartbeat"
)

// Event is one log record. Attrs must already be safe to ship: no raw
// credentials, no unbounded values.
type Event struct {
	Timestamp  time.Time      `json:"timestamp"`
	Stream     string         `json:"stream"`
	SessionID  string         `json:"session_id,omitempty"`
	RequestID  string         `json:"request_id,omitempty"`
	SrcIP      string         `json:"src_ip,omitempty"`
	UserAgent  string         `json:"user_agent,omitempty"`
	Persona    string         `json:"persona,omitempty"`
	Action     string         `json:"action,omitempty"`
	Resource   string         `json:"resource,omitempty"`
	Result     string         `json:"result,omitempty"`
	Status     int            `json:"status,omitempty"`
	ProbeID    string         `json:"probe_id,omitempty"`
	TaskLabels []string       `json:"task_labels,omitempty"`
	Attrs      map[string]any `json:"attrs,omitempty"`
	Body       string         `json:"body,omitempty"`
	BodySHA256 string         `json:"body_sha256,omitempty"`
	ChunkIndex int            `json:"chunk_index"`
	ChunkCount int            `json:"chunk_count"`
}

// Message is the log line text: the body chunk, or the action when the body
// is empty.
func (e Event) Message() string {
	if e.Body != "" {
		return e.Body
	}
	return e.Action
}

// Attributes flattens the event for shipping. The timestamp is Unix ms and the
// body is under "message". Fixed fields win over Attrs on a name clash.
func (e Event) Attributes() map[string]any {
	m := make(map[string]any, len(e.Attrs)+16)
	for k, v := range e.Attrs {
		m[k] = v
	}
	m["timestamp"] = e.Timestamp.UnixMilli()
	m["message"] = e.Message()
	m["stream"] = e.Stream
	for k, v := range map[string]string{
		"session_id": e.SessionID, "request_id": e.RequestID, "src_ip": e.SrcIP,
		"user_agent": e.UserAgent, "persona": e.Persona, "action": e.Action,
		"resource": e.Resource, "result": e.Result, "probe_id": e.ProbeID,
	} {
		if v != "" {
			m[k] = v
		}
	}
	if e.Status != 0 {
		m["status"] = e.Status
	}
	if len(e.TaskLabels) > 0 {
		m["task_labels"] = e.TaskLabels
	}
	m["body_sha256"] = e.BodySHA256
	m["chunk_index"] = e.ChunkIndex
	m["chunk_count"] = e.ChunkCount
	return m
}

// Chunk splits e.Body into pieces of at most max runes (clamped to
// (0, MaxChunk]). Every piece carries the SHA-256 of the whole body and its
// index and count. An empty body gives one event. The caller bounds body size.
func Chunk(e Event, max int) []Event {
	if max <= 0 || max > MaxChunk {
		max = MaxChunk
	}
	sum := sha256.Sum256([]byte(e.Body))
	e.BodySHA256 = hex.EncodeToString(sum[:])

	n := utf8.RuneCountInString(e.Body)
	count := (n + max - 1) / max
	if count == 0 {
		count = 1
	}
	out := make([]Event, 0, count)
	body := e.Body
	for i := 0; i < count; i++ {
		cut := len(body)
		if n > max {
			cut = 0
			for r := 0; r < max; r++ {
				_, w := utf8.DecodeRuneInString(body[cut:])
				cut += w
			}
		}
		c := e
		c.Body = body[:cut]
		c.ChunkIndex = i
		c.ChunkCount = count
		out = append(out, c)
		body = body[cut:]
		n -= max
	}
	return out
}
