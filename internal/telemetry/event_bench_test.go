package telemetry

import (
	"strings"
	"testing"
	"time"
)

// Benchmark hot path: event chunking and log-item sizing

func BenchmarkChunkSmallBody(b *testing.B) {
	e := Event{
		Timestamp: time.Now(),
		Stream:    StreamEdge,
		Action:    "request",
		Body:      "short log message",
	}

	for b.Loop() {
		_ = Chunk(e, MaxChunk)
	}
}

func BenchmarkChunkTypicalLog(b *testing.B) {
	e := Event{
		Timestamp: time.Now(),
		Stream:    StreamTranscript,
		Action:    "completion",
		Body:      strings.Repeat("typical log entry with some content. ", 20), // ~700 chars
	}

	for b.Loop() {
		_ = Chunk(e, MaxChunk)
	}
}

func BenchmarkChunkLargeBody(b *testing.B) {
	e := Event{
		Timestamp: time.Now(),
		Stream:    StreamProbe,
		Action:    "capture",
		Body:      strings.Repeat("x", 10000), // 10KB, requires chunking
	}

	for b.Loop() {
		_ = Chunk(e, MaxChunk)
	}
}

func BenchmarkChunkMultibyte(b *testing.B) {
	// Mixed ASCII, Latin-1, CJK, emoji: realistic for international logs
	body := strings.Repeat("a\u00e9\u4e16\U0001F600", 1000) // 4000 runes
	e := Event{
		Timestamp: time.Now(),
		Stream:    StreamEdge,
		Action:    "request",
		Body:      body,
	}

	for b.Loop() {
		_ = Chunk(e, MaxChunk)
	}
}

func BenchmarkChunkEmptyBody(b *testing.B) {
	e := Event{
		Timestamp: time.Now(),
		Stream:    StreamHeartbeat,
		Action:    "ping",
		Body:      "",
	}

	for b.Loop() {
		_ = Chunk(e, MaxChunk)
	}
}

func BenchmarkChunkMaxSize(b *testing.B) {
	// At the chunk boundary: 3500 runes
	e := Event{
		Timestamp: time.Now(),
		Stream:    StreamRuntime,
		Action:    "log",
		Body:      strings.Repeat("x", MaxChunk),
	}

	for b.Loop() {
		_ = Chunk(e, MaxChunk)
	}
}

func BenchmarkChunkSmallLimit(b *testing.B) {
	e := Event{
		Timestamp: time.Now(),
		Stream:    StreamEdge,
		Action:    "request",
		Body:      strings.Repeat("x", 1000),
	}

	for b.Loop() {
		_ = Chunk(e, 500)
	}
}

func BenchmarkAttributes(b *testing.B) {
	e := Event{
		Timestamp:  time.Now(),
		Stream:     StreamEdge,
		SessionID:  "sess_123",
		RequestID:  "req_456",
		SrcIP:      "192.0.2.1",
		UserAgent:  "curl/7.68.0",
		Persona:    "researcher",
		Action:     "chat_completion",
		Resource:   "/v1/chat/completions",
		Result:     "success",
		Status:     200,
		TaskLabels: []string{"code_generation", "instruction_following"},
		Attrs: map[string]any{
			"model":       "gpt-4",
			"tokens":      1234,
			"duration_ms": 567,
		},
		Body:       "response body content",
		BodySHA256: "abc123",
		ChunkIndex: 0,
		ChunkCount: 1,
	}

	for b.Loop() {
		_ = e.Attributes()
	}
}

func BenchmarkMessage(b *testing.B) {
	e := Event{
		Action: "request",
		Body:   "log message body",
	}

	for b.Loop() {
		_ = e.Message()
	}
}

func BenchmarkMessageEmptyBody(b *testing.B) {
	e := Event{
		Action: "ping",
		Body:   "",
	}

	for b.Loop() {
		_ = e.Message()
	}
}
