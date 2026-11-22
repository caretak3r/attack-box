package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"unicode/utf8"
)

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestChunkRuneSafe(t *testing.T) {
	body := strings.Repeat("a\u00e9\u4e16\U0001F600", 5) // 20 runes, mixed widths
	got := Chunk(Event{Body: body, Action: "x"}, 7)
	if len(got) != 3 {
		t.Fatalf("chunks = %d, want 3", len(got))
	}
	var joined strings.Builder
	for i, c := range got {
		if c.ChunkIndex != i || c.ChunkCount != 3 {
			t.Errorf("chunk %d: index %d count %d", i, c.ChunkIndex, c.ChunkCount)
		}
		if c.BodySHA256 != sha(body) {
			t.Errorf("chunk %d: sha mismatch", i)
		}
		if !utf8.ValidString(c.Body) {
			t.Errorf("chunk %d split a rune", i)
		}
		joined.WriteString(c.Body)
	}
	if joined.String() != body {
		t.Error("chunks do not reassemble to the body")
	}
	if n := utf8.RuneCountInString(got[0].Body); n != 7 {
		t.Errorf("first chunk runes = %d", n)
	}
	if n := utf8.RuneCountInString(got[2].Body); n != 6 {
		t.Errorf("last chunk runes = %d", n)
	}
}

func TestChunkExactMultiple(t *testing.T) {
	got := Chunk(Event{Body: strings.Repeat("x", 10)}, 5)
	if len(got) != 2 || got[1].Body != "xxxxx" {
		t.Fatalf("got %d chunks: %+v", len(got), got)
	}
}

func TestChunkEmptyBody(t *testing.T) {
	got := Chunk(Event{Stream: "edge", Action: "GET /v1/models"}, 100)
	if len(got) != 1 {
		t.Fatalf("chunks = %d", len(got))
	}
	c := got[0]
	if c.ChunkIndex != 0 || c.ChunkCount != 1 || c.BodySHA256 != sha("") {
		t.Errorf("bad empty chunk: %+v", c)
	}
	if c.Message() != "GET /v1/models" {
		t.Errorf("message = %q", c.Message())
	}
}

func TestChunkClamp(t *testing.T) {
	body := strings.Repeat("z", 10000)
	for _, max := range []int{0, -5, 4000, 1 << 30, MaxChunk} {
		got := Chunk(Event{Body: body}, max)
		if len(got) != 3 {
			t.Fatalf("max %d: chunks = %d, want 3", max, len(got))
		}
		for _, c := range got {
			if n := utf8.RuneCountInString(c.Body); n > MaxChunk {
				t.Fatalf("max %d: chunk of %d runes", max, n)
			}
		}
		if len(got[2].Body) != 10000-2*MaxChunk {
			t.Errorf("last chunk len = %d", len(got[2].Body))
		}
	}
}

func TestAttributes(t *testing.T) {
	e := Chunk(Event{
		Stream: StreamEdge, SessionID: "s1", Action: "POST", Status: 401, Body: "hi",
		Attrs: map[string]any{"stream": "spoof", "extra": 1},
	}, 10)[0]
	a := e.Attributes()
	if a["stream"] != "edge" || a["extra"] != 1 || a["message"] != "hi" {
		t.Errorf("attrs = %v", a)
	}
	if _, ok := a["src_ip"]; ok {
		t.Error("empty field emitted")
	}
	if a["chunk_count"] != 1 || a["status"] != 401 {
		t.Errorf("attrs = %v", a)
	}
}
