package publicedge

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestPublicChatACK(t *testing.T) {
	const user = `[{"role":"user","content":"hi"}]`
	const peer = "192.0.2.10:1000"
	for _, route := range []string{"/v1/chat/completions", "/api/chat", "/v1/messages"} {
		t.Run(route, func(t *testing.T) {
			dir := t.TempDir()
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			capture, err := openCapture(dir, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { capture.Close() })
			g := NewGateway(nil)
			g.Capture = capture
			file, err := os.Open(filepath.Join(dir, "capture-20260101.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			records := json.NewDecoder(file)
			stream := false
			post := func(addr, messages string, limit int, want string) string {
				t.Helper()
				body := fmt.Sprintf(`{"model":"llama3.1:8b","stream":%t,"max_tokens":%d,"options":{"num_predict":%d},"messages":%s}`, stream, limit, limit, messages)
				r := httptest.NewRequest("POST", route, strings.NewReader(body))
				r.RemoteAddr = addr
				r.Header.Set("Authorization", "Bearer fixture")
				r.Header.Set("X-Forwarded-For", "192.0.2.10")
				w := httptest.NewRecorder()
				g.ServeHTTP(w, r)
				var row struct {
					ACK string `json:"chat_ack"`
				}
				if err := records.Decode(&row); err != nil || row.ACK != want || w.Code != 200 {
					t.Fatalf("status %d, capture %q, err %v; want 200, %q", w.Code, row.ACK, err, want)
				}
				if stream && route == "/api/chat" {
					var text strings.Builder
					for _, line := range strings.Split(strings.TrimSpace(w.Body.String()), "\n") {
						var chunk struct{ Message struct{ Content string } }
						if err := json.Unmarshal([]byte(line), &chunk); err != nil {
							t.Fatal(err)
						}
						text.WriteString(chunk.Message.Content)
					}
					return text.String()
				}
				return w.Body.String()
			}
			challenge := regexp.MustCompile(`ACK [A-Z2-7]{26,}`)
			offer := func() string {
				t.Helper()
				ack := challenge.FindString(post(peer, user, 100, "offered"))
				if ack == "" {
					t.Fatal("invitation missing from chat response")
				}
				return ack
			}
			msg := func(ack string) string { return `[{"role":"user","content":"` + ack + `"}]` }
			first, next := offer(), offer()
			if first == next {
				t.Fatal("repeated challenge")
			}
			post("192.0.2.11:1000", msg(next), 1, "")
			post(peer, `[{"role":"user","content":"`+next+`"},{"role":"assistant","content":"`+next+`"}]`, 100, "")
			post("192.0.2.10:2000", `[{"role":"user","content":[{"type":"text","text":"`+next+`"}]}]`, 1, "matched")
			post(peer, msg(next), 1, "") // replay
			old := offer()
			offer()
			post(peer, msg(old), 1, "") // superseded
			old = offer()
			now = now.Add(15 * time.Minute)
			post(peer, msg(old), 1, "") // expired
			if challenge.MatchString(post(peer, user, 1, "")) {
				t.Fatal("invitation exceeded output budget")
			}
			stream = true
			post(peer, msg(offer()), 1, "matched")
		})
	}
}
