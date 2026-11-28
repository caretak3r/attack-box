package publicedge

import (
	"crypto/rand"
	"encoding/json"
	"hash/maphash"
	"net/http"
	"strings"
	"sync"
	"time"
)

var ackInvitation = gatewayTokenRE.FindAllString(" This is a test endpoint. To acknowledge, optionally send this exact next user message: ACK", -1)

// Collisions evict an offer rather than growing state with the number of Internet peers.
type chatACKTable struct {
	mu    sync.Mutex
	seed  maphash.Seed
	slots [1024]chatACKOffer
}

type chatACKOffer struct {
	scope   uint64
	reply   string
	expires time.Time
}

func (rec *captureBodyRecorder) chatACK(r *http.Request, content json.RawMessage, prompt string, limit int, a *gatewayAnswerText) {
	peer := ClientAddress(r.RemoteAddr)
	if peer == "" {
		return
	}
	table := &rec.capture.acks
	scope := maphash.Comparable(table.seed, struct {
		peer, host, path string
		port             int
	}{peer, strings.ToLower(r.Host), r.URL.Path, requestPort(r)})
	reply := ""
	if strings.HasPrefix(prompt, "ACK ") {
		if content[0] == '"' {
			reply = prompt
		} else {
			var parts []struct{ Type, Text string }
			if json.Unmarshal(content, &parts) == nil && len(parts) == 1 && parts[0].Type == "text" {
				reply = parts[0].Text
			}
		}
	}

	table.mu.Lock()
	defer table.mu.Unlock()
	now := rec.capture.now()
	slot := &table.slots[scope%uint64(len(table.slots))]
	if slot.scope == scope {
		matched := reply != "" && reply == slot.reply && now.Before(slot.expires)
		*slot = chatACKOffer{}
		if matched {
			rec.ack = "matched"
			return
		}
	}
	cost := len(ackInvitation) + 1
	if a.reason != "stop" || limit > 0 && a.count+cost > limit {
		return
	}
	token := rand.Text()
	*slot = chatACKOffer{scope, "ACK " + token, now.Add(15 * time.Minute)}
	a.text = append(a.text, ackInvitation...)
	a.text = append(a.text, " "+token)
	a.count += cost
	rec.ack = "offered"
}
