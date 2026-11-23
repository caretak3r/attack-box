package hostevidence

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
)

const MaxSourceRecord = 8 << 20
const sourceSegment = 128 << 10

type Sender struct{ Socket, Role string }

// Send retains full source bytes as base64 segments. The caller advances its
// cursor only after every segment has a durable local receipt. Lost receipts
// replay the same IDs; duplicates are possible and detectable.
func (s Sender) Send(ctx context.Context, key string, data []byte) error {
	if len(data) > MaxSourceRecord {
		return fmt.Errorf("host evidence: source record exceeds %d bytes; cursor retained", MaxSourceRecord)
	}
	if s.Role != "runtime" && s.Role != "egress" {
		return fmt.Errorf("host evidence: invalid role")
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(data))
	identity := fmt.Sprintf("%x", sha256.Sum256([]byte(s.Role+":"+key+":"+hash)))
	segments := max(1, (len(data)+sourceSegment-1)/sourceSegment)
	for i := 0; i < segments; i++ {
		part := data[min(i*sourceSegment, len(data)):min((i+1)*sourceSegment, len(data))]
		action := "falco"
		if s.Role == "egress" {
			action = "egress_blocked"
		}
		attrs := map[string]any{"source_event_id": identity, "source_sha256": hash, "source_bytes": len(data), "source_segment": i, "source_segments": segments, "source_encoding": "base64"}
		// Only bounded, selected fields are previews. The base64 body remains
		// authoritative, including invalid JSON and binary source bytes.
		var preview map[string]json.RawMessage
		if json.Unmarshal(data, &preview) == nil {
			for _, field := range []string{"rule", "priority", "output", "MESSAGE", "time"} {
				var text string
				if json.Unmarshal(preview[field], &text) == nil && len(text) <= 2048 {
					attrs["event."+field] = text
				}
			}
			var synthetic bool
			if json.Unmarshal(preview["synthetic"], &synthetic) == nil {
				attrs["event.synthetic"] = synthetic
			}
		}
		record := telemetry.Record{V: telemetry.SchemaVersion, ID: fmt.Sprintf("%s-%d", identity[:16], i+1), Event: &telemetry.Event{Stream: s.Role, Action: action, Timestamp: time.Now(), Body: "base64:" + base64.StdEncoding.EncodeToString(part), Attrs: attrs}}
		if err := s.sendRecord(ctx, record); err != nil {
			return err
		}
	}
	return nil
}

func (s Sender) Heartbeat(ctx context.Context) error {
	id := fmt.Sprintf("%x", sha256.Sum256([]byte(s.Role+time.Now().UTC().Format(time.RFC3339Nano))))
	return s.sendRecord(ctx, telemetry.Record{V: telemetry.SchemaVersion, ID: id[:16] + "-1", Event: &telemetry.Event{Stream: telemetry.StreamHeartbeat, Action: s.Role + "_heartbeat", Timestamp: time.Now(), Attrs: map[string]any{"source_reader": "durable", "source_receipts": true}}})
}

func (s Sender) sendRecord(ctx context.Context, r telemetry.Record) error {
	dial := net.Dialer{Timeout: 5 * time.Second}
	c, err := dial.DialContext(ctx, "unix", s.Socket)
	if err != nil {
		return err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(c).Encode(r); err != nil {
		return err
	}
	var receipt shipper.Receipt
	if err := json.NewDecoder(bufio.NewReader(io.LimitReader(c, 1024))).Decode(&receipt); err != nil {
		return fmt.Errorf("host evidence: receipt missing; cursor retained: %w", err)
	}
	if receipt.ID != r.ID || receipt.QueueSeq == 0 || receipt.Reason != "" {
		return fmt.Errorf("host evidence: append refused (%s); cursor retained", receipt.Reason)
	}
	return nil
}
