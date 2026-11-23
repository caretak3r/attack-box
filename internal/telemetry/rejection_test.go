package telemetry

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
)

func TestDurableRejectionClassificationAndRecovery(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 408, 413, 422, 429, 500, 503} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var fail atomic.Bool
			fail.Store(true)
			n := batchClient(t, func(_ string, _ []byte) int {
				if fail.Load() {
					return code
				}
				return 202
			})
			records := []Record{{Event: &Event{Action: "synthetic", Body: "exact evidence"}}}
			err := n.ShipRecords(records)
			if err == nil {
				t.Fatal("expected rejection")
			}
			_, permanent := RejectionReason(err)
			want := code == 400 || code == 413 || code == 422
			if permanent != want {
				t.Fatalf("status %d: permanent=%v want=%v err=%v", code, permanent, want, err)
			}
			fail.Store(false)
			if err := n.ShipRecords(records); err != nil {
				t.Fatal("recovery:", err)
			}
		})
	}
}

func TestDurable413SplitsBeforeRejectingRecords(t *testing.T) {
	var accepted atomic.Int64
	n := batchClient(t, func(_ string, body []byte) int {
		var groups []struct {
			Logs []json.RawMessage `json:"logs"`
		}
		if err := json.Unmarshal(body, &groups); err != nil {
			t.Error(err)
			return 400
		}
		if len(groups[0].Logs) > 1 {
			return 413
		}
		accepted.Add(1)
		return 202
	})
	err := n.ShipRecords([]Record{{Event: &Event{Action: "one"}}, {Event: &Event{Action: "two"}}})
	if err != nil || accepted.Load() != 2 {
		t.Fatalf("accepted=%d err=%v", accepted.Load(), err)
	}
}
