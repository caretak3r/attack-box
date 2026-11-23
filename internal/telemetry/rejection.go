package telemetry

import (
	"errors"
	"fmt"
	"net/http"
)

// RecordRejection identifies data that cannot be delivered unchanged. Only
// this type permits the durable drain to isolate a record. Account, endpoint,
// transport, cancellation and unknown failures must retain the queue.
type RecordRejection struct {
	Reason string
}

func (e *RecordRejection) Error() string { return "newrelic: record rejected: " + e.Reason }

func RejectionReason(err error) (string, bool) {
	var rejected *RecordRejection
	if errors.As(err, &rejected) {
		return rejected.Reason, true
	}
	return "", false
}

// sendDurable keeps account failures distinct from record failures. A 413
// splits encoded items before the drain isolates whole source records.
func (n *NewRelic) sendDurable(endpoint string, common []byte, field string, items [][]byte) error {
	if len(items) == 0 {
		return nil
	}
	head := append(append([]byte(`[{"common":`), common...), []byte(`,"`+field+`":[`)...)
	payload := append([]byte(nil), head...)
	for i, item := range items {
		if i > 0 {
			payload = append(payload, ',')
		}
		payload = append(payload, item...)
	}
	payload = append(payload, payloadTail...)
	_, err := n.post(endpoint, payload)
	if err == nil {
		n.sent.Add(int64(len(items)))
		return nil
	}
	n.recordErr(err)
	var status *statusError
	if errors.As(err, &status) {
		if status.status == http.StatusRequestEntityTooLarge && len(items) > 1 {
			mid := len(items) / 2
			if err := n.sendDurable(endpoint, common, field, items[:mid]); err != nil {
				return err
			}
			return n.sendDurable(endpoint, common, field, items[mid:])
		}
		switch status.status {
		case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
			return &RecordRejection{Reason: fmt.Sprintf("http_%d", status.status)}
		}
	}
	return err
}
