package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
)

// drain reads entries from the queue and delivers them to New Relic. It
// checkpoints only after successful delivery, so a crash or New Relic outage
// replays unacknowledged records. Uncertain recovery suppresses metrics up to
// uncertainThrough to avoid double-counting.
func drain(ctx context.Context, q *shipper.Queue, nr *telemetry.NewRelic, uncertain bool, uncertainThrough uint64) error {
	const (
		readMax      = 200 // entries per Read
		readMaxBytes = 512 << 10
		ackEvery     = 200 // checkpoint after this many delivered records
		ackInterval  = time.Second
	)

	ticker := time.NewTicker(ackInterval)
	defer ticker.Stop()

	var (
		pending     []shipper.Entry
		toAck       int
		lastAck     time.Time
		delivered   int
		retryAt     time.Time
		metricAt    uint64
		needsRewind bool
	)

	if uncertain {
		metricAt = uncertainThrough
		// Emit metric_replay_gap to signal suppressed metrics
		if err := nr.ShipMetric("attackbox.metric_replay_gap", "gauge", 1, time.Now(), nil); err != nil {
			return fmt.Errorf("failed to emit metric_replay_gap: %w", err)
		}
	}

	for {
		if len(pending) == 0 && toAck == 0 {
			// Read more from queue
			entries, err := q.Read(readMax, readMaxBytes)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				// Queue is empty; wait for context or new data
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(100 * time.Millisecond):
					continue
				}
			}
			pending = entries
			retryAt = time.Time{}
		}
		// Deliver pending entries synchronously
		delivered = 0
		for i, e := range pending {
			var rec telemetry.Record
			if err := json.Unmarshal(e.Data, &rec); err != nil {
				// Corrupt JSON: fail closed, do not Ack
				return fmt.Errorf("corrupt queue payload at seq %d: %w", e.Seq, err)
			}

			if rec.Event != nil {
				// ShipEvent blocks until delivered or permanently failed
				if err := nr.ShipEvent(*rec.Event); err != nil {
					// Transient failure: Ack delivered prefix first, then Rewind
					needsRewind = true
					break
				}
			} else if rec.Metric != nil {
				// Skip metrics in uncertain range
				if uncertain && e.Seq <= metricAt {
					delivered = i + 1
					continue
				}
				// ShipMetric blocks until delivered or permanently failed
				if err := nr.ShipMetric(rec.Metric.Name, rec.Metric.Kind, rec.Metric.Value, rec.Metric.At, rec.Metric.Attrs); err != nil {
					// Transient failure: Ack delivered prefix first, then Rewind
					needsRewind = true
					break
				}
			}
			// If context was cancelled after successful delivery, mark this record
			// delivered and stop before the next one to allow its Ack
			if ctx.Err() != nil {
				delivered = i + 1
				break
			}
			delivered = i + 1
		}
		if delivered > 0 {
			pending = pending[delivered:]
			toAck += delivered
		}

		// If a delivery failed, Ack the successfully delivered prefix before Rewind
		if needsRewind {
			if toAck > 0 {
				if err := q.Ack(toAck); err != nil {
					return err
				}
				toAck = 0
				lastAck = time.Now()
			}
			q.Rewind()
			pending = nil // Rewind makes records available for re-reading
			needsRewind = false
			// Check if context was cancelled before retrying
			if ctx.Err() != nil {
				return ctx.Err()
			}
			time.Sleep(250 * time.Millisecond)
			continue
		}

		// Checkpoint if we've accumulated enough or enough time has passed
		now := time.Now()
		shouldAck := toAck >= ackEvery || (toAck > 0 && now.Sub(lastAck) >= ackInterval)

		select {
		case <-ticker.C:
			if toAck > 0 {
				shouldAck = true
			}
		default:
		}

		if shouldAck {
			if err := q.Ack(toAck); err != nil {
				return err
			}
			toAck = 0
			lastAck = now
		}

		// Check for context cancellation
		select {
		case <-ctx.Done():
			// Ack what we delivered before cancellation, but don't try to drain more
			// because shutdown cannot acknowledge queued-only records
			if toAck > 0 {
				q.Ack(toAck)
			}
			return ctx.Err()
		default:
		}

		// If we're waiting for retry, sleep a bit
		if !retryAt.IsZero() && len(pending) > 0 {
			waitFor := time.Until(retryAt)
			if waitFor > 0 {
				time.Sleep(waitFor)
			}
		}
	}
}
