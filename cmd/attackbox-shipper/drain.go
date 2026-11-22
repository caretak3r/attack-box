package main

import (
	"context"
	"encoding/json"
	"time"

	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
)

// drain reads entries from the queue and delivers them to New Relic. It
// checkpoints only after successful delivery, so a crash or New Relic outage
// replays unacknowledged records. Uncertain recovery suppresses metrics up to
// uncertainThrough to avoid double-counting.
func drain(ctx context.Context, q *shipper.Queue, nr *telemetry.NewRelic, uncertain bool, uncertainThrough uint64, timeout time.Duration) error {
	const (
		readMax      = 200 // entries per Read
		readMaxBytes = 512 << 10
		ackEvery     = 200 // checkpoint after this many delivered records
		ackInterval  = time.Second
	)

	ticker := time.NewTicker(ackInterval)
	defer ticker.Stop()

	var (
		pending  []shipper.Entry
		toAck    int
		lastAck  time.Time
		retryAt  time.Time
		metricAt uint64
	)

	if uncertain {
		metricAt = uncertainThrough
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
		var delivered int
		// Try to deliver pending entries
		for i, e := range pending {
			// If we're in retry mode, wait
			if !retryAt.IsZero() && time.Now().Before(retryAt) {
				break
			}

			// Unmarshal the admitted record
			var adm shipper.Admitted
			if err := json.Unmarshal(e.Data, &adm); err != nil {
				// Skip corrupted entry
				delivered = i + 1
				continue
			}

			if adm.Record.Event != nil {
				if !nr.TryEmit(*adm.Record.Event) {
					// Queue full, retry later
					retryAt = time.Now().Add(250 * time.Millisecond)
					break
				}
			} else if adm.Record.Metric != nil {
				// Skip metrics in uncertain range
				if uncertain && e.Seq <= metricAt {
					// Skip, but mark as delivered
					delivered = i + 1
					continue
				}
				switch adm.Record.Metric.Kind {
				case "count":
					nr.Count(adm.Record.Metric.Name, adm.Record.Metric.Value, adm.Record.Metric.Attrs)
				case "gauge":
					nr.Gauge(adm.Record.Metric.Name, adm.Record.Metric.Value, adm.Record.Metric.Attrs)
				}
			}
			delivered = i + 1
		}
		if delivered > 0 {
			pending = pending[delivered:]
			toAck += delivered
			retryAt = time.Time{}
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
			// Drain what we can within timeout
			deadline := time.Now().Add(timeout)
			for time.Now().Before(deadline) && len(pending) > 0 {
				delivered := 0
				for i, e := range pending {
					var adm shipper.Admitted
					if err := json.Unmarshal(e.Data, &adm); err != nil {
						delivered = i + 1
						continue
					}
					if adm.Record.Event != nil {
						if !nr.TryEmit(*adm.Record.Event) {
							break
						}
					} else if adm.Record.Metric != nil {
						if uncertain && e.Seq <= metricAt {
							delivered = i + 1
							continue
						}
						switch adm.Record.Metric.Kind {
						case "count":
							nr.Count(adm.Record.Metric.Name, adm.Record.Metric.Value, adm.Record.Metric.Attrs)
						case "gauge":
							nr.Gauge(adm.Record.Metric.Name, adm.Record.Metric.Value, adm.Record.Metric.Attrs)
						}
					}
					delivered = i + 1
				}
				if delivered > 0 {
					pending = pending[delivered:]
					toAck += delivered
				} else {
					time.Sleep(100 * time.Millisecond)
				}
			}
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
