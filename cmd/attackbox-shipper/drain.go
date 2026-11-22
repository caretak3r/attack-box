package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
)

// drainQueue is the part of shipper.Queue the drain loop uses.
type drainQueue interface {
	Read(max, maxBytes int) ([]shipper.Entry, error)
	Ack(n int) error
}

// drainSink is the part of telemetry.NewRelic the drain loop uses. Both calls
// block until New Relic accepts the item or the attempt fails.
type drainSink interface {
	ShipEvent(telemetry.Event) error
	ShipMetric(name, kind string, value float64, at time.Time, attrs map[string]string) error
}

const (
	drainReadMax      = 200 // entries per Read
	drainReadMaxBytes = 512 << 10
	drainAckEvery     = 200 // checkpoint after this many delivered records
	drainAckInterval  = time.Second
	drainIdlePoll     = 100 * time.Millisecond // wait before re-reading an empty queue
	drainRetryWait    = 250 * time.Millisecond // wait after the sink failed a delivery
)

// drain reads entries from the queue and delivers them to New Relic
// synchronously. It checkpoints only records the sink confirmed, so a crash or
// New Relic outage replays everything the checkpoint does not cover. A failed
// entry stays in memory and is retried; nothing behind it is delivered or
// acknowledged first. Uncertain recovery suppresses metrics up to
// uncertainThrough to avoid double-counting.
func drain(ctx context.Context, q drainQueue, nr drainSink, uncertain bool, uncertainThrough uint64) error {
	var skipThrough uint64
	if uncertain {
		skipThrough = uncertainThrough
		// Signal the suppressed range.
		if err := nr.ShipMetric("attackbox.metric_replay_gap", "gauge", 1, time.Now(), nil); err != nil {
			return fmt.Errorf("failed to emit metric_replay_gap: %w", err)
		}
	}

	var (
		pending []shipper.Entry
		toAck   int
		lastAck = time.Now()
	)
	checkpoint := func() error {
		if toAck == 0 {
			return nil
		}
		if err := q.Ack(toAck); err != nil {
			return err
		}
		toAck = 0
		lastAck = time.Now()
		return nil
	}

	for ctx.Err() == nil {
		idle := false
		if len(pending) == 0 {
			entries, err := q.Read(drainReadMax, drainReadMaxBytes)
			if err != nil {
				return err
			}
			pending = entries
			idle = len(entries) == 0
		}

		n, blocked, err := deliver(ctx, nr, pending, skipThrough)
		pending = pending[n:]
		toAck += n
		if err != nil {
			// Fail closed on a payload that does not decode, but keep what
			// was delivered before it.
			return errors.Join(err, checkpoint())
		}

		if toAck >= drainAckEvery || (toAck > 0 && time.Since(lastAck) >= drainAckInterval) {
			if err := checkpoint(); err != nil {
				return err
			}
		}

		var wait time.Duration
		switch {
		case blocked:
			wait = drainRetryWait
		case idle:
			wait = drainIdlePoll
		default:
			continue
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
		case <-t.C:
		}
		t.Stop()
	}

	// Shutdown: ack what was delivered. Entries still pending replay on the
	// next start. The checkpoint error outranks ctx.Err, which the caller
	// treats as a clean stop.
	if err := checkpoint(); err != nil {
		return err
	}
	return ctx.Err()
}

// deliver hands entries to the sink in order and returns how many were taken
// from the front. blocked reports that the sink failed an item, so the rest
// must wait. Metrics at or below skipThrough are taken but not shipped. A
// delivery that succeeded counts even if ctx ended during the call, but
// nothing after it is attempted. err is set for a payload that does not decode.
func deliver(ctx context.Context, nr drainSink, entries []shipper.Entry, skipThrough uint64) (n int, blocked bool, err error) {
	for _, e := range entries {
		if ctx.Err() != nil {
			return n, false, nil
		}
		var rec telemetry.Record
		if err := json.Unmarshal(e.Data, &rec); err != nil {
			return n, false, fmt.Errorf("corrupt queue payload at seq %d: %w", e.Seq, err)
		}
		switch {
		case rec.Event != nil:
			if err := nr.ShipEvent(*rec.Event); err != nil {
				return n, true, nil
			}
		case rec.Metric != nil && e.Seq > skipThrough:
			m := rec.Metric
			if err := nr.ShipMetric(m.Name, m.Kind, m.Value, m.At, m.Attrs); err != nil {
				return n, true, nil
			}
		}
		n++
	}
	return n, false, nil
}
