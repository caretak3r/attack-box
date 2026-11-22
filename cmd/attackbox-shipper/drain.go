package main

import (
	"context"
	"encoding/json"
	"time"

	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
)

// drainQueue is the part of shipper.Queue the drain loop uses.
type drainQueue interface {
	Read(max, maxBytes int) ([]shipper.Entry, error)
	Ack(n int) error
}

// drainSink is the part of telemetry.NewRelic the drain loop uses.
type drainSink interface {
	TryEmit(telemetry.Event) bool
	Count(name string, value float64, attrs map[string]string)
	Gauge(name string, value float64, attrs map[string]string)
}

const (
	drainReadMax      = 200 // entries per Read
	drainReadMaxBytes = 512 << 10
	drainAckEvery     = 200 // checkpoint after this many delivered records
	drainAckInterval  = time.Second
	drainIdlePoll     = 100 * time.Millisecond // wait before re-reading an empty queue
	drainRetryWait    = 250 * time.Millisecond // wait after the sink refused an event
)

// drain reads entries from the queue and hands them to New Relic. It
// checkpoints after the sink accepts a record, so a crash replays records the
// checkpoint does not cover. Note the sink queue is in memory: ack-after-enqueue
// is at-most-once for what the sink still holds when the process dies.
// Uncertain recovery suppresses metrics up to uncertainThrough to avoid
// double-counting.
func drain(ctx context.Context, q drainQueue, nr drainSink, uncertain bool, uncertainThrough uint64, timeout time.Duration) error {
	var skipThrough uint64
	if uncertain {
		skipThrough = uncertainThrough
	}

	var (
		pending []shipper.Entry
		toAck   int
		lastAck = time.Now()
	)
	// finish gives the sink a last chance at pending, then checkpoints.
	finish := func() error {
		deadline := time.Now().Add(timeout)
		for len(pending) > 0 && time.Now().Before(deadline) {
			n, _ := deliver(nr, pending, skipThrough)
			pending = pending[n:]
			toAck += n
			if len(pending) > 0 {
				time.Sleep(min(drainIdlePoll, time.Until(deadline)))
			}
		}
		if toAck > 0 {
			if err := q.Ack(toAck); err != nil {
				return err
			}
		}
		return ctx.Err()
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

		n, blocked := deliver(nr, pending, skipThrough)
		pending = pending[n:]
		toAck += n

		if toAck >= drainAckEvery || (toAck > 0 && time.Since(lastAck) >= drainAckInterval) {
			if err := q.Ack(toAck); err != nil {
				return err
			}
			toAck = 0
			lastAck = time.Now()
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
	return finish()
}

// deliver hands entries to the sink in order and returns how many were taken
// from the front. blocked reports that the sink refused an event, so the rest
// must wait. Metrics at or below skipThrough are taken but not counted.
func deliver(nr drainSink, entries []shipper.Entry, skipThrough uint64) (n int, blocked bool) {
	for _, e := range entries {
		var rec telemetry.Record
		if err := json.Unmarshal(e.Data, &rec); err != nil {
			n++ // corrupted entry; skip it
			continue
		}
		switch {
		case rec.Event != nil:
			if !nr.TryEmit(*rec.Event) {
				return n, true
			}
		case rec.Metric != nil && e.Seq > skipThrough:
			switch rec.Metric.Kind {
			case "count":
				nr.Count(rec.Metric.Name, rec.Metric.Value, rec.Metric.Attrs)
			case "gauge":
				nr.Gauge(rec.Metric.Name, rec.Metric.Value, rec.Metric.Attrs)
			}
		}
		n++
	}
	return n, false
}
