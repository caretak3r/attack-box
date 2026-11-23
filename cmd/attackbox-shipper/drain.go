package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"attackbox/internal/observability"
	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
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

// batchDrainSink is optional so small test/adapter sinks keep the single-item
// contract. The production client accepts a whole bounded batch synchronously.
type batchDrainSink interface {
	ShipRecords([]telemetry.Record) error
}

type rejectedStore interface {
	Put(shipper.Entry, string) error
}

const (
	drainReadMax      = telemetry.MaxShipRecords // entries per Read
	drainReadMaxBytes = 512 << 10
	drainAckEvery     = 200 // checkpoint after this many delivered records
	drainAckInterval  = time.Second
	drainIdlePoll     = 100 * time.Millisecond // wait before re-reading an empty queue
	drainRetryWait    = 250 * time.Millisecond // wait after the sink failed a delivery
)

// drain reads entries from the queue and delivers them to New Relic
// synchronously. It checkpoints remote receipts or fsynced rejected records, so a crash or
// New Relic outage replays everything the checkpoint does not cover. A failed
// transient failure stays in memory and is retried; nothing behind it is delivered or
// acknowledged first. Uncertain recovery suppresses metrics up to
// uncertainThrough to avoid double-counting.
func drain(ctx context.Context, q drainQueue, nr drainSink, uncertain bool, uncertainThrough uint64, rejected ...rejectedStore) error {
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

		n, blocked, err := deliver(ctx, nr, pending, skipThrough, rejected...)
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
func deliver(ctx context.Context, nr drainSink, entries []shipper.Entry, skipThrough uint64, rejected ...rejectedStore) (n int, blocked bool, err error) {
	if batch, ok := nr.(batchDrainSink); ok {
		return deliverBatch(ctx, batch, entries, skipThrough, rejected...)
	}
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

// deliverBatch never acknowledges a partial remote result. A failed request
// leaves all entries pending, even if an earlier POST in the batch succeeded.
// Stable record/chunk IDs allow log dedup; count metrics remain at-least-once.
// Do not wait for more entries to fill a batch: low-volume traffic ships on
// the first Read, at most drainIdlePoll after reaching an empty queue.
func deliverBatch(ctx context.Context, nr batchDrainSink, entries []shipper.Entry, skipThrough uint64, rejected ...rejectedStore) (int, bool, error) {
	if ctx.Err() != nil || len(entries) == 0 {
		return 0, false, nil
	}
	records := make([]telemetry.Record, 0, len(entries))
	for _, e := range entries {
		var rec telemetry.Record
		if err := json.Unmarshal(e.Data, &rec); err != nil {
			return 0, false, fmt.Errorf("corrupt queue payload at seq %d: %w", e.Seq, err)
		}
		if (rec.Event == nil) == (rec.Metric == nil) {
			return 0, false, fmt.Errorf("invalid queue payload at seq %d: exactly one event or metric required", e.Seq)
		}
		if rec.Metric != nil && e.Seq <= skipThrough {
			continue
		}
		records = append(records, rec)
	}
	if ctx.Err() != nil {
		return 0, false, nil
	}
	if len(records) > 0 {
		_, span := observability.Tracer(ctx).Start(ctx, "shipper.export", trace.WithNewRoot(), trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(attribute.Int("attackbox.batch_records", len(records))))
		sc := span.SpanContext()
		if sc.IsValid() {
			for i := range records {
				if e := records[i].Event; e != nil {
					if e.Attrs == nil {
						e.Attrs = map[string]any{}
					}
					e.Attrs["export.trace.id"] = sc.TraceID().String()
					e.Attrs["export.span.id"] = sc.SpanID().String()
				}
			}
		}
		err := nr.ShipRecords(records)
		if err != nil {
			span.SetStatus(codes.Error, "export_failed")
			span.SetAttributes(attribute.String("error.type", "export_failed"))
		} else {
			span.SetAttributes(attribute.Int("attackbox.batch_accepted", len(records)))
		}
		span.End()
		if err != nil {
			reason, permanent := telemetry.RejectionReason(err)
			if !permanent || len(rejected) == 0 || rejected[0] == nil {
				return 0, true, nil
			}
			if len(entries) > 1 {
				mid := len(entries) / 2
				n, blocked, err := deliverBatch(ctx, nr, entries[:mid], skipThrough, rejected...)
				if blocked || err != nil || n != mid {
					return n, blocked, err
				}
				m, blocked, err := deliverBatch(ctx, nr, entries[mid:], skipThrough, rejected...)
				return n + m, blocked, err
			}
			if err := rejected[0].Put(entries[0], reason); err != nil {
				return 0, false, fmt.Errorf("retain rejected record at seq %d: %w", entries[0].Seq, err)
			}
			return 1, false, nil
		}
	}
	// An accepted batch counts even if cancellation arrived during the POST.
	return len(entries), false, nil
}
