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

// evidenceWriter is the part the drain uses to write evidence envelopes.
type evidenceWriter interface {
	Write(records []telemetry.EvidenceItem) error
}

const (
	drainReadMax      = 200 // entries per Read
	drainReadMaxBytes = 512 << 10
	drainAckEvery     = 200
	drainAckInterval  = time.Second
	drainIdlePoll     = 100 * time.Millisecond
	drainRetryWait    = 250 * time.Millisecond
)

// drain reads entries from the queue and writes them to local evidence files
// synchronously. It checkpoints fsynced writes, so a crash replays everything
// the checkpoint does not cover. A failed write stays in memory and is retried;
// nothing behind it is delivered or acknowledged first. Uncertain recovery
// suppresses metrics up to uncertainThrough to avoid double-counting.
func drain(ctx context.Context, q drainQueue, w evidenceWriter, uncertain bool, uncertainThrough uint64) error {
	var skipThrough uint64
	if uncertain {
		skipThrough = uncertainThrough
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

		n, blocked, err := deliver(ctx, w, pending, skipThrough)
		pending = pending[n:]
		toAck += n
		if err != nil {
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

	if err := checkpoint(); err != nil {
		return err
	}
	return ctx.Err()
}

// deliver writes entries to the evidence writer in one batch, each with its
// producer role. blocked reports that the writer failed, so the rest must wait.
// Metrics at or below skipThrough are taken but not written. err is set for a
// payload that does not decode.
func deliver(ctx context.Context, w evidenceWriter, entries []shipper.Entry, skipThrough uint64) (n int, blocked bool, err error) {
	if len(entries) == 0 || ctx.Err() != nil {
		return 0, false, nil
	}
	var batch []telemetry.EvidenceItem
	for _, e := range entries {
		if ctx.Err() != nil {
			break
		}
		var rec telemetry.Record
		if err := json.Unmarshal(e.Data, &rec); err != nil {
			return n, false, fmt.Errorf("corrupt queue payload at seq %d: %w", e.Seq, err)
		}
		if rec.Metric != nil && e.Seq <= skipThrough {
			n++
			continue
		}
		batch = append(batch, telemetry.EvidenceItem{Role: e.Role.String(), Seq: e.Seq, Data: e.Data})
		n++
	}
	if len(batch) == 0 {
		return n, false, nil
	}
	_, span := observability.Tracer(ctx).Start(ctx, "shipper.export", trace.WithNewRoot(), trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(attribute.Int("attackbox.batch_records", len(batch))))
	werr := w.Write(batch)
	if werr != nil {
		span.SetStatus(codes.Error, "")
		span.SetAttributes(attribute.String("error.type", "export_failed"))
	} else {
		span.SetAttributes(attribute.Int("attackbox.batch_accepted", len(batch)))
	}
	span.End()
	if werr != nil {
		return 0, true, nil
	}
	return n, false, nil
}
