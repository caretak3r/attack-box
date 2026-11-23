package telemetry

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"time"
)

// MaxShipRecords bounds one durable send and its metric aggregation state.
const MaxShipRecords = 200

// Durable counts are event deltas: At is the time of the Count call, not a
// pre-aggregated interval. Assign each delta to its UTC second [start,start+1s)
// and combine equal series/windows in this batch. Separate batches may report
// additive contributions to the same second. The persisted At fixes the window
// across retries; wall-clock export time never moves old counts into new ones.
// This preserves sums and one-second rate resolution without holding a quiet
// request until the window closes. It does not provide exactly-once delivery:
// an accepted POST replayed before the durable checkpoint can duplicate counts.
const durableCountWindow = time.Second

// ShipRecords exports a bounded durable batch immediately. It returns nil only
// after both APIs accept every record and every body chunk. On any error the
// caller must retain the entire batch. Earlier accepted POSTs can be replayed;
// log record/chunk identities stay unchanged so consumers can deduplicate.
// API acceptance is not proof of New Relic's asynchronous validation success.
// Memory for encoded log items is bounded by MaxPayloadBytes plus one chunk;
// a large event is chunked once and sent in successive byte-bounded requests.
func (n *NewRelic) ShipRecords(records []Record) error {
	if len(records) > MaxShipRecords {
		return fmt.Errorf("newrelic: batch has %d records, limit %d", len(records), MaxShipRecords)
	}
	// Validate and aggregate metrics before sending anything. Gauge samples
	// keep their individual timestamps; only count deltas share windows.
	metrics, err := durableMetrics(records)
	if err != nil {
		return &RecordRejection{Reason: "invalid_metric_or_record"}
	}
	common, err := json.Marshal(map[string]any{"attributes": n.cfg.Common})
	if err != nil {
		return fmt.Errorf("marshal common: %w", err)
	}
	logs := durableBatch{n: n, common: common, endpoint: n.cfg.LogURL, field: "logs"}
	at := n.cfg.Now()
	for _, r := range records {
		if r.Event == nil {
			continue
		}
		e := *r.Event
		if e.Timestamp.IsZero() {
			e.Timestamp = at
		}
		e.Attrs = maps.Clone(e.Attrs)
		if e.Attrs == nil {
			e.Attrs = map[string]any{}
		}
		e.Attrs["export_attempt_at_ms"] = at.UnixMilli()
		e.Attrs["export_lag_ms"] = max(int64(0), at.Sub(e.Timestamp).Milliseconds())
		for _, chunk := range Chunk(e, MaxChunk) {
			item, err := logItem(chunk)
			if err != nil {
				return &RecordRejection{Reason: "event_encoding"}
			}
			if err := logs.add(item); err != nil {
				return err
			}
		}
	}
	if err := logs.flush(); err != nil {
		return err
	}
	batch := durableBatch{n: n, common: common, endpoint: n.cfg.MetricURL, field: "metrics"}
	for _, item := range metrics {
		if err := batch.add(item); err != nil {
			return err
		}
	}
	return batch.flush()
}

type durableBatch struct {
	n               *NewRelic
	common          []byte
	endpoint, field string
	items           [][]byte
	bytes           int
}

func (b *durableBatch) add(item []byte) error {
	limit := b.n.cfg.MaxPayloadBytes - len(envelope(b.common, b.field))
	if len(item) > limit {
		err := &RecordRejection{Reason: "item_too_large"}
		b.n.recordErr(err)
		return err
	}
	extra := len(item)
	if len(b.items) > 0 {
		extra++ // comma
	}
	if b.bytes+extra > limit {
		if err := b.flush(); err != nil {
			return err
		}
		extra = len(item)
	}
	b.items = append(b.items, item)
	b.bytes += extra
	return nil
}

func (b *durableBatch) flush() error {
	if len(b.items) == 0 {
		return nil
	}
	if err := b.n.sendDurable(b.endpoint, b.common, b.field, b.items); err != nil {
		return err
	}
	// Clear references: an event larger than one POST must not retain all
	// earlier encoded chunks through the backing array.
	clear(b.items)
	b.items = b.items[:0]
	b.bytes = 0
	return nil
}

func durableMetrics(records []Record) ([][]byte, error) {
	var gauges []MetricRecord
	counts := map[string]MetricRecord{}
	for _, r := range records {
		if (r.Event == nil) == (r.Metric == nil) {
			return nil, fmt.Errorf("newrelic: record must contain exactly one event or metric")
		}
		if r.Metric == nil {
			continue
		}
		m := *r.Metric
		if math.IsNaN(m.Value) || math.IsInf(m.Value, 0) || (m.Kind == "count" && m.Value < 0) {
			return nil, fmt.Errorf("invalid metric value: %v", m.Value)
		}
		m.Attrs = SafeLabels(m.Attrs)
		switch m.Kind {
		case "gauge":
			gauges = append(gauges, m)
		case "count":
			m.At = m.At.Truncate(durableCountWindow)
			key := seriesKey(m.Name, true, m.Attrs) + "|" + strconv.FormatInt(m.At.UnixMilli(), 10)
			if old, ok := counts[key]; ok {
				m.Value += old.Value
				if math.IsInf(m.Value, 0) {
					return nil, fmt.Errorf("newrelic: count sum overflows")
				}
			}
			counts[key] = m
		default:
			return nil, fmt.Errorf("invalid metric kind %q", m.Kind)
		}
	}
	// Deterministic count order keeps replay payloads stable.
	for _, key := range slices.Sorted(maps.Keys(counts)) {
		gauges = append(gauges, counts[key])
	}
	items := make([][]byte, 0, len(gauges))
	for _, m := range gauges {
		item := map[string]any{
			"name": m.Name, "type": m.Kind, "value": m.Value,
			"timestamp": m.At.UnixMilli(), "attributes": m.Attrs,
		}
		if m.Kind == "count" {
			item["interval.ms"] = durableCountWindow.Milliseconds()
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return nil, fmt.Errorf("marshal metric: %w", err)
		}
		items = append(items, encoded)
	}
	return items, nil
}
