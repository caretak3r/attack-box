package telemetry

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
)

// Async moves a possibly blocking sink (JSONLog on a stalled pipe or disk) off
// the request path. Calls enqueue into a bounded queue and never block; when
// the queue is full the item is dropped and counted; the count is also
// written to the wrapped sink as a local_dropped runtime event once the queue
// drains. One goroutine delivers in order, so the wrapped sink needs no extra
// locking.
type Async struct {
	next    Sink
	queue   chan asyncItem
	done    chan struct{}
	dropped atomic.Int64

	mu     sync.RWMutex
	closed bool
}

type asyncItem struct {
	metric bool
	count  bool
	event  Event
	name   string
	value  float64
	attrs  map[string]string
}

// NewAsync starts the delivery goroutine. size <= 0 means 4096.
func NewAsync(next Sink, size int) *Async {
	if size <= 0 {
		size = 4096
	}
	a := &Async{next: next, queue: make(chan asyncItem, size), done: make(chan struct{})}
	go a.run()
	return a
}

func (a *Async) run() {
	defer close(a.done)
	var reported int64
	for it := range a.queue {
		switch {
		case !it.metric:
			a.next.Emit(it.event)
		case it.count:
			a.next.Count(it.name, it.value, it.attrs)
		default:
			a.next.Gauge(it.name, it.value, it.attrs)
		}
		// Report drops once the queue has drained: a stalled writer shows the
		// loss as soon as it recovers, and the record cannot crowd out the
		// backlog.
		if d := a.dropped.Load(); d != reported && len(a.queue) == 0 {
			reported = d
			a.next.Emit(Event{Stream: StreamRuntime, Action: "local_dropped", Result: "error", Attrs: map[string]any{"dropped_total": d}})
		}
	}
}

// Callers may reuse their maps after the call returns, so the queued item
// owns shallow copies.
func (a *Async) Emit(e Event) {
	e.Attrs = maps.Clone(e.Attrs)
	e.TaskLabels = slices.Clone(e.TaskLabels)
	a.put(asyncItem{event: e})
}

func (a *Async) Count(name string, value float64, attrs map[string]string) {
	a.put(asyncItem{metric: true, count: true, name: name, value: value, attrs: maps.Clone(attrs)})
}

func (a *Async) Gauge(name string, value float64, attrs map[string]string) {
	a.put(asyncItem{metric: true, name: name, value: value, attrs: maps.Clone(attrs)})
}

func (a *Async) put(it asyncItem) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		a.dropped.Add(1)
		return
	}
	select {
	case a.queue <- it:
	default:
		a.dropped.Add(1)
	}
}

// Dropped returns the number of items refused by a full queue or after Close.
func (a *Async) Dropped() int64 { return a.dropped.Load() }

// Close stops intake and waits for queued items to reach the wrapped sink.
// It returns an error if ctx ends first or if any item was dropped. Repeated
// calls only wait.
func (a *Async) Close(ctx context.Context) error {
	a.mu.Lock()
	if !a.closed {
		a.closed = true
		close(a.queue)
	}
	a.mu.Unlock()
	select {
	case <-a.done:
	case <-ctx.Done():
		return fmt.Errorf("local log: drain: %w", ctx.Err())
	}
	if d := a.dropped.Load(); d > 0 {
		return fmt.Errorf("local log: %d dropped", d)
	}
	return nil
}
