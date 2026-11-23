package telemetry

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"regexp"
	"testing"
	"time"
)

// metricProbe keeps what reaches the sink, metric labels included.
type metricProbe struct {
	events  []Event
	metrics []map[string]string
}

func (m *metricProbe) Emit(e Event) { m.events = append(m.events, e) }
func (m *metricProbe) Count(_ string, _ float64, a map[string]string) {
	m.metrics = append(m.metrics, a)
}
func (m *metricProbe) Gauge(_ string, _ float64, a map[string]string) {
	m.metrics = append(m.metrics, a)
}

var testStamp = map[string]any{
	"persona_version": 1, "policy_version": 1, "redaction_version": 1,
	"fp_epoch": "0a1b2c3d", "fp_scope": "configured",
}

func TestWithStampEvent(t *testing.T) {
	probe := &metricProbe{}
	s := WithStamp(probe, testStamp)
	s.Emit(Event{Action: "x", Attrs: map[string]any{"direction": "request"}})
	s.Emit(Event{Action: "y"}) // nil Attrs
	if len(probe.events) != 2 {
		t.Fatalf("events = %d", len(probe.events))
	}
	for i, e := range probe.events {
		for k, v := range testStamp {
			if e.Attrs[k] != v {
				t.Errorf("event %d: %s = %v, want %v", i, k, e.Attrs[k], v)
			}
		}
	}
	if probe.events[0].Attrs["direction"] != "request" {
		t.Errorf("event attribute lost: %v", probe.events[0].Attrs)
	}
}

func TestWithStampSkipsMetrics(t *testing.T) {
	probe := &metricProbe{}
	s := WithStamp(probe, testStamp)
	s.Count("attackbox.requests", 1, map[string]string{"persona": "openai"})
	s.Gauge("attackbox.sessions", 3, nil)
	if len(probe.metrics) != 2 {
		t.Fatalf("metrics = %d", len(probe.metrics))
	}
	if !reflect.DeepEqual(probe.metrics[0], map[string]string{"persona": "openai"}) || probe.metrics[1] != nil {
		t.Errorf("metric labels changed: %v", probe.metrics)
	}
}

func TestWithStampWinsOverEvent(t *testing.T) {
	probe := &metricProbe{}
	s := WithStamp(probe, testStamp)
	forged := map[string]any{}
	for k := range testStamp {
		forged[k] = "forged"
	}
	s.Emit(Event{Attrs: forged})
	for k, v := range testStamp {
		if probe.events[0].Attrs[k] != v {
			t.Errorf("%s = %v, want the stamp value %v", k, probe.events[0].Attrs[k], v)
		}
	}
}

func TestWithStampLeavesMapsAlone(t *testing.T) {
	probe := &metricProbe{}
	fixed := map[string]any{"fp_scope": "boot"}
	s := WithStamp(probe, fixed)
	attrs := map[string]any{"fp_scope": "forged", "k": "v"}
	s.Emit(Event{Attrs: attrs})
	if !reflect.DeepEqual(attrs, map[string]any{"fp_scope": "forged", "k": "v"}) {
		t.Errorf("caller's map changed: %v", attrs)
	}
	// A later change to the caller's stamp map does not reach the wrapper.
	fixed["fp_scope"] = "configured"
	fixed["extra"] = true
	s.Emit(Event{})
	if got := probe.events[1].Attrs; !reflect.DeepEqual(got, map[string]any{"fp_scope": "boot"}) {
		t.Errorf("stamp followed the caller's map: %v", got)
	}
	// The event handed on is not the caller's map.
	probe.events[0].Attrs["k"] = "changed"
	if attrs["k"] != "v" {
		t.Error("sink and caller share a map")
	}
}

func TestWithStampEmpty(t *testing.T) {
	for _, fixed := range []map[string]any{nil, {}} {
		probe := &metricProbe{}
		s := WithStamp(probe, fixed)
		attrs := map[string]any{"k": "v"}
		s.Emit(Event{Attrs: attrs})
		s.Emit(Event{})
		if !reflect.DeepEqual(probe.events[0].Attrs, map[string]any{"k": "v"}) || probe.events[1].Attrs != nil {
			t.Errorf("empty stamp %v changed events: %+v", fixed, probe.events)
		}
	}
}

func TestSpoolStamp(t *testing.T) {
	l := newSpoolListener(t)
	forged := map[string]any{"fp_scope": "forged", "direction": "request"}
	s, err := NewSpool(SpoolConfig{Socket: l.path, Heartbeat: 10 * time.Millisecond, Stamp: testStamp})
	if err != nil {
		t.Fatal(err)
	}
	s.Emit(Event{Stream: StreamEdge, Attrs: forged})
	s.Emit(Event{Stream: StreamTranscript}) // nil Attrs
	s.Count("attackbox.requests", 1, map[string]string{"persona": "openai"})

	var events, beats, metrics int
	for i := 0; i < 200 && (events < 2 || beats < 1 || metrics < 1); i++ {
		r := l.next(t)
		if r.Metric != nil {
			metrics++
			if len(r.Metric.Attrs) != 1 || r.Metric.Attrs["persona"] != "openai" {
				t.Errorf("metric labels = %v", r.Metric.Attrs)
			}
			continue
		}
		events++
		if r.Event.Action == "bait_heartbeat" {
			beats++
			events-- // counted apart from the two events emitted above
		}
		for k, v := range testStamp {
			want := v
			if n, ok := v.(int); ok {
				want = float64(n) // JSON numbers decode as float64
			}
			if r.Event.Attrs[k] != want {
				t.Errorf("%s event: %s = %v, want %v", r.Event.Stream, k, r.Event.Attrs[k], want)
			}
		}
		if r.Event.Action == "bait_heartbeat" && r.Event.Attrs["queue_len"] == nil {
			t.Errorf("heartbeat lost its own attributes: %v", r.Event.Attrs)
		}
		if r.Event.Stream == StreamEdge && r.Event.Attrs["direction"] != "request" {
			t.Errorf("event attribute lost: %v", r.Event.Attrs)
		}
	}
	if events < 2 || beats < 1 || metrics < 1 {
		t.Fatalf("saw %d events, %d heartbeats, %d metrics", events, beats, metrics)
	}
	if forged["fp_scope"] != "forged" || len(forged) != 2 {
		t.Errorf("caller's map changed: %v", forged)
	}
	if err := closeSpool(t, s); err != nil {
		t.Fatal(err)
	}
}

func TestSpoolStampIsCopied(t *testing.T) {
	l := newSpoolListener(t)
	stamp := map[string]any{"fp_scope": "boot"}
	s, err := NewSpool(SpoolConfig{Socket: l.path, Heartbeat: -1, Stamp: stamp})
	if err != nil {
		t.Fatal(err)
	}
	stamp["fp_scope"] = "configured"
	s.Emit(Event{Stream: StreamEdge})
	if r := l.next(t); r.Event.Attrs["fp_scope"] != "boot" {
		t.Errorf("fp_scope = %v, the spool followed the caller's map", r.Event.Attrs["fp_scope"])
	}
	if err := closeSpool(t, s); err != nil {
		t.Fatal(err)
	}
}

var epochRe = regexp.MustCompile(`^[0-9a-f]{8}$`)

func TestRedactorTextCount(t *testing.T) {
	r := NewRedactor(bytes.Repeat([]byte{7}, MinRedactorKey))
	for _, in := range []string{
		"", "plain text", `{"password":"hunter2"}`, `{"password":"hunter2"} Bearer tok123`,
		"Cookie: a=1; theme=dark", "[redacted] [redacted:hmac256:0123456789abcdef]",
	} {
		text, n := r.TextCount(in)
		if text != r.Text(in) {
			t.Errorf("TextCount(%q) text %q, Text %q", in, text, r.Text(in))
		}
		if want := map[string]int{`{"password":"hunter2"}`: 1, `{"password":"hunter2"} Bearer tok123`: 2, "Cookie: a=1; theme=dark": 2}[in]; n != want {
			t.Errorf("TextCount(%q) count = %d, want %d", in, n, want)
		}
	}
}

func TestRedactorEpoch(t *testing.T) {
	k1 := bytes.Repeat([]byte{1}, MinRedactorKey)
	k2 := bytes.Repeat([]byte{2}, MinRedactorKey)
	a, b, c := NewRedactor(k1), NewRedactor(k1), NewRedactor(k2)
	if !epochRe.MatchString(a.Epoch()) {
		t.Fatalf("Epoch() = %q, want 8 hex characters", a.Epoch())
	}
	if a.Epoch() != b.Epoch() {
		t.Errorf("same key, epochs %q and %q", a.Epoch(), b.Epoch())
	}
	if a.Epoch() == c.Epoch() {
		t.Errorf("different keys, one epoch %q", a.Epoch())
	}
	m := hmac.New(sha256.New, k1)
	m.Write([]byte("attackbox/fp-epoch"))
	if want := hex.EncodeToString(m.Sum(nil))[:8]; a.Epoch() != want {
		t.Errorf("Epoch() = %q, want %q", a.Epoch(), want)
	}
}

func TestRedactorKeyReplaced(t *testing.T) {
	if NewRedactor(bytes.Repeat([]byte{1}, MinRedactorKey)).KeyReplaced() {
		t.Error("a 32-byte key was reported as replaced")
	}
	if NewRedactor(bytes.Repeat([]byte{1}, 64)).KeyReplaced() {
		t.Error("a 64-byte key was reported as replaced")
	}
	for _, key := range [][]byte{nil, []byte("short"), bytes.Repeat([]byte{1}, MinRedactorKey-1)} {
		r := NewRedactor(key)
		if !r.KeyReplaced() {
			t.Errorf("a %d-byte key was not reported as replaced", len(key))
		}
		if !epochRe.MatchString(r.Epoch()) {
			t.Errorf("replaced key: Epoch() = %q", r.Epoch())
		}
	}
	// Two replaced keys are random, so two epochs differ.
	if NewRedactor(nil).Epoch() == NewRedactor(nil).Epoch() {
		t.Error("two random keys gave one epoch")
	}
}
