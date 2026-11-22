package telemetry

import (
	"encoding/json"
	"io"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Sink receives log events and metrics. Implementations must not block the
// request path.
type Sink interface {
	Emit(Event)
	Count(name string, value float64, attrs map[string]string)
	Gauge(name string, value float64, attrs map[string]string)
}

// Multi fans out to every sink.
type Multi []Sink

func (m Multi) Emit(e Event) {
	for _, s := range m {
		s.Emit(e)
	}
}

func (m Multi) Count(name string, value float64, attrs map[string]string) {
	for _, s := range m {
		s.Count(name, value, attrs)
	}
}

func (m Multi) Gauge(name string, value float64, attrs map[string]string) {
	for _, s := range m {
		s.Gauge(name, value, attrs)
	}
}

var (
	tokenRe    = regexp.MustCompile(`^[a-z0-9_-]{1,48}$`)
	endpointRe = regexp.MustCompile(`^/[A-Za-z0-9/_{}.-]{0,64}$`)
)

const maxEndpointLen = 64

// SafeLabels keeps only bounded-cardinality metric labels. Unknown keys are
// dropped; values that break the label's shape become "other". Source IPs,
// session IDs, nonces and prompts never get through. The caller passes route
// templates (/v1/models/{id}), not raw paths.
func SafeLabels(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs))
	for k, v := range attrs {
		switch k {
		case "persona", "probe_id", "stream", "task", "result", "reason":
			out[k] = pick(tokenRe.MatchString(v), v)
		case "endpoint":
			out[k] = pick(validEndpoint(v), v)
		case "status_class":
			out[k] = pick(len(v) == 3 && v[0] >= '1' && v[0] <= '5' && v[1:] == "xx", v)
		}
	}
	return out
}

func pick(ok bool, v string) string {
	if ok {
		return v
	}
	return "other"
}

func validEndpoint(v string) bool {
	if len(v) > maxEndpointLen || !endpointRe.MatchString(v) {
		return false
	}
	for _, seg := range strings.Split(v, "/") {
		if seg != "" && strings.Trim(seg, "0123456789") == "" {
			return false
		}
	}
	return true
}

// JSONLog writes one JSON object per line. Events are chunked; metrics are
// written as stream "metric" lines.
type JSONLog struct {
	mu  sync.Mutex
	enc *json.Encoder
	now func() time.Time

	// OnError, if set, is called with write failures.
	OnError func(error)
}

func NewJSONLog(w io.Writer) *JSONLog {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &JSONLog{enc: enc, now: time.Now}
}

func (l *JSONLog) Emit(e Event) {
	if e.Timestamp.IsZero() {
		e.Timestamp = l.now()
	}
	for _, c := range Chunk(e, MaxChunk) {
		a := c.Attributes()
		a["timestamp"] = c.Timestamp.UTC().Format(time.RFC3339Nano)
		l.write(a)
	}
}

func (l *JSONLog) Count(name string, value float64, attrs map[string]string) {
	l.metric("count", name, value, attrs)
}

func (l *JSONLog) Gauge(name string, value float64, attrs map[string]string) {
	l.metric("gauge", name, value, attrs)
}

func (l *JSONLog) metric(kind, name string, value float64, attrs map[string]string) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return
	}
	l.write(map[string]any{
		"timestamp": l.now().UTC().Format(time.RFC3339Nano),
		"stream":    "metric",
		"name":      name,
		"type":      kind,
		"value":     value,
		"attrs":     SafeLabels(attrs),
	})
}

func (l *JSONLog) write(v map[string]any) {
	l.mu.Lock()
	err := l.enc.Encode(v)
	l.mu.Unlock()
	if err != nil && l.OnError != nil {
		l.OnError(err)
	}
}
