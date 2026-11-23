package telemetry

import "maps"

// stamped adds a fixed attribute map to every event that passes through. It
// leaves metrics alone: their labels are a closed set (SafeLabels).
type stamped struct {
	Sink
	fixed map[string]any
}

// WithStamp wraps next so that every event carries the attributes in fixed.
// A fixed attribute wins over an event attribute of the same name. The caller's
// maps are never written: fixed is copied here and each event gets a new map.
// An empty fixed returns next unchanged.
func WithStamp(next Sink, fixed map[string]any) Sink {
	if len(fixed) == 0 {
		return next
	}
	return &stamped{Sink: next, fixed: maps.Clone(fixed)}
}

func (s *stamped) Emit(e Event) {
	e.Attrs = mergeStamp(e.Attrs, s.fixed)
	s.Sink.Emit(e)
}

// mergeStamp returns attrs with fixed laid over it, in a new map.
func mergeStamp(attrs, fixed map[string]any) map[string]any {
	if len(fixed) == 0 {
		return attrs
	}
	out := make(map[string]any, len(attrs)+len(fixed))
	maps.Copy(out, attrs)
	maps.Copy(out, fixed)
	return out
}
