package shipper

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"attackbox/internal/telemetry"
)

var admitNow = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

const testBoot = "0123456789abcdef"

func line(t *testing.T, r telemetry.Record) []byte {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ev(e telemetry.Event) telemetry.Record {
	if e.Timestamp.IsZero() {
		e.Timestamp = admitNow.Add(-time.Second)
	}
	return telemetry.Record{ID: testBoot + "-7", Event: &e}
}

func met(name, kind string, v float64, attrs map[string]string) telemetry.Record {
	return telemetry.Record{ID: testBoot + "-8", Metric: &telemetry.MetricRecord{Name: name, Kind: kind, Value: v, At: admitNow, Attrs: attrs}}
}

func mustReject(t *testing.T, role Role, l []byte, reason string) {
	t.Helper()
	_, err := Admit(role, l, admitNow)
	if got := RejectReason(err); got != reason {
		t.Fatalf("reason = %q (%v), want %q", got, err, reason)
	}
}

func TestAdmitRoundTrip(t *testing.T) {
	body := strings.Repeat("héllo wörld 🦀 ", 800) // >10 KiB, multi-byte
	in := telemetry.Event{
		Stream: telemetry.StreamEdge, SessionID: "s1", RequestID: "r1", SrcIP: "203.0.113.9",
		UserAgent: "curl/8", Persona: "openai", Action: "request", Resource: "/v1/chat/completions",
		Result: "ok", Status: 200, ProbeID: "register-model", TaskLabels: []string{"code"},
		Attrs: map[string]any{"headers": map[string]any{"User-Agent": "curl/8"}, "latency_ms": 12.0, "streaming": true, "host": "decoy"},
		Body:  body,
	}
	a, err := Admit(RoleBait, line(t, ev(in)), admitNow)
	if err != nil {
		t.Fatal(err)
	}
	if a.Boot != testBoot || a.Seq != 7 || a.Key() != "bait-"+testBoot+"-7" {
		t.Fatalf("identity = %q %d %q", a.Boot, a.Seq, a.Key())
	}
	e := a.Record.Event
	if e.Body != body || !e.Timestamp.Equal(admitNow.Add(-time.Second)) || e.Attrs["host"] != "decoy" {
		t.Fatal("body, timestamp or attrs changed")
	}
	for k, want := range map[string]any{"source": "bait", "record_id": a.Key(), "boot": testBoot, "seq": "7"} {
		if e.Attrs[k] != want {
			t.Fatalf("%s = %v, want %v", k, e.Attrs[k], want)
		}
	}
	for _, k := range []string{"timestamp_clamped", "attrs_truncated", "fields_truncated", "reserved_attrs_removed"} {
		if _, ok := e.Attrs[k]; ok {
			t.Fatalf("unexpected flag %s", k)
		}
	}
	// The queue payload decodes back to the same record, and the final-hop
	// chunks carry the hash of the original body however often they are
	// re-chunked.
	var back telemetry.Record
	if err := json.Unmarshal(a.Data, &back); err != nil || back.Event.Body != body || back.Event.Attrs["record_id"] != a.Key() {
		t.Fatalf("payload round trip: %v", err)
	}
	sum := sha256.Sum256([]byte(body))
	chunks := telemetry.Chunk(*back.Event, telemetry.MaxChunk)
	var joined strings.Builder
	for i, c := range chunks {
		if c.BodySHA256 != hex.EncodeToString(sum[:]) || c.ChunkIndex != i || c.ChunkCount != len(chunks) || c.Attrs["record_id"] != a.Key() {
			t.Fatalf("chunk %d metadata", i)
		}
		joined.WriteString(c.Body)
	}
	if joined.String() != body || len(chunks) < 2 {
		t.Fatalf("reassembly: %d chunks", len(chunks))
	}
}

func TestAdmitRoleMatrix(t *testing.T) {
	cases := []struct {
		role          Role
		stream, act   string
		ok            bool
		wantRejection string
	}{
		{RoleBait, telemetry.StreamEdge, "request", true, ""},
		{RoleBait, telemetry.StreamTranscript, "x", true, ""},
		{RoleBait, telemetry.StreamProbe, "decision", true, ""},
		{RoleBait, telemetry.StreamHeartbeat, "bait_heartbeat", true, ""},
		{RoleBait, telemetry.StreamHeartbeat, "heartbeat", false, "action"},
		{RoleBait, telemetry.StreamRuntime, "start", true, ""},
		{RoleBait, telemetry.StreamRuntime, "stopped", true, ""},
		{RoleBait, telemetry.StreamRuntime, "falco", false, "action"},
		{RoleBait, telemetry.StreamEgress, "egress_blocked", false, "stream"},
		{RoleBait, "bogus", "", false, "stream"},
		{RoleRuntime, telemetry.StreamRuntime, "falco", true, ""},
		{RoleRuntime, telemetry.StreamRuntime, "start", false, "action"},
		{RoleRuntime, telemetry.StreamEdge, "request", false, "stream"},
		{RoleRuntime, telemetry.StreamHeartbeat, "bait_heartbeat", false, "stream"},
		{RoleEgress, telemetry.StreamEgress, "egress_blocked", true, ""},
		{RoleEgress, telemetry.StreamRuntime, "falco", false, "stream"},
		{RoleEgress, telemetry.StreamProbe, "decision", false, "stream"},
	}
	for _, c := range cases {
		l := line(t, ev(telemetry.Event{Stream: c.stream, Action: c.act}))
		a, err := Admit(c.role, l, admitNow)
		if c.ok {
			if err != nil || a.Record.Event.Attrs["source"] != c.role.String() {
				t.Fatalf("%s %s/%s: %v", c.role, c.stream, c.act, err)
			}
			continue
		}
		if RejectReason(err) != c.wantRejection {
			t.Fatalf("%s %s/%s: %v, want %s", c.role, c.stream, c.act, err, c.wantRejection)
		}
	}
	mustReject(t, Role(0), line(t, ev(telemetry.Event{Stream: "edge"})), "role")
	mustReject(t, Role(9), line(t, ev(telemetry.Event{Stream: "edge"})), "role")
}

func TestAdmitMetrics(t *testing.T) {
	a, err := Admit(RoleBait, line(t, met("attackbox.requests", "count", 3, map[string]string{
		"persona": "openai", "endpoint": "/v1/models", "src_ip": "203.0.113.9", "session_id": "s",
	})), admitNow)
	if err != nil {
		t.Fatal(err)
	}
	if m := a.Record.Metric; m.Value != 3 || len(m.Attrs) != 2 || m.Attrs["persona"] != "openai" || m.Attrs["endpoint"] != "/v1/models" {
		t.Fatalf("metric = %+v", m)
	}
	if _, err := Admit(RoleBait, line(t, met("attackbox.session_duration_seconds", "gauge", -0.5, nil)), admitNow); err != nil {
		t.Fatalf("negative gauge: %v", err)
	}
	if _, err := Admit(RoleEgress, line(t, met(EgressBlockedMetric, "count", 1, nil)), admitNow); err != nil {
		t.Fatalf("egress counter: %v", err)
	}
	old := met("attackbox.sessions", "count", 1, nil)
	old.Metric.At = admitNow.Add(-48 * time.Hour)
	if a, err := Admit(RoleBait, line(t, old), admitNow); err != nil || !a.Record.Metric.At.Equal(admitNow) {
		t.Fatalf("clamp: %v", err)
	}

	mustReject(t, RoleBait, line(t, met("attackbox.junk", "count", 1, nil)), "metric_name")
	mustReject(t, RoleBait, line(t, met("attackbox.heartbeat", "gauge", 1, nil)), "metric_name")
	mustReject(t, RoleBait, line(t, met(EgressBlockedMetric, "count", 1, nil)), "metric_name")
	mustReject(t, RoleRuntime, line(t, met("attackbox.requests", "count", 1, nil)), "metric_name")
	mustReject(t, RoleEgress, line(t, met("attackbox.requests", "count", 1, nil)), "metric_name")
	mustReject(t, RoleBait, line(t, met("attackbox.requests", "gauge", 1, nil)), "metric_kind")
	mustReject(t, RoleBait, line(t, met("attackbox.requests", "summary", 1, nil)), "metric_kind")
	mustReject(t, RoleBait, line(t, met("attackbox.requests", "count", -1, nil)), "metric_value")
	many := map[string]string{}
	for i := range 9 {
		many[strings.Repeat("k", i+1)] = "v"
	}
	mustReject(t, RoleBait, line(t, met("attackbox.requests", "count", 1, many)), "metric_labels")
}

func TestAdmitForgedIdentity(t *testing.T) {
	in := ev(telemetry.Event{Stream: telemetry.StreamEdge, Attrs: map[string]any{
		"source": "runtime", "record_id": "x", "boot": "b", "seq": "1", "instance": "other",
		"Service.Name": "x", "entity.guid": "g", "hostname": "h", "newrelic.source": "s",
		"timestamp": 1.0, "message": "m", "attrs_truncated": false, "kept": "yes",
	}})
	a, err := Admit(RoleBait, line(t, in), admitNow)
	if err != nil {
		t.Fatal(err)
	}
	got := a.Record.Event.Attrs
	want := map[string]any{"kept": "yes", "source": "bait", "record_id": a.Key(), "boot": testBoot, "seq": "7", "reserved_attrs_removed": true}
	if len(got) != len(want) {
		t.Fatalf("attrs = %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestAdmitHostileShapes(t *testing.T) {
	good := line(t, ev(telemetry.Event{Stream: "edge"}))
	if _, err := Admit(RoleBait, good, admitNow); err != nil {
		t.Fatal(err)
	}
	mustReject(t, RoleBait, []byte{'{', 0xff, '}'}, "utf8")
	mustReject(t, RoleBait, append(append([]byte{}, good...), []byte(` {}`)...), "json")
	mustReject(t, RoleBait, []byte(`{"id":"`+testBoot+`-1","event":{"stream":"edge"},"extra":1}`), "json")
	mustReject(t, RoleBait, []byte(`{"id":"`+testBoot+`-1","event":{"stream":"edge","bogus":1}}`), "json")
	mustReject(t, RoleBait, []byte(`not json`), "json")
	mustReject(t, RoleBait, []byte(strings.Repeat(" ", MaxLine+1)), "oversize")
	mustReject(t, RoleBait, []byte(`{"id":"`+testBoot+`-1"}`), "shape")
	both := ev(telemetry.Event{Stream: "edge"})
	both.Metric = &telemetry.MetricRecord{Name: "attackbox.requests", Kind: "count"}
	mustReject(t, RoleBait, line(t, both), "shape")

	for _, id := range []string{"", "0123456789ABCDEF-1", testBoot + "-0", testBoot + "-01", testBoot + "-", "abc-1",
		testBoot + "-123456789012345678901", testBoot + "-99999999999999999999", testBoot + "-1 "} {
		r := ev(telemetry.Event{Stream: "edge"})
		r.ID = id
		mustReject(t, RoleBait, line(t, r), "id")
	}
	r := ev(telemetry.Event{Stream: "edge"})
	r.ID = testBoot + "-18446744073709551615"
	if a, err := Admit(RoleBait, line(t, r), admitNow); err != nil || a.Seq != 1<<64-1 {
		t.Fatalf("max seq: %v", err)
	}

	for name, e := range map[string]telemetry.Event{
		"chunk_fields": {Stream: "edge", BodySHA256: "ab"},
		"status":       {Stream: "edge", Status: 1000},
		"src_ip":       {Stream: "edge", SrcIP: "not-an-ip"},
		"task_labels":  {Stream: "edge", TaskLabels: make([]string, maxLabels+1)},
		"body":         {Stream: "edge", Body: strings.Repeat("a", MaxBody+1)},
	} {
		mustReject(t, RoleBait, line(t, ev(e)), name)
	}
	mustReject(t, RoleBait, line(t, ev(telemetry.Event{Stream: "edge", ChunkIndex: 1})), "chunk_fields")
	mustReject(t, RoleBait, line(t, ev(telemetry.Event{Stream: "edge", ChunkCount: 1})), "chunk_fields")
}

func TestAdmitAttrLimits(t *testing.T) {
	nest := func(depth int) any {
		var v any = "leaf"
		for range depth {
			v = map[string]any{"n": v}
		}
		return v
	}
	ok := map[string]any{"d": nest(maxDepth - 1), "a": make([]any, maxArray)}
	if _, err := Admit(RoleBait, line(t, ev(telemetry.Event{Stream: "edge", Attrs: ok})), admitNow); err != nil {
		t.Fatalf("at limits: %v", err)
	}
	wide := map[string]any{}
	for i := range maxKeys + 1 {
		wide[strings.Repeat("x", 1+i%100)+string(rune('a'+i/100))] = 1.0
	}
	nodes := make([]any, 0, maxArray)
	for range maxArray {
		nodes = append(nodes, make([]any, 20))
	}
	bigStrings := map[string]any{}
	for i := range 40 {
		bigStrings[strings.Repeat("s", i+1)] = strings.Repeat("v", maxString)
	}
	for reason, attrs := range map[string]map[string]any{
		"attrs_depth": {"d": nest(maxDepth)},
		"attrs_array": {"a": make([]any, maxArray+1)},
		"attrs_keys":  wide,
		"attrs_key":   {strings.Repeat("k", maxKeyLen+1): 1.0},
		"attrs_nodes": {"n": nodes},
		"attrs_bytes": bigStrings,
	} {
		mustReject(t, RoleBait, line(t, ev(telemetry.Event{Stream: "edge", Attrs: attrs})), reason)
	}
	mustReject(t, RoleBait, line(t, ev(telemetry.Event{Stream: "edge", Attrs: map[string]any{"in": map[string]any{"": 1.0}}})), "attrs_key")
	mustReject(t, RoleBait, line(t, ev(telemetry.Event{Stream: "edge", Attrs: map[string]any{"a": []any{[]any{[]any{[]any{[]any{[]any{1.0}}}}}}}})), "attrs_depth")
	// Runtime adapters nest the source object under "event"; the same limits apply.
	mustReject(t, RoleRuntime, line(t, ev(telemetry.Event{Stream: "runtime", Action: "falco", Attrs: map[string]any{"event": nest(maxDepth)}})), "attrs_depth")
}

func TestAdmitTruncatesAndClamps(t *testing.T) {
	long := "a" + strings.Repeat("é", maxString) // byte maxString is mid-rune
	in := ev(telemetry.Event{
		Stream: "edge", UserAgent: strings.Repeat("u", 3000) + "€", Resource: strings.Repeat("r", 2000),
		TaskLabels: []string{strings.Repeat("t", 100)},
		Attrs:      map[string]any{"long": long, "nested": []any{long}},
	})
	in.Event.Timestamp = admitNow.Add(time.Hour)
	a, err := Admit(RoleBait, line(t, in), admitNow)
	if err != nil {
		t.Fatal(err)
	}
	e := a.Record.Event
	if len(e.UserAgent) != fieldCaps.ua || len(e.Resource) != fieldCaps.resource || len(e.TaskLabels[0]) != maxLabelLen {
		t.Fatalf("field caps: %d %d %d", len(e.UserAgent), len(e.Resource), len(e.TaskLabels[0]))
	}
	if s := e.Attrs["long"].(string); len(s) != maxString-1 || !strings.HasSuffix(s, "é") {
		t.Fatalf("attr cut not on a rune boundary: %d", len(s))
	}
	if s := e.Attrs["nested"].([]any)[0].(string); len(s) != maxString-1 {
		t.Fatal("nested attr not cut")
	}
	if !e.Timestamp.Equal(admitNow) || e.Attrs["timestamp_clamped"] != true || e.Attrs["attrs_truncated"] != true || e.Attrs["fields_truncated"] != true {
		t.Fatalf("flags: %v", e.Attrs)
	}
	for _, ts := range []time.Time{{}, admitNow.Add(-25 * time.Hour)} {
		r := ev(telemetry.Event{Stream: "edge"})
		r.Event.Timestamp = ts
		b := line(t, r)
		if ts.IsZero() {
			b = []byte(strings.Replace(string(b), `"timestamp":"`+admitNow.Add(-time.Second).Format(time.RFC3339Nano)+`"`, `"timestamp":"0001-01-01T00:00:00Z"`, 1))
		}
		a, err := Admit(RoleBait, b, admitNow)
		if err != nil || !a.Record.Event.Timestamp.Equal(admitNow) || a.Record.Event.Attrs["timestamp_clamped"] != true {
			t.Fatalf("clamp %v: %v", ts, err)
		}
	}
}

func TestAdmitExpandedBound(t *testing.T) {
	// A maximal body with ordinary attrs is admitted: this is the bait's
	// largest legitimate edge event.
	body := strings.Repeat("a", MaxBody)
	if _, err := Admit(RoleBait, line(t, ev(telemetry.Event{Stream: "edge", Body: body, Attrs: map[string]any{"h": strings.Repeat("v", 512)}})), admitNow); err != nil {
		t.Fatalf("max body: %v", err)
	}
	// Attrs repeat in every chunk: ~56 KiB of attrs times ~300 chunks is
	// past the expanded ceiling though each part is within its own cap and
	// each chunk fits MaxItem.
	attrs := map[string]any{"pad": strings.Repeat("v", maxString), "pad2": strings.Repeat("v", 500)}
	for i := range 12 {
		attrs[strings.Repeat("a", i+1)] = strings.Repeat("v", maxString)
	}
	small := ev(telemetry.Event{Stream: "edge", Body: "x", Attrs: attrs})
	if _, err := Admit(RoleBait, line(t, small), admitNow); err != nil {
		t.Fatalf("wide attrs, small body: %v", err)
	}
	mustReject(t, RoleBait, line(t, ev(telemetry.Event{Stream: "edge", Body: body, Attrs: attrs})), "expanded_size")
}

func TestAdmitItemBound(t *testing.T) {
	// HTML-escaped characters grow six-fold in the New Relic item, so raw
	// attr bytes within their cap can still make one chunk too large.
	attrs := map[string]any{}
	for i := range 30 {
		attrs[strings.Repeat("a", i+1)] = strings.Repeat("<", maxString)
	}
	mustReject(t, RoleBait, line(t, ev(telemetry.Event{Stream: "edge", Body: "x", Attrs: attrs})), "item_size")
}

func TestAdmitStripsFixedFieldNames(t *testing.T) {
	// Event.Attributes only overwrites a fixed field when it is non-empty,
	// so every name it owns must be stripped from producer attrs.
	names := []string{
		"session_id", "request_id", "src_ip", "user_agent", "persona", "action",
		"resource", "result", "probe_id", "status", "task_labels",
		"stream", "body_sha256", "chunk_index", "chunk_count", "SRC_IP",
	}
	for _, name := range names {
		in := ev(telemetry.Event{Stream: telemetry.StreamEdge, Attrs: map[string]any{name: "1.2.3.4", "kept": "yes"}})
		a, err := Admit(RoleBait, line(t, in), admitNow)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		e := a.Record.Event
		if _, ok := e.Attrs[name]; ok || e.Attrs["kept"] != "yes" || e.Attrs["reserved_attrs_removed"] != true {
			t.Errorf("%s: attrs = %v", name, e.Attrs)
		}
		if _, ok := e.Attributes()["src_ip"]; ok {
			t.Errorf("%s: src_ip reaches the shipped attributes with an empty SrcIP", name)
		}
	}
}

func TestAdmitSrcIPZone(t *testing.T) {
	mustReject(t, RoleBait, line(t, ev(telemetry.Event{Stream: "edge", SrcIP: "fe80::1%eth0"})), "src_ip")
	for _, ip := range []string{"fe80::1", "203.0.113.9", "2001:db8::1"} {
		if _, err := Admit(RoleBait, line(t, ev(telemetry.Event{Stream: "edge", SrcIP: ip})), admitNow); err != nil {
			t.Fatalf("%s: %v", ip, err)
		}
	}
}

func TestAdmitBaitCannotForgeAdapterActions(t *testing.T) {
	for _, stream := range []string{
		telemetry.StreamEdge, telemetry.StreamTranscript, telemetry.StreamProbe,
		telemetry.StreamHeartbeat, telemetry.StreamRuntime,
	} {
		for _, act := range []string{FalcoAction, EgressAction, "FALCO", "Egress_Blocked"} {
			mustReject(t, RoleBait, line(t, ev(telemetry.Event{Stream: stream, Action: act})), "action")
		}
	}
}

func TestMaxItemFitsMinimumPayload(t *testing.T) {
	// The smallest POST the telemetry client sends must hold an admitted
	// item plus its envelope.
	if MaxItem+itemHeadroom > telemetry.MinPayloadBytes {
		t.Fatalf("MaxItem %d + headroom %d exceeds min payload %d", MaxItem, itemHeadroom, telemetry.MinPayloadBytes)
	}
	// 20 x 4096 bytes of attrs is ~82 KiB: inside every attr cap and the old
	// 256 KiB item bound, but too big for a 64 KiB POST.
	attrs := map[string]any{}
	for i := range 20 {
		attrs[strings.Repeat("a", i+1)] = strings.Repeat("v", maxString)
	}
	mustReject(t, RoleBait, line(t, ev(telemetry.Event{Stream: "edge", Body: "x", Attrs: attrs})), "item_size")
	// Just under the bound is admitted, and the item really fits.
	attrs = map[string]any{}
	for i := range 12 {
		attrs[strings.Repeat("a", i+1)] = strings.Repeat("v", maxString)
	}
	a, err := Admit(RoleBait, line(t, ev(telemetry.Event{Stream: "edge", Body: "x", Attrs: attrs})), admitNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range telemetry.Chunk(*a.Record.Event, telemetry.MaxChunk) {
		if n, _ := telemetry.LogItemSize(c); n > MaxItem {
			t.Fatalf("item %d > MaxItem %d", n, MaxItem)
		}
	}
}
