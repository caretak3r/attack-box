package shipper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"attackbox/internal/telemetry"
)

// Admission limits. A record that breaks a shape or count limit is rejected;
// an over-long string is cut on a rune boundary and the event is flagged, so
// evidence is kept. Every limit is far above what the bait itself produces.
const (
	MaxLine       = 2 << 20  // bytes per wire line without the newline
	MaxBody       = 1 << 20  // Event.Body bytes, the bait's ATTACKBOX_MAX_LOG_BODY cap
	MaxExpanded   = 16 << 20 // total expanded size across all chunks
	MaxItem       = 72 << 10 // one encoded chunk; above the largest MaxChunk chunk with full attrs, so only MaxExpanded caps big bodies
	maxDepth      = 6
	maxNodes      = 4096
	maxKeys       = 128
	maxArray      = 256
	maxKeyLen     = 128
	maxString     = 4096
	maxAttrBytes  = 128 << 10
	maxLabels     = 16
	maxLabelLen   = 64
	maxMetricKeys = 8
	maxPast       = 24 * time.Hour
	maxFuture     = 5 * time.Minute
)

// MaxData bounds Admitted.Data, the queue payload. JSON writes a body byte as
// up to six bytes (\u00XX), so MaxBody takes 6 MiB; attrs, fixed fields and
// structure stay far inside the remaining 2 MiB. The queue MaxPayload must be
// at least MaxData.
const MaxData = 8 << 20

var fieldCaps = struct{ id, ip, ua, token, resource, result int }{128, 64, 2048, 64, 1024, 64}

// RejectError is an admission failure. Reason is a bounded token, safe as a
// metric label.
type RejectError struct {
	Reason string
	err    error
}

func (e *RejectError) Error() string {
	if e.err != nil {
		return "shipper record: " + e.Reason + ": " + e.err.Error()
	}
	return "shipper record: " + e.Reason
}

func reject(reason string, err error) error { return &RejectError{Reason: reason, err: err} }

// RejectReason returns the reason token of an admission error, or "".
func RejectReason(err error) string {
	var re *RejectError
	if errors.As(err, &re) {
		return re.Reason
	}
	return ""
}

// Admitted is a validated record ready for the disk queue.
type Admitted struct {
	Role   Role
	Boot   string
	Seq    uint64
	Record telemetry.Record
	Data   []byte // canonical encoding of Record, the queue payload
}

// Key returns the shipper-namespaced record id: role, producer boot and seq.
// Every chunk of the record carries it, so dedup must also keep chunk_index.
func (a Admitted) Key() string { return recordKey(a.Role, a.Boot, a.Seq) }

func recordKey(r Role, boot string, seq uint64) string {
	return r.String() + "-" + boot + "-" + strconv.FormatUint(seq, 10)
}

var idRe = regexp.MustCompile(`^([0-9a-f]{16})-([1-9][0-9]{0,19})$`)

// Streams each role may send, with the allowed actions (nil allows any).
// The bait's own runtime records are its process lifecycle; Falco records
// carry source=runtime, which a bait connection can never claim. The
// shipper's own heartbeat is server-owned and never accepted from a socket.
var roleEvents = map[Role]map[string][]string{
	RoleBait: {
		telemetry.StreamEdge: nil, telemetry.StreamTranscript: nil, telemetry.StreamProbe: nil,
		telemetry.StreamHeartbeat: {"bait_heartbeat"},
		telemetry.StreamRuntime:   {"start", "stop", "stopped"},
	},
	RoleRuntime: {telemetry.StreamRuntime: {FalcoAction}, telemetry.StreamHeartbeat: {"runtime_heartbeat"}},
	RoleEgress:  {telemetry.StreamEgress: {EgressAction}, telemetry.StreamHeartbeat: {"egress_heartbeat"}},
}

// Actions of the host adapters' events.
const (
	FalcoAction  = "falco"
	EgressAction = "egress_blocked"
)

// Metric names and kinds each role may send: the implementation_plan metric
// table plus the egress counter. Anything else is rejected, so name churn
// cannot crowd out real series.
var roleMetrics = map[Role]map[string]string{
	RoleBait: {
		"attackbox.requests":                   "count",
		"attackbox.sessions":                   "count",
		"attackbox.request_bytes":              "count",
		"attackbox.response_bytes":             "count",
		"attackbox.probes":                     "count",
		"attackbox.probe_followups":            "count",
		"attackbox.session_duration_seconds":   "gauge",
		"attackbox.stream_disconnect_seconds":  "gauge",
		"attackbox.retry_delay_seconds":        "gauge",
		"attackbox.concurrent_status_requests": "gauge",
	},
	RoleEgress: {EgressBlockedMetric: "count"},
}

// EgressBlockedMetric is the plan's egress_blocked_total counter.
const EgressBlockedMetric = "attackbox.egress_blocked"

// reservedAttrs are removed from producer Attrs: the shipper sets these.
// Matching is case-insensitive.
var reservedAttrs = []string{
	"source", "record_id", "boot", "seq",
	"schema_version", "ingest_ts", "producer_ts", "sensor_id", "deployment_id", "shipper_boot",
	"timestamp_clamped", "attrs_truncated", "fields_truncated", "reserved_attrs_removed",
	"session_id", "request_id", "src_ip", "user_agent", "persona", "action",
	"resource", "result", "probe_id", "status", "task_labels",
	"stream", "body_sha256", "chunk_index", "chunk_count",
	"instance", "hostname", "timestamp", "message",
	"service.name", "entity.guid", "entity.name", "entity.type",
}

// baitOnlyAttrs are the bait's own provenance names. Every role but the bait
// loses them from Attrs. Matching is case-insensitive.
var baitOnlyAttrs = []string{
	"persona_version", "policy_version", "redaction_version", "fp_epoch", "fp_scope",
}

// Admit decodes and validates one wire line from a producer whose role the
// socket layer has verified, and returns the sanitized record. The shipper
// sets source, record_id, boot and seq from the verified role and the
// validated id; nothing the producer sends can claim them.
func Admit(role Role, line []byte, now time.Time) (Admitted, error) {
	if !role.valid() {
		return Admitted{}, reject("role", nil)
	}
	if len(line) > MaxLine {
		return Admitted{}, reject("oversize", nil)
	}
	if !utf8.Valid(line) {
		return Admitted{}, reject("utf8", nil)
	}
	var r telemetry.Record
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Admitted{}, reject("json", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Admitted{}, reject("json", errors.New("trailing data"))
	}
	if r.V != telemetry.SchemaVersion {
		return Admitted{}, reject("schema_version", nil)
	}
	m := idRe.FindStringSubmatch(r.ID)
	if m == nil {
		return Admitted{}, reject("id", nil)
	}
	seq, err := strconv.ParseUint(m[2], 10, 64)
	if err != nil {
		return Admitted{}, reject("id", err)
	}
	a := Admitted{Role: role, Boot: m[1], Seq: seq}
	switch {
	case (r.Event == nil) == (r.Metric == nil):
		return Admitted{}, reject("shape", nil)
	case r.Event != nil:
		e, err := admitEvent(role, *r.Event, a.Key(), a.Boot, seq, r.V, now)
		if err != nil {
			return Admitted{}, err
		}
		r.Event = &e
	default:
		mr, err := admitMetric(role, *r.Metric, now)
		if err != nil {
			return Admitted{}, err
		}
		r.Metric = &mr
	}
	a.Record = r
	if a.Data, err = json.Marshal(r); err != nil {
		return Admitted{}, reject("encode", err)
	}
	if len(a.Data) > MaxData {
		return Admitted{}, reject("encoded_size", nil)
	}
	return a, nil
}

func admitEvent(role Role, e telemetry.Event, key, boot string, seq uint64, version int, now time.Time) (telemetry.Event, error) {
	actions, ok := roleEvents[role][e.Stream]
	if !ok {
		return e, reject("stream", nil)
	}
	if actions != nil && !slices.Contains(actions, e.Action) {
		return e, reject("action", nil)
	}
	// Adapter actions on a stream the bait may use freely would pass for
	// host-observed events.
	if role == RoleBait && (strings.EqualFold(e.Action, FalcoAction) || strings.EqualFold(e.Action, EgressAction)) {
		return e, reject("action", nil)
	}
	// Chunk at the last hop is the only producer of chunk metadata.
	if e.BodySHA256 != "" || e.ChunkIndex != 0 || e.ChunkCount != 0 {
		return e, reject("chunk_fields", nil)
	}
	if len(e.Body) > MaxBody {
		return e, reject("body", nil)
	}
	if e.Status < 0 || e.Status > 999 {
		return e, reject("status", nil)
	}
	if e.SrcIP != "" {
		if addr, err := netip.ParseAddr(e.SrcIP); err != nil || addr.Zone() != "" || len(e.SrcIP) > fieldCaps.ip {
			return e, reject("src_ip", nil)
		}
	}
	if len(e.TaskLabels) > maxLabels {
		return e, reject("task_labels", nil)
	}

	cut := false
	clip := func(s *string, n int) {
		if len(*s) > n {
			*s = cutBytes(*s, n)
			cut = true
		}
	}
	clip(&e.SessionID, fieldCaps.id)
	clip(&e.RequestID, fieldCaps.id)
	clip(&e.UserAgent, fieldCaps.ua)
	clip(&e.Persona, fieldCaps.token)
	clip(&e.Action, fieldCaps.token)
	clip(&e.Resource, fieldCaps.resource)
	clip(&e.Result, fieldCaps.result)
	clip(&e.ProbeID, fieldCaps.token)
	if e.TaskLabels != nil {
		labels := make([]string, len(e.TaskLabels))
		for i, l := range e.TaskLabels {
			clip(&l, maxLabelLen)
			labels[i] = l
		}
		e.TaskLabels = labels
	}

	attrs, removed, attrsCut, err := sanitizeAttrs(role, e.Attrs)
	if err != nil {
		return e, err
	}
	switch {
	case e.Timestamp.IsZero(), e.Timestamp.Before(now.Add(-maxPast)), e.Timestamp.After(now.Add(maxFuture)):
		if !e.Timestamp.IsZero() {
			attrs["producer_ts"] = e.Timestamp.UnixMilli()
		}
		e.Timestamp = now
		attrs["timestamp_clamped"] = true
	}
	if removed {
		attrs["reserved_attrs_removed"] = true
	}
	if attrsCut {
		attrs["attrs_truncated"] = true
	}
	if cut {
		attrs["fields_truncated"] = true
	}
	attrs["source"] = role.String()
	attrs["record_id"] = key
	attrs["boot"] = boot
	attrs["seq"] = strconv.FormatUint(seq, 10)
	attrs["schema_version"] = version
	attrs["ingest_ts"] = now.UnixMilli()
	e.Attrs = attrs

	// Bound what this record becomes after the final-hop Chunk: every item
	// must fit the evidence envelope and the total has a hard ceiling.
	total := 0
	for _, c := range telemetry.Chunk(e, telemetry.MaxChunk) {
		data, err := json.Marshal(c)
		if err != nil {
			return e, reject("encode", err)
		}
		n := len(data)
		if n > MaxItem {
			return e, reject("item_size", nil)
		}
		if total += n; total > MaxExpanded {
			return e, reject("expanded_size", nil)
		}
	}
	return e, nil
}

// sanitizeAttrs copies attrs, removes reserved keys and cuts long strings.
// Structure beyond the depth, node, key, array or byte limits is rejected.
func sanitizeAttrs(role Role, in map[string]any) (out map[string]any, removed, cut bool, err error) {
	out = make(map[string]any, len(in)+8)
	if len(in) > maxKeys {
		return nil, false, false, reject("attrs_keys", nil)
	}
	w := walker{}
	for k, v := range in {
		if isReserved(k) || (role != RoleBait && isBaitOnly(k)) {
			removed = true
			continue
		}
		if err := w.key(k); err != nil {
			return nil, false, false, err
		}
		if out[k], err = w.value(v, 1); err != nil {
			return nil, false, false, err
		}
	}
	return out, removed, w.cut, nil
}

func isReserved(k string) bool { return matchFold(reservedAttrs, k) }

func isBaitOnly(k string) bool { return matchFold(baitOnlyAttrs, k) }

func matchFold(names []string, k string) bool {
	for _, r := range names {
		if strings.EqualFold(k, r) {
			return true
		}
	}
	return false
}

type walker struct {
	nodes, bytes int
	cut          bool
}

func (w *walker) key(k string) error {
	if k == "" || len(k) > maxKeyLen {
		return reject("attrs_key", nil)
	}
	w.bytes += len(k)
	if w.bytes > maxAttrBytes {
		return reject("attrs_bytes", nil)
	}
	return nil
}

func (w *walker) value(v any, depth int) (any, error) {
	if w.nodes++; w.nodes > maxNodes {
		return nil, reject("attrs_nodes", nil)
	}
	switch x := v.(type) {
	case nil, bool:
		return x, nil
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return nil, reject("attrs_number", nil)
		}
		return x, nil
	case string:
		if len(x) > maxString {
			x = cutBytes(x, maxString)
			w.cut = true
		}
		if w.bytes += len(x); w.bytes > maxAttrBytes {
			return nil, reject("attrs_bytes", nil)
		}
		return x, nil
	case []any:
		if depth >= maxDepth {
			return nil, reject("attrs_depth", nil)
		}
		if len(x) > maxArray {
			return nil, reject("attrs_array", nil)
		}
		out := make([]any, len(x))
		for i, e := range x {
			var err error
			if out[i], err = w.value(e, depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	case map[string]any:
		if depth >= maxDepth {
			return nil, reject("attrs_depth", nil)
		}
		if len(x) > maxKeys {
			return nil, reject("attrs_keys", nil)
		}
		out := make(map[string]any, len(x))
		for k, e := range x {
			if err := w.key(k); err != nil {
				return nil, err
			}
			var err error
			if out[k], err = w.value(e, depth+1); err != nil {
				return nil, err
			}
		}
		return out, nil
	default:
		return nil, reject("attrs_type", fmt.Errorf("%T", v))
	}
}

func admitMetric(role Role, m telemetry.MetricRecord, now time.Time) (telemetry.MetricRecord, error) {
	kind, ok := roleMetrics[role][m.Name]
	if !ok {
		return m, reject("metric_name", nil)
	}
	if m.Kind != kind {
		return m, reject("metric_kind", nil)
	}
	if math.IsNaN(m.Value) || math.IsInf(m.Value, 0) || (kind == "count" && m.Value < 0) {
		return m, reject("metric_value", nil)
	}
	if len(m.Attrs) > maxMetricKeys {
		return m, reject("metric_labels", nil)
	}
	if m.At.IsZero() || m.At.Before(now.Add(-maxPast)) || m.At.After(now.Add(maxFuture)) {
		m.At = now
	}
	m.Attrs = telemetry.SafeLabels(m.Attrs)
	if len(m.Attrs) == 0 {
		m.Attrs = nil
	}
	return m, nil
}

// cutBytes cuts s to at most n bytes on a rune boundary.
func cutBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
