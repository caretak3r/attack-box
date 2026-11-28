package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
)

type producedRecord struct {
	role shipper.Role
	rec  telemetry.Record
}

// shipToEvidence admits each record for its role, queues it, drains the real
// queue into a real evidence log and returns the envelopes on disk in order.
func shipToEvidence(t *testing.T, produced []producedRecord) []telemetry.Envelope {
	t.Helper()
	dir := t.TempDir()
	q, _, err := shipper.OpenQueue(shipper.QueueConfig{
		Dir:          filepath.Join(dir, "queue"),
		SegmentBytes: 16 << 20,
		MaxBytes:     96 << 20,
		RoleBytes:    map[shipper.Role]int64{shipper.RoleBait: 32 << 20, shipper.RoleRuntime: 32 << 20, shipper.RoleEgress: 32 << 20},
		MaxPayload:   shipper.MaxData,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	evidenceDir := filepath.Join(dir, "evidence")
	if err := os.Mkdir(evidenceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	evidence, err := telemetry.NewEvidenceLog(telemetry.EvidenceConfig{Dir: evidenceDir, OnError: func(err error) { t.Error(err) }})
	if err != nil {
		t.Fatal(err)
	}
	defer evidence.Close()

	now := time.Now()
	for i, p := range produced {
		p.rec.V = telemetry.SchemaVersion
		p.rec.ID = fmt.Sprintf("0123456789abcdef-%d", i+1)
		line, err := json.Marshal(p.rec)
		if err != nil {
			t.Fatal(err)
		}
		admitted, err := shipper.Admit(p.role, line, now)
		if err != nil {
			t.Fatalf("admit record %d for %s: %v", i+1, p.role, err)
		}
		if _, err := q.Append([]shipper.Item{{Role: p.role, Data: admitted.Data}}); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- drain(ctx, q, evidence, false, 0) }()
	var envelopes []telemetry.Envelope
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if envelopes = readEnvelopes(t, evidenceDir); len(envelopes) >= len(produced) {
			break
		}
	}
	cancel()
	if err := <-done; err != nil && err != context.Canceled {
		t.Fatalf("drain: %v", err)
	}
	if len(envelopes) != len(produced) {
		t.Fatalf("evidence has %d envelopes, want %d", len(envelopes), len(produced))
	}
	if st := q.Stats(); st.Inflight != 0 || st.Total != 0 {
		t.Fatalf("queue after drain: inflight %d, unacknowledged %d bytes; want everything checkpointed", st.Inflight, st.Total)
	}
	return envelopes
}

func readEnvelopes(t *testing.T, dir string) []telemetry.Envelope {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "events-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var out []telemetry.Envelope
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		for dec := json.NewDecoder(f); dec.More(); {
			var env telemetry.Envelope
			if err := dec.Decode(&env); err != nil {
				f.Close()
				t.Fatalf("%s: %v", path, err)
			}
			out = append(out, env)
		}
		f.Close()
	}
	return out
}

func TestShipperIntegration(t *testing.T) {
	now := time.Now()
	envelopes := shipToEvidence(t, []producedRecord{
		{shipper.RoleBait, telemetry.Record{Event: &telemetry.Event{Stream: telemetry.StreamEdge, Action: "request", Timestamp: now}}},
		{shipper.RoleBait, telemetry.Record{Metric: &telemetry.MetricRecord{Name: "attackbox.requests", Kind: "count", Value: 1, At: now}}},
	})
	for i, env := range envelopes {
		if env.Role != "bait" || env.Seq == 0 || env.Ts == "" {
			t.Errorf("envelope %d = role %q seq %d ts %q; want the bait role, a queue sequence and a time", i, env.Role, env.Seq, env.Ts)
		}
	}
	if envelopes[0].Record.Event == nil || envelopes[1].Record.Metric == nil {
		t.Fatalf("records = %+v, want the event then the metric", envelopes)
	}
}

func TestSixStreams(t *testing.T) {
	now := time.Now()
	cases := []struct {
		role   shipper.Role
		stream string
		action string
	}{
		{shipper.RoleBait, telemetry.StreamEdge, "request"},
		{shipper.RoleBait, telemetry.StreamTranscript, "transcript"},
		{shipper.RoleBait, telemetry.StreamProbe, "probe_start"},
		{shipper.RoleEgress, telemetry.StreamEgress, shipper.EgressAction},
		{shipper.RoleRuntime, telemetry.StreamRuntime, shipper.FalcoAction},
		{shipper.RoleBait, telemetry.StreamHeartbeat, "bait_heartbeat"},
	}
	var produced []producedRecord
	for _, c := range cases {
		produced = append(produced, producedRecord{c.role, telemetry.Record{Event: &telemetry.Event{Stream: c.stream, Action: c.action, Timestamp: now}}})
	}
	envelopes := shipToEvidence(t, produced)
	for i, c := range cases {
		env := envelopes[i]
		// The console and reports classify evidence by the verified producer role.
		if env.Role != c.role.String() || env.Record.Event == nil || env.Record.Event.Stream != c.stream || env.Record.Event.Action != c.action {
			t.Errorf("envelope %d = role %q record %+v; want role %q stream %q action %q", i, env.Role, env.Record.Event, c.role, c.stream, c.action)
		}
	}
}

func TestFullMetric(t *testing.T) {
	now := time.Now()
	metrics := []struct {
		role shipper.Role
		name string
		kind string
	}{
		{shipper.RoleBait, "attackbox.requests", "count"},
		{shipper.RoleBait, "attackbox.sessions", "count"},
		{shipper.RoleBait, "attackbox.request_bytes", "count"},
		{shipper.RoleBait, "attackbox.response_bytes", "count"},
		{shipper.RoleBait, "attackbox.probes", "count"},
		{shipper.RoleBait, "attackbox.probe_followups", "count"},
		{shipper.RoleBait, "attackbox.session_duration_seconds", "gauge"},
		{shipper.RoleBait, "attackbox.stream_disconnect_seconds", "gauge"},
		{shipper.RoleBait, "attackbox.retry_delay_seconds", "gauge"},
		{shipper.RoleBait, "attackbox.concurrent_status_requests", "gauge"},
		{shipper.RoleEgress, shipper.EgressBlockedMetric, "count"},
	}
	var produced []producedRecord
	for i, m := range metrics {
		produced = append(produced, producedRecord{m.role, telemetry.Record{Metric: &telemetry.MetricRecord{Name: m.name, Kind: m.kind, Value: float64(i + 1), At: now}}})
	}
	envelopes := shipToEvidence(t, produced)
	for i, m := range metrics {
		got := envelopes[i].Record.Metric
		if envelopes[i].Role != m.role.String() || got == nil || got.Name != m.name || got.Kind != m.kind || got.Value != float64(i+1) {
			t.Errorf("envelope %d = role %q metric %+v; want role %q %s %s %d", i, envelopes[i].Role, got, m.role, m.name, m.kind, i+1)
		}
	}
}
