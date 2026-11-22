package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
)

const testLicenseKey = "0123456789abcdef0123456789abcdef01234567"

// shortDir returns a directory under /tmp: socket paths are limited to about
// 100 bytes and t.TempDir can exceed that.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "abs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func testEnv(t *testing.T, extra map[string]string) func(string) string {
	t.Helper()
	dir := shortDir(t)
	env := map[string]string{
		"ATTACKBOX_SHIP_QUEUE_DIR":        filepath.Join(dir, "queue"),
		"ATTACKBOX_NR_LICENSE_KEY":        testLicenseKey,
		"ATTACKBOX_SPOOL_SOCKET":          filepath.Join(dir, "spool.sock"),
		"ATTACKBOX_RUNTIME_SOCKET":        filepath.Join(dir, "runtime.sock"),
		"ATTACKBOX_EGRESS_SOCKET":         filepath.Join(dir, "egress.sock"),
		"ATTACKBOX_SHIP_SHUTDOWN_TIMEOUT": "1s",
	}
	for k, v := range extra {
		env[k] = v
	}
	return func(k string) string { return env[k] }
}

// Every optional socket set: the burst of each must clear MaxLine, or
// NewIngest refuses the whole config at startup.
func TestLoadConfigAllSocketsBindsIngest(t *testing.T) {
	cfg, err := loadConfig(testEnv(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.endpoints) != 3 {
		t.Fatalf("got %d endpoints, want 3", len(cfg.endpoints))
	}
	q, _, err := shipper.OpenQueue(queueConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	ing, err := shipper.NewIngest(shipper.IngestConfig{Endpoints: cfg.endpoints, Queue: q})
	if err != nil {
		t.Fatalf("NewIngest: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ing.Serve(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestLoadConfigRejectsQueueBelowOneMaxFramePerRole(t *testing.T) {
	_, err := loadConfig(testEnv(t, map[string]string{"ATTACKBOX_SHIP_QUEUE_BYTES": "16777216"}))
	if err == nil || !strings.Contains(err.Error(), "ATTACKBOX_SHIP_QUEUE_BYTES") {
		t.Fatalf("got %v, want a queue size error", err)
	}
}

// The largest record the admission layer lets through must be appendable on
// every role at the smallest allowed queue, not dropped as oversize.
func TestMaxAdmittedRecordIsAppendable(t *testing.T) {
	cfg, err := loadConfig(testEnv(t, map[string]string{
		"ATTACKBOX_SHIP_QUEUE_BYTES": strconv.FormatInt(minQueueBytes, 10),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.queueBytes != minQueueBytes {
		t.Fatalf("test queue size %d is not minQueueBytes %d", cfg.queueBytes, int64(minQueueBytes))
	}
	q, _, err := shipper.OpenQueue(queueConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	// '<' encodes as <: six bytes per body byte, the worst case.
	body := strings.Repeat("<", shipper.MaxBody)
	lines := map[shipper.Role]string{
		shipper.RoleBait:    `{"stream":"edge","action":"x","body":"` + body + `"}`,
		shipper.RoleRuntime: `{"stream":"runtime","action":"falco","body":"` + body + `"}`,
		shipper.RoleEgress:  `{"stream":"egress","action":"egress_blocked","body":"` + body + `"}`,
	}
	for role, ev := range lines {
		line := []byte(`{"id":"0123456789abcdef-1","event":` + ev + `}`)
		a, err := shipper.Admit(role, line, time.Now())
		if err != nil {
			t.Fatalf("%s: Admit: %v", role, err)
		}
		if len(a.Data) <= telemetry.MinPayloadBytes {
			t.Fatalf("%s: record is %d bytes, not a large record", role, len(a.Data))
		}
		seqs, err := q.Append([]shipper.Item{{Role: a.Role, Data: a.Data}})
		if err != nil || seqs[0] == 0 {
			t.Fatalf("%s: Append of %d bytes: seq=%v err=%v (oversize=%d)", role, len(a.Data), seqs, err, q.Stats().Oversize[role])
		}
	}
}

// A graceful stop must return promptly with no error: both goroutines are
// started and both channels are read exactly once.
func TestRunGracefulShutdown(t *testing.T) {
	nr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }))
	defer nr.Close()
	cfg, err := loadConfig(testEnv(t, map[string]string{
		"ATTACKBOX_NR_LOG_URL":    nr.URL + "/log/v1",
		"ATTACKBOX_NR_METRIC_URL": nr.URL + "/metric/v1",
	}))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var stderr bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, &stderr) }()

	waitForSocket(t, cfg.endpoints[0].Path)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v on a graceful stop\nstderr: %s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after the context ended")
	}
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	waitFor(t, "socket "+path, func() bool {
		fi, err := os.Lstat(path)
		return err == nil && fi.Mode().Type() == os.ModeSocket
	})
}
