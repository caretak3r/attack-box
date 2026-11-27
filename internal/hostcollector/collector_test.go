package hostcollector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(now time.Time) Snapshot {
	s := Snapshot{Version: 1, Time: now}
	for _, name := range units {
		s.Units = append(s.Units, Unit{Name: name, Known: true, Load: "loaded", Active: "active", Sub: "running"})
	}
	for _, name := range containers {
		s.Containers = append(s.Containers, Container{Name: name, Known: true, Running: true, Health: "healthy", Runtime: "runsc", Memory: 512 << 20, NanoCPUs: 1e9})
	}
	return s
}
func output(c *Collector) string {
	r := httptest.NewRecorder()
	c.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return r.Body.String()
}
func requireMetric(t *testing.T, body, line string) {
	t.Helper()
	if !strings.Contains(body, line+"\n") {
		t.Fatalf("missing %s in %s", line, body)
	}
}
func TestAbsentSnapshotNeverHealthy(t *testing.T) {
	c := New()
	b := output(c)
	for _, name := range append(append([]string{}, units...), containers...) {
		requireMetric(t, b, `attackbox_component_observed{component="`+name+`"} 0`)
		requireMetric(t, b, `attackbox_component_running{component="`+name+`"} -1`)
		requireMetric(t, b, `attackbox_component_ready{component="`+name+`"} -1`)
	}
}
func TestStaleSnapshotDoesNotCarryHealthyState(t *testing.T) {
	c := New()
	c.valid = true
	c.snapshot = fixture(time.Now().Add(-MaxAge - time.Second))
	b := output(c)
	requireMetric(t, b, "attackbox_inventory_snapshot_valid 0")
	requireMetric(t, b, `attackbox_component_running{component="docker.service"} -1`)
	requireMetric(t, b, `attackbox_container_health{component="attackbox-bait"} -1`)
}
func TestActiveIsNotReadiness(t *testing.T) {
	c := New()
	c.valid = true
	c.snapshot = fixture(time.Now())
	b := output(c)
	requireMetric(t, b, `attackbox_component_running{component="auditd.service"} 1`)
	requireMetric(t, b, `attackbox_component_ready{component="auditd.service"} -1`)
	requireMetric(t, b, `attackbox_component_coverage_verified{component="auditd.service"} -1`)
}
func TestMissingUnitAndCommandFailures(t *testing.T) {
	s := collect(context.Background(), func(_ context.Context, cmd string, args ...string) ([]byte, error) {
		if cmd == "/usr/bin/docker" {
			return nil, errors.New("absent")
		}
		return []byte("Id=auditd.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\n"), errors.New("absent")
	})
	c := New()
	c.valid = true
	c.snapshot = s
	b := output(c)
	requireMetric(t, b, `attackbox_component_running{component="auditd.service"} 0`)
	requireMetric(t, b, `attackbox_component_observed{component="auditd.service"} 1`)
	requireMetric(t, b, `attackbox_component_running{component="docker.service"} -1`)
	requireMetric(t, b, `attackbox_container_restarts{component="attackbox-bait"} -1`)
}
func TestSnapshotTrust(t *testing.T) {
	now := time.Now()
	uid := uint32(os.Getuid())
	for _, tc := range []string{"valid", "stale", "future", "bad-owner", "writable-file", "writable-dir", "symlink", "oversized", "malicious-name", "unknown-field", "trailing", "missing-component", "not-json", "directory"} {
		t.Run(tc, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "inventory.json")
			s := fixture(now)
			if tc == "stale" {
				s.Time = now.Add(-MaxAge - time.Second)
			}
			if tc == "future" {
				s.Time = now.Add(time.Minute)
			}
			if tc == "malicious-name" {
				s.Units[0].Name = "evil\"} 1\n"
			}
			if tc == "missing-component" {
				s.Units = s.Units[:1]
			}
			b, _ := json.Marshal(s)
			if tc == "oversized" {
				b = []byte(strings.Repeat(" ", MaxSnapshotBytes+1))
			}
			if tc == "unknown-field" {
				b = append([]byte(`{"unknown":true,`), b[1:]...)
			}
			if tc == "trailing" {
				b = append(b, []byte(" {}")...)
			}
			if tc == "not-json" {
				b = []byte("bad")
			}
			if err := os.WriteFile(path, b, 0644); err != nil {
				t.Fatal(err)
			}
			owner := uid
			if tc == "bad-owner" {
				owner++
			}
			if tc == "writable-file" {
				os.Chmod(path, 0666)
			}
			if tc == "writable-dir" {
				os.Chmod(dir, 0777)
			}
			if tc == "symlink" {
				target := path + ".target"
				os.Rename(path, target)
				os.Symlink(target, path)
			}
			if tc == "directory" {
				os.Remove(path)
				os.Mkdir(path, 0755)
			}
			_, err := readSnapshot(path, now, owner)
			if tc == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("accepted untrusted snapshot")
			}
		})
	}
}
func TestProbe(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		models     bool
		want       int
	}{
		{"models", `{"object":"list","data":[{"id":"model"}]}`, 200, true, 1},
		{"empty-models", `{"object":"list","data":[]}`, 200, true, 0},
		{"not-models", `{"data":[{"id":"x"}]}`, 200, true, 0},
		{"invalid-json", "bad", 200, true, 0},
		{"bad-status", `{"object":"list","data":[{"id":"x"}]}`, 503, true, 0},
		{"oversized", strings.Repeat("x", (64<<10)+1), 200, true, 0},
		{"collector", `{"status":"Server available"}`, 200, false, 1},
		{"collector-bad", `{"status":"Unavailable"}`, 200, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); io.WriteString(w, tc.body) }))
			defer server.Close()
			if got := probe(context.Background(), server.Client(), server.URL, tc.models); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}
func TestProbeTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if got := probe(ctx, server.Client(), server.URL, true); got != 0 {
		t.Fatal(got)
	}
}
func TestFixedProbeDestinationsAndRedirect(t *testing.T) {
	c := New()
	_, err := c.client.Get("http://example.com/")
	if err == nil {
		t.Fatal("external destination permitted")
	}
	if c.client.CheckRedirect(nil, nil) == nil {
		t.Fatal("redirect allowed")
	}
}
func TestListenLoopbackOnly(t *testing.T) {
	l, err := Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	addr := l.Addr().(*net.TCPAddr)
	if !addr.IP.Equal(net.ParseIP("127.0.0.1")) || addr.Port != 9465 {
		t.Fatal(addr)
	}
}
func TestBoundedCommandOutput(t *testing.T) {
	b := boundedBuffer{limit: 4}
	if _, err := b.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("5")); err == nil {
		t.Fatal("unbounded output")
	}
}
func TestReadinessExpiresSeparately(t *testing.T) {
	c := New()
	c.valid = true
	c.snapshot = fixture(time.Now())
	c.probes["attackbox-bait"] = probeResult{1, time.Now().Add(-MaxAge - time.Second)}
	requireMetric(t, output(c), `attackbox_component_ready{component="attackbox-bait"} -1`)
}

func TestCollectFixedFields(t *testing.T) {
	s := collect(context.Background(), func(_ context.Context, cmd string, args ...string) ([]byte, error) {
		switch cmd {
		case "/usr/bin/systemctl":
			if len(args) != 3+len(units) || args[0] != "show" || args[2] != "--property=Id,LoadState,ActiveState,SubState" {
				t.Errorf("unexpected systemctl args: %v", args)
			}
			var data strings.Builder
			for _, name := range args[3:] {
				fmt.Fprintf(&data, "Id=%s\nLoadState=loaded\nActiveState=active\nSubState=running\n\n", name)
			}
			return []byte(data.String()), nil
		case "/usr/bin/docker":
			if len(args) != 5 || args[0] != "inspect" || strings.Contains(args[3], ".Config.Env") {
				t.Errorf("unexpected docker args: %v", args)
			}
			return []byte(`{"running":true,"health":"healthy","restarts":2,"oom":false,"runtime":"runsc","memory":1000,"nano_cpus":1000000000}`), nil
		default:
			t.Errorf("unexpected command %q", cmd)
			return nil, errors.New("unexpected")
		}
	})
	if err := validate(s, time.Now()); err != nil {
		t.Fatal(err)
	}
	c := New()
	c.valid = true
	c.snapshot = s
	b := output(c)
	requireMetric(t, b, `attackbox_container_restarts{component="attackbox-bait"} 2`)
	requireMetric(t, b, `attackbox_container_runtime_approved{component="attackbox-bait"} 1`)
}

func TestBatchUnitIdentityAndDuplicates(t *testing.T) {
	calls := 0
	s := collect(context.Background(), func(_ context.Context, cmd string, args ...string) ([]byte, error) {
		if cmd != "/usr/bin/systemctl" {
			return nil, errors.New("missing")
		}
		calls++
		return []byte("Id=docker.service\nLoadState=loaded\nActiveState=active\nSubState=running\n\nId=auditd.service\nLoadState=loaded\nActiveState=active\nSubState=running\n\nId=auditd.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\n"), nil
	})
	if calls != 1 {
		t.Fatal(calls)
	}
	for _, u := range s.Units {
		if u.Name == "docker.service" && !u.Known {
			t.Fatal(u)
		}
		if u.Name != "docker.service" && u.Known {
			t.Fatal(u)
		}
	}
}
