// Package hostcollector observes a fixed local service inventory. It does not
// collect forensic evidence or certify telemetry delivery.
package hostcollector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const SnapshotPath = "/run/attackbox-monitoring/inventory.json"
const MaxSnapshotBytes = 64 << 10
const MaxAge = 90 * time.Second

var units = []string{"attackbox.service", "docker.service", "containerd.service", "falco-modern-bpf.service", "auditd.service", "attackbox-auditfilter.service", "attackbox-falco-adapter.service", "attackbox-egress-adapter.service", "attackbox-shipper.service", "attackbox-otel.service", "attackbox-hostcollector.service"}
var containers = []string{"attackbox-bait", "attackbox-proxy"}

type Unit struct {
	Name   string `json:"name"`
	Known  bool   `json:"known"`
	Load   string `json:"load"`
	Active string `json:"active"`
	Sub    string `json:"sub"`
}
type Container struct {
	Name     string `json:"name"`
	Known    bool   `json:"known"`
	Running  bool   `json:"running"`
	Health   string `json:"health"`
	Restarts int64  `json:"restarts"`
	OOM      bool   `json:"oom"`
	Runtime  string `json:"runtime"`
	Memory   int64  `json:"memory"`
	NanoCPUs int64  `json:"nano_cpus"`
}
type Snapshot struct {
	Version    int         `json:"version"`
	Time       time.Time   `json:"time"`
	Units      []Unit      `json:"units"`
	Containers []Container `json:"containers"`
}

type command func(context.Context, string, ...string) ([]byte, error)
type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errors.New("command output limit")
	}
	return b.Buffer.Write(p)
}
func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	var out = boundedBuffer{limit: 16 << 10}
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	err := cmd.Run()
	return out.Bytes(), err
}

// Collect uses only fixed commands and fixed output fields. In particular it
// never requests container environment variables, labels, mounts or secrets.
func Collect(ctx context.Context) Snapshot { return collect(ctx, run) }
func collect(ctx context.Context, command command) Snapshot {
	s := Snapshot{Version: 1, Units: make([]Unit, len(units)), Containers: make([]Container, len(containers))}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	work := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); sem <- struct{}{}; defer func() { <-sem }(); f() }()
	}
	work(func() {
		args := append([]string{"show", "--no-pager", "--property=Id,LoadState,ActiveState,SubState"}, units...)
		data, _ := command(ctx, "/usr/bin/systemctl", args...)
		// systemctl may return nonzero for a missing unit. Require a complete,
		// unique record with its own Id; never assign by response order.
		found := map[string][]Unit{}
		for _, block := range strings.Split(strings.TrimSpace(string(data)), "\n\n") {
			u := Unit{}
			for _, line := range strings.Split(block, "\n") {
				k, v, _ := strings.Cut(line, "=")
				switch k {
				case "Id":
					u.Name = v
				case "LoadState":
					u.Load = v
				case "ActiveState":
					u.Active = v
				case "SubState":
					u.Sub = v
				}
			}
			found[u.Name] = append(found[u.Name], u)
		}
		for i, name := range units {
			u := Unit{Name: name}
			if rows := found[name]; len(rows) == 1 {
				u = rows[0]
				u.Known = u.Load != "" && u.Active != "" && u.Sub != ""
			}
			s.Units[i] = u
		}
	})
	const format = `{"running":{{json .State.Running}},"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}"none"{{end}},"restarts":{{json .RestartCount}},"oom":{{json .State.OOMKilled}},"runtime":{{json .HostConfig.Runtime}},"memory":{{json .HostConfig.Memory}},"nano_cpus":{{json .HostConfig.NanoCpus}}}`
	for i, name := range containers {
		work(func() {
			c := Container{Name: name}
			data, err := command(ctx, "/usr/bin/docker", "inspect", "--type=container", "--format", format, name)
			if err == nil && json.Unmarshal(data, &c) == nil {
				c.Known = true
			}
			c.Name = name
			s.Containers[i] = c
		})
	}
	wg.Wait()
	s.Time = time.Now().UTC()
	return s
}

func trusted(info os.FileInfo, uid uint32) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uid && info.Mode().Perm()&0022 == 0
}
func checkDir(path string, uid uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || !trusted(info, uid) {
		return errors.New("untrusted inventory directory")
	}
	return nil
}
func WriteSnapshot(s Snapshot) error {
	dir := filepath.Dir(SnapshotPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if err := checkDir(dir, 0); err != nil {
		return err
	}
	if err := validate(s, time.Now()); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if len(data) > MaxSnapshotBytes {
		return errors.New("snapshot too large")
	}
	f, err := os.CreateTemp(dir, ".inventory-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0644); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), SnapshotPath)
}
func ReadSnapshot(now time.Time) (Snapshot, error) { return readSnapshot(SnapshotPath, now, 0) }
func readSnapshot(path string, now time.Time, uid uint32) (Snapshot, error) {
	var s Snapshot
	if err := checkDir(filepath.Dir(path), uid); err != nil {
		return s, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return s, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return s, err
	}
	if !info.Mode().IsRegular() || !trusted(info, uid) || info.Size() > MaxSnapshotBytes {
		return s, errors.New("untrusted or oversized snapshot")
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxSnapshotBytes+1))
	if err != nil {
		return s, err
	}
	if len(data) > MaxSnapshotBytes {
		return s, errors.New("snapshot too large")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(&s); err != nil {
		return s, err
	}
	if d.Decode(new(any)) != io.EOF {
		return s, errors.New("trailing snapshot data")
	}
	return s, validate(s, now)
}
func validate(s Snapshot, now time.Time) error {
	if s.Version != 1 || s.Time.IsZero() || now.Sub(s.Time) > MaxAge || s.Time.After(now.Add(5*time.Second)) {
		return errors.New("invalid or stale snapshot")
	}
	if len(s.Units) != len(units) || len(s.Containers) != len(containers) {
		return errors.New("incomplete inventory")
	}
	for i, u := range s.Units {
		if u.Name != units[i] || !token(u.Load) || !token(u.Active) || !token(u.Sub) || (u.Known && (!oneOf(u.Load, "loaded", "not-found", "error", "bad-setting", "masked", "merged", "stub") || !oneOf(u.Active, "active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "refreshing") || u.Sub == "")) {
			return fmt.Errorf("invalid unit %d", i)
		}
	}
	for i, c := range s.Containers {
		if c.Name != containers[i] || !token(c.Runtime) || !oneOf(c.Health, "", "none", "starting", "healthy", "unhealthy") || c.Restarts < 0 || c.Memory < 0 || c.NanoCPUs < 0 {
			return fmt.Errorf("invalid container %d", i)
		}
	}
	return nil
}
func token(s string) bool {
	if len(s) > 64 {
		return false
	}
	for _, c := range s {
		if c != '-' && c != '_' && !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func oneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}
