// attackbox-auditfilter preserves audit groups and removes one verified routine
// observation. It has no network access or New Relic credential.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"attackbox/internal/auditfilter"
	"attackbox/internal/hostevidence"
)

type output struct {
	dir  string
	file *os.File
}

func (o *output) open() error {
	p := filepath.Join(o.dir, "events.jsonl")
	f, e := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || int(st.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		f.Close()
		return errors.New("unsafe audit output")
	}
	// A crash can leave an uncommitted partial JSON line. The source cursor
	// still precedes this batch, so replay recovers it. Do not concatenate the
	// partial tail with the first replayed record.
	if st.Size() > 0 {
		n := min(st.Size(), int64(auditfilter.MaxBatch))
		tail := make([]byte, n)
		if _, e = f.ReadAt(tail, st.Size()-n); e != nil {
			f.Close()
			return e
		}
		if tail[len(tail)-1] != '\n' {
			end := bytes.LastIndexByte(tail, '\n')
			if end < 0 && st.Size() > n {
				f.Close()
				return errors.New("unbounded partial audit output")
			}
			if e = f.Truncate(st.Size() - n + int64(end+1)); e == nil {
				e = f.Sync()
			}
			if e != nil {
				f.Close()
				return e
			}
			log.Print("recovered uncommitted partial audit output; source will replay")
		}
	}
	o.file = f
	return nil
}
func (o *output) write(data []byte) error {
	st, e := o.file.Stat()
	if e != nil {
		return e
	}
	if st.Size()+int64(len(data)) > 64<<20 {
		retired := int64(0)
		if old, err := os.Lstat(filepath.Join(o.dir, "events.jsonl.3")); err == nil {
			if !old.Mode().IsRegular() {
				return errors.New("unsafe rotated audit output")
			}
			retired = old.Size()
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if e = o.file.Close(); e != nil {
			return e
		}
		for i := 3; i >= 1; i-- {
			old := filepath.Join(o.dir, fmt.Sprintf("events.jsonl.%d", i))
			if i == 3 {
				e = os.Remove(old)
			} else {
				e = os.Rename(old, filepath.Join(o.dir, fmt.Sprintf("events.jsonl.%d", i+1)))
			}
			if e != nil && !errors.Is(e, os.ErrNotExist) {
				return e
			}
		}
		if e = os.Rename(filepath.Join(o.dir, "events.jsonl"), filepath.Join(o.dir, "events.jsonl.1")); e != nil {
			return e
		}
		if e = o.open(); e != nil {
			return e
		}
		d, e := os.Open(o.dir)
		if e != nil {
			return e
		}
		e = d.Sync()
		d.Close()
		if e != nil {
			return e
		}
		marker, err := json.Marshal(map[string]any{"message": "audit output rotated", "action": "audit_output_rotation", "audit_policy": auditfilter.Policy, "retired_local_bytes": retired})
		if err != nil {
			return err
		}
		if _, e = o.file.Write(append(marker, '\n')); e != nil {
			return e
		}
	}
	if _, e = o.file.Write(data); e != nil {
		return e
	}
	return o.file.Sync()
}
func processTrusted(r auditfilter.Record) bool {
	pid, e := strconv.Atoi(r.Fields["pid"])
	if e != nil || pid < 2 {
		return false
	}
	dir := fmt.Sprintf("/proc/%d", pid)
	// The kernel audit SYSCALL already identifies the executable at event time.
	// Reading another process's /proc/exe would require CAP_SYS_PTRACE in this
	// capability-free service. Keep that capability absent. Verify the recorded
	// identity against live unit, UID, parent, and process start time instead.
	b, e := os.ReadFile(dir + "/cgroup")
	if e != nil {
		return false
	}
	if !strings.Contains("\n"+string(b), "\n0::/system.slice/newrelic-infra.service\n") {
		return false
	}
	b, e = os.ReadFile(dir + "/status")
	if e != nil {
		return false
	}
	if !strings.Contains(string(b), "\nUid:\t0\t0\t0\t0\n") {
		return false
	}
	// A PID may have exited or been reused. Keep historical observations unless
	// this process started before the recorded event.
	b, e = os.ReadFile(dir + "/stat")
	if e != nil {
		return false
	}
	end := strings.LastIndexByte(string(b), ')')
	if end < 0 {
		return false
	}
	fields := strings.Fields(string(b)[end+1:])
	if len(fields) < 20 {
		return false
	}
	if fields[1] != r.Fields["ppid"] {
		return false
	}
	ticks, e := strconv.ParseFloat(fields[19], 64)
	if e != nil {
		return false
	}
	up, e := os.ReadFile("/proc/uptime")
	if e != nil {
		return false
	}
	u := strings.Fields(string(up))
	if len(u) < 1 {
		return false
	}
	secs, e := strconv.ParseFloat(u[0], 64)
	if e != nil {
		return false
	}
	when, _, ok := strings.Cut(r.ID, ":")
	if !ok {
		return false
	}
	at, e := strconv.ParseFloat(when, 64)
	if e != nil {
		return false
	}
	// Linux amd64 USER_HZ is 100. This filter profile is explicitly x86_64 only.
	started := float64(time.Now().UnixNano())/1e9 - secs + ticks/100
	return at >= started+1 && at <= float64(time.Now().Unix())+2
}
func render(lines []string, boot, batch string, trust auditfilter.Trust) ([]byte, error) {
	entries, stats := auditfilter.Batch(lines, boot, trust)
	var b strings.Builder
	enc := json.NewEncoder(&b)
	for _, entry := range entries {
		if e := enc.Encode(entry); e != nil {
			return nil, e
		}
	}
	firstEvent, lastEvent := "", ""
	for _, line := range lines {
		if record := auditfilter.Parse(line); record.ID != "" {
			if firstEvent == "" {
				firstEvent = record.ID
			}
			lastEvent = record.ID
		}
	}
	summary := map[string]any{"first_audit_event_id": firstEvent, "last_audit_event_id": lastEvent, "message": "attackbox audit batch", "action": "audit_budget_batch", "audit_policy": auditfilter.Policy, "audit_reader_boot_id": boot, "audit_batch_id": batch, "input_rows": stats.InputRows, "kept_rows": stats.KeptRows, "suppressed_rows": stats.SuppressedRows, "kept_events": stats.KeptEvents, "suppressed_events": stats.SuppressedEvents}
	if e := enc.Encode(summary); e != nil {
		return nil, e
	}
	return []byte(b.String()), nil
}
func follow(ctx context.Context, source, stateDir, outputDir string) error {
	state, e := hostevidence.OpenState(stateDir, "audit")
	if e != nil {
		return e
	}
	defer state.Close()
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return e
	}
	o := output{dir: outputDir}
	if e = o.open(); e != nil {
		return e
	}
	defer func() {
		if o.file != nil {
			o.file.Close()
		}
	}()
	var lines []string
	size := 0
	first := ""
	lastFlush := time.Now()
	r := hostevidence.FileReader{Path: source, State: state, NumericRotation: true}
	defer r.Close()
	flush := func() error {
		if len(lines) == 0 {
			return nil
		}
		sum := sha256.Sum256([]byte(first))
		data, e := render(lines, strings.TrimSpace(string(boot)), fmt.Sprintf("%x", sum), processTrusted)
		if e != nil {
			return e
		}
		if e = o.write(data); e != nil {
			return e
		}
		if e = state.Save(state.Position); e != nil {
			return e
		}
		lines = nil
		size = 0
		first = ""
		lastFlush = time.Now()
		return nil
	}
	r.Deliver = func(_ context.Context, key string, line []byte) error {
		if len(line) > auditfilter.MaxBatch {
			return errors.New("audit line exceeds batch bound; cursor retained")
		}
		if size+len(line) > auditfilter.MaxBatch {
			if e := flush(); e != nil {
				return e
			}
		}
		if first == "" {
			first = key
		}
		lines = append(lines, strings.TrimSuffix(string(line), "\n"))
		size += len(line)
		return nil
	}
	// Only the batch flush persists this volatile position, after output fsync.
	r.Commit = func(p hostevidence.Position) error { state.Position = p; return nil }
	for ctx.Err() == nil {
		progress, e := r.Step(ctx)
		if e != nil {
			return e
		}
		if time.Since(lastFlush) >= 5*time.Second {
			if e = flush(); e != nil {
				return e
			}
		}
		if !progress {
			select {
			case <-ctx.Done():
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	return flush()
}
func main() {
	stdin := flag.Bool("stdin", false, "compact synthetic stdin without suppression or state")
	source := flag.String("source", "/var/log/audit/audit.log", "audit file")
	state := flag.String("state-dir", "/var/lib/attackbox-auditfilter", "durable cursor directory")
	out := flag.String("output-dir", "/var/log/attackbox-audit", "private output directory")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected arguments")
	}
	if *stdin {
		scanner := bufio.NewScanner(io.LimitReader(os.Stdin, auditfilter.MaxBatch+1))
		scanner.Buffer(make([]byte, 4096), hostevidence.MaxSourceRecord)
		var lines []string
		size := 0
		for scanner.Scan() {
			size += len(scanner.Bytes()) + 1
			if size > auditfilter.MaxBatch {
				log.Fatal("batch too large")
			}
			lines = append(lines, scanner.Text())
		}
		if e := scanner.Err(); e != nil {
			log.Fatal(e)
		}
		b, e := render(lines, "offline", "offline", nil)
		if e != nil {
			log.Fatal(e)
		}
		os.Stdout.Write(b)
		return
	}
	if os.Geteuid() != 0 {
		log.Fatal("audit reader requires root")
	}
	info, e := os.Lstat(*out)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		log.Fatal("untrusted output directory")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if e = follow(ctx, *source, *state, *out); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
