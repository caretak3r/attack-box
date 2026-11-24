// attackbox-watch takes bounded read-only snapshots over the existing SSH alias.
// Captured log text is parsed as data and is never executed or written to reports.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxInput = 8 << 20

type sample struct {
	From, Until time.Time
	Counts      map[string]int
	Metrics     map[string]float64
	Warnings    []string
}

type capped struct {
	bytes.Buffer
	exceeded bool
}

func (b *capped) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len()+n > maxInput {
		b.exceeded = true
		p = p[:maxInput-b.Len()]
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}

// The only interpolation is server-independent integer timestamps. No log value
// or command-line string is inserted into the remote shell program.
func script(from, until time.Time) string {
	return fmt.Sprintf(`set -u
printf '@@memory\n'
cat /proc/meminfo || printf '@@failure_memory\n'
printf '@@load\n'
cat /proc/loadavg || printf '@@failure_load\n'
printf '@@disk\n'
df -Pk / || printf '@@failure_disk\n'
printf '@@metrics\n'
curl -fsS --max-time 5 http://127.0.0.1:9465/metrics || printf '@@failure_metrics\n'
printf '\n@@otel\n'
curl -fsS --max-time 5 http://127.0.0.1:8888/metrics || printf '@@failure_otel\n'
printf '\n@@failed\n'
systemctl --failed --no-legend --plain --no-pager || printf '@@failure_failed\n'
printf '@@files\n'
stat -c '%%n %%s %%Y' /var/log/falco-events.jsonl /var/lib/attackbox-shipper/queue/checkpoint /var/lib/attackbox-falco-reader/cursor.json /var/lib/attackbox-egress-reader/cursor.json 2>/dev/null || printf '@@failure_files\n'
printf '@@proxy\n'
journalctl -u docker.service --since '@%d' --until '@%d' -n 2000 -o json --no-pager || printf '@@failure_proxy\n'
printf '@@kernel\n'
journalctl _TRANSPORT=kernel --since '@%d' --until '@%d' -n 2000 -o json --no-pager || printf '@@failure_kernel\n'
printf '@@falco\n'
tail -n 1000 /var/log/falco-events.jsonl 2>/dev/null || printf '@@failure_falco\n'
printf '\n@@end\n'
`, from.Unix(), until.Unix(), from.Unix(), until.Unix())
}

var metricLine = regexp.MustCompile(`^(attackbox_(?:inventory_snapshot_valid|inventory_snapshot_age_seconds|component_observed|component_running|component_ready|component_probe_failed|container_health|container_restarts|container_runtime_approved))(\{component="[a-zA-Z0-9_.-]{1,64}"\})? ([0-9.eE+-]+)$`)
var unitName = regexp.MustCompile(`^[a-zA-Z0-9_.@-]{1,100}\.service$`)

func parse(data []byte, from, until time.Time) sample {
	s := sample{From: from, Until: until, Counts: map[string]int{}, Metrics: map[string]float64{}}
	section := ""
	rows := map[string]int{}
	scan := bufio.NewScanner(bytes.NewReader(data))
	scan.Buffer(make([]byte, 4096), 2<<20)
	for scan.Scan() {
		line := scan.Text()
		if strings.HasPrefix(line, "@@") {
			section = strings.TrimPrefix(line, "@@")
			if strings.HasPrefix(section, "failure_") {
				s.Warnings = append(s.Warnings, section)
			}
			continue
		}
		f := strings.Fields(line)
		switch section {
		case "memory":
			if len(f) == 3 && (f[0] == "MemAvailable:" || f[0] == "MemTotal:" || f[0] == "SwapFree:") {
				v, _ := strconv.ParseFloat(f[1], 64)
				s.Metrics[strings.TrimSuffix(f[0], ":")+"_KiB"] = v
			}
		case "load":
			if len(f) >= 3 {
				v, _ := strconv.ParseFloat(f[0], 64)
				s.Metrics["load_1m"] = v
			}
		case "disk":
			if len(f) >= 6 && f[5] == "/" {
				v, _ := strconv.ParseFloat(strings.TrimSuffix(f[4], "%"), 64)
				s.Metrics["root_disk_used_percent"] = v
			}
		case "metrics":
			m := metricLine.FindStringSubmatch(line)
			if m != nil {
				v, e := strconv.ParseFloat(m[3], 64)
				if e == nil && !math.IsNaN(v) && !math.IsInf(v, 0) {
					s.Metrics[m[1]+m[2]] = v
				}
			}
		case "failed":
			if len(f) > 0 && unitName.MatchString(f[0]) {
				s.Counts["failed_unit_samples:"+f[0]]++
			}
		case "otel":
			if len(f) < 2 {
				continue
			}
			name := strings.SplitN(f[0], "{", 2)[0]
			switch name {
			case "otelcol_exporter_sent_spans", "otelcol_exporter_sent_spans_total", "otelcol_exporter_send_failed_spans", "otelcol_exporter_send_failed_spans_total", "otelcol_receiver_refused_spans", "otelcol_receiver_refused_spans_total", "otelcol_exporter_queue_size", "otelcol_exporter_queue_capacity":
				v, e := strconv.ParseFloat(f[1], 64)
				if e == nil && !math.IsNaN(v) && !math.IsInf(v, 0) {
					s.Metrics[name] += v
				}
			}
		case "files":
			if len(f) == 3 {
				for key, path := range map[string]string{"falco_source": "/var/log/falco-events.jsonl", "shipper_checkpoint": "/var/lib/attackbox-shipper/queue/checkpoint", "falco_cursor": "/var/lib/attackbox-falco-reader/cursor.json", "egress_cursor": "/var/lib/attackbox-egress-reader/cursor.json"} {
					if f[0] == path {
						n, e := strconv.ParseInt(f[2], 10, 64)
						if e == nil {
							s.Metrics[key+"_age_seconds"] = float64(until.Unix() - n)
						}
					}
				}
			}
		case "proxy", "kernel", "falco":
			rows[section]++
			var j map[string]any
			if json.Unmarshal([]byte(line), &j) != nil {
				s.Counts[section+"_unparsed"]++
				continue
			}
			if section == "falco" {
				at, e := time.Parse(time.RFC3339Nano, stringValue(j["time"]))
				if e != nil {
					s.Counts["falco_time_unparsed"]++
					continue
				}
				if at.After(from) && !at.After(until) {
					s.Counts["falco_events"]++
					h := sha256.Sum256([]byte(stringValue(j["rule"])))
					s.Counts[fmt.Sprintf("falco_rule_hash:%x", h[:6])]++
				}
				continue
			}
			// Journal since/until are inclusive. Use the microsecond timestamp to
			// keep adjacent successful windows disjoint; unknown times are explicit.
			us, e := strconv.ParseInt(stringValue(j["__REALTIME_TIMESTAMP"]), 10, 64)
			if e != nil {
				s.Counts[section+"_time_unparsed"]++
				continue
			}
			if us <= from.UnixMicro() || us > until.UnixMicro() {
				continue
			}
			msg := stringValue(j["MESSAGE"])
			if section == "kernel" {
				for _, prefix := range []string{"OUTPUT-DROP:", "CONTAINER-EGRESS:", "METADATA-BLOCK:", "METADATA-BLOCK-OUT:"} {
					if strings.Contains(msg, prefix) {
						s.Counts["kernel:"+prefix]++
					}
				}
				continue
			}
			if stringValue(j["CONTAINER_NAME"]) != "attackbox-proxy" {
				s.Counts["docker_non_proxy_rows"]++
				continue
			}
			var access struct {
				Status  int    `json:"status"`
				IP      string `json:"client_ip"`
				Request string `json:"request"`
				UA      string `json:"user_agent"`
			}
			if json.Unmarshal([]byte(msg), &access) != nil || access.Status < 100 || access.Status > 599 {
				s.Counts["proxy_non_access_rows"]++
				continue
			}
			s.Counts["http_total"]++
			s.Counts[fmt.Sprintf("http_status:%d", access.Status)]++
			ip, err := netip.ParseAddr(access.IP)
			if err != nil {
				s.Counts["http_source_unknown"]++
			} else if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				s.Counts["http_private_source"]++
			} else {
				s.Counts["http_public_source"]++
			}
			if strings.HasPrefix(access.UA, "attackbox-synthetic-") {
				s.Counts["http_synthetic_label_claimed"]++
			}
			s.Counts["route:"+route(access.Request)]++
		}
	}
	if scan.Err() != nil {
		s.Warnings = append(s.Warnings, "input_parse_limit")
	}
	if section != "end" {
		s.Warnings = append(s.Warnings, "missing_end_marker")
	}
	for _, source := range []string{"proxy", "kernel"} {
		if rows[source] >= 2000 {
			s.Warnings = append(s.Warnings, source+"_2000_row_cap")
		}
	}
	if rows["falco"] >= 1000 {
		s.Warnings = append(s.Warnings, "falco_1000_row_tail_bound")
	}
	if s.Metrics["attackbox_inventory_snapshot_valid"] != 1 {
		s.Warnings = append(s.Warnings, "inventory_not_valid")
	}
	if s.Metrics["attackbox_inventory_snapshot_age_seconds"] > 180 {
		s.Warnings = append(s.Warnings, "inventory_stale")
	}
	components := 0
	for k, v := range s.Metrics {
		if strings.HasPrefix(k, "attackbox_component_running{") {
			components++
			if v != 1 {
				s.Warnings = append(s.Warnings, "component_not_running:"+k)
			}
		}
		if strings.HasPrefix(k, "attackbox_component_observed{") && v != 1 {
			s.Warnings = append(s.Warnings, "component_not_observed:"+k)
		}
		if strings.HasPrefix(k, "attackbox_component_probe_failed{") && v == 1 {
			s.Warnings = append(s.Warnings, "component_probe_failed:"+k)
		}
	}
	if components != 12 {
		s.Warnings = append(s.Warnings, "component_count_not_12")
	}
	if _, ok := s.Metrics["attackbox_inventory_snapshot_age_seconds"]; !ok {
		s.Warnings = append(s.Warnings, "inventory_age_missing")
	}
	if s.Metrics["root_disk_used_percent"] >= 85 {
		s.Warnings = append(s.Warnings, "disk_at_least_85_percent")
	}
	if v, ok := s.Metrics["MemAvailable_KiB"]; ok && v < 512*1024 {
		s.Warnings = append(s.Warnings, "available_memory_below_512_MiB")
	}
	return s
}

func stringValue(v any) string { s, _ := v.(string); return s }
func route(request string) string {
	f := strings.Fields(request)
	if len(f) < 2 {
		return "unknown"
	}
	p := strings.SplitN(f[1], "?", 2)[0]
	switch p {
	case "/v1/models", "/v1/chat/completions", "/v1/completions", "/v1/responses", "/v1/embeddings", "/api/chat", "/api/generate", "/api/tags", "/health", "/ready", "/":
		return p
	}
	if strings.HasPrefix(p, "/mcp") {
		return "mcp_other"
	}
	return "other"
}

func collect(from, until time.Time) sample {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2", "attackbox", "sh", "-s")
	cmd.Stdin = strings.NewReader(script(from, until))
	var out, errOut capped
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	s := parse(out.Bytes(), from, until)
	if err != nil {
		s.Warnings = append(s.Warnings, "ssh_collect_failed")
	}
	if out.exceeded || errOut.exceeded {
		s.Warnings = append(s.Warnings, "ssh_output_cap")
	}
	return s
}

func atomicWrite(path string, b []byte) error {
	if err := os.WriteFile(path+".tmp", b, 0600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func report(out string, samples []sample, start, deadline time.Time, state string) error {
	counts := map[string]int{}
	warnings := map[string]int{}
	for _, s := range samples {
		for k, v := range s.Counts {
			counts[k] += v
		}
		for _, w := range s.Warnings {
			warnings[w]++
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Overnight watch\n\nState: %s. Start: %s. Deadline: %s. Samples: %d.\n\n", state, start.Format(time.RFC3339), deadline.Format(time.RFC3339), len(samples))
	b.WriteString("Read-only SSH observations of attackbox. No probes, remediation, attacker contact or VPS configuration changes. New Relic receipt and provider firewall are not checked by this watcher. Counts describe observed activity, not confirmed attacks. Synthetic labels can be forged. Public ingress was closed at setup; re-check before interpreting silence.\n\nCollection runs on the operator Mac and requires power and connectivity. Gaps, capped journals and source rotation can hide events. A stale idle-source cursor alone does not prove failure. Raw paths, query strings, headers and payloads are not stored in this report.\n\n## Activity totals\n\n")
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "- %s: %d\n", k, counts[k])
	}
	b.WriteString("\n## Collection warnings\n\n")
	keys = nil
	for k := range warnings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		b.WriteString("No collection warnings recorded. This does not prove complete capture.\n")
	}
	for _, k := range keys {
		fmt.Fprintf(&b, "- %s: %d samples\n", k, warnings[k])
	}
	if len(samples) > 0 {
		last := samples[len(samples)-1]
		fmt.Fprintf(&b, "\n## Latest snapshot\n\nUTC: %s\n\n", last.Until.Format(time.RFC3339))
		keys = nil
		for k := range last.Metrics {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "- %s: %g\n", k, last.Metrics[k])
		}
	}
	return atomicWrite(filepath.Join(out, "REPORT.md"), []byte(b.String()))
}

func run() error {
	out := flag.String("out", "", "new absolute private output directory")
	duration := flag.Duration("duration", 8*time.Hour, "watch duration (maximum12h)")
	interval := flag.Duration("interval", 5*time.Minute, "poll interval (minimum1m)")
	once := flag.Bool("once", false, "one read-only baseline snapshot")
	flag.Parse()
	if !filepath.IsAbs(*out) || *duration <= 0 || *duration > 12*time.Hour || *interval < time.Minute {
		return fmt.Errorf("invalid output path, duration or interval")
	}
	if err := os.Mkdir(*out, 0700); err != nil {
		return err
	}
	start := time.Now().UTC().Truncate(time.Second)
	deadline := start.Add(*duration)
	pid := []byte(strconv.Itoa(os.Getpid()) + "\n")
	if err := atomicWrite(filepath.Join(*out, "watch.pid"), pid); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(*out, "samples.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var samples []sample
	from := start.Add(-5 * time.Minute)
	for {
		until := time.Now().UTC().Truncate(time.Second)
		s := collect(from, until)
		samples = append(samples, s)
		if err := json.NewEncoder(f).Encode(s); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		state := "running"
		if *once || !time.Now().Before(deadline) {
			state = "complete"
		}
		if err := report(*out, samples, start, deadline, state); err != nil {
			return err
		}
		if state == "complete" {
			return nil
		}
		// Failed windows are recorded as gaps; no silent catch-up or double count.
		from = until
		wait := min(*interval, time.Until(deadline))
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return report(*out, samples, start, deadline, "interrupted")
		case <-timer.C:
		}
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "watch failed:", err)
		os.Exit(1)
	}
}
