// attackbox-findings publishes numeric watch summaries from an isolated checkout.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const destination = "findings/2026-11-24/README.md"
const branch = "findings/overnight-20261124"

var operationDeadline time.Time

type sample struct {
	From, Until time.Time
	Counts      map[string]int64
	Metrics     map[string]float64
	Warnings    []string
}

func set(words string) map[string]bool {
	m := map[string]bool{}
	for _, s := range strings.Fields(words) {
		m[s] = true
	}
	return m
}

var countKeys = set(`http_total http_private_source http_public_source http_source_unknown http_synthetic_label_claimed falco_events falco_unparsed falco_time_unparsed proxy_unparsed proxy_time_unparsed kernel_unparsed kernel_time_unparsed docker_non_proxy_rows proxy_non_access_rows unknown_section_marker kernel:OUTPUT-DROP: kernel:CONTAINER-EGRESS-BLOCK: kernel:METADATA-BLOCK: kernel:METADATA-BLOCK-OUT:`)
var routes = set(`/ /v1/models /v1/chat/completions /v1/completions /v1/responses /v1/embeddings /api/chat /api/generate /api/tags /health /ready mcp_other other unknown`)
var metricKeys = set(`MemAvailable_KiB MemTotal_KiB SwapFree_KiB load_1m root_disk_used_percent attackbox_inventory_snapshot_valid attackbox_inventory_snapshot_age_seconds falco_source_age_seconds shipper_checkpoint_age_seconds falco_cursor_age_seconds egress_cursor_age_seconds otelcol_exporter_sent_spans otelcol_exporter_sent_spans_total otelcol_exporter_send_failed_spans otelcol_exporter_send_failed_spans_total otelcol_receiver_refused_spans otelcol_receiver_refused_spans_total otelcol_exporter_queue_size otelcol_exporter_queue_capacity`)
var components = set(`attackbox-bait attackbox-proxy attackbox-auditfilter.service attackbox-egress-adapter.service attackbox-falco-adapter.service attackbox-hostcollector.service attackbox-otel.service attackbox-shipper.service attackbox.service auditd.service containerd.service docker.service falco-modern-bpf.service`)
var componentMetric = regexp.MustCompile(`^(attackbox_(?:component_observed|component_running|component_ready|component_probe_failed|container_health|container_restarts|container_runtime_approved))\{component="([a-zA-Z0-9_.-]+)"\}$`)
var statusKey = regexp.MustCompile(`^http_status:[1-5][0-9]{2}$`)
var stateLine = regexp.MustCompile(`(?m)^State: (running|complete|interrupted)\. Start: ([0-9TZ:+-]+)\. Deadline: ([0-9TZ:+-]+)\. Samples: ([0-9]+)\.$`)
var warnings = set(`failure_memory failure_load failure_disk failure_metrics failure_otel failure_failed failure_files failure_proxy failure_kernel failure_falco input_parse_limit missing_end_marker proxy_2000_row_cap kernel_2000_row_cap falco_1000_row_tail_bound inventory_not_valid inventory_stale component_count_not_12 inventory_age_missing disk_at_least_85_percent available_memory_below_512_MiB ssh_collect_failed ssh_output_cap collection_gap_exceeds_interval`)

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	if len(b) > 8<<20 {
		return nil, errors.New("input limit")
	}
	return b, err
}

// Unrecognized labels are discarded. No source strings enter Markdown unless
// they match an exact allowlist (HTTP status codes are a bounded numeric enum).
func render(data, report []byte) ([]byte, bool, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, false, errors.New("incomplete sample write")
	}
	state := stateLine.FindSubmatch(report)
	if state == nil {
		return nil, false, errors.New("missing watch state")
	}
	counts, notices := map[string]int64{}, map[string]int64{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var last sample
	var samples []sample
	n := 0
	var first time.Time
	for {
		var s sample
		err := dec.Decode(&s)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false, errors.New("invalid sample JSON")
		}
		if s.From.IsZero() || !s.Until.After(s.From) || (n > 0 && !s.From.Equal(last.Until)) {
			return nil, false, errors.New("invalid sample window")
		}
		if n == 0 {
			first = s.From
		}
		n++
		if n > 1000 {
			return nil, false, errors.New("sample limit")
		}
		for k, v := range s.Counts {
			if v < 0 || v > 1_000_000_000 {
				return nil, false, errors.New("invalid count")
			}
			switch {
			case countKeys[k], statusKey.MatchString(k), strings.HasPrefix(k, "route:") && routes[strings.TrimPrefix(k, "route:")]:
				counts[k] += v
			case strings.HasPrefix(k, "failed_unit_samples:"):
				counts["failed_service_sample_occurrences"] += v
			}
		}
		for _, w := range s.Warnings {
			switch {
			case warnings[w]:
				notices[w]++
			case strings.HasPrefix(w, "component_not_running:"):
				notices["component_not_running"]++
			case strings.HasPrefix(w, "component_not_observed:"):
				notices["component_not_observed"]++
			case strings.HasPrefix(w, "component_probe_failed:"):
				notices["component_probe_failed"]++
			default:
				notices["unrecognized_warning"]++
			}
		}
		last = s
		samples = append(samples, s)
	}
	if n == 0 || string(state[4]) != fmt.Sprint(n) {
		return nil, false, errors.New("report/sample update in progress")
	}
	var b strings.Builder
	deadline, err := time.Parse(time.RFC3339, string(state[3]))
	if err != nil {
		return nil, false, errors.New("invalid watch deadline")
	}
	fmt.Fprintf(&b, "# Host and private-proxy watch\n\n**Watch: %s · %d snapshots · last observation %s**\n\nCoverage: %s to %s. Planned final collection: %s. The first snapshot includes a five-minute baseline.\n\n", state[1], n, clockLabel(last.Until), clockLabel(first), clockLabel(last.Until), clockLabel(deadline))
	debrief(&b, samples, counts, notices)
	b.WriteString("\n<details>\n<summary>Technical evidence: exact counters, collection warnings and latest metrics</summary>\n\n## Activity totals\n\nFailed-service counts are sample occurrences. Falco parse errors can include repeated old records. These are not unique attacks.\n\n")
	writeCounts := func(m map[string]int64) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "- `%s`: %d\n", k, m[k])
		}
		if len(keys) == 0 {
			b.WriteString("No entries recorded. This does not prove complete capture.\n")
		}
	}
	writeCounts(counts)
	b.WriteString("\n## Collection warnings\n\nCounts below are occurrences across samples.\n\n")
	writeCounts(notices)
	b.WriteString("\n## Latest health and telemetry snapshot\n\nCounters below are cumulative source counters, not window totals. Component values of -1 mean unknown. A stale idle-source cursor alone does not prove failure.\n\n| Metric | Value |\n| --- | ---: |\n")
	keys := make([]string, 0, len(last.Metrics))
	for k, v := range last.Metrics {
		m := componentMetric.FindStringSubmatch(k)
		if (metricKeys[k] || (m != nil && components[m[2]])) && !math.IsNaN(v) && !math.IsInf(v, 0) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "| `%s` | %g |\n", k, last.Metrics[k])
	}
	b.WriteString("\n</details>\n")
	return []byte(b.String()), string(state[1]) != "running", nil
}

func git(dir string, args ...string) ([]byte, error) {
	limit := 30 * time.Second
	if !operationDeadline.IsZero() {
		limit = min(limit, time.Until(operationDeadline))
		if limit <= 0 {
			return nil, errors.New("Git deadline reached")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	base := []string{"-c", "core.sshCommand=ssh -oBatchMode=yes -oConnectTimeout=10 -oServerAliveInterval=5 -oServerAliveCountMax=2"}
	cmd := exec.CommandContext(ctx, "git", append(base, args...)...)
	cmd.Dir = dir
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "GIT_") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, "GIT_TERMINAL_PROMPT=0")
	cmd.WaitDelay = time.Second
	// Never echo Git output: errors may contain credential-bearing remote URLs.
	b, err := cmd.Output()
	if err != nil {
		return nil, errors.New("git operation failed: " + args[0])
	}
	return b, nil
}

func publish(dir string, content []byte) error {
	// Dedicated findings-only index and history. Never run in the source checkout.
	name, err := git(dir, "symbolic-ref", "--short", "HEAD")
	if err != nil || strings.TrimSpace(string(name)) != branch {
		return errors.New("unexpected branch")
	}
	tracked, err := git(dir, "ls-files", "-z")
	if err != nil {
		return err
	}
	for _, p := range bytes.Split(tracked, []byte{0}) {
		if len(p) > 0 && string(p) != destination {
			return errors.New("non-findings tracked file")
		}
	}
	// A deleted private file remains in Git history. Reject such ancestry too.
	refs, err := git(dir, "for-each-ref", "--format=%(objectname)", "refs/heads/"+branch)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(refs)) > 0 {
		history, err := git(dir, "log", "--format=", "--name-only", "--no-renames", "HEAD")
		if err != nil {
			return err
		}
		for _, p := range strings.Split(string(history), "\n") {
			if p != "" && p != destination {
				return errors.New("non-findings history")
			}
		}
	}
	path := filepath.Join(dir, destination)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		return err
	}
	if _, err = git(dir, "add", "--", destination); err != nil {
		return err
	}
	diff, err := git(dir, "diff", "--cached", "--name-only")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(diff)) != "" {
		if strings.TrimSpace(string(diff)) != destination {
			return errors.New("unexpected staged path")
		}
		if _, err = git(dir, "commit", "-m", "findings: overnight observation "+time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	// Always retry the push, including when a previous commit is already local.
	_, err = git(dir, "push", "origin", "HEAD:refs/heads/"+branch)
	return err
}

func run() error {
	source := flag.String("source", "", "absolute private watch directory")
	checkout := flag.String("checkout", "", "absolute isolated findings-only checkout")
	archiveDir := flag.String("archive", "", "absolute evidence archive directory for local reads")
	deadlineText := flag.String("deadline", "2026-11-24T11:00:00Z", "stop retrying at this UTC deadline")
	once := flag.Bool("once", false, "publish once and exit")
	mainDate := flag.String("main-date", "", "publish this YYYY-MM-DD debrief to main")
	if *mainDate != "" {
		return runMain(*source, *checkout, *deadlineText, *mainDate, *archiveDir, *once)
	}
	deadline, err := time.Parse(time.RFC3339, *deadlineText)
	if err != nil || !filepath.IsAbs(*source) || !filepath.IsAbs(*checkout) || (!*once && (time.Until(deadline) <= 0 || time.Until(deadline) > 12*time.Hour)) {
		return errors.New("invalid paths or deadline")
	}
	if !*once {
		operationDeadline = deadline
	}
	lock, err := os.OpenFile(filepath.Join(*checkout, "publisher.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("publisher already running")
	}
	for {
		if !*once && !time.Now().Before(deadline) {
			return errors.New("publisher deadline reached before final publication")
		}
		data, e := readBounded(filepath.Join(*source, "samples.jsonl"))
		var summary []byte
		done := false
		if e == nil {
			var report []byte
			report, e = readBounded(filepath.Join(*source, "REPORT.md"))
			if e == nil {
				summary, done, e = render(data, report)
			}
		}
		if e == nil {
			e = publish(*checkout, summary)
		}
		if e != nil {
			fmt.Fprintln(os.Stderr, time.Now().UTC().Format(time.RFC3339), "publication failed; will retry")
		} else {
			fmt.Println(time.Now().UTC().Format(time.RFC3339), "published")
		}
		if *once {
			return e
		}
		if e == nil && done {
			return nil
		}
		if !time.Now().Before(deadline) {
			return errors.New("publisher deadline reached before final publication")
		}
		time.Sleep(min(time.Minute, time.Until(deadline)))
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
