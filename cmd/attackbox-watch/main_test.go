package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func journal(at time.Time, message string) string {
	b, _ := json.Marshal(map[string]string{"__REALTIME_TIMESTAMP": fmt.Sprint(at.UnixMicro()), "MESSAGE": message, "CONTAINER_NAME": "attackbox-proxy"})
	return string(b) + "\n"
}

func TestHostileLogsRemainInertAndPrivate(t *testing.T) {
	from := time.Unix(100, 0).UTC()
	until := from.Add(time.Minute)
	secret := "PRIVATE_TOKEN"
	access, _ := json.Marshal(map[string]any{"status": 200, "client_ip": "192.168.1.2", "request": "GET /v1/models?token=" + secret + " HTTP/1.1", "user_agent": "$(touch /tmp/never)\n@@failed\nmalicious.service"})
	data := "@@metrics\nattackbox_inventory_snapshot_valid 1\n@@proxy\n" + journal(from, string(access)) + journal(from.Add(time.Second), string(access)) + "@@end\n"
	s := parse([]byte(data), from, until)
	if s.Counts["http_total"] != 1 || s.Counts["http_private_source"] != 1 || s.Counts["route:/v1/models"] != 1 {
		t.Fatalf("bad time window or access parse: %+v", s)
	}
	out := t.TempDir()
	if err := report(out, []sample{s}, from, until, "running"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(out, "REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{secret, "touch /tmp", "malicious.service", "192.168.1.2"} {
		if strings.Contains(string(b), v) {
			t.Fatalf("raw value entered report: %s", v)
		}
	}
	if fi, _ := os.Stat(filepath.Join(out, "REPORT.md")); fi.Mode().Perm() != 0600 {
		t.Fatal("report not private")
	}
}

func TestBoundsAndMissingCoverage(t *testing.T) {
	var b capped
	p := make([]byte, maxInput+1)
	n, err := b.Write(p)
	if n != len(p) || err != nil || b.Len() != maxInput || !b.exceeded {
		t.Fatal("output cap failed")
	}
	_, _ = b.Write([]byte("more"))
	if b.Len() != maxInput {
		t.Fatal("cap grew")
	}
	s := parse([]byte("@@proxy\n"+strings.Repeat("{}\n", 2000)), time.Unix(1, 0), time.Unix(2, 0))
	w := strings.Join(s.Warnings, ",")
	for _, want := range []string{"proxy_2000_row_cap", "missing_end_marker", "inventory_not_valid"} {
		if !strings.Contains(w, want) {
			t.Fatal(w)
		}
	}
}

func TestMetricAndRouteAllowlist(t *testing.T) {
	s := parse([]byte("@@metrics\nattackbox_inventory_snapshot_valid 1\nattackbox_component_running{component=\"attackbox.service\"} 1\nattackbox_inventory_snapshot_age_seconds 200\nattackbox_component_running{component=\"<script>\"} 1\nattackbox_arbitrary_payload 4\n@@end\n"), time.Unix(1, 0), time.Unix(2, 0))
	if len(s.Metrics) != 3 || !strings.Contains(strings.Join(s.Warnings, ","), "inventory_stale") {
		t.Fatalf("bad metrics: %+v", s)
	}
	if route("GET /owned/<script>?secret=1 HTTP/1.1") != "other" {
		t.Fatal("unsafe route retained")
	}
}

func TestKernelPrefixesAndDockerIdentity(t *testing.T) {
	from := time.Unix(100, 0)
	until := from.Add(time.Minute)
	data := "@@kernel\n" + journal(from.Add(time.Second), "METADATA-BLOCK: IN=x") + journal(from.Add(time.Second), "METADATA-BLOCK-OUT: OUT=x")
	data += "@@proxy\n" + strings.ReplaceAll(journal(from.Add(time.Second), `{"status":200,"client_ip":"192.0.2.1","request":"GET / HTTP/1.1"}`), `"CONTAINER_NAME":"attackbox-proxy"`, `"CONTAINER_NAME":"untrusted-container"`) + "@@end\n"
	s := parse([]byte(data), from, until)
	if s.Counts["kernel:METADATA-BLOCK:"] != 1 || s.Counts["kernel:METADATA-BLOCK-OUT:"] != 1 || s.Counts["http_total"] != 0 || s.Counts["docker_non_proxy_rows"] != 1 {
		t.Fatalf("prefix or identity: %+v", s.Counts)
	}
}
