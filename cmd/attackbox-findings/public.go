package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type otlpSpan struct {
	Attributes []struct {
		Key   string          `json:"key"`
		Value json.RawMessage `json:"value"`
	} `json:"attributes"`
}

type otlpTrace struct {
	ResourceSpans []struct {
		ScopeSpans []struct {
			Spans []otlpSpan `json:"spans"`
		} `json:"scopeSpans"`
	} `json:"resourceSpans"`
}

type captureRecord struct {
	Route      string `json:"route"`
	Status     int    `json:"status"`
	Method     string `json:"method"`
	RemoteAddr string `json:"remote_addr"`
}

func readEvidence(archiveDir string, day time.Time) ([]captureRecord, []otlpSpan, error) {
	zone, _ := time.LoadLocation("America/New_York")
	start := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, zone).UTC()
	var captures []captureRecord
	var spans []otlpSpan
	capturePattern := fmt.Sprintf("/var/lib/attackbox-public-capture/requests/capture-%04d%02d%02d.jsonl", start.Year(), start.Month(), start.Day())
	var captureData, otlpData []byte
	var err error
	if archiveDir != "" {
		capturePath := filepath.Join(archiveDir, capturePattern)
		otlpPath := filepath.Join(archiveDir, "/var/lib/attackbox-evidence/public-otel/traces.jsonl")
		captureData, _ = os.ReadFile(capturePath)
		otlpData, _ = os.ReadFile(otlpPath)
	} else {
		captureData, err = sshRead(capturePattern)
		if err != nil {
			return nil, nil, err
		}
		otlpData, err = sshRead("/var/lib/attackbox-evidence/public-otel/traces.jsonl")
		if err != nil {
			return nil, nil, err
		}
	}
	scanner := bufio.NewScanner(bytes.NewReader(captureData))
	for scanner.Scan() {
		var rec captureRecord
		if json.Unmarshal(scanner.Bytes(), &rec) == nil {
			captures = append(captures, rec)
		}
	}
	scanner = bufio.NewScanner(bytes.NewReader(otlpData))
	for scanner.Scan() {
		var trace otlpTrace
		if json.Unmarshal(scanner.Bytes(), &trace) == nil {
			for _, rs := range trace.ResourceSpans {
				for _, ss := range rs.ScopeSpans {
					spans = append(spans, ss.Spans...)
				}
			}
		}
	}
	return captures, spans, nil
}

func sshRead(path string) ([]byte, error) {
	cmd := exec.Command("/bin/bash", "scripts/vultr-launch.sh", "ssh", fmt.Sprintf("cat %s 2>/dev/null || true", path))
	cmd.Stdin = bytes.NewReader(nil)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func publicReport(day, until time.Time, archiveDir string) ([]byte, error) {
	captures, spans, err := readEvidence(archiveDir, day)
	if err != nil {
		return nil, err
	}
	return renderPublic(captures, spans, day, until)
}

func minTime(a, b time.Time) time.Time {
	if !b.IsZero() && b.Before(a) {
		return b
	}
	return a
}

func renderPublic(captures []captureRecord, spans []otlpSpan, day, until time.Time) ([]byte, error) {
	requestCount := 0
	unattributedCount := 0
	table := map[string]float64{}
	for _, c := range captures {
		if c.RemoteAddr == "" {
			unattributedCount++
			continue
		}
		requestCount++
		route := c.Route
		if !routes[route] && route != "/unmatched" && route != "/openai/deployments/{deployment}/chat/completions" {
			route = "other"
		}
		status := fmt.Sprintf("%d", c.Status)
		if !statusKey.MatchString("http_status:" + status) {
			status = "unknown"
		}
		method := c.Method
		if !set("GET POST PUT PATCH DELETE HEAD OPTIONS CONNECT TRACE _OTHER")[method] {
			method = "_OTHER"
		}
		table[fmt.Sprintf("`%s` | `%s` | %s", method, route, status)]++
	}
	connectionTotals := map[string]float64{}
	for _, span := range spans {
		for _, attr := range span.Attributes {
			if attr.Key == "attackbox.connection.outcome" {
				var val struct {
					StringValue string `json:"stringValue"`
				}
				if json.Unmarshal(attr.Value, &val) == nil {
					outcome := val.StringValue
					if !set("tls_failed no_data no_request not_tls rejected")[outcome] {
						outcome = "other"
					}
					connectionTotals[outcome]++
				}
			}
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Security debrief — %s\n\nUpdated from local evidence at %s. HTTP and connection totals cover the Eastern calendar day through %s. The end time trails the query by one minute. Later runs re-query the full day to include delayed arrivals.\n\n## What we observed\n\nThe HTTPS decoy on port 443 recorded **%d request records with a recorded transport peer**, representing **%d distinct span IDs**. Distinct counts can be estimates above 50,000 IDs. These are telemetry observations, not confirmed attackers or exploits. Operator probes can be present. The captured metadata cannot identify the purpose of a caller.\n\n**%d additional request spans without a recorded peer are excluded from the visitor table.** Older versions exported loopback health checks with no peer.\n\n| Method | Route | Status | Requests |\n| --- | --- | --- | --- |\n", clockLabel(day), clockLabel(time.Now()), clockLabel(until), requestCount, requestCount, unattributedCount)
	keys := make([]string, 0, len(table))
	for k := range table {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "| %s | %.0f |\n", k, table[k])
	}
	b.WriteString("\n## Connection activity and service response\n\nA request to `/unmatched` reached an unrecognized route. A 404 response shows that the route was not served; the route category does not preserve the attempted path or prove an exploit attempt. A 2xx response shows HTTP success, not successful execution of an attack.\n\n")
	for _, k := range []string{"tls_failed", "no_data", "no_request", "not_tls", "rejected", "other"} {
		if n := connectionTotals[k]; n > 0 {
			fmt.Fprintf(&b, "- `%s`: %.0f connection span records.\n", k, n)
		}
	}
	b.WriteString("\nTLS failures, empty connections and plaintext on a TLS port are consistent with scanning, client errors or operator tests. They do not identify a tool, actor or exploit. Connections that end before HTTP do not have an HTTP response to inspect.\n\n## Telemetry receipt and limits\n\nLocal evidence collection replaced the external telemetry pipeline. The public profile records request metadata and response status. It does not retain request or response bodies. This evidence cannot reconstruct prompts, exact replies, tool instructions, attacker sessions or exploit success. The private proxy has a separate capture path; its counts below do not measure public HTTPS traffic.\n\nPublic-service and host health use separate collection paths. This report does not verify the provider firewall, complete packet capture or all telemetry pipelines. Raw addresses, identities, credentials, payloads and captured instructions are excluded. No captured command is executed and no observed destination is contacted.\n\nThe local publisher checks every five minutes. It commits only this daily report, with or without public activity.\n")
	return []byte(b.String()), nil
}
