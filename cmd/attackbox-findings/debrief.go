package main

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// This campaign takes place in November, after the Eastern daylight-time change.
func clockLabel(t time.Time) string {
	return t.In(time.FixedZone("EST", -5*60*60)).Format("Jan 2 15:04:05 EST") + " / " + t.UTC().Format("15:04:05 UTC")
}

func metric(s sample, key string) (float64, bool) {
	v, ok := s.Metrics[key]
	return v, ok && !math.IsNaN(v) && !math.IsInf(v, 0)
}

func debrief(b *strings.Builder, samples []sample, counts, notices map[string]int64) {
	last := samples[len(samples)-1]
	total, public, private := counts["http_total"], counts["http_public_source"], counts["http_private_source"]
	b.WriteString("## Assessment\n\n")
	switch {
	case public > 0:
		fmt.Fprintf(b, "**External-source activity needs review.** The proxy recorded %d requests with addresses classified as public. That classification alone does not identify an attacker or prove malicious intent. Inspect the original records before assigning an attack method or outcome.\n\n", public)
	case total > 0:
		fmt.Fprintf(b, "**No public-source requests were recorded in the collected HTTP evidence.** The proxy recorded %d requests, including %d from private, loopback or link-local addresses. These observations do not establish an attack or compromise.\n\n", total, private)
	default:
		b.WriteString("**No HTTP activity was recorded in the collected evidence.** This can mean no traffic or incomplete collection; it does not establish that the service was idle or safe.\n\n")
	}
	b.WriteString("These HTTP counts cover the private proxy, not the separate public decoy. The watcher does not re-check the provider firewall. Private-proxy silence does not measure public traffic.\n\n## What took place\n\n")
	if total > 0 {
		fmt.Fprintf(b, "The proxy recorded **%d HTTP requests**: %d with public-source addresses, %d with private/local addresses and %d with unparseable source addresses.\n\n", total, public, private, counts["http_source_unknown"])
		if counts["route:/v1/models"] > 0 {
			fmt.Fprintf(b, "The model-list endpoint received **%d requests**. This endpoint lists the models that the simulated AI service advertises. Requests here can be inventory checks or reconnaissance; the route alone does not show the caller's purpose.\n\n", counts["route:/v1/models"])
			if total == counts["route:/v1/models"] && total == private {
				b.WriteString("**Working interpretation:** all recorded HTTP activity targeted the model list from private/local addresses. This is consistent with routine service polling. The samples do not verify who made the requests or why.\n\n")
			}
		}
		type routeCount struct {
			name  string
			count int64
		}
		var other []routeCount
		for route := range routes {
			if route != "/v1/models" && counts["route:"+route] > 0 {
				other = append(other, routeCount{route, counts["route:"+route]})
			}
		}
		sort.Slice(other, func(i, j int) bool {
			if other[i].count == other[j].count {
				return other[i].name < other[j].name
			}
			return other[i].count > other[j].count
		})
		if len(other) > 0 {
			b.WriteString("Other requested surfaces:\n\n")
			for _, r := range other {
				fmt.Fprintf(b, "- `%s`: %d requests.\n", r.name, r.count)
			}
			b.WriteString("\nThese route categories do not reveal payloads, exploit techniques or a sequence of actions by one caller.\n\n")
		}
	}
	b.WriteString("## Service response and containment\n\n")
	var success, redirect, clientError, serverError int64
	for k, v := range counts {
		if statusKey.MatchString(k) {
			switch k[len("http_status:")] {
			case '2':
				success += v
			case '3':
				redirect += v
			case '4':
				clientError += v
			case '5':
				serverError += v
			}
		}
	}
	if total > 0 {
		fmt.Fprintf(b, "Recorded HTTP outcomes: **%d successful responses (2xx)**, %d redirects (3xx), %d client-error responses (4xx), and %d server-error responses (5xx). A 2xx status does not prove an exploit worked. This summary does not inspect response bodies or link status totals to individual routes.\n\n", success, redirect, clientError, serverError)
	}
	hostBlocks := counts["kernel:OUTPUT-DROP:"]
	containerBlocks := counts["kernel:CONTAINER-EGRESS-BLOCK:"]
	metadataBlocks := counts["kernel:METADATA-BLOCK:"] + counts["kernel:METADATA-BLOCK-OUT:"]
	fmt.Fprintf(b, "Firewall logs contained **%d host-output deny records**, **%d container-egress deny records**, and **%d metadata-access deny records**. These are logged packet denials, not unique sessions or attackers. They can include routine blocked traffic. The aggregates do not link a deny record to an HTTP request or prove that all unwanted traffic was blocked.\n\n", hostBlocks, containerBlocks, metadataBlocks)
	if counts["falco_events"] > 0 {
		fmt.Fprintf(b, "The runtime sensor recorded **%d timestamped Falco events** inside the collection windows. Review the original rule and process context before treating these as execution, persistence or compromise.\n\n", counts["falco_events"])
	} else {
		b.WriteString("No timestamped Falco events were counted inside the collection windows. The bounded file tail can miss events, so this does not rule out process activity.\n\n")
	}
	b.WriteString("## Host and logging health\n\n")
	observed, running := 0, 0
	for name := range components {
		if v, ok := metric(last, `attackbox_component_running{component="`+name+`"}`); ok {
			observed++
			if v == 1 {
				running++
			}
		}
	}
	fmt.Fprintf(b, "At the latest snapshot, **%d of %d expected components reported running**; running-state values were available for %d. Running state does not prove full application or logging health.\n\n", running, len(components), observed)
	if disk, ok := metric(last, "root_disk_used_percent"); ok {
		fmt.Fprintf(b, "Root disk use was **%.0f%%**. ", disk)
	}
	if ram, ok := metric(last, "MemAvailable_KiB"); ok {
		fmt.Fprintf(b, "Available memory was **%.2f GiB**. ", ram/(1024*1024))
	}
	b.WriteString("\n\n")
	if queue, ok := metric(last, "otelcol_exporter_queue_size"); ok {
		fmt.Fprintf(b, "The telemetry exporter reported a queue size of **%g** at the latest snapshot. A nonzero queue can be transient; one sample does not prove a delivery fault. ", queue)
	}
	b.WriteString("The watcher does not query New Relic for receipt. Export counters and a running collector are not end-to-end delivery proof.\n\n")
	if counts["failed_service_sample_occurrences"] > 0 {
		fmt.Fprintf(b, "Failed systemd units were reported **%d times across snapshots**. One persistent failure can appear repeatedly. These counts are not distinct outages and do not identify a security incident.\n\n", counts["failed_service_sample_occurrences"])
	}
	b.WriteString("## Evidence gaps and next checks\n\n")
	if notices["ssh_collect_failed"] > 0 {
		fmt.Fprintf(b, "- **Collection failed in %d snapshots.** Treat those windows as incomplete; do not interpret their missing activity as silence.\n", notices["ssh_collect_failed"])
	}
	if notices["falco_1000_row_tail_bound"] > 0 {
		fmt.Fprintf(b, "- The runtime-sensor read reached its 1,000-row tail limit in %d snapshots. Older events can fall outside the view.\n", notices["falco_1000_row_tail_bound"])
	}
	if notices["proxy_2000_row_cap"]+notices["kernel_2000_row_cap"] > 0 {
		b.WriteString("- Proxy or kernel journal reads reached their row cap. Activity counts can be lower than the actual totals.\n")
	}
	if counts["falco_unparsed"]+counts["falco_time_unparsed"] > 0 {
		b.WriteString("- Some runtime-sensor rows could not be parsed or timed. Re-reading an old tail can count the same problem again.\n")
	}
	if len(notices) > 0 {
		b.WriteString("- Collection warnings are present. Their exact labels and occurrence counts are in the technical evidence below.\n")
	}
	b.WriteString("- Confirm current ingress policy before describing this as a public attack campaign.\n- Use the original private logs and New Relic traces to establish actor sequences, payloads, exact responses and any exploit outcome. This aggregate report cannot establish them.\n- Check the latest observation time. The collector requires Mac power and connectivity; a stopped process can leave a running state.\n\n")
	b.WriteString("## Recent observation timeline\n\nEach row is one collection window. Rows are not linked attacker sessions. The table shows the latest 12 windows; totals above cover the full watch.\n\n| Window end (EST / UTC) | Observed activity | Collection status |\n| --- | --- | --- |\n")
	start := max(0, len(samples)-12)
	for _, s := range samples[start:] {
		status := "No warnings recorded"
		if len(s.Warnings) > 0 {
			status = fmt.Sprintf("%d collection/health warnings", len(s.Warnings))
		}
		for _, w := range s.Warnings {
			if w == "ssh_collect_failed" {
				status = "SSH collection failed; partial evidence"
			}
		}
		fmt.Fprintf(b, "| %s | %d HTTP requests (%d public-source); %d host-output denies; %d container-egress denies; %d metadata denies; %d runtime events | %s |\n", clockLabel(s.Until), s.Counts["http_total"], s.Counts["http_public_source"], s.Counts["kernel:OUTPUT-DROP:"], s.Counts["kernel:CONTAINER-EGRESS-BLOCK:"], s.Counts["kernel:METADATA-BLOCK:"]+s.Counts["kernel:METADATA-BLOCK-OUT:"], s.Counts["falco_events"], status)
	}
	b.WriteString("\nThis debrief uses fixed narrative rules and numeric observations. It does not execute captured text, contact observed sources or change the VPS. Raw requests, response bodies, addresses, identities and captured instructions are excluded from the public report.\n")
}
