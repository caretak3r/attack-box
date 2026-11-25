package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type nrResult struct {
	Data struct {
		Actor struct {
			Account map[string]struct {
				Results []map[string]json.RawMessage `json:"results"`
			} `json:"account"`
		} `json:"actor"`
	} `json:"data"`
	Errors []json.RawMessage `json:"errors"`
}

func publicQuery(day, until time.Time) string {
	// This watch uses Eastern calendar days. Convert midnight to UTC once.
	zone, _ := time.LoadLocation("America/New_York")
	start := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, zone)
	window := fmt.Sprintf(" SINCE %d UNTIL %d", start.Unix(), until.Unix())
	base := "FROM Span SELECT count(*),uniqueCount(id, precision: 50000) WHERE service.name='attackbox-public-443' AND name="
	queries := map[string]string{
		"total":       base + "'public.request'" + window,
		"requests":    base + "'public.request'" + window + " FACET `http.route`,`http.response.status_code`,`http.request.method` LIMIT MAX",
		"connections": base + "'public.connection'" + window + " FACET `attackbox.connection.outcome` LIMIT MAX",
		"health":      "FROM Span SELECT latest(timestamp),latest(`attackbox.otel_dropped_spans_total`),latest(`attackbox.otel_export_failed_spans_total`),latest(`attackbox.rate_limited_requests`) WHERE service.name='attackbox-public-443' AND name='public.health' SINCE 10 minutes ago",
	}
	account, err := strconv.ParseUint(os.Getenv("NEW_RELIC_ACCOUNT_ID"), 10, 64)
	if err != nil || account == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "{actor{account(id:%d){", account)
	for _, name := range []string{"total", "requests", "connections", "health"} {
		q, _ := json.Marshal(queries[name])
		fmt.Fprintf(&b, "%s:nrql(query:%s,timeout:20){results}", name, q)
	}
	b.WriteString("}}}")
	return b.String()
}

func publicReport(day, until time.Time) ([]byte, error) {
	query := publicQuery(day, until)
	key := os.Getenv("NEW_RELIC_API_KEY")
	if query == "" || key == "" {
		return nil, errors.New("missing New Relic query credentials")
	}
	data, _ := json.Marshal(map[string]string{"query": query})
	ctx, cancel := context.WithDeadline(context.Background(), minTime(time.Now().Add(30*time.Second), operationDeadline))
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.newrelic.com/graphql", bytes.NewReader(data))
	req.Header.Set("API-Key", key)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.New("New Relic query transport failed")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || res.StatusCode != http.StatusOK || len(raw) > 1<<20 {
		return nil, errors.New("New Relic query HTTP failure or response limit")
	}
	return renderPublic(raw, day, until)
}

func minTime(a, b time.Time) time.Time {
	if !b.IsZero() && b.Before(a) {
		return b
	}
	return a
}

func number(row map[string]json.RawMessage, key string) (float64, bool) {
	var n float64
	err := json.Unmarshal(row[key], &n)
	return n, len(row[key]) > 0 && string(row[key]) != "null" && err == nil && n >= 0 && !math.IsNaN(n) && !math.IsInf(n, 0)
}

// All external labels are converted to bounded enums. No caller-controlled
// field, source address, request content or query response enters the report.
func renderPublic(raw []byte, day, until time.Time) ([]byte, error) {
	var r nrResult
	if json.Unmarshal(raw, &r) != nil || len(r.Errors) > 0 {
		return nil, errors.New("New Relic query JSON or GraphQL failure")
	}
	account := r.Data.Actor.Account
	for _, name := range []string{"total", "requests", "connections", "health"} {
		if _, ok := account[name]; !ok {
			return nil, errors.New("incomplete New Relic query")
		}
	}
	totals := account["total"].Results
	if len(totals) != 1 {
		return nil, errors.New("missing public request total")
	}
	total, ok := number(totals[0], "count")
	unique, uok := number(totals[0], "uniqueCount.id")
	if !ok || !uok {
		return nil, errors.New("invalid public request total")
	}
	table := map[string]float64{}
	var grouped float64
	for _, row := range account["requests"].Results {
		var facet []string
		n, ok := number(row, "count")
		if !ok || json.Unmarshal(row["facet"], &facet) != nil || len(facet) != 3 {
			return nil, errors.New("invalid request facets")
		}
		route, status, method := facet[0], facet[1], facet[2]
		if !routes[route] && route != "/unmatched" && route != "/openai/deployments/{deployment}/chat/completions" {
			route = "other"
		}
		if !statusKey.MatchString("http_status:" + status) {
			status = "unknown"
		}
		if !set("GET POST PUT PATCH DELETE HEAD OPTIONS CONNECT TRACE _OTHER")[method] {
			method = "_OTHER"
		}
		table[fmt.Sprintf("`%s` | `%s` | %s", method, route, status)] += n
		grouped += n
	}
	if grouped != total {
		return nil, errors.New("public request facets do not cover total")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Security debrief — %s\n\nUpdated from New Relic at %s. HTTP and connection totals cover the Eastern calendar day through %s. The end time trails the query by one minute. Later runs re-query the full day to include delayed arrivals.\n\n## What we observed\n\nThe HTTPS decoy on port 443 recorded **%.0f request span records**, representing **%.0f distinct span IDs**. Distinct counts can be estimates above 50,000 IDs. These are telemetry observations, not confirmed attackers or exploits. Operator probes, health checks and other traffic can be present. The captured metadata cannot identify the purpose of a caller.\n\n| Method | Route category | HTTP status | Span records |\n| --- | --- | ---: | ---: |\n", day.Format("2 January 2006"), clockLabel(time.Now().UTC().Truncate(time.Second)), clockLabel(until), total, unique)
	keys := make([]string, 0, len(table))
	for k := range table {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "| %s | %.0f |\n", k, table[k])
	}
	b.WriteString("\n## Connection activity and service response\n\nA request to `/unmatched` reached an unrecognized route. A 404 response shows that the route was not served; the route category does not preserve the attempted path or prove an exploit attempt. A 2xx response shows HTTP success, not successful execution of an attack.\n\n")
	connectionTotals := map[string]float64{}
	for _, row := range account["connections"].Results {
		var outcome string
		n, ok := number(row, "count")
		if !ok || json.Unmarshal(row["facet"], &outcome) != nil {
			return nil, errors.New("invalid connection facets")
		}
		if !set("tls_failed no_data no_request not_tls rejected")[outcome] {
			outcome = "other"
		}
		connectionTotals[outcome] += n
	}
	for _, k := range []string{"tls_failed", "no_data", "no_request", "not_tls", "rejected", "other"} {
		if n := connectionTotals[k]; n > 0 {
			fmt.Fprintf(&b, "- `%s`: %.0f connection span records.\n", k, n)
		}
	}
	b.WriteString("\nTLS failures, empty connections and plaintext on a TLS port are consistent with scanning, client errors or operator tests. They do not identify a tool, actor or exploit. Connections that end before HTTP do not have an HTTP response to inspect.\n\n## Telemetry receipt and limits\n\n")
	for _, row := range account["health"].Results {
		if n, ok := number(row, "latest.timestamp"); ok {
			fmt.Fprintf(&b, "Latest public-service heartbeat received in New Relic: **%s**.\n\n", clockLabel(time.UnixMilli(int64(n))))
		}
		for _, field := range []string{"attackbox.otel_dropped_spans_total", "attackbox.otel_export_failed_spans_total", "attackbox.rate_limited_requests"} {
			if n, ok := number(row, "latest."+field); ok {
				fmt.Fprintf(&b, "- `%s`: %.0f in the latest received heartbeat.\n", field, n)
			}
		}
	}
	if len(account["health"].Results) == 0 {
		b.WriteString("**No public heartbeat received in the queried ten-minute window.** Collection health needs review.\n")
	}
	b.WriteString("\nThe public profile records request metadata and response status. It does not retain request or response bodies. This evidence cannot reconstruct prompts, exact replies, tool instructions, attacker sessions or exploit success. The private proxy has a separate capture path; its counts below do not measure public HTTPS traffic.\n\nPublic-service and host health use separate collection paths. This report does not verify the provider firewall, complete packet capture or all New Relic pipelines. Raw addresses, identities, credentials, payloads and captured instructions are excluded. No captured command is executed and no observed destination is contacted.\n\nThe local publisher checks every five minutes. It commits only this daily report, with ordinary hooks and signing. Read the update and observation times: Mac sleep, power loss or network loss stops publication.\n")
	return []byte(b.String()), nil
}
