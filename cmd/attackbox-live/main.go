// attackbox-live serves a loopback dashboard of public gateway traffic.
// It follows the host capture files over the existing SSH alias and polls
// New Relic for pre-HTTP connections. Captured text is data: it is parsed,
// bounded, kept in memory only, and sent to the page as JSON.
package main

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web
var webFS embed.FS

const (
	maxLine  = 128 << 10 // one capture record stays under this
	feedSize = 300
	topSize  = 100
	flowSize = 10
)

type event struct {
	Seq           uint64      `json:"seq"`
	Time          time.Time   `json:"time"`
	Kind          string      `json:"kind"`   // request or connection
	Source        string      `json:"source"` // capture or newrelic
	IP            string      `json:"ip"`
	Own           bool        `json:"own,omitempty"` // the source is one of the operator's own addresses
	Port          int         `json:"port"`
	Endpoint      string      `json:"endpoint"`
	Method        string      `json:"method,omitempty"`
	Target        string      `json:"target,omitempty"`
	Host          string      `json:"host,omitempty"`
	UserAgent     string      `json:"user_agent,omitempty"`
	Route         string      `json:"route,omitempty"`
	Status        int         `json:"status,omitempty"`
	Probe         string      `json:"probe,omitempty"`
	Proto         string      `json:"proto,omitempty"`
	Outcome       string      `json:"outcome,omitempty"`
	SNI           string      `json:"sni,omitempty"`
	ContentType   string      `json:"content_type,omitempty"`
	Model         string      `json:"model,omitempty"`
	BodyBytes     int64       `json:"body_bytes,omitempty"`
	BodyTruncated bool        `json:"body_truncated,omitempty"`
	BodySHA256    string      `json:"body_sha256,omitempty"`
	Preview       string      `json:"preview,omitempty"`
	Headers       [][2]string `json:"headers,omitempty"`
	Body          string      `json:"body,omitempty"`

	id  string // New Relic span id, for de-duplication
	hay string // lower-case text that the filter searches
}

func clip(s string, n int) string {
	if len(s) > n {
		return strings.ToValidUTF8(s[:n], "")
	}
	return s
}

// extractPreview derives a plain-text preview from the request body for the feed.
func extractPreview(body string) string {
	if body == "" {
		return ""
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err == nil {
		if s, ok := obj["prompt"].(string); ok && s != "" {
			return s
		}
		if msgs, ok := obj["messages"].([]any); ok && len(msgs) > 0 {
			if last, ok := msgs[len(msgs)-1].(map[string]any); ok {
				if content, ok := last["content"].(string); ok && content != "" {
					return content
				}
				if parts, ok := last["content"].([]any); ok {
					var texts []string
					for _, p := range parts {
						if pm, ok := p.(map[string]any); ok {
							if text, ok := pm["text"].(string); ok && text != "" {
								texts = append(texts, text)
							}
						}
					}
					if len(texts) > 0 {
						return strings.Join(texts, " ")
					}
				}
			}
		}
		if s, ok := obj["input"].(string); ok && s != "" {
			return s
		}
		if arr, ok := obj["input"].([]any); ok && len(arr) > 0 {
			if s, ok := arr[0].(string); ok && s != "" {
				return s
			}
		}
	}
	return body
}

// cleanPreview makes one line of at most 160 runes; only the start of the text is read.
func cleanPreview(s string) string {
	s = strings.ToValidUTF8(s[:min(len(s), 1024)], "")
	s = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, s)), " ")
	if r := []rune(s); len(r) > 160 {
		return string(r[:160]) + "…"
	}
	return s
}

// finish derives the endpoint label and the filter text.
func (e *event) finish() {
	p := ":" + strconv.Itoa(e.Port) + " "
	target, _, _ := strings.Cut(e.Target, "?")
	switch {
	case e.Kind == "connection":
		e.Endpoint = p + "pre-HTTP " + e.Outcome
	case e.Route != "" && e.Route != "/unmatched":
		e.Endpoint = p + e.Route
	case target != "":
		e.Endpoint = p + clip(target, 80)
	case e.Probe != "":
		e.Endpoint = p + "/unmatched (" + e.Probe + ")"
	default:
		e.Endpoint = p + "/unmatched"
	}
	e.Preview = cleanPreview(extractPreview(e.Body))
	e.hay = strings.ToLower(strings.Join([]string{e.IP, e.Method, e.Target, e.Host, e.UserAgent, e.Route,
		e.Probe, e.Outcome, e.Model, strconv.Itoa(e.Status), e.Body}, "\n"))
}

// parseCapture reads one line of the gateway capture file.
func parseCapture(line []byte, port int) (event, bool) {
	var c struct {
		Time          string      `json:"time"`
		Peer          string      `json:"peer"`
		Method        string      `json:"method"`
		Target        string      `json:"target"`
		Host          string      `json:"host"`
		UserAgent     string      `json:"user_agent"`
		Route         string      `json:"route"`
		Status        int         `json:"status"`
		Probe         string      `json:"probe"`
		Port          int         `json:"port"`
		Proto         string      `json:"proto"`
		Headers       [][2]string `json:"headers"`
		Body          string      `json:"body"`
		BodyBytes     int64       `json:"body_bytes"`
		BodySHA256    string      `json:"body_sha256"`
		BodyTruncated bool        `json:"body_truncated"`
	}
	if json.Unmarshal(line, &c) != nil {
		return event{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, c.Time)
	if err != nil {
		return event{}, false
	}
	if c.Port != 0 {
		port = c.Port
	}
	e := event{Time: t, Kind: "request", Source: "capture", IP: c.Peer, Port: port, Method: c.Method, Target: c.Target,
		Host: c.Host, UserAgent: c.UserAgent, Route: c.Route, Status: c.Status, Probe: c.Probe, Proto: c.Proto,
		Headers: c.Headers, Body: c.Body, BodyBytes: c.BodyBytes, BodySHA256: c.BodySHA256, BodyTruncated: c.BodyTruncated}
	e.finish()
	return e, true
}

type sourceStatus struct {
	State  string    `json:"state"`
	Detail string    `json:"detail,omitempty"`
	Last   time.Time `json:"last"`
}

type store struct {
	mu          sync.Mutex
	events      []event // sorted by time when dirty is false
	dirty       bool
	seq         uint64
	keep        int
	seen        map[string]struct{}
	captureFrom time.Time // earliest capture record; New Relic requests after it are duplicates
	status      map[string]sourceStatus
	own         map[string]bool // the operator's own addresses, such as the Mac egress and the host itself
}

func newStore(keep int) *store {
	return &store{keep: keep, seen: map[string]struct{}{}, status: map[string]sourceStatus{}}
}

func (s *store) add(e event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.Own = s.own[e.IP]
	if e.id != "" {
		if _, dup := s.seen[e.id]; dup {
			return
		}
		s.seen[e.id] = struct{}{}
	}
	if e.Source == "capture" && (s.captureFrom.IsZero() || e.Time.Before(s.captureFrom)) {
		s.captureFrom = e.Time
	}
	s.seq++
	e.Seq = s.seq
	if n := len(s.events); n > 0 && e.Time.Before(s.events[n-1].Time) {
		s.dirty = true
	}
	s.events = append(s.events, e)
	if len(s.events) > s.keep+s.keep/4 {
		s.sorted()
		for _, old := range s.events[:len(s.events)-s.keep] {
			delete(s.seen, old.id)
		}
		s.events = append([]event(nil), s.events[len(s.events)-s.keep:]...)
	}
}

func (s *store) sorted() {
	if s.dirty {
		sort.SliceStable(s.events, func(i, j int) bool { return s.events[i].Time.Before(s.events[j].Time) })
		s.dirty = false
	}
}

func (s *store) setStatus(name, state, detail string, last time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if last.IsZero() {
		last = s.status[name].Last
	}
	s.status[name] = sourceStatus{State: state, Detail: clip(detail, 200), Last: last}
}

func (s *store) find(seq uint64) (event, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].Seq == seq {
			return s.events[i], true
		}
	}
	return event{}, false
}

type ipRow struct {
	IP          string    `json:"ip"`
	Own         bool      `json:"own,omitempty"`
	Requests    int       `json:"requests"`
	Connections int       `json:"connections"`
	First       time.Time `json:"first"`
	Last        time.Time `json:"last"`
	UserAgent   string    `json:"user_agent"`
	UserAgents  int       `json:"user_agents"`
	Endpoints   int       `json:"endpoints"`
}

type portRow struct {
	Port        int       `json:"port"`
	Requests    int       `json:"requests"`
	Connections int       `json:"connections"`
	IPs         int       `json:"ips"`
	Last        time.Time `json:"last,omitzero"`
}

type node struct {
	ID    string `json:"id"`
	Count int    `json:"count"`
	IPs   int    `json:"ips,omitempty"`
}

type link struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Count  int    `json:"count"`
}

type tally struct {
	Events int `json:"events"`
	IPs    int `json:"ips"`
}

type view struct {
	Now         time.Time               `json:"now"`
	Since       time.Time               `json:"since"`
	Sources     map[string]sourceStatus `json:"sources"`
	OwnAddrs    []string                `json:"own_addresses"`
	Outside     tally                   `json:"outside"` // whole window, before the who, ip, endpoint and q filters
	Mine        tally                   `json:"own"`
	Requests    int                     `json:"requests"`
	Connections int                     `json:"connections"`
	IPs         int                     `json:"ips"`
	Timeline    [][2]int                `json:"timeline"` // per bucket: requests, connections
	Top         []ipRow                 `json:"top"`
	Endpoints   []node                  `json:"endpoints"`
	FlowSources []node                  `json:"flow_sources"`
	FlowTargets []node                  `json:"flow_targets"`
	FlowLinks   []link                  `json:"flow_links"`
	Feed        []event                 `json:"feed"`
	Ports       []portRow               `json:"ports"`
}

const other = "other"

// state aggregates the events of one window. who selects outside traffic (default), "own" or "all";
// ip, endpoint and port match exactly; q matches a substring. ports is the list of configured listener ports.
func (s *store) state(now time.Time, window time.Duration, who, ip, endpoint, q string, port int, ports []int) view {
	const buckets = 60
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sorted()
	since := now.Add(-window)
	v := view{Now: now, Since: since, Sources: map[string]sourceStatus{}, Timeline: make([][2]int, buckets)}
	for k, st := range s.status {
		v.Sources[k] = st
	}
	for a := range s.own {
		v.OwnAddrs = append(v.OwnAddrs, a)
	}
	sort.Strings(v.OwnAddrs)
	q = strings.ToLower(q)
	type agg struct {
		row ipRow
		uas map[string]int
		eps map[string]struct{}
	}
	ips := map[string]*agg{}
	eps := map[string]*node{}
	epIPs := map[link]int{} // Source is the IP, Target the endpoint
	counted := map[string]bool{}
	type portAgg struct {
		row portRow
		ips map[string]bool
	}
	portMap := map[int]*portAgg{}
	for i := len(s.events) - 1; i >= 0; i-- {
		e := &s.events[i]
		if e.Time.Before(since) {
			break
		}
		if e.Time.After(now) ||
			(e.Source == "newrelic" && e.Kind == "request" && !s.captureFrom.IsZero() && !e.Time.Before(s.captureFrom)) {
			continue
		}
		side := &v.Outside
		if e.Own {
			side = &v.Mine
		}
		side.Events++
		if !counted[e.IP] {
			counted[e.IP] = true
			side.IPs++
		}
		if (who != "all" && e.Own != (who == "own")) || (ip != "" && e.IP != ip) || (endpoint != "" && e.Endpoint != endpoint) ||
			(q != "" && !strings.Contains(e.hay, q)) {
			continue
		}
		// Counted before the port filter, so the ports table still shows the other ports while one is selected.
		pa := portMap[e.Port]
		if pa == nil {
			pa = &portAgg{row: portRow{Port: e.Port, Last: e.Time}, ips: map[string]bool{}}
			portMap[e.Port] = pa
		}
		if e.Kind == "connection" {
			pa.row.Connections++
		} else {
			pa.row.Requests++
		}
		pa.ips[e.IP] = true
		if port != 0 && e.Port != port {
			continue
		}
		a := ips[e.IP]
		if a == nil {
			a = &agg{row: ipRow{IP: e.IP, Own: e.Own, Last: e.Time}, uas: map[string]int{}, eps: map[string]struct{}{}}
			ips[e.IP] = a
		}
		a.row.First = e.Time
		a.eps[e.Endpoint] = struct{}{}
		b := int(e.Time.Sub(since) * buckets / window)
		if b >= buckets {
			b = buckets - 1
		}
		if e.Kind == "connection" {
			v.Connections++
			a.row.Connections++
			v.Timeline[b][1]++
		} else {
			v.Requests++
			a.row.Requests++
			v.Timeline[b][0]++
			if e.UserAgent != "" {
				a.uas[e.UserAgent]++
			}
		}
		n := eps[e.Endpoint]
		if n == nil {
			n = &node{ID: e.Endpoint}
			eps[e.Endpoint] = n
		}
		n.Count++
		epIPs[link{Source: e.IP, Target: e.Endpoint}]++
		if len(v.Feed) < feedSize {
			f := *e
			f.Headers, f.Body = nil, ""
			v.Feed = append(v.Feed, f)
		}
	}
	v.IPs = len(ips)
	for _, a := range ips {
		a.row.UserAgents, a.row.Endpoints = len(a.uas), len(a.eps)
		best := 0
		for ua, n := range a.uas {
			if n > best || (n == best && ua < a.row.UserAgent) {
				best, a.row.UserAgent = n, ua
			}
		}
		v.Top = append(v.Top, a.row)
	}
	sort.Slice(v.Top, func(i, j int) bool {
		a, b := v.Top[i], v.Top[j]
		if x, y := a.Requests+a.Connections, b.Requests+b.Connections; x != y {
			return x > y
		}
		return a.IP < b.IP
	})
	for l := range epIPs {
		eps[l.Target].IPs++
	}
	for _, n := range eps {
		v.Endpoints = append(v.Endpoints, *n)
	}
	sort.Slice(v.Endpoints, func(i, j int) bool {
		if v.Endpoints[i].Count != v.Endpoints[j].Count {
			return v.Endpoints[i].Count > v.Endpoints[j].Count
		}
		return v.Endpoints[i].ID < v.Endpoints[j].ID
	})

	// The flow keeps the busiest sources and endpoints and folds the rest into "other".
	left, right := map[string]bool{}, map[string]bool{}
	for i := range min(len(v.Top), flowSize) {
		left[v.Top[i].IP] = true
	}
	for i := range min(len(v.Endpoints), flowSize) {
		right[v.Endpoints[i].ID] = true
	}
	links, lsum, rsum := map[link]int{}, map[string]int{}, map[string]int{}
	for l, n := range epIPs {
		if !left[l.Source] {
			l.Source = other
		}
		if !right[l.Target] {
			l.Target = other
		}
		links[l] += n
		lsum[l.Source] += n
		rsum[l.Target] += n
	}
	for l, n := range links {
		l.Count = n
		v.FlowLinks = append(v.FlowLinks, l)
	}
	sort.Slice(v.FlowLinks, func(i, j int) bool {
		a, b := v.FlowLinks[i], v.FlowLinks[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.Source+"\n"+a.Target < b.Source+"\n"+b.Target
	})
	v.FlowSources, v.FlowTargets = flowNodes(lsum), flowNodes(rsum)
	if len(v.Top) > topSize {
		v.Top = v.Top[:topSize]
	}
	if len(v.Endpoints) > topSize {
		v.Endpoints = v.Endpoints[:topSize]
	}
	for _, p := range ports {
		if portMap[p] == nil {
			portMap[p] = &portAgg{row: portRow{Port: p}, ips: map[string]bool{}}
		}
	}
	for _, pa := range portMap {
		pa.row.IPs = len(pa.ips)
		v.Ports = append(v.Ports, pa.row)
	}
	sort.Slice(v.Ports, func(i, j int) bool { return v.Ports[i].Port < v.Ports[j].Port })
	return v
}

func flowNodes(sum map[string]int) []node {
	out := make([]node, 0, len(sum))
	for id, n := range sum {
		out = append(out, node{ID: id, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].ID == other) != (out[j].ID == other) {
			return out[j].ID == other
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// readLines calls fn for each complete line. An over-long line gives fn(nil) so that the line count stays exact.
func readLines(r io.Reader, fn func([]byte)) error {
	br := bufio.NewReaderSize(r, maxLine)
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = br.ReadSlice('\n')
			}
			if err != nil {
				return err
			}
			fn(nil)
			continue
		}
		if err != nil {
			return err // a partial last line is not counted; the next read starts there
		}
		fn(line)
	}
}

type capture struct {
	ssh   string // SSH alias; empty reads dir on this machine
	dir   string
	days  int
	port  int
	lines map[string]int // complete lines consumed for each day file
}

func (c *capture) command(ctx context.Context, day string, follow bool) *exec.Cmd {
	args := []string{"-n", "+" + strconv.Itoa(c.lines[day]+1)}
	if follow {
		args = append(args, "-F")
	}
	args = append(args, path.Join(c.dir, "capture-"+day+".jsonl"))
	if c.ssh == "" {
		return exec.CommandContext(ctx, "/usr/bin/tail", args...)
	}
	// dir and the alias pass a strict pattern in main, so the remote command line holds no shell syntax.
	return exec.CommandContext(ctx, "/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2", c.ssh, "tail "+strings.Join(args, " "))
}

type tailWriter struct{ b []byte }

func (w *tailWriter) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	if len(w.b) > 400 {
		w.b = w.b[len(w.b)-400:]
	}
	return len(p), nil
}

func (c *capture) read(ctx context.Context, st *store, day string, follow bool) string {
	cmd := c.command(ctx, day, follow)
	var stderr tailWriter
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		return "cannot start the reader"
	}
	if follow {
		st.setStatus("capture", "following", "", time.Time{})
	}
	_ = readLines(out, func(line []byte) {
		c.lines[day]++
		if e, ok := parseCapture(line, c.port); ok {
			st.add(e)
			if follow {
				st.setStatus("capture", "following", "", e.Time) // the record time, not the read time
			}
		}
	})
	_ = cmd.Wait()
	return strings.TrimSpace(string(bytes.ToValidUTF8(stderr.b, nil)))
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func (c *capture) run(ctx context.Context, st *store) {
	now := time.Now().UTC()
	for d := c.days - 1; d >= 1 && ctx.Err() == nil; d-- {
		c.read(ctx, st, now.AddDate(0, 0, -d).Format("20060102"), false)
	}
	for ctx.Err() == nil {
		now = time.Now().UTC()
		// The gateway starts a new file each UTC day. Follow the old one a little longer to read its last lines.
		end := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 10, 0, time.UTC)
		dayCtx, cancel := context.WithDeadline(ctx, end)
		detail := c.read(dayCtx, st, now.Format("20060102"), true)
		cancel()
		if ctx.Err() == nil && time.Now().Before(end) {
			st.setStatus("capture", "waiting", detail, time.Time{})
			sleep(ctx, 5*time.Second)
		}
	}
}

var nrURL = "https://api.newrelic.com/graphql"

type newRelic struct {
	key     string
	account uint64
	service string
	port    int
}

func (n newRelic) query(ctx context.Context, since time.Time) ([]map[string]any, error) {
	nrql := "SELECT timestamp, id, name, `client.address`, `attackbox.connection.outcome`, `attackbox.tls.sni`, `http.route`, " +
		"`http.request.method`, `http.response.status_code`, `attackbox.probe.class`, `attackbox.request.content_type`, " +
		"`http.request.body.size`, `gen_ai.request.model`, `server.port` FROM Span WHERE service.name = '" + n.service +
		// Spans without client.address come from loopback or private peers, such as the container health check.
		"' AND name IN ('public.request', 'public.connection') AND `client.address` IS NOT NULL SINCE " + strconv.FormatInt(since.UnixMilli(), 10) + " LIMIT MAX"
	quoted, _ := json.Marshal(nrql)
	body, _ := json.Marshal(map[string]string{"query": fmt.Sprintf("{actor{account(id:%d){nrql(query:%s,timeout:20){results}}}}", n.account, quoted)})
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, nrURL, bytes.NewReader(body))
	req.Header.Set("API-Key", n.key)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.New("query transport failed")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("query returned HTTP %d", res.StatusCode)
	}
	var r struct {
		Data struct {
			Actor struct {
				Account struct {
					NRQL struct {
						Results []map[string]any `json:"results"`
					} `json:"nrql"`
				} `json:"account"`
			} `json:"actor"`
		} `json:"data"`
		Errors []json.RawMessage `json:"errors"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, 16<<20)).Decode(&r) != nil || len(r.Errors) > 0 {
		return nil, errors.New("query response was not usable")
	}
	return r.Data.Actor.Account.NRQL.Results, nil
}

func (n newRelic) event(row map[string]any) (event, bool) {
	str := func(k string) string { s, _ := row[k].(string); return clip(s, 256) }
	num := func(k string) int64 { f, _ := row[k].(float64); return int64(f) }
	e := event{Time: time.UnixMilli(num("timestamp")), Source: "newrelic", id: str("id"), IP: str("client.address"), Port: n.port,
		Route: str("http.route"), Method: str("http.request.method"), Status: int(num("http.response.status_code")),
		Probe: str("attackbox.probe.class"), ContentType: str("attackbox.request.content_type"), Model: str("gen_ai.request.model"),
		BodyBytes: num("http.request.body.size"), Outcome: str("attackbox.connection.outcome"), SNI: str("attackbox.tls.sni")}
	if p := num("server.port"); p > 0 {
		e.Port = int(p)
	}
	switch str("name") {
	case "public.request":
		e.Kind = "request"
	case "public.connection":
		e.Kind = "connection"
	default:
		return event{}, false
	}
	if e.id == "" || num("timestamp") == 0 {
		return event{}, false
	}
	e.finish()
	return e, true
}

func (n newRelic) run(ctx context.Context, st *store) {
	// shortcut: one query returns at most 5000 spans, so the first load can miss older spans on a busy day.
	since := time.Now().Add(-24 * time.Hour)
	for ctx.Err() == nil {
		rows, err := n.query(ctx, since)
		if err != nil {
			st.setStatus("newrelic", "error", err.Error(), time.Time{})
		} else {
			st.setStatus("newrelic", "ok", "", time.Now())
			for _, row := range rows {
				if e, ok := n.event(row); ok {
					st.add(e)
				}
			}
			// Spans can arrive late; query a little overlap and let the span id remove duplicates.
			since = time.Now().Add(-5 * time.Minute)
		}
		sleep(ctx, 20*time.Second)
	}
}

var windows = map[string]time.Duration{"15m": 15 * time.Minute, "1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour}

// handler serves the page and the JSON API. It accepts only the loopback names in hosts,
// so a web page on another origin cannot read captured data through DNS rebinding.
func handler(st *store, hosts map[string]bool, ports []int) http.Handler {
	mux := http.NewServeMux()
	web, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServerFS(web))
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		window, ok := windows[q.Get("window")]
		if !ok {
			window = time.Hour
		}
		port, _ := strconv.Atoi(q.Get("port"))
		if port < 1 || port > 65535 {
			port = 0
		}
		writeJSON(w, st.state(time.Now(), window, q.Get("who"), q.Get("ip"), q.Get("endpoint"), clip(q.Get("q"), 200), port, ports))
	})
	mux.HandleFunc("/api/event", func(w http.ResponseWriter, r *http.Request) {
		seq, _ := strconv.ParseUint(r.URL.Query().Get("seq"), 10, 64)
		e, ok := st.find(seq)
		if !ok {
			http.Error(w, "event is no longer in memory", http.StatusNotFound)
			return
		}
		writeJSON(w, e)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hosts[r.Host] || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

// loopbackHosts returns the Host values that the server accepts, or an error for a non-loopback address.
func loopbackHosts(listen string) (map[string]bool, error) {
	host, port, err := net.SplitHostPort(listen)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		return nil, errors.New("listen address must be a loopback IP and port, for example 127.0.0.1:8765")
	}
	return map[string]bool{listen: true, "localhost:" + port: true}, nil
}

var (
	aliasRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]*$`)
	dirRe     = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	serviceRe = regexp.MustCompile(`^[a-z0-9-]+$`)
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8765", "loopback address of the dashboard")
	alias := flag.String("ssh", "attackbox", "SSH alias of the host that holds the capture files")
	local := flag.String("dir", "", "read capture files from this local directory and do not use SSH")
	remote := flag.String("remote-dir", "/var/lib/attackbox-public-capture/requests", "capture directory on the host")
	days := flag.Int("days", 2, "UTC days of capture files to load (1 to 7)")
	service := flag.String("service", "attackbox-public-443", "New Relic service name of the public gateway")
	port := flag.Int("port", 443, "listener port for records that do not carry one")
	portsFlag := flag.String("ports", "80,443,1234,3000,4000,8000,8080,8188,8888,11434", "comma-separated listener ports always listed")
	keep := flag.Int("keep", 200000, "events kept in memory")
	own := flag.String("own", "", "comma-separated addresses of your own machines, for example your egress address and the host; the page shows their traffic apart from outside traffic")
	flag.Parse()
	var ports []int
	for _, s := range strings.Split(*portsFlag, ",") {
		p, parseErr := strconv.Atoi(strings.TrimSpace(s))
		if parseErr != nil || p < 1 || p > 65535 {
			fmt.Fprintln(os.Stderr, "attackbox-live: -ports must be 1 to 16 comma-separated ports, each 1 to 65535")
			os.Exit(2)
		}
		ports = append(ports, p)
	}
	if len(ports) < 1 || len(ports) > 16 {
		fmt.Fprintln(os.Stderr, "attackbox-live: -ports must be 1 to 16 comma-separated ports, each 1 to 65535")
		os.Exit(2)
	}

	hosts, err := loopbackHosts(*listen)
	c := &capture{ssh: *alias, dir: *remote, days: *days, port: *port, lines: map[string]int{}}
	if *local != "" {
		c.ssh, c.dir = "", *local
	}
	switch {
	case err != nil:
	case c.ssh != "" && !aliasRe.MatchString(c.ssh):
		err = errors.New("-ssh must be a plain SSH alias")
	case !dirRe.MatchString(c.dir):
		err = errors.New("the capture directory must be an absolute path of letters, digits, dot, dash, underscore and slash")
	case *days < 1 || *days > 7 || *keep < 1000 || !serviceRe.MatchString(*service):
		err = errors.New("-days must be 1 to 7, -keep at least 1000, and -service a lower-case name")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "attackbox-live:", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	st := newStore(*keep)
	st.own = map[string]bool{}
	for _, ip := range strings.Split(*own, ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			st.own[ip] = true
		}
	}
	st.setStatus("capture", "waiting", "", time.Time{})
	go c.run(ctx, st)
	account, _ := strconv.ParseUint(os.Getenv("NEW_RELIC_ACCOUNT_ID"), 10, 64)
	if key := os.Getenv("NEW_RELIC_API_KEY"); key != "" && account != 0 {
		go newRelic{key: key, account: account, service: *service, port: *port}.run(ctx, st)
	} else {
		st.setStatus("newrelic", "off", "set NEW_RELIC_API_KEY and NEW_RELIC_ACCOUNT_ID to see pre-HTTP connections", time.Time{})
	}

	srv := &http.Server{Addr: *listen, Handler: handler(st, hosts, ports), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	fmt.Fprintf(os.Stderr, "attackbox-live: open http://%s/\n", *listen)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "attackbox-live:", err)
		os.Exit(1)
	}
}
