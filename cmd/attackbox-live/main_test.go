package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseCapture(t *testing.T) {
	line := `{"time":"2026-11-25T10:00:00.5Z","peer":"203.0.113.9","method":"POST","target":"/.env?a=1","host":"h","user_agent":"<script>x</script>","route":"/unmatched","status":404,"probe":"env_file","headers":[["Accept","*/*"]],"body":"k=v","body_bytes":3}`
	e, ok := parseCapture([]byte(line), 443)
	if !ok || e.IP != "203.0.113.9" || e.Endpoint != ":443 /.env" || e.Headers[0][1] != "*/*" || e.Body != "k=v" || e.Kind != "request" {
		t.Fatalf("unexpected event: %+v ok=%v", e, ok)
	}
	if e, _ := parseCapture([]byte(`{"time":"2026-11-25T10:00:00Z","route":"/v1/models","target":"/v1/models?x=1","port":8000}`), 443); e.Endpoint != ":8000 /v1/models" {
		t.Fatalf("matched route endpoint = %q", e.Endpoint)
	}
	for _, bad := range []string{``, `not json`, `{"time":"yesterday"}`} {
		if _, ok := parseCapture([]byte(bad), 443); ok {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestReadLinesCountsOverlongLines(t *testing.T) {
	in := "a\n" + strings.Repeat("x", maxLine+10) + "\nb\npartial"
	var got []string
	_ = readLines(strings.NewReader(in), func(l []byte) { got = append(got, strings.TrimSpace(string(l))) })
	if strings.Join(got, ",") != "a,,b" {
		t.Fatalf("lines = %q", got)
	}
}

func TestCaptureReadResumesWithoutDuplicates(t *testing.T) {
	dir, day := t.TempDir(), "20261125"
	file := filepath.Join(dir, "capture-"+day+".jsonl")
	rec := func(ip string) string {
		return `{"time":"2026-11-25T10:00:00Z","peer":"` + ip + `","method":"GET","target":"/","route":"/unmatched","status":404}` + "\n"
	}
	if err := os.WriteFile(file, []byte(rec("198.51.100.1")+rec("198.51.100.2")), 0o600); err != nil {
		t.Fatal(err)
	}
	st, c := newStore(1000), &capture{dir: dir, port: 443, lines: map[string]int{}}
	c.read(context.Background(), st, day, false)
	f, _ := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString(rec("198.51.100.3"))
	_ = f.Close()
	c.read(context.Background(), st, day, false)
	if len(st.events) != 3 || c.lines[day] != 3 || st.events[2].IP != "198.51.100.3" {
		t.Fatalf("events=%d lines=%d", len(st.events), c.lines[day])
	}
}

func TestStateAggregatesAndFilters(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	st := newStore(1000)
	add := func(e event) {
		e.Port = 443
		e.finish()
		st.add(e)
	}
	// New Relic also reports the two captured requests; only the one before the capture start may count.
	add(event{Time: now.Add(-50 * time.Minute), Kind: "request", Source: "newrelic", id: "old", IP: "203.0.113.1", Route: "/v1/models"})
	add(event{Time: now.Add(-10 * time.Minute), Kind: "request", Source: "newrelic", id: "dup", IP: "203.0.113.1", Route: "/unmatched", Probe: "env_file"})
	add(event{Time: now.Add(-10 * time.Minute), Kind: "request", Source: "newrelic", id: "dup", IP: "203.0.113.1", Route: "/unmatched"})
	add(event{Time: now.Add(-10 * time.Minute), Kind: "request", Source: "capture", IP: "203.0.113.1", Method: "GET", Target: "/.env", Route: "/unmatched", UserAgent: "zgrab"})
	add(event{Time: now.Add(-5 * time.Minute), Kind: "request", Source: "capture", IP: "203.0.113.2", Method: "POST", Target: "/v1/chat/completions", Route: "/v1/chat/completions", Body: "secret-body"})
	add(event{Time: now.Add(-2 * time.Minute), Kind: "connection", Source: "newrelic", id: "c1", IP: "203.0.113.1", Outcome: "tls_failed"})
	add(event{Time: now.Add(-3 * time.Hour), Kind: "connection", Source: "newrelic", id: "c0", IP: "203.0.113.3", Outcome: "no_data"})

	v := st.state(now, time.Hour, "", "", "", "", 0, nil)
	if v.Requests != 3 || v.Connections != 1 || v.IPs != 2 || len(v.Feed) != 4 {
		t.Fatalf("requests=%d connections=%d ips=%d feed=%d", v.Requests, v.Connections, v.IPs, len(v.Feed))
	}
	if top := v.Top[0]; top.IP != "203.0.113.1" || top.Requests != 2 || top.Connections != 1 || top.UserAgent != "zgrab" || top.Endpoints != 3 {
		t.Fatalf("top source = %+v", top)
	}
	if v.Feed[0].Outcome != "tls_failed" || len(v.FlowLinks) != 4 {
		t.Fatalf("feed head = %+v, links = %d", v.Feed[0], len(v.FlowLinks))
	}
	raw, _ := json.Marshal(v)
	if strings.Contains(string(raw), `"body":"`) {
		t.Fatal("the state view must not carry body fields in the feed")
	}
	if v := st.state(now, time.Hour, "", "203.0.113.2", "", "", 0, nil); v.Requests != 1 || v.Connections != 0 {
		t.Fatalf("ip filter: %+v", v)
	}
	if v := st.state(now, time.Hour, "", "", ":443 pre-HTTP tls_failed", "", 0, nil); v.Requests != 0 || v.Connections != 1 {
		t.Fatalf("endpoint filter: %+v", v)
	}
	if v := st.state(now, time.Hour, "", "", "", "ZGRAB", 0, nil); v.Requests != 1 {
		t.Fatalf("text filter: %+v", v)
	}
	if e, ok := st.find(4); !ok || e.Body != "secret-body" {
		t.Fatalf("find = %+v %v", e, ok)
	}
}

func TestStateSeparatesOwnTraffic(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	st := newStore(1000)
	st.own = map[string]bool{"198.51.100.9": true}
	for _, ip := range []string{"198.51.100.9", "198.51.100.9", "203.0.113.7"} {
		st.add(event{Time: now.Add(-time.Minute), Kind: "request", Source: "capture", IP: ip})
	}
	for who, want := range map[string]int{"": 1, "own": 2, "all": 3} {
		v := st.state(now, time.Hour, who, "", "", "", 0, nil)
		if v.Requests != want || v.Outside != (tally{1, 1}) || v.Mine != (tally{2, 1}) {
			t.Fatalf("who=%q: requests=%d outside=%+v own=%+v", who, v.Requests, v.Outside, v.Mine)
		}
	}
}

func TestStoreKeepsNewestEvents(t *testing.T) {
	st := newStore(1000)
	base := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	for i := range 1251 {
		st.add(event{Time: base.Add(time.Duration(1251-i) * time.Second), id: strconv.Itoa(i)})
	}
	if len(st.events) != 1000 || len(st.seen) != 1000 || !st.events[0].Time.Equal(base.Add(252*time.Second)) {
		t.Fatalf("events=%d seen=%d first=%v", len(st.events), len(st.seen), st.events[0].Time)
	}
}

func TestPortsTableAndFiltering(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	st := newStore(1000)
	st.own = map[string]bool{"198.51.100.9": true} // own traffic must not count while the page shows outside traffic
	st.add(event{Time: now.Add(-10 * time.Minute), Kind: "request", Source: "capture", IP: "203.0.113.1", Port: 443, Endpoint: ":443 /v1"})
	st.add(event{Time: now.Add(-8 * time.Minute), Kind: "request", Source: "capture", IP: "203.0.113.2", Port: 8080, Endpoint: ":8080 /test"})
	st.add(event{Time: now.Add(-6 * time.Minute), Kind: "connection", Source: "newrelic", IP: "203.0.113.3", Port: 8080, Endpoint: ":8080 pre-HTTP", id: "c1"})
	st.add(event{Time: now.Add(-4 * time.Minute), Kind: "request", Source: "capture", IP: "203.0.113.1", Port: 11434, Endpoint: ":11434 /api"})
	st.add(event{Time: now.Add(-2 * time.Minute), Kind: "request", Source: "capture", IP: "198.51.100.9", Port: 80, Endpoint: ":80 /own"})
	ports := []int{80, 443, 1234, 8000, 8080, 11434}
	v := st.state(now, time.Hour, "", "", "", "", 0, ports)
	if len(v.Ports) != 6 {
		t.Fatalf("ports table should have 6 rows, got %d", len(v.Ports))
	}
	var p443, p8080, p80 portRow
	for _, p := range v.Ports {
		if p.Port == 443 {
			p443 = p
		} else if p.Port == 8080 {
			p8080 = p
		} else if p.Port == 80 {
			p80 = p
		}
	}
	if p443.Requests != 1 || p443.Connections != 0 || p443.IPs != 1 {
		t.Fatalf("port 443 = %+v", p443)
	}
	if p8080.Requests != 1 || p8080.Connections != 1 || p8080.IPs != 2 {
		t.Fatalf("port 8080 = %+v", p8080)
	}
	if p80.Requests != 0 || p80.Connections != 0 || p80.IPs != 0 {
		t.Fatalf("port 80 should be zero, got %+v", p80)
	}
	vFiltered := st.state(now, time.Hour, "", "", "", "", 8080, ports)
	if vFiltered.Requests != 1 || vFiltered.Connections != 1 || len(vFiltered.Feed) != 2 {
		t.Fatalf("port=8080 filter: requests=%d connections=%d feed=%d", vFiltered.Requests, vFiltered.Connections, len(vFiltered.Feed))
	}
	if len(vFiltered.Endpoints) != 2 {
		t.Fatalf("port=8080 filter endpoints = %+v", vFiltered.Endpoints)
	}
	if len(vFiltered.Ports) != 6 {
		t.Fatalf("port filter should not narrow ports table, got %d rows", len(vFiltered.Ports))
	}
	var p8080Filtered portRow
	for _, p := range vFiltered.Ports {
		if p.Port == 8080 {
			p8080Filtered = p
			break
		}
	}
	if p8080Filtered.Requests != 1 || p8080Filtered.Connections != 1 || p8080Filtered.IPs != 2 {
		t.Fatalf("port 8080 in filtered view = %+v", p8080Filtered)
	}
}

func TestHandlerRefusesOtherOriginsAndMethods(t *testing.T) {
	hosts, err := loopbackHosts("127.0.0.1:8765")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loopbackHosts("0.0.0.0:8765"); err == nil {
		t.Fatal("accepted a non-loopback listen address")
	}
	h := handler(newStore(1000), hosts, []int{80, 443})
	do := func(method, host, target string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, nil)
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := do("GET", "evil.example:8765", "/api/state"); w.Code != http.StatusForbidden {
		t.Fatalf("foreign Host got %d", w.Code)
	}
	if w := do("POST", "127.0.0.1:8765", "/api/state"); w.Code != http.StatusForbidden {
		t.Fatalf("POST got %d", w.Code)
	}
	w := do("GET", "localhost:8765", "/api/state?window=15m")
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/json" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("state: %d %v", w.Code, w.Header())
	}
	for _, p := range []string{"/", "/app.js", "/style.css"} {
		if w := do("GET", "127.0.0.1:8765", p); w.Code != 200 {
			t.Fatalf("%s got %d", p, w.Code)
		}
	}
}

func TestNewRelicRowsBecomeEvents(t *testing.T) {
	var gotKey, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("API-Key")
		var body struct{ Query string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotQuery = body.Query
		_, _ = w.Write([]byte(`{"data":{"actor":{"account":{"nrql":{"results":[
			{"timestamp":1795600000000,"id":"s1","name":"public.connection","client.address":"203.0.113.7","attackbox.connection.outcome":"not_tls","attackbox.tls.sni":"none"},
			{"timestamp":1795600001000,"id":"s2","name":"public.request","client.address":"203.0.113.7","http.route":"/unmatched","http.request.method":"GET","http.response.status_code":404,"attackbox.probe.class":"vcs","server.port":443},
			{"timestamp":1795600002000,"id":"s3","name":"public.health"}]}}}}}`))
	}))
	defer srv.Close()
	old := nrURL
	nrURL = srv.URL
	defer func() { nrURL = old }()

	n := newRelic{key: "test-key", account: 42, service: "attackbox-public-443", port: 443}
	rows, err := n.query(context.Background(), time.UnixMilli(1795500000000))
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	if gotKey != "test-key" || !strings.Contains(gotQuery, "account(id:42)") || !strings.Contains(gotQuery, "SINCE 1795500000000") {
		t.Fatalf("request: key=%q query=%q", gotKey, gotQuery)
	}
	c, ok1 := n.event(rows[0])
	r, ok2 := n.event(rows[1])
	_, ok3 := n.event(rows[2])
	if !ok1 || !ok2 || ok3 || c.Endpoint != ":443 pre-HTTP not_tls" || r.Endpoint != ":443 /unmatched (vcs)" || r.Status != 404 || r.IP != "203.0.113.7" {
		t.Fatalf("connection=%+v request=%+v ok=%v,%v,%v", c, r, ok1, ok2, ok3)
	}
}

func TestPreviewExtraction(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"prompt", `{"prompt":"Tell me a joke"}`, "Tell me a joke"},
		{"messages string content", `{"messages":[{"role":"user","content":"Hello"}]}`, "Hello"},
		{"messages parts content", `{"messages":[{"role":"user","content":[{"type":"text","text":"First"},{"type":"text","text":"Second"}]}]}`, "First Second"},
		{"input string", `{"input":"What is 2+2?"}`, "What is 2+2?"},
		{"input array", `{"input":["First item","Second item"]}`, "First item"},
		{"non-json body", "plain text request", "plain text request"},
		{"empty body", "", ""},
		{"whitespace collapse", `{"prompt":"Line 1\n\t  Line 2\r\n  Line 3"}`, "Line 1 Line 2 Line 3"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			preview, _ := extractPreview(tc.body, "")
			got := cleanPreview(preview)
			if got != tc.want {
				t.Errorf("extractPreview(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

func TestFeedPromptEvidence(t *testing.T) {
	for _, tc := range []struct {
		path, body string
		want       bool
	}{
		{"/api/generate", `{"prompt":"hello"}`, true},
		{"/v1/chat/completions", `{"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"reply"}]}`, true},
		{"/v1/responses", `{"input":[{"role":"user","content":[{"type":"input_text","text":"hello"}]}]}`, true},
		{"/v1/responses?stream=1", `{"input":"hello"}`, true},
		{"/v1/embeddings", `{"input":"hello"}`, false},
		{"/api/chat", `{"messages":[{"role":"system","content":"instructions"},{"role":"tool","content":"result"}]}`, false},
		{"/api/chat", `{"messages":[{"role":"user","content":[{"type":"image","text":"metadata"}]}]}`, false},
		{"/api/generate", `{"prompt":"   "}`, false},
		{"/api/generate", `{"prompt":"truncated`, false},
		{"/api/tags", "", false},
	} {
		e := event{Kind: "request", Body: tc.body, Target: tc.path}
		e.finish()
		if e.HasPrompt != tc.want {
			t.Errorf("%s %s: has_prompt = %t, want %t", tc.path, tc.body, e.HasPrompt, tc.want)
		}
	}
}

func TestPreviewClipping(t *testing.T) {
	long := strings.Repeat("a", 200)
	got := cleanPreview(long)
	r := []rune(got)
	if len(r) != 161 || !strings.HasSuffix(got, "…") {
		t.Errorf("long preview has %d runes, want 161 with ellipsis", len(r))
	}
}

func TestStateFeedHasPreviewNotBody(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	st := newStore(1000)
	add := func(e event) {
		e.Port = 443
		e.finish()
		st.add(e)
	}
	add(event{Time: now.Add(-1 * time.Minute), Kind: "request", Source: "capture", IP: "203.0.113.1", Method: "POST", Target: "/v1/chat/completions", Body: `{"prompt":"secret test"}`})
	add(event{Time: now.Add(-2 * time.Minute), Kind: "request", Source: "capture", IP: "203.0.113.2", Method: "POST", Target: "/api", Body: `{"messages":[{"role":"user","content":"another secret"}]}`})
	add(event{Time: now.Add(-3 * time.Minute), Kind: "request", Source: "capture", IP: "203.0.113.3", Method: "GET", Target: "/health"})

	v := st.state(now, time.Hour, "", "", "", "", 0, nil)
	if len(v.Feed) != 3 {
		t.Fatalf("feed length = %d, want 3", len(v.Feed))
	}
	raw, _ := json.Marshal(v.Feed)
	if strings.Contains(string(raw), "secret") && !strings.Contains(string(raw), "preview") {
		t.Fatal("feed must not contain body field with secrets")
	}
	for _, e := range v.Feed {
		if e.Body != "" {
			t.Fatal("feed must not contain body field")
		}
	}
	if v.Feed[0].Preview != "secret test" || v.Feed[1].Preview != "another secret" || v.Feed[2].Preview != "" {
		t.Errorf("previews = %q, %q, %q", v.Feed[0].Preview, v.Feed[1].Preview, v.Feed[2].Preview)
	}
}

func TestTextFilterMatchesBody(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	st := newStore(1000)
	add := func(e event) {
		e.Port = 443
		e.finish()
		st.add(e)
	}
	add(event{Time: now.Add(-1 * time.Minute), Kind: "request", Source: "capture", IP: "203.0.113.1", Method: "POST", Target: "/api", Body: `{"prompt":"unicorn rainbow"}`})
	add(event{Time: now.Add(-2 * time.Minute), Kind: "request", Source: "capture", IP: "203.0.113.2", Method: "GET", Target: "/health?check=ok"})
	add(event{Time: now.Add(-3 * time.Minute), Kind: "request", Source: "capture", IP: "203.0.113.3", Method: "POST", Target: "/api", Body: `{"prompt":"normal request"}`})

	v := st.state(now, time.Hour, "", "", "", "unicorn", 0, nil)
	if v.Requests != 1 {
		t.Errorf("text filter 'unicorn' found %d requests, want 1", v.Requests)
	}
	if len(v.Feed) != 1 || v.Feed[0].IP != "203.0.113.1" {
		t.Errorf("text filter matched wrong request")
	}

	v = st.state(now, time.Hour, "", "", "", "check", 0, nil)
	if v.Requests != 1 || v.Feed[0].IP != "203.0.113.2" {
		t.Errorf("text filter 'check' should match query string")
	}
}
