package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseCapture(t *testing.T) {
	line := `{"time":"2024-11-22T10:00:00Z","peer":"203.0.113.1","method":"POST","target":"/v1/chat/completions","route":"/v1/chat/completions","status":200,"port":443,"body":"{\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}"}`
	e, ok := parseCapture([]byte(line), 443)
	if !ok {
		t.Fatal("parse failed")
	}
	if e.IP != "203.0.113.1" || e.Route != "/v1/chat/completions" || e.Method != "POST" || e.Status != 200 {
		t.Errorf("got %+v", e)
	}
}

func TestParseOTLP(t *testing.T) {
	// Real OTLP/JSON shape from fileexporter (protojson)
	line := `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"attackbox-public-443"}}]},"scopeSpans":[{"spans":[{"name":"public.connection","startTimeUnixNano":"1700000000000000000","attributes":[{"key":"client.address","value":{"stringValue":"203.0.113.5"}},{"key":"server.port","value":{"intValue":"443"}},{"key":"attackbox.connection.outcome","value":{"stringValue":"tls_failed"}},{"key":"attackbox.tls.sni","value":{"stringValue":"unknown"}}]}]}]}]}`
	events, ok := parseOTLP([]byte(line), 443)
	if !ok || len(events) != 1 {
		t.Fatalf("parse failed: ok=%v len=%d", ok, len(events))
	}
	e := events[0]
	if e.IP != "203.0.113.5" || e.Kind != "connection" || e.Outcome != "tls_failed" || e.SNI != "unknown" || e.Port != 443 {
		t.Errorf("got %+v", e)
	}

	// Map-shaped attributes are ignored (old test shape)
	badLine := `{"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"public.connection","startTimeUnixNano":"1700000000000000000","attributes":{"client.address":"203.0.113.5"}}]}]}]}`
	events, ok = parseOTLP([]byte(badLine), 443)
	if ok {
		t.Errorf("map-shaped attributes should be ignored, got %d events", len(events))
	}
}

func TestOTLPModelMergesIntoCapture(t *testing.T) {
	captureLine := `{"time":"2023-11-22T10:00:00Z","peer":"203.0.113.1","port":11434,"method":"POST","target":"/v1/chat/completions","route":"/v1/chat/completions","status":200}`
	captureEvent, ok := parseCapture([]byte(captureLine), 443)
	if !ok {
		t.Fatal("capture parse failed")
	}
	spanLine := `{"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"public.request","startTimeUnixNano":"1700647200000000000","attributes":[{"key":"client.address","value":{"stringValue":"203.0.113.1"}},{"key":"server.port","value":{"intValue":"11434"}},{"key":"http.route","value":{"stringValue":"/v1/chat/completions"}},{"key":"gen_ai.request.model","value":{"stringValue":"deepseek-r1:8b"}},{"key":"attackbox.stream","value":{"boolValue":true}}]}]}]}]}`
	spanEvents, ok := parseOTLP([]byte(spanLine), 443)
	if !ok || len(spanEvents) != 1 {
		t.Fatalf("span parse failed: ok=%v len=%d", ok, len(spanEvents))
	}
	if spanEvents[0].Port != 11434 || spanEvents[0].Model != "deepseek-r1:8b" || !spanEvents[0].Stream {
		t.Fatalf("span event = %+v", spanEvents[0])
	}
	st := newStore(10)
	st.add(captureEvent)
	st.add(spanEvents[0])
	if len(st.events) != 1 || st.events[0].Model != "deepseek-r1:8b" || !st.events[0].Stream {
		t.Fatalf("merged events = %+v", st.events)
	}
}

func TestParseShipperEnvelope(t *testing.T) {
	// Fixture 1: Falco event (real shape from internal/hostevidence/send.go)
	// Base64-encoded: {"rule":"Terminal shell in container","priority":"Notice","output_fields":{"fd.sip":"10.0.0.1"}}
	falcoLine := `{"ts":"2024-11-22T10:00:00Z","role":"runtime","seq":1,"record":{"v":1,"id":"abc-1","event":{"timestamp":"2024-11-22T10:00:00Z","stream":"runtime","action":"falco","body":"base64:eyJydWxlIjoiVGVybWluYWwgc2hlbGwgaW4gY29udGFpbmVyIiwicHJpb3JpdHkiOiJOb3RpY2UiLCJvdXRwdXRfZmllbGRzIjp7ImZkLnNpcCI6IjEwLjAuMC4xIn19","attrs":{"source_event_id":"abc","source_segment":0,"source_segments":1}}}}`
	events, ok := parseShipperEnvelope([]byte(falcoLine))
	if !ok || len(events) != 1 {
		t.Fatalf("falco parse failed: ok=%v len=%d", ok, len(events))
	}
	e := events[0]
	if e.Kind != "security" || e.RuleName != "Terminal shell in container" || e.Priority != "Notice" || e.IP != "10.0.0.1" {
		t.Errorf("falco event: %+v", e)
	}

	// Fixture 2: Egress reply ACK (noise)
	// Base64-encoded: {"MESSAGE":"CONTAINER-EGRESS-BLOCK SRC=10.0.0.5 DST=1.2.3.4 SPT=12345 DPT=443 ACK"}
	egressReplyLine := `{"ts":"2024-11-22T10:00:01Z","role":"egress","seq":2,"record":{"v":1,"id":"xyz-1","event":{"timestamp":"2024-11-22T10:00:01Z","stream":"egress","action":"egress_blocked","body":"base64:eyJNRVNTQUdFIjoiQ09OVEFJTkVSLUVHUkVTUy1CTE9DSyBTUkM9MTAuMC4wLjUgRFNUPTEuMi4zLjQgU1BUPTI3MDAwIERQVD00NDMgQUNLIn0=","attrs":{"source_event_id":"xyz","source_segment":0,"source_segments":1}}}}`
	events, ok = parseShipperEnvelope([]byte(egressReplyLine))
	if !ok || len(events) != 1 {
		t.Fatalf("egress parse failed: ok=%v len=%d", ok, len(events))
	}
	e = events[0]
	if e.Kind != "security" || e.BlockType != "container_egress" || e.IP != "10.0.0.5" || e.Priority != "reply" {
		t.Errorf("egress reply event: %+v", e)
	}

	// Fixture 3: Container SYN (outbound)
	// Base64-encoded: {"MESSAGE":"CONTAINER-EGRESS-BLOCK SRC=10.0.0.5 DST=8.8.8.8 SPT=54321 DPT=53 SYN"}
	egressSYNLine := `{"ts":"2024-11-22T10:00:02Z","role":"egress","seq":3,"record":{"v":1,"id":"def-1","event":{"timestamp":"2024-11-22T10:00:02Z","stream":"egress","action":"egress_blocked","body":"base64:eyJNRVNTQUdFIjoiQ09OVEFJTkVSLUVHUkVTUy1CTE9DSyBTUkM9MTAuMC4wLjUgRFNUPTguOC44LjggU1BUPTU0MzIxIERQVD01MyBTWU4ifQ==","attrs":{"source_event_id":"def","source_segment":0,"source_segments":1}}}}`
	events, ok = parseShipperEnvelope([]byte(egressSYNLine))
	if !ok || len(events) != 1 {
		t.Fatalf("egress SYN parse failed: ok=%v len=%d", ok, len(events))
	}
	e = events[0]
	if e.Kind != "security" || e.BlockType != "container_egress" || e.IP != "10.0.0.5" || e.Priority != "outbound" {
		t.Errorf("egress SYN event: %+v", e)
	}

	// Fixture 4: METADATA-BLOCK
	// Base64-encoded: {"MESSAGE":"METADATA-BLOCK SRC=10.0.0.6 DST=169.254.169.254 DPT=80"}
	metadataLine := `{"ts":"2024-11-22T10:00:03Z","role":"egress","seq":4,"record":{"v":1,"id":"ghi-1","event":{"timestamp":"2024-11-22T10:00:03Z","stream":"egress","action":"egress_blocked","body":"base64:eyJNRVNTQUdFIjoiTUVUQURBVEEtQkxPQ0sgU1JDPTEwLjAuMC42IERTVD0xNjkuMjU0LjE2OS4yNTQgRFBUPTgwIn0=","attrs":{"source_event_id":"ghi","source_segment":0,"source_segments":1}}}}`
	events, ok = parseShipperEnvelope([]byte(metadataLine))
	if !ok || len(events) != 1 {
		t.Fatalf("metadata parse failed: ok=%v len=%d", ok, len(events))
	}
	e = events[0]
	if e.Kind != "security" || e.BlockType != "metadata" || e.IP != "10.0.0.6" {
		t.Errorf("metadata event: %+v", e)
	}

	// Fixture 5: Bait event (from internal/server/log.go, role=bait)
	baitLine := `{"ts":"2024-11-22T10:00:04Z","role":"bait","seq":5,"record":{"v":1,"id":"jkl-1","event":{"timestamp":"2024-11-22T10:00:04Z","stream":"edge","action":"request","src_ip":"203.0.113.1"}}}`
	events, ok = parseShipperEnvelope([]byte(baitLine))
	if !ok || len(events) != 1 {
		t.Fatalf("bait parse failed: ok=%v len=%d", ok, len(events))
	}
	e = events[0]
	if e.Kind != "bait" {
		t.Errorf("bait event: %+v", e)
	}

	// Fixture 6: Heartbeat (should be accepted but not produce events)
	heartbeatLine := `{"ts":"2024-11-22T10:00:05Z","role":"runtime","seq":6,"record":{"v":1,"id":"mno-1","event":{"timestamp":"2024-11-22T10:00:05Z","stream":"heartbeat","action":"runtime_heartbeat","attrs":{"source_reader":"durable"}}}}`
	events, ok = parseShipperEnvelope([]byte(heartbeatLine))
	if !ok || len(events) != 0 {
		t.Fatalf("heartbeat should return ok=true but no events: ok=%v len=%d", ok, len(events))
	}
}

func TestOriginClassification(t *testing.T) {
	st := newStore(1000)
	st.own["203.0.113.10"] = true
	st.host = "203.0.113.20"

	st.add(event{Time: time.Now(), IP: "203.0.113.1", Kind: "request"})
	st.add(event{Time: time.Now(), IP: "203.0.113.10", Kind: "request"})
	st.add(event{Time: time.Now(), IP: "203.0.113.20", Kind: "request"})
	st.add(event{Time: time.Now(), IP: "203.0.113.30", Kind: "request", UserAgent: "attackbox-deploy-test/abcdef123456"})
	st.add(event{Time: time.Now(), IP: "203.0.113.40", Kind: "bait"})
	st.add(event{Time: time.Now(), IP: "203.0.113.50", Kind: "security"})

	if st.events[0].Origin != "internet" {
		t.Errorf("event 0 should be internet, got %s", st.events[0].Origin)
	}
	if st.events[1].Origin != "test" {
		t.Errorf("event 1 should be test (own), got %s", st.events[1].Origin)
	}
	if st.events[2].Origin != "test" {
		t.Errorf("event 2 should be test (host), got %s", st.events[2].Origin)
	}
	if st.events[3].Origin != "test" {
		t.Errorf("event 3 should be test (deploy UA), got %s", st.events[3].Origin)
	}
	if st.events[4].Origin != "test" {
		t.Errorf("event 4 should be test (bait), got %s", st.events[4].Origin)
	}
	if st.events[5].Origin != "test" {
		t.Errorf("event 5 should be test (security), got %s", st.events[5].Origin)
	}
}

func TestChainDetectionOpenWebUI(t *testing.T) {
	now := time.Now()
	c := newChainDetector()
	c.add(event{Time: now, IP: "203.0.113.1", Route: "/api/v1/auths/signup", Method: "POST"})
	c.add(event{Time: now.Add(time.Minute), IP: "203.0.113.1", Route: "/api/v1/tools/create", Method: "POST"})
	c.add(event{Time: now.Add(2 * time.Minute), IP: "203.0.113.1", Route: "/api/v1/tools/id/{id}/delete", Method: "DELETE"})
	chains := c.report()
	if len(chains) == 0 {
		t.Fatal("no chain detected")
	}
	var found bool
	for _, ch := range chains {
		if ch["chain"] == "open_webui" {
			found = true
			if _, ok := ch["signup"]; !ok {
				t.Error("missing signup time")
			}
			if _, ok := ch["create"]; !ok {
				t.Error("missing create time")
			}
			if _, ok := ch["delete"]; !ok {
				t.Error("missing delete time")
			}
			break
		}
	}
	if !found {
		t.Error("open_webui chain not detected")
	}
}

func TestChainDetectionMCP(t *testing.T) {
	now := time.Now()
	c := newChainDetector()
	c.add(event{Time: now, IP: "203.0.113.2", MCPMethod: "initialize"})
	c.add(event{Time: now.Add(time.Second), IP: "203.0.113.2", MCPMethod: "tools/list"})
	c.add(event{Time: now.Add(2 * time.Second), IP: "203.0.113.2", MCPMethod: "tools/call"})
	chains := c.report()
	if len(chains) == 0 {
		t.Fatal("no chain detected")
	}
	var found bool
	for _, ch := range chains {
		if ch["chain"] == "mcp" {
			found = true
			if _, ok := ch["initialize"]; !ok {
				t.Error("missing initialize time")
			}
			if _, ok := ch["tools_list"]; !ok {
				t.Error("missing tools_list time")
			}
			if _, ok := ch["tools_call"]; !ok {
				t.Error("missing tools_call time")
			}
			break
		}
	}
	if !found {
		t.Error("mcp chain not detected")
	}
}

func TestReadLinesCountsOverlongLines(t *testing.T) {
	r := strings.NewReader("ok\n" + strings.Repeat("x", maxLineLength+100) + "\nok2\n")
	var lines [][]byte
	if err := readLines(r, func(b []byte) { lines = append(lines, b) }); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3", len(lines))
	}
	if string(lines[0]) != "ok" {
		t.Errorf("line 0: got %q", lines[0])
	}
	if len(lines[1]) <= maxLineLength {
		t.Errorf("line 1: not truncated")
	}
	if string(lines[2]) != "ok2" {
		t.Errorf("line 2: got %q", lines[2])
	}
}

func TestCaptureReadResumesWithoutDuplicates(t *testing.T) {
	dir := t.TempDir()
	day := "20241122"
	path := filepath.Join(dir, "capture-"+day+".jsonl")
	line := `{"time":"2024-11-22T10:00:00Z","peer":"203.0.113.1","method":"GET","target":"/","route":"/","status":200}`
	if err := os.WriteFile(path, []byte(line+"\n"+line+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := &capture{dir: dir, port: 443, lines: map[string]int{}}
	st := newStore(1000)
	state := c.read(context.Background(), st, day, false)
	if state != "ok" {
		t.Errorf("state: %s", state)
	}
	if c.lines[day] != 2 {
		t.Errorf("lines: %d, want 2", c.lines[day])
	}
	if len(st.events) != 2 {
		t.Errorf("events: %d, want 2", len(st.events))
	}
	c.lines[day] = 1
	st2 := newStore(1000)
	state = c.read(context.Background(), st2, day, false)
	if state != "ok" {
		t.Errorf("state: %s", state)
	}
	if c.lines[day] != 2 {
		t.Errorf("lines after resume: %d, want 2", c.lines[day])
	}
	if len(st2.events) != 1 {
		t.Errorf("events after resume: %d, want 1", len(st2.events))
	}
}

func TestStateAggregatesAndFilters(t *testing.T) {
	now := time.Now()
	st := newStore(1000)
	add := func(e event) {
		e.Time = now
		st.add(e)
	}
	add(event{IP: "203.0.113.1", Port: 443, Route: "/v1/chat/completions", Method: "POST", Status: 200, Kind: "request", UserAgent: "curl", Body: "{}"})
	add(event{IP: "203.0.113.1", Port: 443, Route: "/v1/models", Method: "GET", Status: 200, Kind: "request"})
	add(event{IP: "203.0.113.2", Port: 443, Kind: "connection", Outcome: "tls_failed"})
	add(event{IP: "203.0.113.3", Port: 8080, Route: "/health", Method: "GET", Status: 200, Kind: "request"})

	v := st.state(now, time.Hour, "", "", "", "", 0, []int{443, 8080}, &sourceStatus{})
	if v.InternetEvents != 4 {
		t.Errorf("total: %d, want 4", v.InternetEvents)
	}
	if v.InternetSources != 3 {
		t.Errorf("sources: %d, want 3", v.InternetSources)
	}
	if len(v.Feed) != 4 {
		t.Errorf("feed: %d, want 4", len(v.Feed))
	}

	v = st.state(now, time.Hour, "", "203.0.113.1", "", "", 0, []int{443, 8080}, &sourceStatus{})
	if v.InternetEvents != 2 {
		t.Errorf("filtered total: %d, want 2", v.InternetEvents)
	}

	v = st.state(now, time.Hour, "", "", "", "", 8080, []int{443, 8080}, &sourceStatus{})
	if v.InternetEvents != 1 {
		t.Errorf("port filtered: %d, want 1", v.InternetEvents)
	}

	v = st.state(now, time.Hour, "", "", "", "curl", 0, []int{443, 8080}, &sourceStatus{})
	if v.InternetEvents != 1 {
		t.Errorf("text filtered: %d, want 1", v.InternetEvents)
	}
}

func TestStateSeparatesTestTraffic(t *testing.T) {
	now := time.Now()
	st := newStore(1000)
	st.own["203.0.113.10"] = true
	add := func(e event) {
		e.Time = now
		st.add(e)
	}
	add(event{IP: "203.0.113.1", Port: 443, Route: "/v1/models", Method: "GET", Status: 200, Kind: "request"})
	add(event{IP: "203.0.113.10", Port: 443, Route: "/v1/models", Method: "GET", Status: 200, Kind: "request"})
	timelineCounts := func(timeline [][2]int) (requests, connections int) {
		for _, bucket := range timeline {
			requests += bucket[0]
			connections += bucket[1]
		}
		return requests, connections
	}

	v := st.state(now, time.Hour, "", "", "", "", 0, []int{443}, &sourceStatus{})
	if v.InternetEvents != 1 || v.TestEvents != 1 {
		t.Errorf("split: internet=%d test=%d, want 1, 1", v.InternetEvents, v.TestEvents)
	}

	v = st.state(now, time.Hour, "own", "", "", "", 0, []int{443}, &sourceStatus{})
	if len(v.Feed) != 1 || v.Feed[0].IP != "203.0.113.10" {
		t.Errorf("own filter failed")
	}
	if requests, connections := timelineCounts(v.Timeline); requests != 1 || connections != 0 {
		t.Errorf("own timeline = %d requests, %d connections; want 1, 0", requests, connections)
	}

	v = st.state(now, time.Hour, "all", "", "", "", 0, []int{443}, &sourceStatus{})
	if len(v.Feed) != 2 {
		t.Errorf("all filter: got %d events, want 2", len(v.Feed))
	}
	if requests, connections := timelineCounts(v.Timeline); requests != 2 || connections != 0 {
		t.Errorf("all timeline = %d requests, %d connections; want 2, 0", requests, connections)
	}
}

func TestStoreKeepsNewestEvents(t *testing.T) {
	st := newStore(2)
	st.add(event{Time: time.Now(), Seq: 1})
	st.add(event{Time: time.Now(), Seq: 2})
	st.add(event{Time: time.Now(), Seq: 3})
	if len(st.events) != 2 {
		t.Fatalf("len: %d, want 2", len(st.events))
	}
	if st.events[0].Seq != 2 || st.events[1].Seq != 3 {
		t.Errorf("kept wrong events: %v", st.events)
	}
}

func TestPortsTableAndFiltering(t *testing.T) {
	now := time.Now()
	st := newStore(1000)
	add := func(e event) {
		e.Time = now
		st.add(e)
	}
	add(event{IP: "203.0.113.1", Port: 443, Route: "/v1/models", Method: "GET", Status: 200, Kind: "request"})
	add(event{IP: "203.0.113.1", Port: 443, Route: "/v1/chat/completions", Method: "POST", Status: 200, Kind: "request"})
	add(event{IP: "203.0.113.2", Port: 443, Kind: "connection", Outcome: "tls_failed"})
	add(event{IP: "203.0.113.3", Port: 8080, Route: "/health", Method: "GET", Status: 200, Kind: "request"})

	v := st.state(now, time.Hour, "", "", "", "", 0, []int{443, 8080, 1234}, &sourceStatus{})
	if len(v.Ports) != 3 {
		t.Fatalf("ports: %d, want 3", len(v.Ports))
	}
	var p443, p8080, p1234 map[string]any
	for _, p := range v.Ports {
		switch p["port"].(int) {
		case 443:
			p443 = p
		case 8080:
			p8080 = p
		case 1234:
			p1234 = p
		}
	}
	if p443["requests"].(int)+p443["connections"].(int) != 3 || p443["connections"].(int) != 1 || p443["sources"].(int) != 2 {
		t.Errorf("port 443: %+v", p443)
	}
	if p8080["requests"].(int)+p8080["connections"].(int) != 1 || p8080["connections"].(int) != 0 || p8080["sources"].(int) != 1 {
		t.Errorf("port 8080: %+v", p8080)
	}
	if p1234["requests"].(int)+p1234["connections"].(int) != 0 {
		t.Errorf("port 1234: %+v", p1234)
	}
}

func TestFlowBucketsOverflowNodes(t *testing.T) {
	now := time.Now()
	st := newStore(100)
	for i := range flowSize + 2 {
		st.add(event{
			Time: now, Kind: "request", IP: fmt.Sprintf("192.0.2.%d", i+1),
			Port: 443, Route: fmt.Sprintf("/route/%02d", i), Method: "GET",
		})
	}
	state := st.state(now, time.Hour, "all", "", "", "", 0, []int{443}, &sourceStatus{})
	nodes := state.Flow["nodes"].([]map[string]any)
	otherCounts := make(map[string]int)
	otherNames := make(map[string]string)
	for _, node := range nodes {
		if node["other"].(bool) {
			side := node["side"].(string)
			otherCounts[side] = node["count"].(int)
			otherNames[side] = node["name"].(string)
		}
	}
	if otherCounts["source"] != 2 || otherCounts["target"] != 2 {
		t.Errorf("other node counts = %+v, want source=2 target=2", otherCounts)
	}
	if otherNames["source"] != "other sources" || otherNames["target"] != "other endpoints" {
		t.Errorf("other node names = %+v", otherNames)
	}
}

func TestHandlerRefusesOtherOriginsAndMethods(t *testing.T) {
	st := newStore(1000)
	hosts := map[string]bool{"127.0.0.1:8765": true}
	h := handler(st, hosts, []int{443}, &sourceStatus{})
	tests := []struct {
		host   string
		method string
		want   int
	}{
		{"127.0.0.1:8765", "GET", 200},
		{"127.0.0.1:8765", "POST", 403},
		{"evil.com", "GET", 403},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, "http://"+tt.host+"/", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tt.want {
			t.Errorf("%s %s: got %d, want %d", tt.method, tt.host, w.Code, tt.want)
		}
	}
}

func TestDirModeReadsLocalArchive(t *testing.T) {
	dir := t.TempDir()
	captureDir := filepath.Join(dir, "var/lib/attackbox-public-capture/requests")
	if err := os.MkdirAll(captureDir, 0700); err != nil {
		t.Fatal(err)
	}
	day := time.Now().UTC().Format("20060102")
	line := `{"time":"2024-11-22T10:00:00Z","peer":"203.0.113.1","method":"GET","target":"/","route":"/","status":200}`
	if err := os.WriteFile(filepath.Join(captureDir, "capture-"+day+".jsonl"), []byte(line+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	c := &capture{dir: filepath.Join(dir, "/var/lib/attackbox-public-capture/requests"), port: 443, lines: map[string]int{}}
	st := newStore(1000)
	state := c.read(context.Background(), st, day, false)
	if state != "ok" {
		t.Errorf("state: %s", state)
	}
	if len(st.events) != 1 {
		t.Errorf("events: %d, want 1", len(st.events))
	}
}

func TestPreviewExtraction(t *testing.T) {
	tests := []struct {
		path, body, want string
		prompt           bool
	}{
		{"/api/chat", `{"messages":[{"role":"user","content":"hello world"},{"role":"assistant","content":"reply"}]}`, "hello world", true},
		{"/api/generate", `{"prompt":"test prompt"}`, "test prompt", true},
		{"/responses", `{"input":[{"role":"user","content":[{"type":"input_text","text":"a"},{"type":"text","text":"b"}]}]}`, "a b", true},
		{"/v1/responses/?model=test", `{"input":"input text"}`, "input text", true},
		{"/embeddings", `{"input":"input text"}`, "input text", false},
		{"/", `{"text":"some text"}`, "some text", false},
		{"/api/chat", `{"messages":[{"role":"system","content":"secret"}]}`, `{"messages":[{"role":"system","content":"secret"}]}`, false},
		{"/api/chat", `{"prompt":"   "}`, `{"prompt":"   "}`, false},
		{"/api/chat", `{"prompt":"partial`, `{"prompt":"partial`, false},
		{"/", `plain text`, "plain text", false},
		{"/api/tags", ``, "", false},
	}
	for _, tt := range tests {
		line, err := json.Marshal(map[string]string{"time": "2026-11-28T05:31:28Z", "target": tt.path, "body": tt.body})
		if err != nil {
			t.Fatal(err)
		}
		e, ok := parseCapture(line, 443)
		if !ok || e.Preview != tt.want || e.HasPrompt != tt.prompt {
			t.Errorf("%s %s: got (%q, %t), want (%q, %t)", tt.path, tt.body, e.Preview, e.HasPrompt, tt.want, tt.prompt)
		}
	}
}

func TestPreviewClipping(t *testing.T) {
	long := strings.Repeat("x", 200)
	got := cleanPreview(long)
	if len([]rune(got)) > maxPreviewRuns {
		t.Errorf("preview not clipped: %d runes", len([]rune(got)))
	}
	if !strings.HasSuffix(got, "…") {
		t.Error("preview not marked as clipped")
	}
}

func TestStateFeedHasPreviewNotBody(t *testing.T) {
	now := time.Now()
	st := newStore(1000)
	e, ok := parseCapture([]byte(`{"time":"`+now.Format(time.RFC3339Nano)+`","peer":"203.0.113.1","target":"/v1/chat/completions","body":"{\"messages\":[{\"role\":\"user\",\"content\":\"hello world\"}]}"}`), 443)
	if !ok {
		t.Fatal("invalid fixture")
	}
	st.add(e)

	v := st.state(now, time.Hour, "", "", "", "", 0, []int{443}, &sourceStatus{})
	if len(v.Feed) != 1 {
		t.Fatal("no feed")
	}
	if !v.Feed[0].HasPrompt || v.Feed[0].Preview != "hello world" {
		t.Errorf("preview: %q, want 'hello world'", v.Feed[0].Preview)
	}
	if v.Feed[0].Body != "" {
		t.Error("body should not be in feed")
	}
}

func TestTextFilterMatchesBody(t *testing.T) {
	now := time.Now()
	st := newStore(1000)
	st.add(event{Time: now, IP: "203.0.113.1", Port: 443, Route: "/v1/chat/completions", Method: "POST", Status: 200, Kind: "request", Body: `{"messages":[{"role":"user","content":"search term"}]}`})
	st.add(event{Time: now, IP: "203.0.113.2", Port: 443, Route: "/v1/models", Method: "GET", Status: 200, Kind: "request"})

	v := st.state(now, time.Hour, "", "", "", "search term", 0, []int{443}, &sourceStatus{})
	if len(v.Feed) != 1 {
		t.Errorf("filtered feed: %d, want 1", len(v.Feed))
	}
	if len(v.Feed) > 0 && v.Feed[0].IP != "203.0.113.1" {
		t.Error("wrong event matched")
	}
}

func TestToolsExtraction(t *testing.T) {
	line := `{"time":"2024-11-22T10:00:00Z","peer":"203.0.113.1","method":"POST","target":"/v1/chat/completions","route":"/v1/chat/completions","status":200,"body":"{\"tools\":[{\"function\":{\"name\":\"get_weather\"}},{\"name\":\"search\"}]}"}`
	e, ok := parseCapture([]byte(line), 443)
	if !ok {
		t.Fatal("parse failed")
	}
	if e.Tools != "get_weather,search" {
		t.Errorf("tools: %q, want 'get_weather,search'", e.Tools)
	}
}

func TestSystemMessageDetection(t *testing.T) {
	line := `{"time":"2024-11-22T10:00:00Z","peer":"203.0.113.1","method":"POST","target":"/v1/chat/completions","route":"/v1/chat/completions","status":200,"body":"{\"messages\":[{\"role\":\"system\",\"content\":\"You are helpful\"}]}"}`
	e, ok := parseCapture([]byte(line), 443)
	if !ok {
		t.Fatal("parse failed")
	}
	if !e.SystemMsg {
		t.Error("system message not detected")
	}
}

func TestArchiveLayoutReadsContractPaths(t *testing.T) {
	root := t.TempDir()
	day := time.Now().UTC().Format("20060102")

	captureDir := filepath.Join(root, "var/lib/attackbox-public-capture/requests")
	if err := os.MkdirAll(captureDir, 0700); err != nil {
		t.Fatal(err)
	}
	captureLine := `{"time":"2024-11-22T10:00:00Z","peer":"203.0.113.1","method":"GET","target":"/","route":"/","status":200}`
	if err := os.WriteFile(filepath.Join(captureDir, "capture-"+day+".jsonl"), []byte(captureLine+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	otelDir := filepath.Join(root, "var/lib/attackbox-evidence/public-otel")
	if err := os.MkdirAll(otelDir, 0700); err != nil {
		t.Fatal(err)
	}
	otelLine := `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"attackbox-public-443"}}]},"scopeSpans":[{"spans":[{"name":"public.connection","startTimeUnixNano":"1700000000000000000","attributes":[{"key":"client.address","value":{"stringValue":"203.0.113.5"}},{"key":"server.port","value":{"intValue":"443"}},{"key":"attackbox.connection.outcome","value":{"stringValue":"no_data"}},{"key":"attackbox.tls.sni","value":{"stringValue":"none"}}]}]}]}]}`
	if err := os.WriteFile(filepath.Join(otelDir, "traces.jsonl"), []byte(otelLine+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	shipperDir := filepath.Join(root, "var/lib/attackbox-evidence/shipper")
	if err := os.MkdirAll(shipperDir, 0700); err != nil {
		t.Fatal(err)
	}
	shipperLine := `{"ts":"2024-11-22T10:00:00Z","role":"runtime","seq":1,"record":{"v":1,"id":"test-1","event":{"timestamp":"2024-11-22T10:00:00Z","stream":"runtime","action":"falco","body":"base64:eyJydWxlIjoiVGVzdCBydWxlIiwicHJpb3JpdHkiOiJXYXJuaW5nIiwib3V0cHV0X2ZpZWxkcyI6eyJmZC5zaXAiOiIxMC4wLjAuMSJ9fQ==","attrs":{"source_event_id":"test","source_segment":0,"source_segments":1}}}}`
	if err := os.WriteFile(filepath.Join(shipperDir, "events-"+day+".jsonl"), []byte(shipperLine+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	c := &capture{dir: filepath.Join(root, "/var/lib/attackbox-public-capture/requests"), port: 443, lines: map[string]int{}}
	st := newStore(1000)
	state := c.read(context.Background(), st, day, false)
	if state != "ok" {
		t.Errorf("capture state: %s", state)
	}
	if len(st.events) != 1 {
		t.Errorf("capture events: %d, want 1", len(st.events))
	}

	otel := &otelSource{dir: root, port: 443}
	st2 := newStore(1000)
	otelState := otel.read(context.Background(), st2, day, false)
	if otelState != "ok" {
		t.Errorf("otel state: %s", otelState)
	}
	if len(st2.events) != 1 {
		t.Errorf("otel events: %d, want 1", len(st2.events))
	}
	if st2.events[0].Kind != "connection" {
		t.Errorf("otel event kind: %s, want connection", st2.events[0].Kind)
	}

	shipper := &shipperSource{dir: root}
	st3 := newStore(1000)
	shipperState := shipper.read(context.Background(), st3, day, false)
	if shipperState != "ok" {
		t.Errorf("shipper state: %s", shipperState)
	}
	if len(st3.events) != 1 {
		t.Errorf("shipper events: %d, want 1", len(st3.events))
	}
	if st3.events[0].Kind != "security" {
		t.Errorf("shipper event kind: %s, want security", st3.events[0].Kind)
	}
}

func TestStatePanelsAndAggregation(t *testing.T) {
	now := time.Now()
	st := newStore(1000)
	st.own["203.0.113.10"] = true
	add := func(e event) {
		e.Time = now
		st.add(e)
	}

	// AI activity from two sources
	add(event{IP: "203.0.113.1", Port: 443, Route: "/v1/chat/completions", Method: "POST", Status: 200, Kind: "request", Model: "gpt-4", Tools: "read_file,write_file", SystemMsg: true, Stream: true, UserAgent: "openai-python/1.0"})
	add(event{IP: "203.0.113.1", Port: 443, Route: "/v1/chat/completions", Method: "POST", Status: 200, Kind: "request", Model: "gpt-4", Tools: "bash", SystemMsg: false, Stream: false, UserAgent: "openai-python/1.0"})
	add(event{IP: "203.0.113.2", Port: 443, Route: "/v1/completions", Method: "POST", Status: 200, Kind: "request", Model: "claude-3", Tools: "", SystemMsg: false, Stream: true, UserAgent: "anthropic-sdk/1.0"})

	// Open WebUI chain
	add(event{IP: "203.0.113.3", Port: 443, Route: "/api/v1/auths/signup", Method: "POST", Status: 200, Kind: "request", Time: now})
	add(event{IP: "203.0.113.3", Port: 443, Route: "/api/v1/tools/create", Method: "POST", Status: 200, Kind: "request", Time: now.Add(time.Minute)})
	add(event{IP: "203.0.113.3", Port: 443, Route: "/api/v1/tools/delete", Method: "DELETE", Status: 200, Kind: "request", Time: now.Add(2 * time.Minute)})

	// MCP chain
	add(event{IP: "203.0.113.4", Port: 443, Route: "/mcp", Method: "POST", Status: 200, Kind: "request", MCPMethod: "initialize", Time: now})
	add(event{IP: "203.0.113.4", Port: 443, Route: "/mcp", Method: "POST", Status: 200, Kind: "request", MCPMethod: "tools/list", Time: now.Add(time.Second)})
	add(event{IP: "203.0.113.4", Port: 443, Route: "/mcp", Method: "POST", Status: 200, Kind: "request", MCPMethod: "tools/call", Time: now.Add(2 * time.Second)})

	// Falco events
	add(event{IP: "10.0.0.1", Port: 0, Kind: "security", RuleName: "Terminal shell in container", Priority: "Warning", Origin: "test"})
	add(event{IP: "10.0.0.2", Port: 0, Kind: "security", RuleName: "Write below etc", Priority: "Error", Origin: "test"})

	// Egress blocks
	add(event{IP: "10.0.0.3", Port: 0, Kind: "security", RuleName: "egress_block", BlockType: "reply", Origin: "test"})
	add(event{IP: "10.0.0.4", Port: 0, Kind: "security", RuleName: "egress_block", BlockType: "container", Origin: "test"})

	// Test traffic (own)
	add(event{IP: "203.0.113.10", Port: 443, Route: "/health", Method: "GET", Status: 200, Kind: "request", Origin: "test"})

	v := st.state(now.Add(time.Hour), 2*time.Hour, "", "", "", "", 0, []int{443}, &sourceStatus{})

	// AI activity should aggregate by source
	if len(v.AIActivity) != 2 {
		t.Errorf("AI activity rows: %d, want 2", len(v.AIActivity))
	}
	ip1 := v.AIActivity[0]
	if ip1["ip"] != "203.0.113.1" {
		t.Errorf("AI activity first IP: %v, want 203.0.113.1", ip1["ip"])
	}
	if ip1["chat"].(int) != 2 {
		t.Errorf("AI activity chat count: %d, want 2", ip1["chat"])
	}
	if ip1["gen"].(int) != 0 {
		t.Errorf("AI activity gen count: %d, want 0", ip1["gen"])
	}
	models := ip1["models"].([]string)
	if len(models) != 1 || models[0] != "gpt-4" {
		t.Errorf("AI activity models: %v, want [gpt-4]", models)
	}
	tools := ip1["tools"].([]string)
	if len(tools) != 3 {
		t.Errorf("AI activity tools count: %d, want 3", len(tools))
	}
	if !ip1["has_system"].(bool) {
		t.Error("AI activity should have system flag")
	}
	if !ip1["has_stream"].(bool) {
		t.Error("AI activity should have stream flag")
	}

	// Chains should detect both
	if len(v.Chains) != 2 {
		t.Errorf("Chains: %d, want 2", len(v.Chains))
	}
	var hasOpenWebUI, hasMCP bool
	for _, ch := range v.Chains {
		if ch["kind"] == "open_webui" {
			hasOpenWebUI = true
		}
		if ch["kind"] == "mcp" {
			hasMCP = true
		}
	}
	if !hasOpenWebUI {
		t.Error("Missing open_webui chain")
	}
	if !hasMCP {
		t.Error("Missing mcp chain")
	}

	// Host security should appear in default internet view
	hs := v.HostSecurity
	rules := hs["falco_rules"].(map[string]int)
	if len(rules) != 2 {
		t.Errorf("Falco rules count: %d, want 2", len(rules))
	}
	if rules["Terminal shell in container"] != 1 {
		t.Errorf("Terminal shell rule count: %d, want 1", rules["Terminal shell in container"])
	}
	priorities := hs["falco_priorities"].(map[string]int)
	if len(priorities) != 2 {
		t.Errorf("Falco priorities count: %d, want 2", len(priorities))
	}
	blocks := hs["egress_blocks"].(map[string]int)
	if len(blocks) != 2 {
		t.Errorf("Egress blocks count: %d, want 2", len(blocks))
	}
	if blocks["reply"] != 1 {
		t.Errorf("Reply blocks: %d, want 1", blocks["reply"])
	}
	if blocks["container"] != 1 {
		t.Errorf("Container blocks: %d, want 1", blocks["container"])
	}

	// Test environment counts only test-origin traffic
	vAll := st.state(now.Add(time.Hour), 2*time.Hour, "all", "", "", "", 0, []int{443}, &sourceStatus{})
	te := vAll.TestEnv
	if te["own_traffic"].(int) != 1 {
		t.Errorf("Own traffic: %d, want 1", te["own_traffic"])
	}
	if te["private_bait"].(int) != 0 {
		t.Errorf("Private bait: %d, want 0", te["private_bait"])
	}
}

func TestStaticServing(t *testing.T) {
	st := newStore(1000)
	hosts := map[string]bool{"localhost:8080": true}
	h := handler(st, hosts, []int{443}, &sourceStatus{})
	server := httptest.NewServer(h)
	defer server.Close()

	tests := []struct {
		path string
		ct   string
	}{
		{"/app.js", "application/javascript"},
		{"/style.css", "text/css"},
	}
	for _, tt := range tests {
		req := httptest.NewRequest("GET", tt.path, nil)
		req.Host = "localhost:8080"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Errorf("%s status: %d, want 200", tt.path, w.Code)
		}
		ct := w.Header().Get("Content-Type")
		if ct != tt.ct {
			t.Errorf("%s Content-Type: %s, want %s", tt.path, ct, tt.ct)
		}
	}
}

func TestMCPCorrelation(t *testing.T) {
	st := newStore(1000)
	// Add a capture event with no MCP method
	captureLine := `{"time":"2023-11-22T10:00:00Z","peer":"203.0.113.1","method":"POST","target":"/mcp/v1","route":"/mcp/v1","status":200,"port":443}`
	captureEvent, ok := parseCapture([]byte(captureLine), 443)
	if !ok {
		t.Fatal("capture parse failed")
	}
	st.add(captureEvent)

	// Add an OTLP event with MCP method that correlates by IP, port, route, time
	otlpLine := `{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"attackbox-public-443"}}]},"scopeSpans":[{"spans":[{"name":"public.request","startTimeUnixNano":"1700647200000000000","attributes":[{"key":"client.address","value":{"stringValue":"203.0.113.1"}},{"key":"server.port","value":{"intValue":"443"}},{"key":"http.route","value":{"stringValue":"/mcp/v1"}},{"key":"http.request.method","value":{"stringValue":"POST"}},{"key":"http.response.status_code","value":{"intValue":"200"}},{"key":"attackbox.mcp.method","value":{"stringValue":"initialize"}}]}]}]}]}`
	otlpEvents, ok := parseOTLP([]byte(otlpLine), 443)
	if !ok || len(otlpEvents) != 1 {
		t.Fatal("otlp parse failed")
	}
	// Verify OTLP event was parsed correctly
	otelEvent := otlpEvents[0]
	if otelEvent.Source != "otel" {
		t.Fatalf("OTLP event source: %q, want %q", otelEvent.Source, "otel")
	}
	if otelEvent.MCPMethod != "initialize" {
		t.Fatalf("OTLP event MCPMethod: %q, want %q", otelEvent.MCPMethod, "initialize")
	}
	if otelEvent.IP != "203.0.113.1" {
		t.Fatalf("OTLP event IP: %q, want %q", otelEvent.IP, "203.0.113.1")
	}
	if otelEvent.Route != "/mcp/v1" {
		t.Fatalf("OTLP event Route: %q, want %q", otelEvent.Route, "/mcp/v1")
	}
	st.add(otlpEvents[0])

	// Check that the capture event now has the MCP method
	if st.events[0].MCPMethod != "initialize" {
		t.Errorf("capture event MCPMethod: %q, want %q", st.events[0].MCPMethod, "initialize")
	}
	if len(st.events) != 1 || st.events[0].Source != "capture" {
		t.Fatalf("correlated events = %+v, want one capture event", st.events)
	}
}

func TestRequestCorrelationKeepsCaptureInEitherOrder(t *testing.T) {
	now := time.Now()
	capture := event{
		Time: now, Kind: "request", Source: "capture", IP: "192.0.2.10",
		Port: 443, Route: "/v1/chat/completions", Target: "/v1/chat/completions",
	}
	span := event{
		Time: now.Add(time.Second), Kind: "request", Source: "otel", IP: "192.0.2.10",
		Port: 443, Route: "/v1/chat/completions", Model: "deepseek-r1:8b", Stream: true,
	}
	for _, tc := range []struct {
		name  string
		first event
		last  event
	}{
		{"capture first", capture, span},
		{"span first", span, capture},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newStore(10)
			st.add(tc.first)
			st.add(tc.last)
			if len(st.events) != 1 {
				t.Fatalf("events = %d, want 1", len(st.events))
			}
			got := st.events[0]
			if got.Source != "capture" || got.Model != "deepseek-r1:8b" || !got.Stream {
				t.Fatalf("correlated event = %+v", got)
			}
		})
	}
}

func TestEventJSONFieldNames(t *testing.T) {
	// Lock in the json field names that app.js reads
	e := event{
		Time:          time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Seq:           1,
		Kind:          "request",
		Source:        "capture",
		Origin:        "internet",
		IP:            "192.0.2.1",
		Port:          443,
		Route:         "/api/test",
		Method:        "POST",
		Target:        "/api/test",
		Host:          "example.test",
		UserAgent:     "test-agent",
		Status:        200,
		Probe:         "test-probe",
		Proto:         "HTTP/1.1",
		Headers:       [][2]string{{"Content-Type", "application/json"}},
		SNI:           "example.test",
		Outcome:       "success",
		ContentType:   "application/json",
		Model:         "gpt-4",
		Stream:        true,
		Tools:         "tool1,tool2",
		SystemMsg:     true,
		MCPMethod:     "initialize",
		CanaryKey:     "canary",
		Credential:    "credential",
		BodyBytes:     100,
		BodySHA256:    strings.Repeat("0", 64),
		BodyTruncated: true,
		RuleName:      "test-rule",
		Priority:      "high",
		BlockType:     "egress",
		Body:          `{"model":"gpt-4"}`,
	}
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	// Check lowercase snake_case names that app.js uses
	required := []string{
		"time", "seq", "kind", "source", "origin", "ip", "port", "route",
		"method", "target", "host", "user_agent", "status", "probe", "proto",
		"headers", "sni", "outcome", "content_type", "model", "stream", "tools",
		"system_msg", "mcp_method", "canary_key", "credential", "body_bytes",
		"body_sha256", "body_truncated", "rule_name", "priority", "block_type", "body", "preview", "has_prompt",
	}
	for _, field := range required {
		if _, ok := m[field]; !ok {
			t.Errorf("missing json field %q", field)
		}
	}
	// Ensure no capitalized field names leak through
	for field := range m {
		if field != strings.ToLower(field) {
			t.Errorf("field %q is not lowercase", field)
		}
		if strings.Contains(field, " ") {
			t.Errorf("field %q contains spaces", field)
		}
	}
}

func TestAPIStateJSONFieldNames(t *testing.T) {
	now := time.Now().UTC()
	st := newStore(1000)
	add := func(e event) {
		if e.Time.IsZero() {
			e.Time = now
		}
		st.add(e)
	}
	add(event{
		Kind: "request", Source: "capture", IP: "192.0.2.1", Port: 443,
		Route: "/v1/chat/completions", Method: "POST", Target: "/v1/chat/completions",
		UserAgent: "test-agent", Status: 200, Probe: "chat", Model: "deepseek-r1:8b",
		Stream: true, Tools: "func1,func2", BodyBytes: 54,
		Body: `{"messages":[{"role":"user","content":"test"}]}`,
	})
	for i, route := range []string{"/api/v1/auths/signup", "/api/v1/tools/create", "/api/v1/tools/id/x/delete"} {
		add(event{
			Time: now.Add(time.Duration(i) * time.Second), Kind: "request", Source: "capture",
			IP: "192.0.2.2", Port: 443, Route: route, Method: "POST", Target: route, Status: 200,
		})
	}
	for i, method := range []string{"initialize", "tools/list", "tools/call"} {
		add(event{
			Time: now.Add(time.Duration(i) * time.Second), Kind: "request", Source: "capture",
			IP: "192.0.2.3", Port: 443, Route: "/mcp", Method: "POST", Target: "/mcp",
			Status: 200, MCPMethod: method,
		})
	}
	add(event{
		Kind: "connection", Source: "otel", IP: "192.0.2.4", Port: 443,
		Outcome: "tls_failed", SNI: "unknown",
	})
	add(event{
		Kind: "request", Source: "capture", IP: "127.0.0.1", Port: 443,
		Route: "/v1/models", Method: "GET", Target: "/v1/models",
		UserAgent: "attackbox-deploy-test/0123456789ab", Status: 401,
	})
	add(event{Kind: "security", Source: "shipper", RuleName: "PTRACE attached to process", Priority: "Critical"})
	add(event{Kind: "security", Source: "shipper", BlockType: "container_egress", Priority: "reply"})
	add(event{Kind: "bait", Source: "shipper"})

	status := &sourceStatus{}
	offsetTime := time.Date(2024, 1, 1, 7, 0, 0, 0, time.FixedZone("EST", -5*60*60))
	for _, source := range []string{"capture", "otel", "shipper"} {
		status.set(source, "following", offsetTime)
	}
	h := handler(st, map[string]bool{"localhost:8080": true}, []int{443}, status)
	req := httptest.NewRequest("GET", "http://localhost:8080/api/state?window=7d&who=all", nil)
	req.Host = "localhost:8080"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("/api/state status = %d, body = %s", w.Code, w.Body.String())
	}
	var state map[string]any
	if err := json.NewDecoder(w.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}

	requireFields := func(label string, object map[string]any, fields ...string) {
		t.Helper()
		for _, field := range fields {
			if _, ok := object[field]; !ok {
				t.Errorf("%s missing field %q", label, field)
			}
		}
	}
	asObject := func(label string, value any) map[string]any {
		t.Helper()
		object, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("%s = %T, want object", label, value)
		}
		return object
	}
	asArray := func(label string, value any) []any {
		t.Helper()
		array, ok := value.([]any)
		if !ok {
			t.Fatalf("%s = %T, want array", label, value)
		}
		if len(array) == 0 {
			t.Fatalf("%s is empty", label)
		}
		return array
	}

	requireFields("state", state,
		"now", "since", "internet_events", "test_events", "internet_sources", "test_sources",
		"sources", "endpoints", "ports", "timeline", "flow", "feed", "ai_activity", "chains",
		"host_security", "test_env", "sources_status",
	)
	if state["internet_events"] != float64(8) || state["test_events"] != float64(1) {
		t.Errorf("totals = internet %v, test %v; want 8, 1", state["internet_events"], state["test_events"])
	}
	timeline := asArray("timeline", state["timeline"])
	if len(timeline) != timelineBuckets {
		t.Errorf("timeline buckets = %d, want %d", len(timeline), timelineBuckets)
	}
	var timelineRequests, timelineConnections float64
	for i, value := range timeline {
		bucket, ok := value.([]any)
		if !ok || len(bucket) != 2 {
			t.Fatalf("timeline[%d] = %#v, want [requests, connections]", i, value)
		}
		timelineRequests += bucket[0].(float64)
		timelineConnections += bucket[1].(float64)
	}
	if timelineRequests != 8 || timelineConnections != 1 {
		t.Errorf("timeline = %.0f requests, %.0f connections; want 8, 1", timelineRequests, timelineConnections)
	}
	var request map[string]any
	for _, value := range asArray("feed", state["feed"]) {
		item := asObject("feed item", value)
		if item["target"] == "/v1/chat/completions" {
			request = item
			break
		}
	}
	if request == nil {
		t.Fatal("request fixture missing from feed")
	}
	requireFields("feed request", request,
		"time", "seq", "kind", "source", "origin", "ip", "port", "method", "target",
		"status", "route", "user_agent", "body_bytes", "preview", "has_prompt", "probe",
	)

	source := asObject("source", asArray("sources", state["sources"])[0])
	requireFields("source", source, "ip", "own", "count", "last", "ua")
	endpoint := asObject("endpoint", asArray("endpoints", state["endpoints"])[0])
	requireFields("endpoint", endpoint, "route", "endpoint", "count", "last")
	port := asObject("port", asArray("ports", state["ports"])[0])
	requireFields("port", port, "port", "requests", "connections", "sources", "last")

	flow := asObject("flow", state["flow"])
	node := asObject("flow node", asArray("flow.nodes", flow["nodes"])[0])
	requireFields("flow node", node, "id", "name", "count", "side", "other")
	link := asObject("flow link", asArray("flow.links", flow["links"])[0])
	requireFields("flow link", link, "source", "target", "value")

	activity := asObject("ai activity", asArray("ai_activity", state["ai_activity"])[0])
	requireFields("ai activity", activity,
		"ip", "chat", "gen", "models", "tools", "has_system", "has_stream", "user_agents",
	)
	for i, value := range asArray("chains", state["chains"]) {
		chain := asObject(fmt.Sprintf("chain %d", i), value)
		requireFields("chain", chain, "ip", "chain", "steps", "complete")
		switch chain["chain"] {
		case "open_webui":
			requireFields("open_webui chain", chain, "signup", "create", "delete")
		case "mcp":
			requireFields("mcp chain", chain, "initialize", "tools_list", "tools_call")
		}
	}
	hostSecurity := asObject("host_security", state["host_security"])
	requireFields("host_security", hostSecurity, "falco_rules", "falco_priorities", "egress_blocks")
	testEnv := asObject("test_env", state["test_env"])
	requireFields("test_env", testEnv, "own_traffic", "private_bait")
	if testEnv["own_traffic"] != float64(1) || testEnv["private_bait"] != float64(1) {
		t.Errorf("test_env = %+v, want one own request and one bait event", testEnv)
	}

	sourcesStatus := asObject("sources_status", state["sources_status"])
	for _, sourceName := range []string{"capture", "otel", "shipper"} {
		sourceStatus := asObject("sources_status."+sourceName, sourcesStatus[sourceName])
		requireFields("sources_status."+sourceName, sourceStatus, "state", "last")
		last, _ := sourceStatus["last"].(string)
		if !strings.HasSuffix(last, "Z") {
			t.Errorf("sources_status.%s.last = %q, want UTC", sourceName, last)
		}
	}
}

func TestModelAndStreamFromBody(t *testing.T) {
	body := `{"model":"deepseek-r1:8b","stream":true,"messages":[{"role":"user","content":"test"}]}`
	line := fmt.Sprintf(`{"time":"2024-01-01T12:00:00Z","peer":"192.0.2.1","method":"POST","target":"/v1/chat/completions","route":"/v1/chat/completions","status":200,"port":443,"body":%q}`, body)
	e, ok := parseCapture([]byte(line), 443)
	if !ok {
		t.Fatal("parseCapture failed")
	}
	if e.Model != "deepseek-r1:8b" {
		t.Errorf("model = %q, want deepseek-r1:8b", e.Model)
	}
	if !e.Stream {
		t.Error("stream = false, want true")
	}
}
