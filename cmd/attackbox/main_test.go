package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"attackbox/internal/responder"
	"attackbox/internal/secret"
	"attackbox/internal/server"
	"attackbox/internal/telemetry"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadConfigDefaults(t *testing.T) {
	c, err := loadConfig(envOf(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.listeners) != 1 || c.listeners[0] != (listener{"openai", "127.0.0.1:8080"}) {
		t.Fatalf("listeners = %+v", c.listeners)
	}
	if host, _, err := net.SplitHostPort(c.listeners[0].addr); err != nil || !net.ParseIP(host).IsLoopback() {
		t.Fatalf("zero-config listener %q must be loopback-only", c.listeners[0].addr)
	}
	if c.holdSilent != 150*time.Second || c.idleInterval != 45*time.Second || c.maxStream != 180*time.Second {
		t.Fatalf("hold defaults = %v %v %v", c.holdSilent, c.idleInterval, c.maxStream)
	}
	if c.maxBody != 1<<20 || c.maxLogBody != 128<<10 {
		t.Fatalf("body defaults = %d %d", c.maxBody, c.maxLogBody)
	}
	if !c.timing {
		t.Fatal("response pacing must be on by default")
	}
	if len(c.secret) != minSecret {
		t.Fatalf("random secret len = %d", len(c.secret))
	}
	if bytes.Equal(c.derive("session"), c.derive("embed")) {
		t.Fatal("derived keys must differ per purpose")
	}
}

func TestLoadConfigFull(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, bytes.Repeat([]byte{7}, 48), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig(envOf(map[string]string{
		"ATTACKBOX_OPENAI_ADDR":     "127.0.0.1:18080",
		"ATTACKBOX_VLLM_ADDR":       ":8000",
		"ATTACKBOX_OLLAMA_ADDR":     "[::1]:11434",
		"ATTACKBOX_MODELS":          "qwen3:8b, llama3.1:8b",
		"ATTACKBOX_TRUSTED_PROXIES": "172.18.0.0/16, 10.0.0.5",
		"ATTACKBOX_SECRET_FILE":     secret,
		"ATTACKBOX_HOLD_SILENT":     "2s",
		"ATTACKBOX_MAX_STREAM":      "5s",
		"ATTACKBOX_MAX_LOG_BODY":    "1048576",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.listeners) != 3 || c.listeners[2].persona != "ollama" {
		t.Fatalf("listeners = %+v", c.listeners)
	}
	if c.maxLogBody != 1<<20 {
		t.Fatalf("maxLogBody = %d", c.maxLogBody)
	}
	if len(c.models) != 2 || c.models[1] != "llama3.1:8b" {
		t.Fatalf("models = %q", c.models)
	}
	if len(c.trustedProxies) != 2 || c.trustedProxies[1].String() != "10.0.0.5/32" {
		t.Fatalf("proxies = %v", c.trustedProxies)
	}
	c2, err := loadConfig(envOf(map[string]string{"ATTACKBOX_SECRET_FILE": secret, "ATTACKBOX_TIMING": "false"}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.derive("session"), c2.derive("session")) {
		t.Fatal("same secret file must give the same session key across restarts")
	}
	if c2.timing {
		t.Fatal("ATTACKBOX_TIMING=false must turn response pacing off")
	}
	c3, err := loadConfig(envOf(map[string]string{"ATTACKBOX_SPOOL_SOCKET": "/run/attackbox/spool.sock", "ATTACKBOX_SPOOL_QUEUE": "100000", "ATTACKBOX_SPOOL_TIMEOUT": "2s"}))
	if err != nil {
		t.Fatalf("spool mode needs no key: %v", err)
	}
	if c3.spoolSocket != "/run/attackbox/spool.sock" || c3.spoolQueue != 100000 || c3.spoolTimeout != 2*time.Second {
		t.Fatalf("spool config = %+v", c3)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	tmp := t.TempDir()
	short := filepath.Join(tmp, "short")
	if err := os.WriteFile(short, []byte("tiny"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 48)
	open, group, huge := filepath.Join(tmp, "open"), filepath.Join(tmp, "group"), filepath.Join(tmp, "huge")
	if err := os.WriteFile(open, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(group, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(group, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(huge, bytes.Repeat([]byte{7}, 5000), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(tmp, "dir")
	_ = os.Mkdir(dir, 0o700)
	cases := map[string]struct {
		env  map[string]string
		want string
	}{
		"bad timing":        {map[string]string{"ATTACKBOX_TIMING": "fast"}, "ATTACKBOX_TIMING"},
		"bad duration":      {map[string]string{"ATTACKBOX_HOLD_SILENT": "soon"}, "ATTACKBOX_HOLD_SILENT"},
		"negative duration": {map[string]string{"ATTACKBOX_IDLE_INTERVAL": "-1s"}, "ATTACKBOX_IDLE_INTERVAL"},
		"hold over stream":  {map[string]string{"ATTACKBOX_HOLD_SILENT": "10s", "ATTACKBOX_MAX_STREAM": "5s"}, "must not exceed"},
		"bad int":           {map[string]string{"ATTACKBOX_MAX_SESSIONS": "0"}, "ATTACKBOX_MAX_SESSIONS"},
		"no listeners":      {map[string]string{"ATTACKBOX_OPENAI_ADDR": "off"}, "no listener enabled"},
		"bad addr":          {map[string]string{"ATTACKBOX_OPENAI_ADDR": "example.com:80"}, "host must be an IP"},
		"bad port":          {map[string]string{"ATTACKBOX_VLLM_ADDR": ":99999"}, "invalid port"},
		"dup addr":          {map[string]string{"ATTACKBOX_VLLM_ADDR": "127.0.0.1:8080"}, "already used"},
		"wildcard overlap":  {map[string]string{"ATTACKBOX_VLLM_ADDR": ":8080"}, "already used"},
		"bad proxy":         {map[string]string{"ATTACKBOX_TRUSTED_PROXIES": "proxy.local"}, "not an IP or CIDR"},
		"bad model":         {map[string]string{"ATTACKBOX_MODELS": "a\x01b"}, "invalid model"},
		"bad instance":      {map[string]string{"ATTACKBOX_INSTANCE": "has space"}, "ATTACKBOX_INSTANCE"},
		"short secret":      {map[string]string{"ATTACKBOX_SECRET_FILE": short}, "at least 32 bytes"},
		"missing secret":    {map[string]string{"ATTACKBOX_SECRET_FILE": "/nonexistent/secret"}, "ATTACKBOX_SECRET_FILE"},
		"open secret":       {map[string]string{"ATTACKBOX_SECRET_FILE": open}, "readable by group or others"},
		"group secret":      {map[string]string{"ATTACKBOX_SECRET_FILE": group}, "readable by group or others"},
		"dir secret":        {map[string]string{"ATTACKBOX_SECRET_FILE": dir}, "not a regular file"},
		"huge secret":       {map[string]string{"ATTACKBOX_SECRET_FILE": huge}, "at most 4096"},
		"sessions cap":      {map[string]string{"ATTACKBOX_MAX_SESSIONS": "100001"}, "ATTACKBOX_MAX_SESSIONS: want an integer from 1 to 100000"},
		"body cap":          {map[string]string{"ATTACKBOX_MAX_BODY_BYTES": "9223372036854775807"}, "ATTACKBOX_MAX_BODY_BYTES"},
		"log body cap":      {map[string]string{"ATTACKBOX_MAX_LOG_BODY": "1048577"}, "ATTACKBOX_MAX_LOG_BODY"},
		"in-flight cap":     {map[string]string{"ATTACKBOX_MAX_IN_FLIGHT": "10001"}, "ATTACKBOX_MAX_IN_FLIGHT"},
		"per-source cap":    {map[string]string{"ATTACKBOX_MAX_PER_SOURCE": "1001"}, "ATTACKBOX_MAX_PER_SOURCE"},
		"per-source>total":  {map[string]string{"ATTACKBOX_MAX_PER_SOURCE": "20", "ATTACKBOX_MAX_IN_FLIGHT": "10"}, "must not exceed ATTACKBOX_MAX_IN_FLIGHT"},
		"duration cap":      {map[string]string{"ATTACKBOX_SHUTDOWN_TIMEOUT": "2h"}, "ATTACKBOX_SHUTDOWN_TIMEOUT"},
		"relative spool":    {map[string]string{"ATTACKBOX_SPOOL_SOCKET": "spool.sock"}, "ATTACKBOX_SPOOL_SOCKET: spool: socket path must be absolute"},
		"long spool":        {map[string]string{"ATTACKBOX_SPOOL_SOCKET": "/" + strings.Repeat("s", 107)}, "at most 107"},
		"spool queue cap":   {map[string]string{"ATTACKBOX_SPOOL_SOCKET": "/run/s.sock", "ATTACKBOX_SPOOL_QUEUE": "100001"}, "ATTACKBOX_SPOOL_QUEUE: want an integer from 1 to 100000"},
		"spool timeout":     {map[string]string{"ATTACKBOX_SPOOL_SOCKET": "/run/s.sock", "ATTACKBOX_SPOOL_TIMEOUT": "0s"}, "ATTACKBOX_SPOOL_TIMEOUT"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadConfig(envOf(tc.env))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCLIFlags(t *testing.T) {
	var out, errb bytes.Buffer
	if code := cli([]string{"-version"}, envOf(nil), &out, &errb); code != 0 || strings.TrimSpace(out.String()) != version {
		t.Fatalf("version: code %d out %q", code, out.String())
	}
	out.Reset()
	if code := cli([]string{"-check-config"}, envOf(nil), &out, &errb); code != 0 || !strings.Contains(out.String(), "configuration ok") {
		t.Fatalf("check-config: code %d out %q err %q", code, out.String(), errb.String())
	}
	out.Reset()
	if code := cli([]string{"-check-config"}, envOf(map[string]string{"ATTACKBOX_SPOOL_SOCKET": "/run/attackbox/spool.sock"}), &out, &errb); code != 0 ||
		!strings.Contains(out.String(), "spool /run/attackbox/spool.sock") {
		t.Fatalf("check-config spool: code %d out %q err %q", code, out.String(), errb.String())
	}
	if code := cli([]string{"-nope"}, envOf(nil), &out, &errb); code != 2 {
		t.Fatalf("bad flag code %d", code)
	}
}

func TestHealthcheck(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			w.WriteHeader(404)
		}
	}))
	defer ok.Close()
	if code := cli([]string{"-healthcheck", ok.URL + "/health"}, envOf(nil), io.Discard, io.Discard); code != 0 {
		t.Fatalf("healthy code %d", code)
	}
	if err := healthcheck(ok.URL + "/missing"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("404 err = %v", err)
	}
	for _, u := range []string{"http://192.0.2.1/health", "https://127.0.0.1/health", "::bad", "http://user:pass@127.0.0.1/health", "http://user@localhost/health"} {
		if err := healthcheck(u); err == nil {
			t.Fatalf("%s: want refusal", u)
		}
	}
}

// syncBuf is a goroutine-safe log capture.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) lines(t *testing.T) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(s.b.Bytes()))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", sc.Text())
		}
		out = append(out, m)
	}
	return out
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func startApp(t *testing.T, env map[string]string) (*app, *syncBuf, context.CancelFunc, chan error) {
	t.Helper()
	return startAppWith(t, env, nil)
}

// startAppWith is startApp with a hook that may change the loaded config.
func startAppWith(t *testing.T, env map[string]string, tweak func(*config)) (*app, *syncBuf, context.CancelFunc, chan error) {
	t.Helper()
	cfg, err := loadConfig(envOf(env))
	if err != nil {
		t.Fatal(err)
	}
	if tweak != nil {
		tweak(&cfg)
	}
	logs := &syncBuf{}
	a, err := newApp(cfg, logs)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.run(ctx) }()
	return a, logs, cancel, done
}

func stop(t *testing.T, cancel context.CancelFunc, done chan error) error {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("app did not stop")
		return nil
	}
}

func post(t *testing.T, url, body string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func get(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// TestLiveThreePersonas runs the real listeners on loopback and checks each
// persona, streaming, shared sessions, local logs and redaction.
func TestLiveThreePersonas(t *testing.T) {
	a, logs, cancel, done := startApp(t, map[string]string{
		"ATTACKBOX_OPENAI_ADDR":               "127.0.0.1:0",
		"ATTACKBOX_VLLM_ADDR":                 "127.0.0.1:0",
		"ATTACKBOX_OLLAMA_ADDR":               "127.0.0.1:0",
		"ATTACKBOX_INSTANCE":                  "test-box",
		"ATTACKBOX_SKIP_SELF_PROBE_DETECTION": "true",
	})
	addrs := a.addrs()
	if len(addrs) != 3 {
		t.Fatalf("addrs = %v", addrs)
	}
	openai, vllm, ollama := "http://"+addrs["openai"], "http://"+addrs["vllm"], "http://"+addrs["ollama"]
	const bearer = "sk-proj-REALLOOKINGSECRET0123456789"

	resp, body := get(t, openai+"/v1/models")
	if resp.StatusCode != 200 || !strings.Contains(body, `"object":"list"`) {
		t.Fatalf("openai models: %d %s", resp.StatusCode, body)
	}
	resp, body = post(t, openai+"/v1/chat/completions",
		`{"model":"qwen3:8b","stream":true,"messages":[{"role":"user","content":"hello"}]}`,
		map[string]string{"Authorization": "Bearer " + bearer})
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") ||
		!strings.Contains(body, `"object":"chat.completion.chunk"`) || !strings.HasSuffix(strings.TrimSpace(body), "data: [DONE]") {
		t.Fatalf("openai stream: %d %q", resp.StatusCode, body)
	}
	resp, body = post(t, openai+"/v1/chat/completions", `{"model":"not-a-model","messages":[{"role":"user","content":"hi"}]}`, nil)
	if resp.StatusCode != 404 || !strings.Contains(body, `"error"`) {
		t.Fatalf("unknown model: %d %s", resp.StatusCode, body)
	}

	resp, body = get(t, vllm+"/metrics")
	if resp.StatusCode != 200 || !strings.Contains(body, "vllm:") {
		t.Fatalf("vllm metrics: %d %.200s", resp.StatusCode, body)
	}
	resp, body = post(t, vllm+"/invocations", `{"model":"qwen3:8b","prompt":"hi"}`, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("vllm invocations: %d %s", resp.StatusCode, body)
	}

	resp, body = get(t, ollama+"/")
	if resp.StatusCode != 200 || body != "Ollama is running" {
		t.Fatalf("ollama root: %d %q", resp.StatusCode, body)
	}
	resp, body = post(t, ollama+"/api/chat", `{"model":"qwen3:8b","messages":[{"role":"user","content":"hi"}]}`, nil)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("ollama chat: %d %s %q", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	frames := strings.Split(strings.TrimSpace(body), "\n")
	var last map[string]any
	if err := json.Unmarshal([]byte(frames[len(frames)-1]), &last); err != nil || last["done"] != true {
		t.Fatalf("ollama final frame %q: %v", frames[len(frames)-1], err)
	}
	resp, body = post(t, ollama+"/api/pull", `{"model":"qwen3:8b","stream":false}`, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "success") {
		t.Fatalf("ollama pull: %d %s", resp.StatusCode, body)
	}

	if err := stop(t, cancel, done); err != nil {
		t.Fatalf("run: %v", err)
	}

	out := logs.String()
	if strings.Contains(out, bearer) {
		t.Fatal("raw credential in local log")
	}
	personas := map[string]bool{}
	var started, stopped bool
	for _, l := range logs.lines(t) {
		if l["stream"] == "edge" {
			personas[l["persona"].(string)] = true
		}
		if l["stream"] == "runtime" && l["action"] == "start" {
			started = true
		}
		if l["stream"] == "runtime" && l["action"] == "stopped" {
			stopped = l["result"] == "ok" && l["local_dropped"] == float64(0)
		}
	}
	if !personas["openai"] || !personas["vllm"] || !personas["ollama"] || !started || !stopped {
		t.Fatalf("personas %v started %v stopped %v\n%s", personas, started, stopped, out)
	}
}

func TestLocalOnlyAndPortConflict(t *testing.T) {
	a, logs, cancel, done := startApp(t, map[string]string{"ATTACKBOX_OPENAI_ADDR": "127.0.0.1:0"})
	addr := a.addrs()["openai"]
	if resp, _ := get(t, "http://"+addr+"/health"); resp.StatusCode != 200 {
		t.Fatalf("health %d", resp.StatusCode)
	}

	cfg, err := loadConfig(envOf(map[string]string{"ATTACKBOX_OPENAI_ADDR": addr}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newApp(cfg, io.Discard); err == nil || !strings.Contains(err.Error(), "openai listener") {
		t.Fatalf("port conflict err = %v", err)
	}

	if err := stop(t, cancel, done); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), `"action":"stopped"`) {
		t.Fatal("no stopped event")
	}
	if _, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
		t.Fatal("listener still open after shutdown")
	}
}

type heldReadListener struct {
	net.Listener
	cut     func()
	release <-chan struct{}
}

func (l heldReadListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return heldReadConn{conn, l.cut, l.release}, nil
}

type heldReadConn struct {
	net.Conn
	cut     func()
	release <-chan struct{}
}

func (c heldReadConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.cut()
		<-c.release
	}
	return n, err
}

func TestShutdownCutsHolds(t *testing.T) {
	cfg, err := loadConfig(envOf(map[string]string{
		"ATTACKBOX_OPENAI_ADDR":               "127.0.0.1:0",
		"ATTACKBOX_SHUTDOWN_TIMEOUT":          "500ms",
		"ATTACKBOX_SKIP_SELF_PROBE_DETECTION": "true",
	}))
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuf{}
	a, err := newApp(cfg, logs)
	if err != nil {
		t.Fatal(err)
	}
	cut, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	a.listeners[0] = heldReadListener{a.listeners[0], sync.OnceFunc(func() { close(cut) }), release}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.run(ctx) }()
	// A 100 response proves that the real handler is waiting for the body.
	conn, err := net.Dial("tcp", a.addrs()["openai"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\nExpect: 100-continue\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(conn).ReadString('\n'); line != "HTTP/1.1 100 Continue\r\n" || err != nil {
		t.Fatalf("want 100 Continue, got %q (%v)", line, err)
	}
	cancel()
	select {
	case <-cut:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown did not cancel the handler")
	}
	select {
	case err := <-done:
		t.Fatalf("shutdown returned before the handler finished: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	if err := stop(t, cancel, done); err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	request, stopped := strings.Index(out, `"direction":"request"`), strings.Index(out, `"action":"stopped"`)
	if request < 0 || stopped <= request {
		t.Fatalf("expected the interrupted request log before stopped:\n%s", out)
	}
}

// spoolPeer is a fake host shipper: it accepts unix connections and keeps
// every line it reads.
type spoolPeer struct {
	ln    net.Listener
	mu    sync.Mutex
	lines []string
	wg    sync.WaitGroup
}

func newSpoolPeer(t *testing.T) (*spoolPeer, string) {
	t.Helper()
	// macOS limits sun_path to 104 bytes; t.TempDir() paths are too long.
	dir, err := os.MkdirTemp("", "abx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "spool.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	p := &spoolPeer{ln: ln}
	t.Cleanup(func() { ln.Close(); p.wg.Wait() })
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				defer c.Close()
				r := bufio.NewReaderSize(c, 4<<20)
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					p.mu.Lock()
					p.lines = append(p.lines, l)
					p.mu.Unlock()
				}
			}()
		}
	}()
	return p, sock
}

func (p *spoolPeer) records(t *testing.T) []telemetry.Record {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]telemetry.Record, 0, len(p.lines))
	for _, l := range p.lines {
		var r telemetry.Record
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("spool line %q: %v", l, err)
		}
		out = append(out, r)
	}
	return out
}

// TestSpoolMode runs the bait in the spool deployment: no New Relic key, a
// fake host shipper on a unix socket. Edge, probe and metric records and the
// stop/stopped events must reach the socket before it closes, and the local
// log must keep the authoritative stopped record with the spool counters.
func TestSpoolMode(t *testing.T) {
	peer, sock := newSpoolPeer(t)
	a, logs, cancel, done := startApp(t, map[string]string{
		"ATTACKBOX_SPOOL_SOCKET":              sock,
		"ATTACKBOX_OPENAI_ADDR":               "127.0.0.1:0",
		"ATTACKBOX_TIMING":                    "false",
		"ATTACKBOX_SKIP_SELF_PROBE_DETECTION": "true",
	})
	if a.spool == nil {
		t.Fatal("spool mode must build the spool")
	}
	const bearer = "sk-proj-REALLOOKINGSECRET0123456789"
	resp, _ := post(t, "http://"+a.addrs()["openai"]+"/v1/chat/completions",
		`{"model":"qwen3:8b","messages":[{"role":"user","content":"hello"}]}`,
		map[string]string{"Authorization": "Bearer " + bearer})
	if resp.StatusCode != 200 {
		t.Fatalf("chat %d", resp.StatusCode)
	}
	if err := stop(t, cancel, done); err != nil {
		t.Fatalf("run: %v", err)
	}
	// The spool closed its connection, so the reader ends at EOF once it
	// has every line.
	peer.ln.Close()
	peer.wg.Wait()

	recs := peer.records(t)
	var boot string
	streams, actions, metrics := map[string]int{}, map[string]bool{}, map[string]bool{}
	var shippedStopped *telemetry.Event
	for i, r := range recs {
		b, _, ok := strings.Cut(r.ID, "-")
		if !ok || (boot != "" && b != boot) {
			t.Fatalf("record %d id %q", i, r.ID)
		}
		boot = b
		switch {
		case r.Event != nil:
			streams[r.Event.Stream]++
			if r.Event.Stream == telemetry.StreamRuntime {
				actions[r.Event.Action] = true
				if r.Event.Action == "stopped" {
					shippedStopped = r.Event
				}
			}
			if r.Event.BodySHA256 != "" || r.Event.ChunkCount != 0 {
				t.Fatalf("spooled event carries chunk metadata: %+v", r.Event)
			}
		case r.Metric != nil:
			metrics[r.Metric.Name] = true
		}
	}
	if streams[telemetry.StreamEdge] < 2 || streams[telemetry.StreamProbe] < 1 || !metrics["attackbox.requests"] {
		t.Fatalf("streams %v metrics %v", streams, metrics)
	}
	if !actions["start"] || !actions["stop"] || shippedStopped == nil {
		t.Fatalf("runtime actions on socket = %v, stopped %v", actions, shippedStopped != nil)
	}
	if recs[len(recs)-1].Event != shippedStopped {
		t.Fatal("stopped must be the last record on the socket")
	}
	if shippedStopped.Result != "ok" || shippedStopped.Attrs["spool_dropped"] != float64(0) {
		t.Fatalf("shipped stopped = %+v", shippedStopped)
	}
	for _, l := range peer.lines {
		if strings.Contains(l, bearer) {
			t.Fatal("raw credential on the spool socket")
		}
	}

	var local map[string]any
	for _, l := range logs.lines(t) {
		if l["stream"] == "runtime" && l["action"] == "stopped" {
			local = l
		}
		if l["action"] == "start" && l["spool"] != true {
			t.Fatalf("start event = %v", l)
		}
	}
	if local == nil || local["result"] != "ok" || local["spool_written"] != float64(len(recs)) ||
		local["spool_lost"] != float64(0) || local["spool_dropped"] != float64(0) {
		t.Fatalf("local stopped = %v (socket got %d records)", local, len(recs))
	}
}

// TestSpoolModeNeedsShipper checks that a missing host shipper fails startup
// instead of running without telemetry.
func TestSpoolModeNeedsShipper(t *testing.T) {
	dir, err := os.MkdirTemp("", "abx")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	cfg, err := loadConfig(envOf(map[string]string{"ATTACKBOX_SPOOL_SOCKET": filepath.Join(dir, "none.sock"), "ATTACKBOX_OPENAI_ADDR": "127.0.0.1:0"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newApp(cfg, io.Discard); err == nil || !strings.Contains(err.Error(), "spool") {
		t.Fatalf("err = %v, want spool dial error", err)
	}
}

// TestPartialBindClosesSpool checks that a failed listener closes the spool.
func TestPartialBindClosesSpool(t *testing.T) {
	peer, sock := newSpoolPeer(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	cfg, err := loadConfig(envOf(map[string]string{
		"ATTACKBOX_SPOOL_SOCKET": sock,
		"ATTACKBOX_OPENAI_ADDR":  "127.0.0.1:0",
		"ATTACKBOX_VLLM_ADDR":    busy.Addr().String(),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newApp(cfg, io.Discard); err == nil || !strings.Contains(err.Error(), "vllm listener") || strings.Contains(err.Error(), "spool close") {
		t.Fatalf("err = %v, want only the bind error", err)
	}
	peer.ln.Close()
	peer.wg.Wait() // returns only once the spool closed its connection
}

var (
	provKeys    = []string{"persona_version", "policy_version", "redaction_version", "fp_epoch", "fp_scope"}
	counterKeys = []string{
		"written_total", "dropped_total", "oversize_total", "lost_total", "resent_total",
		"errors_total", "reconnects", "local_dropped_total", "uptime_ms",
	}
)

// wantProvenance checks the five stamps on the attributes of one decoded event.
func wantProvenance(t *testing.T, what string, attrs map[string]any, epoch, scope string) {
	t.Helper()
	want := map[string]any{
		"persona_version":   float64(server.PersonaVersion),
		"policy_version":    float64(responder.PolicyVersion),
		"redaction_version": float64(secret.RedactionVersion),
		"fp_epoch":          epoch,
		"fp_scope":          scope,
	}
	for _, k := range provKeys {
		if attrs[k] != want[k] {
			t.Errorf("%s: %s = %v, want %v", what, k, attrs[k], want[k])
		}
	}
}

// wantCounters checks the cumulative counters of bait_heartbeat and stopped.
func wantCounters(t *testing.T, what string, attrs map[string]any) {
	t.Helper()
	for _, k := range counterKeys {
		if _, ok := attrs[k]; !ok {
			t.Errorf("%s: counter %s missing from %v", what, k, attrs)
		}
	}
}

// spoolEnv is a spool-mode environment with a secret file.
func spoolEnv(t *testing.T, sock string) map[string]string {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, bytes.Repeat([]byte{9}, 48), 0o600); err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"ATTACKBOX_SPOOL_SOCKET":              sock,
		"ATTACKBOX_OPENAI_ADDR":               "127.0.0.1:0",
		"ATTACKBOX_TIMING":                    "false",
		"ATTACKBOX_SECRET_FILE":               keyFile,
		"ATTACKBOX_SKIP_SELF_PROBE_DETECTION": "true",
	}
}

// waitFor polls cond for up to five seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// hasStream reports whether any key of m is "<stream>/<action>" for stream.
// The edge actions depend on the request, so tests match on the stream.
func hasStream[V any](m map[string]V, stream string) bool {
	for k := range m {
		if strings.HasPrefix(k, stream+"/") {
			return true
		}
	}
	return false
}

func hasAction(recs []telemetry.Record, action string) bool {
	for _, r := range recs {
		if r.Event != nil && r.Event.Action == action {
			return true
		}
	}
	return false
}

// TestProvenanceSpoolMode checks the five stamps on the spool records, the
// spool heartbeat and the local log, the counters of heartbeat and stopped, and
// that nothing follows stopped.
func TestProvenanceSpoolMode(t *testing.T) {
	peer, sock := newSpoolPeer(t)
	var epoch string
	a, logs, cancel, done := startAppWith(t, spoolEnv(t, sock), func(c *config) {
		c.beat = 20 * time.Millisecond
		epoch = telemetry.NewRedactor(c.derive("redact")).Epoch()
	})
	if len(epoch) != 8 {
		t.Fatalf("epoch %q", epoch)
	}
	resp, _ := post(t, "http://"+a.addrs()["openai"]+"/v1/chat/completions",
		`{"model":"qwen3:8b","messages":[{"role":"user","content":"hello"}]}`, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("chat %d", resp.StatusCode)
	}
	waitFor(t, "a spool heartbeat", func() bool { return hasAction(peer.records(t), "bait_heartbeat") })
	if err := stop(t, cancel, done); err != nil {
		t.Fatalf("run: %v", err)
	}
	peer.ln.Close()
	peer.wg.Wait()

	recs := peer.records(t)
	seen := map[string]bool{}
	stoppedAt := -1
	for i, r := range recs {
		if r.Metric != nil {
			for _, k := range provKeys {
				if _, ok := r.Metric.Attrs[k]; ok {
					t.Errorf("metric %s carries %s", r.Metric.Name, k)
				}
			}
			if len(telemetry.SafeLabels(r.Metric.Attrs)) != len(r.Metric.Attrs) {
				t.Errorf("metric %s labels left the closed set: %v", r.Metric.Name, r.Metric.Attrs)
			}
			continue
		}
		e := r.Event
		what := e.Stream + "/" + e.Action
		seen[what] = true
		wantProvenance(t, "spool "+what, e.Attrs, epoch, "configured")
		switch e.Action {
		case "bait_heartbeat":
			wantCounters(t, "spool "+what, e.Attrs)
			if stoppedAt >= 0 {
				t.Errorf("bait_heartbeat at record %d follows stopped at %d", i, stoppedAt)
			}
		case "stopped":
			stoppedAt = i
			wantCounters(t, "spool "+what, e.Attrs)
			if e.Attrs["forced"] != false || e.Result != "ok" {
				t.Errorf("graceful stopped: forced %v result %q", e.Attrs["forced"], e.Result)
			}
		}
	}
	for _, w := range []string{"runtime/start", "runtime/stop", "runtime/stopped", "heartbeat/bait_heartbeat"} {
		if !seen[w] {
			t.Errorf("no %s on the socket; saw %v", w, seen)
		}
	}
	if !hasStream(seen, telemetry.StreamEdge) {
		t.Errorf("no edge event on the socket; saw %v", seen)
	}
	if stoppedAt != len(recs)-1 {
		t.Errorf("stopped at record %d of %d, want the last", stoppedAt, len(recs))
	}

	localSeen := map[string]bool{}
	for _, l := range logs.lines(t) {
		if l["stream"] == "metric" {
			for _, k := range provKeys {
				if _, ok := l[k]; ok {
					t.Errorf("local metric carries %s", k)
				}
			}
			continue
		}
		what := l["stream"].(string) + "/" + l["action"].(string)
		localSeen[what] = true
		wantProvenance(t, "local "+what, l, epoch, "configured")
		if l["action"] == "stopped" {
			wantCounters(t, "local "+what, l)
			if l["forced"] != false || l["local_dropped"] != l["local_dropped_total"] {
				t.Errorf("local stopped: forced %v local_dropped %v total %v", l["forced"], l["local_dropped"], l["local_dropped_total"])
			}
		}
	}
	for _, w := range []string{"runtime/start", "runtime/stop", "runtime/stopped"} {
		if !localSeen[w] {
			t.Errorf("no %s in the local log; saw %v", w, localSeen)
		}
	}
	if !hasStream(localSeen, telemetry.StreamEdge) {
		t.Errorf("no edge event in the local log; saw %v", localSeen)
	}
}

// gatedWriter blocks every write until gate is closed.
type gatedWriter struct {
	syncBuf
	gate chan struct{}
}

func (g *gatedWriter) Write(p []byte) (int, error) {
	<-g.gate
	return g.syncBuf.Write(p)
}

// TestProvenanceOnLocalDropped checks that local_dropped, which the queue
// writes itself, passes through the stamp.
func TestProvenanceOnLocalDropped(t *testing.T) {
	cfg, err := loadConfig(envOf(map[string]string{"ATTACKBOX_OPENAI_ADDR": "127.0.0.1:0"}))
	if err != nil {
		t.Fatal(err)
	}
	out := &gatedWriter{gate: make(chan struct{})}
	a, err := newApp(cfg, out)
	if err != nil {
		t.Fatal(err)
	}
	// The writer is stuck on the first event, so the queue fills and the rest
	// is dropped.
	for i := 0; i < 5000; i++ {
		a.local.Emit(telemetry.Event{Stream: telemetry.StreamRuntime, Action: "fill"})
	}
	if a.local.Dropped() == 0 {
		t.Fatal("nothing dropped")
	}
	close(out.gate)
	a.closeListeners()
	_ = a.closeLocal() // reports the drops
	var found bool
	for _, l := range out.lines(t) {
		if l["action"] == "local_dropped" {
			found = true
			wantProvenance(t, "local_dropped", l, telemetry.NewRedactor(cfg.derive("redact")).Epoch(), "boot")
		}
	}
	if !found {
		t.Fatal("no local_dropped event")
	}
}

// TestForcedShutdown checks that a hold that outlives the grace period sets
// forced on stopped, on the socket and in the local log, and that stopped is
// still the last record.
func TestForcedShutdown(t *testing.T) {
	peer, sock := newSpoolPeer(t)
	env := spoolEnv(t, sock)
	env["ATTACKBOX_SHUTDOWN_TIMEOUT"] = "200ms"
	a, logs, cancel, done := startAppWith(t, env, func(c *config) { c.beat = 20 * time.Millisecond })
	// The body never arrives, so the connection stays active and Shutdown gives up.
	conn, err := net.Dial("tcp", a.addrs()["openai"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\nExpect: 100-continue\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusContinue {
		t.Fatalf("waiting for the body read: got %s", resp.Status)
	}
	if err := stop(t, cancel, done); err != nil {
		t.Fatalf("run: %v", err)
	}
	peer.ln.Close()
	peer.wg.Wait()

	recs := peer.records(t)
	last := recs[len(recs)-1].Event
	if last == nil || last.Action != "stopped" {
		t.Fatalf("last record = %+v, want stopped", recs[len(recs)-1])
	}
	if last.Attrs["forced"] != true || last.Result != "error" {
		t.Errorf("spool stopped: forced %v result %q", last.Attrs["forced"], last.Result)
	}
	for i, r := range recs[:len(recs)-1] {
		if r.Event != nil && r.Event.Action == "stopped" {
			t.Errorf("second stopped at record %d", i)
		}
	}
	var local map[string]any
	for _, l := range logs.lines(t) {
		if l["action"] == "stopped" {
			local = l
		}
	}
	if local == nil || local["forced"] != true || local["result"] != "error" {
		t.Fatalf("local stopped = %v", local)
	}
}
