package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
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
)

const testNRKey = "0123456789abcdef0123456789abcdefNRAL"

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadConfigDefaults(t *testing.T) {
	c, err := loadConfig(envOf(map[string]string{"ATTACKBOX_NR_DISABLED": "true"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.listeners) != 1 || c.listeners[0] != (listener{"openai", ":8080"}) {
		t.Fatalf("listeners = %+v", c.listeners)
	}
	if c.holdSilent != 150*time.Second || c.idleInterval != 45*time.Second || c.maxStream != 180*time.Second {
		t.Fatalf("hold defaults = %v %v %v", c.holdSilent, c.idleInterval, c.maxStream)
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
		"ATTACKBOX_NR_LICENSE_KEY":  testNRKey,
		"ATTACKBOX_NR_LOG_URL":      "http://127.0.0.1:1/log",
		"ATTACKBOX_OPENAI_ADDR":     "127.0.0.1:18080",
		"ATTACKBOX_VLLM_ADDR":       ":8000",
		"ATTACKBOX_OLLAMA_ADDR":     "[::1]:11434",
		"ATTACKBOX_MODELS":          "qwen3:8b, llama3.1:8b",
		"ATTACKBOX_TRUSTED_PROXIES": "172.18.0.0/16, 10.0.0.5",
		"ATTACKBOX_SECRET_FILE":     secret,
		"ATTACKBOX_HOLD_SILENT":     "2s",
		"ATTACKBOX_MAX_STREAM":      "5s",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.listeners) != 3 || c.listeners[2].persona != "ollama" {
		t.Fatalf("listeners = %+v", c.listeners)
	}
	if len(c.models) != 2 || c.models[1] != "llama3.1:8b" {
		t.Fatalf("models = %q", c.models)
	}
	if len(c.trustedProxies) != 2 || c.trustedProxies[1].String() != "10.0.0.5/32" {
		t.Fatalf("proxies = %v", c.trustedProxies)
	}
	c2, err := loadConfig(envOf(map[string]string{"ATTACKBOX_NR_DISABLED": "1", "ATTACKBOX_SECRET_FILE": secret}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.derive("session"), c2.derive("session")) {
		t.Fatal("same secret file must give the same session key across restarts")
	}
}

func TestLoadConfigErrors(t *testing.T) {
	short := filepath.Join(t.TempDir(), "short")
	_ = os.WriteFile(short, []byte("tiny"), 0o600)
	cases := map[string]struct {
		env  map[string]string
		want string
	}{
		"nr key required":   {map[string]string{}, "ATTACKBOX_NR_LICENSE_KEY is required"},
		"nr conflict":       {map[string]string{"ATTACKBOX_NR_DISABLED": "true", "ATTACKBOX_NR_LICENSE_KEY": testNRKey}, "conflicts"},
		"bad bool":          {map[string]string{"ATTACKBOX_NR_DISABLED": "maybe"}, "want true or false"},
		"bad duration":      {map[string]string{"ATTACKBOX_NR_DISABLED": "1", "ATTACKBOX_HOLD_SILENT": "soon"}, "ATTACKBOX_HOLD_SILENT"},
		"negative duration": {map[string]string{"ATTACKBOX_NR_DISABLED": "1", "ATTACKBOX_IDLE_INTERVAL": "-1s"}, "ATTACKBOX_IDLE_INTERVAL"},
		"hold over stream":  {map[string]string{"ATTACKBOX_NR_DISABLED": "1", "ATTACKBOX_HOLD_SILENT": "10s", "ATTACKBOX_MAX_STREAM": "5s"}, "must not exceed"},
		"bad int":           {map[string]string{"ATTACKBOX_NR_DISABLED": "1", "ATTACKBOX_MAX_SESSIONS": "0"}, "ATTACKBOX_MAX_SESSIONS"},
		"no listeners":      {map[string]string{"ATTACKBOX_NR_DISABLED": "1", "ATTACKBOX_OPENAI_ADDR": "off"}, "no listener enabled"},
		"bad addr":          {map[string]string{"ATTACKBOX_NR_DISABLED": "1", "ATTACKBOX_OPENAI_ADDR": "example.com:80"}, "host must be an IP"},
		"bad port":          {map[string]string{"ATTACKBOX_NR_DISABLED": "1", "ATTACKBOX_VLLM_ADDR": ":99999"}, "invalid port"},
		"dup addr":          {map[string]string{"ATTACKBOX_NR_DISABLED": "1", "ATTACKBOX_VLLM_ADDR": ":8080"}, "already used"},
		"bad proxy":         {map[string]string{"ATTACKBOX_NR_DISABLED": "1", "ATTACKBOX_TRUSTED_PROXIES": "proxy.local"}, "not an IP or CIDR"},
		"bad model":         {map[string]string{"ATTACKBOX_NR_DISABLED": "1", "ATTACKBOX_MODELS": "a\x01b"}, "invalid model"},
		"bad instance":      {map[string]string{"ATTACKBOX_NR_DISABLED": "1", "ATTACKBOX_INSTANCE": "has space"}, "ATTACKBOX_INSTANCE"},
		"short secret":      {map[string]string{"ATTACKBOX_NR_DISABLED": "1", "ATTACKBOX_SECRET_FILE": short}, "at least 32 bytes"},
		"missing secret":    {map[string]string{"ATTACKBOX_NR_DISABLED": "1", "ATTACKBOX_SECRET_FILE": "/nonexistent/secret"}, "ATTACKBOX_SECRET_FILE"},
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
	if code := cli([]string{"-check-config"}, envOf(map[string]string{"ATTACKBOX_NR_DISABLED": "1"}), &out, &errb); code != 0 || !strings.Contains(out.String(), "new relic disabled") {
		t.Fatalf("check-config: code %d out %q err %q", code, out.String(), errb.String())
	}
	errb.Reset()
	if code := cli([]string{"-check-config"}, envOf(nil), &out, &errb); code != 2 || !strings.Contains(errb.String(), "ATTACKBOX_NR_LICENSE_KEY") {
		t.Fatalf("missing key: code %d err %q", code, errb.String())
	}
	if code := cli([]string{"stray"}, envOf(nil), &out, &errb); code != 2 {
		t.Fatalf("stray arg code %d", code)
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
	for _, u := range []string{"http://192.0.2.1/health", "https://127.0.0.1/health", "::bad"} {
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

// nrIntake is a fake New Relic Log and Metric API.
type nrIntake struct {
	mu    sync.Mutex
	posts map[string][][]byte
	keys  []string
}

func (n *nrIntake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	b, _ := io.ReadAll(zr)
	n.mu.Lock()
	n.posts[r.URL.Path] = append(n.posts[r.URL.Path], b)
	n.keys = append(n.keys, r.Header.Get("Api-Key"))
	n.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
}

func startApp(t *testing.T, env map[string]string) (*app, *syncBuf, context.CancelFunc, chan error) {
	t.Helper()
	cfg, err := loadConfig(envOf(env))
	if err != nil {
		t.Fatal(err)
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

// TestLiveThreePersonas runs the real listeners on loopback with a fake New
// Relic intake and checks each persona, streaming, shared sessions, local
// logs, redaction and the shutdown flush.
func TestLiveThreePersonas(t *testing.T) {
	intake := &nrIntake{posts: map[string][][]byte{}}
	nr := httptest.NewServer(intake)
	defer nr.Close()

	a, logs, cancel, done := startApp(t, map[string]string{
		"ATTACKBOX_NR_LICENSE_KEY": testNRKey,
		"ATTACKBOX_NR_LOG_URL":     nr.URL + "/log/v1",
		"ATTACKBOX_NR_METRIC_URL":  nr.URL + "/metric/v1",
		"ATTACKBOX_OPENAI_ADDR":    "127.0.0.1:0",
		"ATTACKBOX_VLLM_ADDR":      "127.0.0.1:0",
		"ATTACKBOX_OLLAMA_ADDR":    "127.0.0.1:0",
		"ATTACKBOX_INSTANCE":       "test-box",
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
	if strings.Contains(out, bearer) || strings.Contains(out, testNRKey) {
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
			stopped = l["result"] == "ok" && l["nr_lost"] == float64(0) && l["nr_sent"].(float64) > 0
		}
	}
	if !personas["openai"] || !personas["vllm"] || !personas["ollama"] || !started || !stopped {
		t.Fatalf("personas %v started %v stopped %v\n%s", personas, started, stopped, out)
	}

	intake.mu.Lock()
	defer intake.mu.Unlock()
	if len(intake.posts["/log/v1"]) == 0 || len(intake.posts["/metric/v1"]) == 0 {
		t.Fatalf("nr posts = %d logs, %d metrics", len(intake.posts["/log/v1"]), len(intake.posts["/metric/v1"]))
	}
	for _, k := range intake.keys {
		if k != testNRKey {
			t.Fatalf("Api-Key = %q", k)
		}
	}
	var shipped strings.Builder
	for _, p := range intake.posts["/log/v1"] {
		shipped.Write(p)
	}
	s := shipped.String()
	if strings.Contains(s, bearer) || !strings.Contains(s, `"instance":"test-box"`) || !strings.Contains(s, `"persona":"ollama"`) {
		t.Fatalf("shipped logs unexpected: %.400s", s)
	}
}

// TestNRFailureIsReported checks that a failing intake makes run return an
// error and logs the failure locally, instead of claiming delivery.
func TestNRFailureIsReported(t *testing.T) {
	nr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	defer nr.Close()
	a, logs, cancel, done := startApp(t, map[string]string{
		"ATTACKBOX_NR_LICENSE_KEY": testNRKey,
		"ATTACKBOX_NR_LOG_URL":     nr.URL + "/log/v1",
		"ATTACKBOX_NR_METRIC_URL":  nr.URL + "/metric/v1",
		"ATTACKBOX_OPENAI_ADDR":    "127.0.0.1:0",
	})
	get(t, "http://"+a.addrs()["openai"]+"/health")
	err := stop(t, cancel, done)
	if err == nil || !strings.Contains(err.Error(), "lost") {
		t.Fatalf("run err = %v, want lost-events error", err)
	}
	out := logs.String()
	if !strings.Contains(out, `"action":"newrelic_error"`) || !strings.Contains(out, `"result":"error"`) || strings.Contains(out, testNRKey) {
		t.Fatalf("local log: %s", out)
	}
}

func TestLocalOnlyAndPortConflict(t *testing.T) {
	a, logs, cancel, done := startApp(t, map[string]string{"ATTACKBOX_NR_DISABLED": "true", "ATTACKBOX_OPENAI_ADDR": "127.0.0.1:0"})
	addr := a.addrs()["openai"]
	if resp, _ := get(t, "http://"+addr+"/health"); resp.StatusCode != 200 {
		t.Fatalf("health %d", resp.StatusCode)
	}

	cfg, err := loadConfig(envOf(map[string]string{"ATTACKBOX_NR_DISABLED": "true", "ATTACKBOX_OPENAI_ADDR": addr}))
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

// TestShutdownCutsHolds checks that a held stream does not block shutdown past
// the grace period.
func TestShutdownCutsHolds(t *testing.T) {
	a, _, cancel, done := startApp(t, map[string]string{
		"ATTACKBOX_NR_DISABLED":      "true",
		"ATTACKBOX_OPENAI_ADDR":      "127.0.0.1:0",
		"ATTACKBOX_SHUTDOWN_TIMEOUT": "200ms",
	})
	// Never send the body: the connection is active, so Shutdown must give up.
	conn, err := net.Dial("tcp", a.addrs()["openai"])
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n{"))
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	if err := stop(t, cancel, done); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("shutdown took %v", d)
	}
}
