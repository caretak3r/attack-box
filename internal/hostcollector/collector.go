package hostcollector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const ListenAddress = "127.0.0.1:9465"
const modelURL = "https://127.0.0.1:8443/v1/models"
const collectorURL = "http://127.0.0.1:13133/"

type probeResult struct {
	ready int
	at    time.Time
}
type Collector struct {
	mu       sync.RWMutex
	snapshot Snapshot
	valid    bool
	updated  time.Time
	probes   map[string]probeResult
	client   *http.Client
	read     func(time.Time) (Snapshot, error)
}

func New() *Collector {
	return &Collector{read: ReadSnapshot, probes: make(map[string]probeResult), client: &http.Client{
		Timeout:       2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect prohibited") },
		Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, // Fixed loopback self-signed endpoint only; no caller-supplied URL.
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != "127.0.0.1:8443" && address != "127.0.0.1:13133" {
					return nil, errors.New("probe destination prohibited")
				}
				return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
			},
			MaxIdleConns: 2, MaxConnsPerHost: 1, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: time.Second, MaxResponseHeaderBytes: 8192,
		}}}
}
func (c *Collector) Refresh(ctx context.Context) {
	now := time.Now()
	s, err := c.read(now)
	model := probe(ctx, c.client, modelURL, true)
	collector := probe(ctx, c.client, collectorURL, false)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snapshot = s
	c.valid = err == nil
	c.updated = time.Now()
	c.probes = map[string]probeResult{
		"attackbox-bait": {model, c.updated}, "attackbox-proxy": {model, c.updated}, "attackbox-otel.service": {collector, c.updated},
	}
}
func (c *Collector) Run(ctx context.Context) {
	c.Refresh(ctx)
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Refresh(ctx)
		}
	}
}
func probe(ctx context.Context, client *http.Client, url string, models bool) int {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "attackbox-hostcollector/1")
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10+1))
	if err != nil || len(b) > 64<<10 || resp.StatusCode != 200 {
		return 0
	}
	if models {
		var data struct {
			Object string `json:"object"`
			Data   []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if json.Unmarshal(b, &data) != nil || data.Object != "list" || len(data.Data) == 0 || len(data.Data) > 100 {
			return 0
		}
		for _, m := range data.Data {
			if m.ID == "" {
				return 0
			}
		}
	} else {
		var data struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(b, &data) != nil || data.Status != "Server available" {
			return 0
		}
	}
	return 1
}
func (c *Collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/metrics" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	now := time.Now()
	valid := c.valid && validate(c.snapshot, now) == nil
	var b strings.Builder
	typed := make(map[string]bool)
	metric := func(name, component string, value float64) {
		if !typed[name] {
			fmt.Fprintf(&b, "# TYPE attackbox_%s gauge\n", name)
			typed[name] = true
		}
		if component == "" {
			fmt.Fprintf(&b, "attackbox_%s %g\n", name, value)
		} else {
			fmt.Fprintf(&b, "attackbox_%s{component=%q} %g\n", name, component, value)
		}
	}
	metric("inventory_snapshot_valid", "", boolean(valid))
	age := -1.0
	if !c.snapshot.Time.IsZero() {
		age = max(0, now.Sub(c.snapshot.Time).Seconds())
	}
	metric("inventory_snapshot_age_seconds", "", age)
	timestamp := func(name string, known bool) {
		at := 0.0
		if known {
			at = float64(c.snapshot.Time.UnixNano()) / 1e9
		}
		metric("component_observation_timestamp_seconds", name, at)
	}
	common := func(name string, known bool, running float64) {
		metric("component_observed", name, boolean(known))
		metric("component_running", name, running)
		timestamp(name, known)
		ready := -1.0
		probeAt := 0.0
		if p, ok := c.probes[name]; ok && now.Sub(p.at) <= MaxAge {
			ready = float64(p.ready)
			probeAt = float64(p.at.UnixNano()) / 1e9
		}
		if name == "attackbox-hostcollector.service" && !c.updated.IsZero() && now.Sub(c.updated) <= MaxAge {
			ready = 1
			probeAt = float64(c.updated.UnixNano()) / 1e9
		}
		metric("component_ready", name, ready)
		failed := -1.0
		if ready >= 0 {
			failed = boolean(ready == 0)
		}
		metric("component_probe_failed", name, failed)
		metric("component_readiness_timestamp_seconds", name, probeAt)
		// No unit-state or readiness probe establishes remote forensic coverage.
		metric("component_coverage_verified", name, -1)
	}
	for i, name := range units {
		known := valid && c.snapshot.Units[i].Known
		running := -1.0
		if known {
			running = boolean(c.snapshot.Units[i].Active == "active" && c.snapshot.Units[i].Load == "loaded")
		}
		common(name, known, running)
	}
	for i, name := range containers {
		known := valid && c.snapshot.Containers[i].Known
		running := -1.0
		health := -1.0
		restarts := -1.0
		oom := -1.0
		runtime := -1.0
		memory := -1.0
		cpus := -1.0
		if known {
			v := c.snapshot.Containers[i]
			running = boolean(v.Running)
			if v.Health == "healthy" {
				health = 1
			} else if v.Health == "unhealthy" || v.Health == "starting" {
				health = 0
			}
			restarts = float64(v.Restarts)
			oom = boolean(v.OOM)
			runtime = boolean(v.Runtime == "runsc")
			memory = float64(v.Memory)
			cpus = float64(v.NanoCPUs) / 1e9
		}
		common(name, known, running)
		metric("container_health", name, health)
		metric("container_restarts", name, restarts)
		metric("container_oom", name, oom)
		metric("container_runtime_approved", name, runtime)
		metric("container_memory_limit_bytes", name, memory)
		metric("container_cpu_limit", name, cpus)
	}
	io.WriteString(w, b.String())
}
func boolean(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

// Listen has no address override: neither a flag nor environment can expose it.
func Listen() (net.Listener, error) { return net.Listen("tcp4", ListenAddress) }
