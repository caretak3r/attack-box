package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// metrics serves a Prometheus page shaped like vLLM's. The counters grow with
// uptime; no value reflects real traffic.
func (s *Server) metrics(c *call) {
	model := s.cfg.Models[0]
	up := max(int64(0), s.cfg.Now().Sub(s.started).Milliseconds()/1000)
	lbl := fmt.Sprintf(`{engine="0",model_name=%q}`, model)
	var b strings.Builder
	gauge := func(name, help, value string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n%s%s %s\n", name, help, name, name, lbl, value)
	}
	counter := func(name, help, labels string, v int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n%s%s %d.0\n", name, help, name, name, labels, v)
	}
	gauge("vllm:num_requests_running", "Number of requests in model execution batches.", "0.0")
	gauge("vllm:num_requests_waiting", "Number of requests waiting to be processed.", "0.0")
	gauge("vllm:kv_cache_usage_perc", "KV-cache usage. 1 means 100 percent usage.", "0.0")
	counter("vllm:prompt_tokens_total", "Number of prefill tokens processed.", lbl, up*37)
	counter("vllm:generation_tokens_total", "Number of generation tokens processed.", lbl, up*11)
	counter("vllm:request_success_total", "Count of successfully processed requests.",
		fmt.Sprintf(`{engine="0",finished_reason="stop",model_name=%q}`, model), up/9)
	fmt.Fprintf(&b, "# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.\n"+
		"# TYPE process_start_time_seconds gauge\nprocess_start_time_seconds %d.0\n", s.started.Unix())
	c.plain(http.StatusOK, "text/plain; version=1.0.0; charset=utf-8", b.String())
}

const docsPage = `
    <!DOCTYPE html>
    <html>
    <head>
    <link type="text/css" rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
    <title>FastAPI - Swagger UI</title>
    </head>
    <body>
    <div id="swagger-ui">
    </div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
    const ui = SwaggerUIBundle({
        url: '/openapi.json',
    "dom_id": "#swagger-ui",
"layout": "BaseLayout",
"deepLinking": true,
"showExtensions": true,
"showCommonExtensions": true
    })
    </script>
    </body>
    </html>
    `

func (s *Server) docs(c *call) { c.plain(http.StatusOK, "text/html; charset=utf-8", docsPage) }

func (s *Server) openapiJSON(c *call) {
	c.w.Header().Set("Content-Type", "application/json")
	c.sendBody(http.StatusOK, s.openapi)
}

// buildOpenAPI renders the schema of the routes that carry a summary. Only the
// vLLM persona publishes one.
func (s *Server) buildOpenAPI() []byte {
	if s.persona != PersonaVLLM {
		return nil
	}
	paths := map[string]map[string]any{}
	for _, rt := range s.routes {
		if rt.summary == "" {
			continue
		}
		op := map[string]any{
			"summary":     rt.summary,
			"operationId": operationID(rt),
			"responses": map[string]any{"200": map[string]any{
				"description": "Successful Response",
				"content":     map[string]any{"application/json": map[string]any{"schema": map[string]any{}}},
			}},
		}
		var params []map[string]any
		for _, seg := range rt.segs {
			if len(seg) > 2 && seg[0] == '{' {
				name := seg[1 : len(seg)-1]
				params = append(params, map[string]any{
					"name": name, "in": "path", "required": true,
					"schema": map[string]any{"type": "string", "title": strings.ToTitle(name[:1]) + name[1:]},
				})
			}
		}
		if params != nil {
			op["parameters"] = params
		}
		if paths[rt.pattern] == nil {
			paths[rt.pattern] = map[string]any{}
		}
		paths[rt.pattern][strings.ToLower(rt.method)] = op
	}
	doc := map[string]any{
		"openapi": "3.1.0",
		"info":    map[string]any{"title": "FastAPI", "version": "0.1.0"},
		"paths":   paths,
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return []byte("{}")
	}
	return b
}

// operationID mimics FastAPI: summary words joined by underscores, then the
// path and method.
func operationID(rt route) string {
	name := strings.ToLower(strings.ReplaceAll(rt.summary, " ", "_"))
	path := strings.NewReplacer("/", "_", "{", "_", "}", "_").Replace(rt.pattern)
	return name + path + "_" + strings.ToLower(rt.method)
}
