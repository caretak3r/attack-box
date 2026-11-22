package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

type route struct {
	method  string
	pattern string
	segs    []string
	handle  func(*call)
	summary string // OpenAPI summary; empty keeps the route out of the schema
}

func newRoute(method, pattern, summary string, h func(*call)) route {
	return route{method: method, pattern: pattern, segs: strings.Split(pattern, "/"), handle: h, summary: summary}
}

func (rt route) match(path string) (map[string]string, bool) {
	segs := strings.Split(path, "/")
	if len(segs) != len(rt.segs) {
		return nil, false
	}
	var params map[string]string
	for i, p := range rt.segs {
		if len(p) > 2 && p[0] == '{' && p[len(p)-1] == '}' {
			if segs[i] == "" {
				return nil, false
			}
			if params == nil {
				params = make(map[string]string, 1)
			}
			params[p[1:len(p)-1]] = segs[i]
			continue
		}
		if p != segs[i] {
			return nil, false
		}
	}
	return params, true
}

// buildRoutes returns the published surface of the persona.
func (s *Server) buildRoutes() []route {
	v1 := []route{
		newRoute("GET", "/v1/models", "Show Available Models", s.listModels),
		newRoute("GET", "/v1/models/{model}", "Show Model", s.getModel),
		newRoute("POST", "/v1/chat/completions", "Create Chat Completion", s.chat),
		newRoute("POST", "/v1/completions", "Create Completion", s.completions),
		newRoute("POST", "/v1/responses", "Create Responses", s.responses),
		newRoute("GET", "/v1/responses/{response_id}", "Retrieve Responses", s.getResponse),
		newRoute("POST", "/v1/embeddings", "Create Embedding", s.embeddings),
		newRoute("GET", "/v1/edge/{label}/status", "", s.edgeStatus),
	}
	switch s.persona {
	case PersonaOllama:
		return append(v1, s.ollamaRoutes()...)
	case PersonaVLLM:
		v1 = append(v1,
			newRoute("POST", "/v1/responses/{response_id}/cancel", "Cancel Responses", s.cancelResponse),
			newRoute("GET", "/health", "Health", s.health),
			newRoute("GET", "/version", "Show Version", s.version),
			newRoute("POST", "/invocations", "Invocations", s.invocations),
			newRoute("GET", "/metrics", "", s.metrics),
			newRoute("GET", "/docs", "", s.docs),
			newRoute("GET", "/openapi.json", "", s.openapiJSON),
		)
		return v1
	}
	return append(v1,
		newRoute("POST", "/v1/responses/{response_id}/cancel", "Cancel Responses", s.cancelResponse),
		newRoute("GET", "/health", "Health", s.health),
		newRoute("GET", "/version", "Show Version", s.version),
	)
}

// lookup finds the handler for the request. With no handler it returns the
// methods that the path does support, which is empty for an unknown path.
func (s *Server) lookup(c *call) (func(*call), []string) {
	var allowed []string
	path := c.r.URL.Path
	for _, rt := range s.routes {
		params, ok := rt.match(path)
		if !ok {
			continue
		}
		if rt.method == c.r.Method {
			c.endpoint, c.params = rt.pattern, params
			return rt.handle, nil
		}
		c.endpoint = rt.pattern
		allowed = append(allowed, rt.method)
	}
	sort.Strings(allowed)
	return nil, allowed
}

func (s *Server) notFound(c *call) {
	switch c.style {
	case styleVLLM:
		c.jsonStatus(http.StatusNotFound, map[string]string{"detail": "Not Found"})
	case styleOllama, styleOllamaV1:
		c.plain(http.StatusNotFound, "text/plain", "404 page not found")
	default:
		c.fail(http.StatusNotFound, fmt.Sprintf("Invalid URL (%s %s)", cleanEcho(c.r.Method, 16), cleanEcho(c.r.URL.Path, 128)), "", "")
	}
}

func (s *Server) methodNotAllowed(c *call, allowed []string) {
	switch c.style {
	case styleVLLM:
		c.w.Header().Set("Allow", strings.Join(allowed, ", "))
		c.jsonStatus(http.StatusMethodNotAllowed, map[string]string{"detail": "Method Not Allowed"})
	case styleOllama, styleOllamaV1:
		// gin answers a wrong method with its 404 page.
		s.notFound(c)
	default:
		c.w.Header().Set("Allow", strings.Join(allowed, ", "))
		c.fail(http.StatusMethodNotAllowed, fmt.Sprintf("Invalid method for URL (%s %s)", cleanEcho(c.r.Method, 16), cleanEcho(c.r.URL.Path, 128)), "", "")
	}
}

// errStyle is the error body dialect.
type errStyle int

const (
	styleOpenAI errStyle = iota
	styleVLLM
	styleOllama   // native /api/* errors: {"error": "..."}
	styleOllamaV1 // OpenAI-shaped errors on Ollama's /v1/*
)

func (s *Server) styleFor(path string) errStyle {
	switch s.persona {
	case PersonaVLLM:
		return styleVLLM
	case PersonaOllama:
		if strings.HasPrefix(path, "/v1/") {
			return styleOllamaV1
		}
		return styleOllama
	}
	return styleOpenAI
}

type openAIError struct {
	Error openAIErrorBody `json:"error"`
}

type openAIErrorBody struct {
	Message string  `json:"message"`
	Type    string  `json:"type"`
	Param   *string `json:"param"`
	Code    *string `json:"code"`
}

type vllmError struct {
	Object  string  `json:"object"`
	Message string  `json:"message"`
	Type    string  `json:"type"`
	Param   *string `json:"param"`
	Code    int     `json:"code"`
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func openAIType(status int) string {
	switch {
	case status == http.StatusTooManyRequests:
		return "requests"
	case status >= 500:
		return "server_error"
	}
	return "invalid_request_error"
}

func vllmType(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "BadRequestError"
	case http.StatusNotFound:
		return "NotFoundError"
	case http.StatusMethodNotAllowed:
		return "MethodNotAllowed"
	case http.StatusRequestEntityTooLarge:
		return "RequestEntityTooLarge"
	case http.StatusTooManyRequests:
		return "TooManyRequests"
	}
	return "InternalServerError"
}

func ollamaV1Type(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid_request_error"
	case http.StatusNotFound:
		return "not_found_error"
	}
	return "api_error"
}

// fail writes an error in the dialect of the request.
func (c *call) fail(status int, msg, param, code string) {
	switch c.style {
	case styleVLLM:
		c.jsonStatus(status, vllmError{Object: "error", Message: msg, Type: vllmType(status), Code: status})
	case styleOllama:
		c.jsonStatus(status, map[string]string{"error": msg})
	case styleOllamaV1:
		c.jsonStatus(status, openAIError{openAIErrorBody{Message: msg, Type: ollamaV1Type(status), Param: optional(param), Code: optional(code)}})
	default:
		c.jsonStatus(status, openAIError{openAIErrorBody{Message: msg, Type: openAIType(status), Param: optional(param), Code: optional(code)}})
	}
}

// marshal encodes v without HTML escaping, as the real servers do.
func marshal(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return []byte(`{}` + "\n")
	}
	return b.Bytes()
}

func (c *call) contentType() string {
	if c.s.persona == PersonaOllama && c.style == styleOllama {
		return "application/json; charset=utf-8"
	}
	return "application/json"
}

func (c *call) jsonStatus(status int, v any) {
	c.w.Header().Set("Content-Type", c.contentType())
	c.w.WriteHeader(status)
	_, _ = c.w.Write(marshal(v))
}

func (c *call) json(v any) { c.jsonStatus(http.StatusOK, v) }

func (c *call) plain(status int, ctype, body string) {
	h := c.w.Header()
	h.Set("Content-Type", ctype)
	c.w.WriteHeader(status)
	_, _ = c.w.Write([]byte(body))
}

func (c *call) empty(status int) {
	c.w.Header().Set("Content-Length", "0")
	c.w.WriteHeader(status)
}
