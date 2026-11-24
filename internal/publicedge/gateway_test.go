package publicedge

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGatewayModelsRoute(t *testing.T) {
	g := NewGateway(nil)
	req := httptest.NewRequest("GET", "/v1/models", nil)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"local-instruct-8b"`) {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

func TestGatewayChatCompletion(t *testing.T) {
	g := NewGateway(nil)
	body := `{"model":"local-instruct-8b","messages":[{"role":"user","content":"test"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"chatcmpl-`) {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

func TestGatewayStreamingChatCompletion(t *testing.T) {
	g := NewGateway(nil)
	body := `{"model":"local-instruct-8b","messages":[{"role":"user","content":"test"}],"stream":true}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("expected text/event-stream, got %s", w.Header().Get("Content-Type"))
	}
	if !strings.Contains(w.Body.String(), "data: [DONE]") {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

func TestGatewayCompletion(t *testing.T) {
	g := NewGateway(nil)
	body := `{"model":"local-instruct-8b","prompt":"test"}`
	req := httptest.NewRequest("POST", "/v1/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"cmpl-`) {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

func TestGatewayAzureDeployment(t *testing.T) {
	g := NewGateway(nil)
	body := `{"messages":[{"role":"user","content":"test"}]}`
	req := httptest.NewRequest("POST", "/openai/deployments/local-instruct-8b/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"chatcmpl-`) {
		t.Fatalf("unexpected body: %s", w.Body.String())
	}
}

func TestGatewayRejectsUnknownModel(t *testing.T) {
	g := NewGateway(nil)
	body := `{"model":"unknown","messages":[{"role":"user","content":"test"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGatewayRejectsInvalidRequest(t *testing.T) {
	g := NewGateway(nil)
	body := `{"model":"local-instruct-8b"}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestGatewayRejectsLargeBody(t *testing.T) {
	g := NewGateway(nil)
	body := strings.Repeat("x", 65*1024)
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
}

func TestGatewayBusyWhenSlotsFull(t *testing.T) {
	g := NewGateway(nil)
	for i := 0; i < 16; i++ {
		g.slots <- struct{}{}
	}
	req := httptest.NewRequest("GET", "/v1/models", nil)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") != "1" {
		t.Fatalf("expected Retry-After: 1, got %s", w.Header().Get("Retry-After"))
	}
}

func TestGatewayWriterFlush(t *testing.T) {
	w := &gatewayWriter{ResponseWriter: httptest.NewRecorder()}
	w.Flush()
	if w.status != http.StatusOK {
		t.Fatalf("expected status 200 after flush, got %d", w.status)
	}
}

func TestGatewayReadObjectRejectsInvalid(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	_, status := gatewayReadObject(req)
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", status)
	}
}

func TestGatewayReadObjectRejectsOversized(t *testing.T) {
	req := httptest.NewRequest("POST", "/", io.NopCloser(bytes.NewReader(make([]byte, 65*1024))))
	req.ContentLength = 65 * 1024
	req.Body = http.MaxBytesReader(httptest.NewRecorder(), req.Body, gatewayBodyLimit)
	_, status := gatewayReadObject(req)
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", status)
	}
}
