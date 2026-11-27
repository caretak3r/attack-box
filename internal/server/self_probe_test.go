package server

import (
	"net/http/httptest"
	"testing"
)

// Self-probes (loopback healthcheck and hostcollector from private addresses)
// serve normally but emit no telemetry: no edge events, no evidence records,
// no bait.request/response spans. Other traffic from private addresses keeps
// full telemetry.
func TestSelfProbeTelemetryMuted(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		userAgent  string
		wantEvents bool
	}{
		{
			name:       "loopback healthcheck",
			remoteAddr: "127.0.0.1:1234",
			userAgent:  "Go-http-client/1.1",
			wantEvents: false,
		},
		{
			name:       "loopback IPv6",
			remoteAddr: "[::1]:5678",
			userAgent:  "curl/7.0",
			wantEvents: false,
		},
		{
			name:       "hostcollector from docker host",
			remoteAddr: "172.18.0.1:2345",
			userAgent:  "attackbox-hostcollector/1",
			wantEvents: false,
		},
		{
			name:       "other probe from docker host keeps telemetry",
			remoteAddr: "172.18.0.1:2345",
			userAgent:  "acceptance-test/1",
			wantEvents: true,
		},
		{
			name:       "public IP with hostcollector UA keeps telemetry",
			remoteAddr: "192.0.2.10:3456",
			userAgent:  "attackbox-hostcollector/1",
			wantEvents: true,
		},
		{
			name:       "RFC1918 with other UA keeps telemetry",
			remoteAddr: "10.0.0.5:4567",
			userAgent:  "curl/8.0",
			wantEvents: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t, PersonaOpenAI)
			req := httptest.NewRequest("GET", "/v1/models", nil)
			req.RemoteAddr = tt.remoteAddr
			req.Header.Set("User-Agent", tt.userAgent)
			rec := r.serve(req)

			if rec.Code != 200 {
				t.Fatalf("response failed: %d", rec.Code)
			}

			edges := r.sink.edges("request")
			gotEvents := len(edges) > 0

			if gotEvents != tt.wantEvents {
				t.Errorf("got events=%v, want events=%v; edge count=%d", gotEvents, tt.wantEvents, len(edges))
			}

			if tt.wantEvents {
				// Verify full telemetry
				edge := r.sink.lastEdge(t)
				if edge.SrcIP == "" || edge.UserAgent == "" {
					t.Errorf("edge missing source/UA: %+v", edge)
				}
			}
		})
	}
}
