package main

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestHealthcheckValidatesCertificate(t *testing.T) {
	cfg, _, sink, _ := publicTestConfig(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	defer listener.Close()
	a, err := newApp(cfg, func() (net.Listener, error) { return listener, nil })
	if err != nil {
		t.Fatal(err)
	}

	ctx, stop := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- a.run(ctx) }()

	probeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for range 5 { // the counters below show that no probe went through the visitor limit
		if err := healthcheck(probeCtx, cfg.cert, addr); err != nil {
			stop()
			<-finished
			t.Fatal(err)
		}
	}
	stop()
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if a.accepted.Load() != 0 || a.limited.Load() != 0 || a.preHTTP.Load() != 0 {
		t.Fatalf("healthcheck counted as visitor traffic: accepted=%d limited=%d preHTTP=%d", a.accepted.Load(), a.limited.Load(), a.preHTTP.Load())
	}
	for len(sink.requests) > 0 {
		for _, r := range (<-sink.requests).ResourceSpans {
			for _, s := range r.ScopeSpans {
				for _, span := range s.Spans {
					if span.Name == "public.request" || span.Name == "public.connection" {
						t.Errorf("healthcheck exported %s", span.Name)
					}
				}
			}
		}
	}
}
