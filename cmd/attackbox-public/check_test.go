package main

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestHealthcheckValidatesCertificate(t *testing.T) {
	cfg, _, _, _ := publicTestConfig(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	a, err := newApp(cfg, func() (net.Listener, error) {
		return net.Listen("tcp4", addr)
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, stop := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- a.run(ctx) }()
	defer func() {
		stop()
		_ = <-finished
	}()

	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := healthcheck(ctx, cfg.cert); err != nil {
		t.Fatal(err)
	}
}
