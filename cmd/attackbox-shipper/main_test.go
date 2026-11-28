package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"attackbox/internal/telemetry"
)

func TestQuietAdapterHeartbeat(t *testing.T) {
	for _, role := range []string{"runtime", "egress"} {
		t.Run(role, func(t *testing.T) {
			dir, err := os.MkdirTemp("/tmp", "abx-beat-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			path := filepath.Join(dir, "s")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			_ = listener.(*net.UnixListener).SetDeadline(time.Now().Add(3 * time.Second))
			input, writer := io.Pipe()
			defer input.Close()
			defer writer.Close()
			done := make(chan error, 1)
			go func() { done <- runAdapter(role, func(string) string { return path }, input, io.Discard) }()
			conn, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			var record telemetry.Record
			if err := json.NewDecoder(conn).Decode(&record); err != nil {
				t.Fatal(err)
			}
			if record.Event == nil || record.Event.Stream != telemetry.StreamHeartbeat || record.Event.Action != role+"_heartbeat" {
				t.Fatalf("wrong quiet adapter heartbeat: %+v", record.Event)
			}
			_ = writer.Close()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("adapter did not stop on EOF")
			}
		})
	}
}

func TestIgnoreCanceled(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{"nil", nil, nil},
		{"other", io.EOF, io.EOF},
		{"canceled", context.Canceled, nil},
		{"wrapped", fmt.Errorf("wrap: %w", context.Canceled), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ignoreCanceled(tt.err)
			if !errors.Is(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
