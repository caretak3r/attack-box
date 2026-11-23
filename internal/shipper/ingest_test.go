package shipper

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// unixPair returns two connected unix sockets. The path is short because
// socket paths are limited to about 100 bytes and t.TempDir can exceed that.
func unixPair(t *testing.T) (client, server *net.UnixConn) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "abi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err = net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	server, err = ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

func testConn(t *testing.T, server *net.UnixConn, idle time.Duration) (*conn, *Ingest) {
	t.Helper()
	in := &Ingest{cfg: IngestConfig{IdleTimeout: idle, LineTimeout: idle, Now: time.Now}}
	in.ctx, in.cancel = context.WithCancel(context.Background())
	t.Cleanup(in.cancel)
	return &conn{in: in, c: server, br: bufio.NewReaderSize(server, readBuffer)}, in
}

// A discarded line is counted, never allocated: a producer must not turn one
// long line into an equally large buffer.
func TestReadLineOversizeDoesNotAllocate(t *testing.T) {
	client, server := unixPair(t)
	cn, _ := testConn(t, server, 30*time.Second)

	const total = 64 << 20
	go func() {
		chunk := []byte(strings.Repeat("a", 1<<20))
		for sent := 0; sent < total; sent += len(chunk) {
			if _, err := client.Write(chunk); err != nil {
				return
			}
		}
		client.Write([]byte("\n"))
	}()

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	line, n, oversize, err := cn.readLine()
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if !oversize || line != nil || n != total {
		t.Fatalf("got oversize=%v line=%d n=%d, want oversize, no line, n=%d", oversize, len(line), n, total)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 16<<20 {
		t.Fatalf("readLine allocated %d bytes for a %d byte discarded line", grew, total)
	}
}

func TestReadLineKeepsShortLine(t *testing.T) {
	client, server := unixPair(t)
	cn, _ := testConn(t, server, 5*time.Second)
	client.Write([]byte("hello\n"))
	line, n, oversize, err := cn.readLine()
	if err != nil || oversize || string(line) != "hello" || n != 5 {
		t.Fatalf("got %q n=%d oversize=%v err=%v", line, n, oversize, err)
	}
}

// Shutdown cuts the open reads. A read that starts after the cut must not
// extend its deadline and sit out the idle timeout.
func TestReadLineAfterShutdownDoesNotWait(t *testing.T) {
	_, server := unixPair(t)
	cn, in := testConn(t, server, time.Hour)
	in.cancel()
	server.SetReadDeadline(time.Unix(1, 0)) // what shutdown does

	done := make(chan error, 1)
	go func() {
		_, _, _, err := cn.readLine()
		done <- err
	}()
	select {
	case err := <-done:
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("got %v, want a timeout", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("readLine waited past shutdown")
	}
}

// A producer that sends no wire version is counted under schema_version and
// nothing it sent reaches the queue.
func TestIngestCountsSchemaVersionRejects(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "abi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	q, _ := mustOpen(t, testConfig(queueDir(t)))
	ep := Endpoint{
		Path: filepath.Join(dir, "bait.sock"), Role: RoleBait, Mode: 0o600,
		UIDs: []uint32{uint32(os.Getuid())}, MaxConns: 1, Rate: 1 << 20, Burst: 4 << 20,
	}
	in, err := NewIngest(IngestConfig{Queue: q, Endpoints: []Endpoint{ep}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- in.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-served
	})

	c, err := net.Dial("unix", ep.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	waitStats := func(what string, ok func(RoleStats) bool) RoleStats {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			st := in.Stats()[RoleBait]
			if ok(st) {
				return st
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s; stats = %+v", what, st)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	if _, err := c.Write([]byte(`{"id":"` + testBoot + `-1","event":{"stream":"edge"}}` + "\n")); err != nil {
		t.Fatal(err)
	}
	st := waitStats("the unversioned line", func(s RoleStats) bool { return s.Rejected["schema_version"] > 0 })
	if st.Rejected["schema_version"] != 1 || st.Lines != 1 || st.Queued != 0 || q.Stats().Total != 0 {
		t.Fatalf("stats = %+v, queue bytes %d; want one schema_version reject and an empty queue", st, q.Stats().Total)
	}

	// The same line with v is admitted, so the reject was about v alone.
	if _, err := c.Write([]byte(`{"id":"` + testBoot + `-2","v":1,"event":{"stream":"edge"}}` + "\n")); err != nil {
		t.Fatal(err)
	}
	st = waitStats("the versioned line", func(s RoleStats) bool { return s.Queued > 0 })
	if st.Queued != 1 || st.Rejected["schema_version"] != 1 {
		t.Fatalf("stats = %+v, want the versioned line queued and no second reject", st)
	}
}
