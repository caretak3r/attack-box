// Command attackbox-shipper accepts bait and host-adapter records on unix
// sockets, durably queues them and writes them to local evidence files.
//
// Flags:
//
//	-stdin-stream runtime|egress   wrap stdin JSON lines and write to the socket
//	-version                        print the version and exit
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"attackbox/internal/observability"
	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
)

var version = "dev"

func main() {
	os.Exit(cli(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func cli(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("attackbox-shipper", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print the version and exit")
	stdinStream := fs.String("stdin-stream", "", "runtime or egress: wrap stdin JSON lines for the socket")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "attackbox-shipper: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if *stdinStream != "" {
		if err := runAdapter(*stdinStream, getenv, os.Stdin, stderr); err != nil {
			fmt.Fprintln(stderr, "attackbox-shipper:", err)
			return 1
		}
		return 0
	}
	cfg, err := loadConfig(getenv)
	if err != nil {
		fmt.Fprintln(stderr, "attackbox-shipper: configuration error:\n"+err.Error())
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, stderr); err != nil {
		fmt.Fprintln(stderr, "attackbox-shipper:", err)
		return 1
	}
	return 0
}

func runAdapter(stream string, getenv func(string) string, stdin io.Reader, stderr io.Writer) error {
	role, action := shipper.RoleRuntime, "falco"
	switch stream {
	case "runtime":
	case "egress":
		role, action = shipper.RoleEgress, "egress_blocked"
	default:
		return fmt.Errorf("stdin-stream must be runtime or egress, got %q", stream)
	}
	socket := getenv("ATTACKBOX_SPOOL_SOCKET")
	if socket == "" {
		socket = "/run/attackbox/spool.sock"
	}
	if err := telemetry.ValidSocketPath(socket); err != nil {
		return err
	}
	cfg := telemetry.SpoolConfig{
		Socket:       socket,
		QueueSize:    1000,
		WriteTimeout: 5 * time.Second,
		MaxRecord:    2 << 20,
		Heartbeat:    -1,
		Now:          time.Now,
		OnError: func(err error) {
			fmt.Fprintln(stderr, "spool:", err)
		},
	}
	sp, err := telemetry.NewSpool(cfg)
	if err != nil {
		return err
	}
	defer sp.Close(context.Background())
	// Quiet sensors must keep their socket alive and expose local transport loss.
	// This heartbeat proves adapter liveness, not source or remote receipt.
	stopBeat, beatDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(beatDone)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			stats := sp.Stats()
			sp.Emit(telemetry.Event{Stream: telemetry.StreamHeartbeat,
				Action: role.String() + "_heartbeat", Timestamp: time.Now(),
				Attrs: map[string]any{"written_total": stats.Written, "dropped_total": stats.Dropped,
					"lost_total": stats.Lost, "errors_total": stats.Errors, "reconnects_total": stats.Reconnects}})
			select {
			case <-stopBeat:
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() { close(stopBeat); <-beatDone }()

	sc := bufio.NewScanner(stdin)
	sc.Buffer(make([]byte, 8192), 8<<10)
	for sc.Scan() {
		var raw json.RawMessage
		if err := json.Unmarshal(sc.Bytes(), &raw); err != nil {
			continue
		}
		e := telemetry.Event{
			Stream:    streamForRole(role),
			Action:    action,
			Timestamp: time.Now(),
			Attrs:     map[string]any{"event": raw},
		}
		sp.Emit(e)
	}
	return sc.Err()
}

func streamForRole(r shipper.Role) string {
	switch r {
	case shipper.RoleRuntime:
		return telemetry.StreamRuntime
	case shipper.RoleEgress:
		return telemetry.StreamEgress
	default:
		return telemetry.StreamEdge
	}
}

// queueConfig derives the queue bounds from cfg. MaxPayload covers the largest
// admitted record, and loadConfig keeps every role cap above one such frame.
func queueConfig(cfg config) shipper.QueueConfig {
	return shipper.QueueConfig{
		Dir:          cfg.queueDir,
		SegmentBytes: cfg.segmentBytes,
		MaxBytes:     cfg.queueBytes,
		RoleBytes: map[shipper.Role]int64{
			shipper.RoleBait:    (cfg.queueBytes * 60) / 100,
			shipper.RoleRuntime: (cfg.queueBytes * 20) / 100,
			shipper.RoleEgress:  (cfg.queueBytes * 20) / 100,
		},
		MaxPayload: shipper.MaxData,
	}
}

// newShipperBoot returns the ID of this shipper process, 16 hex characters. A
// new one marks a restart of the delivery path in the accounting rows.
func newShipperBoot() string {
	var b [8]byte
	rand.Read(b[:]) // never fails
	return hex.EncodeToString(b[:])
}

func run(ctx context.Context, cfg config, stderr io.Writer) error {
	tracing, err := observability.New(ctx, cfg.tracing, "attackbox-shipper", version)
	if err != nil {
		return err
	}
	defer tracing.Close()
	ctx = observability.WithTracer(ctx, tracing.Tracer)
	q, rec, err := shipper.OpenQueue(queueConfig(cfg))
	if err != nil {
		return err
	}
	defer q.Close()

	evidence, err := telemetry.NewEvidenceLog(telemetry.EvidenceConfig{
		Dir:           cfg.evidenceDir,
		RetentionDays: 30,
		MaxBytes:      8 << 30,
		Now:           time.Now,
		OnError: func(err error) {
			fmt.Fprintln(stderr, "evidence:", err)
		},
	})
	if err != nil {
		return err
	}
	defer evidence.Close()

	ing, err := shipper.NewIngest(shipper.IngestConfig{
		Endpoints: cfg.endpoints,
		Queue:     q,
		Now:       time.Now,
		OnError: func(err error) {
			fmt.Fprintln(stderr, "ingest:", err)
		},
	})
	if err != nil {
		return err
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	drainDone := make(chan error, 1)
	ingestDone := make(chan error, 1)
	go func() {
		drainDone <- drain(runCtx, q, evidence, "shipper", rec.Uncertain, rec.UncertainThrough)
	}()
	go func() {
		ingestDone <- ing.Serve(runCtx)
	}()

	var drainErr, ingestErr error
	var drainSeen, ingestSeen bool
	select {
	case <-ctx.Done():
	case drainErr, drainSeen = <-drainDone:
	case ingestErr, ingestSeen = <-ingestDone:
	}
	cancelRun()
	if !ingestSeen {
		ingestErr = <-ingestDone
	}
	if !drainSeen {
		drainErr = <-drainDone
	}

	local := telemetry.NewJSONLog(stderr)
	local.Emit(telemetry.Event{
		Stream:    telemetry.StreamRuntime,
		Action:    "stopped",
		Timestamp: time.Now(),
		Attrs: map[string]any{
			"queue_backlog_bytes": q.Stats().Total,
		},
	})

	return errors.Join(ignoreCanceled(ingestErr), ignoreCanceled(drainErr))
}

func ignoreCanceled(err error) error {
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
