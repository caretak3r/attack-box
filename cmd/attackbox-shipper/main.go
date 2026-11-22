// Command attackbox-shipper accepts bait and host-adapter records on unix
// sockets, durably queues them and ships them to New Relic. It runs on the
// host as a different user, so the bait process never holds the license key.
//
// Flags:
//
//	-stdin-stream runtime|egress   wrap stdin JSON lines and write to the socket
//	-version                        print the version and exit
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

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

func run(ctx context.Context, cfg config, stderr io.Writer) error {
	qcfg := shipper.QueueConfig{
		Dir:          cfg.queueDir,
		SegmentBytes: cfg.segmentBytes,
		MaxBytes:     cfg.queueBytes,
		RoleBytes: map[shipper.Role]int64{
			shipper.RoleBait:    (cfg.queueBytes * 60) / 100,
			shipper.RoleRuntime: (cfg.queueBytes * 20) / 100,
			shipper.RoleEgress:  (cfg.queueBytes * 20) / 100,
		},
		MaxPayload: telemetry.MinPayloadBytes - shipper.FrameHeader,
	}
	q, rec, err := shipper.OpenQueue(qcfg)
	if err != nil {
		return err
	}
	defer q.Close()

	nrcfg := telemetry.NRConfig{
		LicenseKey:        cfg.nrLicenseKey,
		LogURL:            cfg.nrLogURL,
		MetricURL:         cfg.nrMetricURL,
		QueueSize:         20000,
		FlushInterval:     5 * time.Second,
		MaxPayloadBytes:   900_000,
		HeartbeatInterval: 30 * time.Second,
		Now:               time.Now,
		Common: map[string]any{
			"service.name": "attackbox",
			"hostname":     cfg.hostname,
		},
		OnError: func(err error) {
			fmt.Fprintln(stderr, "newrelic:", err)
		},
	}
	nr, err := telemetry.NewNewRelic(nrcfg)
	if err != nil {
		return err
	}

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

	var drainDone, ingestDone chan error
	drainDone = make(chan error, 1)
	nrcfg.HeartbeatAttrs = func() map[string]any {
		stats := ing.Stats()
		baitStats, ok := stats[shipper.RoleBait]
		baitConn := ok && baitStats.Conns > 0
		lastAge := int64(-1)
		if ok && !baitStats.LastRecord.IsZero() {
			lastAge = time.Since(baitStats.LastRecord).Milliseconds()
		}
		qstats := q.Stats()
		return map[string]any{
			"source":                  "shipper",
			"bait_connected":          baitConn,
			"last_bait_record_age_ms": lastAge,
			"spool_clients":           baitStats.Conns,
			"queue_bytes":             qstats.Total,
			"queue_backlog_bytes":     qstats.Total,
			"ship_dropped_total":      qstats.Dropped,
		}
	}

	nr, err = telemetry.NewNewRelic(nrcfg)
	if err != nil {
		return err
	}

	go func() {
		drainDone <- drain(ctx, q, nr, rec.Uncertain, rec.UncertainThrough)
	}()
	go func() {
		ingestDone <- ing.Serve(ctx)
	}()

	select {
	case <-ctx.Done():
	case err := <-drainDone:
		if err != nil {
			return err
		}
	case err := <-ingestDone:
		if err != nil {
			return err
		}
	}

	flushCtx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
	defer cancel()

	if err := <-ingestDone; err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, "ingest:", err)
	}
	drainErr := <-drainDone
	if closeErr := nr.Close(flushCtx); closeErr != nil {
		fmt.Fprintln(stderr, "newrelic close:", closeErr)
	}

	stats := nr.Stats()
	local := telemetry.NewJSONLog(stderr)
	local.Emit(telemetry.Event{
		Stream:    telemetry.StreamRuntime,
		Action:    "stopped",
		Timestamp: time.Now(),
		Attrs: map[string]any{
			"nr_sent":             stats.Sent,
			"nr_dropped":          stats.Dropped,
			"nr_lost":             stats.Lost,
			"nr_errors":           stats.Errors,
			"queue_backlog_bytes": q.Stats().Total,
		},
	})

	return drainErr
}
