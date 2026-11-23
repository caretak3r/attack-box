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
	rejected, err := shipper.OpenQuarantine(cfg.queueDir + "/quarantine")
	if err != nil {
		return err
	}
	defer rejected.Close()

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

	shipperBoot := newShipperBoot()
	nr, err := telemetry.NewNewRelic(telemetry.NRConfig{
		LicenseKey:        cfg.nrLicenseKey,
		LogURL:            cfg.nrLogURL,
		MetricURL:         cfg.nrMetricURL,
		QueueSize:         20000,
		FlushInterval:     5 * time.Second,
		MaxPayloadBytes:   900_000,
		HeartbeatInterval: 30 * time.Second,
		Now:               time.Now,
		Common: map[string]any{
			"service.name":  "attackbox",
			"hostname":      cfg.hostname,
			"sensor_id":     cfg.sensorID,
			"deployment_id": cfg.deploymentID,
		},
		HeartbeatAttrs: func() map[string]any {
			stats := ing.Stats()
			baitStats, ok := stats[shipper.RoleBait]
			baitConn := ok && baitStats.Conns > 0
			lastAge := int64(-1)
			if ok && !baitStats.LastRecord.IsZero() {
				lastAge = time.Since(baitStats.LastRecord).Milliseconds()
			}
			qstats := q.Stats()
			quarantineRecords, quarantineBytes := rejected.Stats()
			attrs := map[string]any{
				"source":                     "shipper",
				"shipper_boot":               shipperBoot,
				"quarantine_records":         quarantineRecords,
				"quarantine_bytes":           quarantineBytes,
				"bait_connected":             baitConn,
				"last_bait_record_age_ms":    lastAge,
				"spool_clients":              baitStats.Conns,
				"queue_bytes":                qstats.Total,
				"queue_backlog_bytes":        qstats.Total,
				"ship_dropped_total":         qstats.Dropped,
				"ship_dropped_bait_total":    qstats.Dropped[shipper.RoleBait],
				"ship_dropped_runtime_total": qstats.Dropped[shipper.RoleRuntime],
				"ship_dropped_egress_total":  qstats.Dropped[shipper.RoleEgress],
				"ship_queue_dropped_total":   qstats.Dropped[shipper.RoleBait] + qstats.Dropped[shipper.RoleRuntime] + qstats.Dropped[shipper.RoleEgress],
			}
			for k, v := range tracing.Health() {
				attrs[k] = v
			}
			for _, role := range []shipper.Role{shipper.RoleRuntime, shipper.RoleEgress} {
				age := int64(-1)
				if st, ok := stats[role]; ok && !st.LastRecord.IsZero() {
					age = time.Since(st.LastRecord).Milliseconds()
				}
				attrs["last_"+role.String()+"_record_age_ms"] = age
			}
			return attrs
		},
		AccountingReport: func(now time.Time) []telemetry.Event {
			return ing.Accounting(now, shipperBoot)
		},
		OnError: func(err error) {
			fmt.Fprintln(stderr, "newrelic:", err)
		},
	})
	if err != nil {
		// Serve was never started; a canceled context just releases the sockets.
		stopped, cancel := context.WithCancel(ctx)
		cancel()
		ing.Serve(stopped)
		return err
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	drainDone := make(chan error, 1)
	ingestDone := make(chan error, 1)
	go func() {
		drainDone <- drain(runCtx, q, nr, rec.Uncertain, rec.UncertainThrough, rejected)
	}()
	go func() {
		ingestDone <- ing.Serve(runCtx)
	}()

	// Whichever side ends first stops the other. Read each channel once.
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

	flushCtx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
	defer cancel()
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

	// A graceful stop ends both sides with context.Canceled. A broken queue
	// arrives as ErrQueueBroken from either side and must exit non-zero.
	return errors.Join(ignoreCanceled(ingestErr), ignoreCanceled(drainErr))
}

func ignoreCanceled(err error) error {
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
