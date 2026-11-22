package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
)

type config struct {
	endpoints       []shipper.Endpoint
	queueDir        string
	queueBytes      int64
	segmentBytes    int64
	nrLicenseKey    string
	nrLogURL        string
	nrMetricURL     string
	hostname        string
	shutdownTimeout time.Duration
}

func loadConfig(getenv func(string) string) (config, error) {
	var c config
	var errs []error

	// Queue settings
	c.queueDir = getenv("ATTACKBOX_SHIP_QUEUE_DIR")
	if c.queueDir == "" {
		c.queueDir = "/var/lib/attackbox-shipper/queue"
	}

	c.queueBytes = parseBytes(getenv("ATTACKBOX_SHIP_QUEUE_BYTES"), 256<<20)
	if c.queueBytes < 16<<20 || c.queueBytes > 8<<30 {
		errs = append(errs, errors.New("ATTACKBOX_SHIP_QUEUE_BYTES must be 16MB..8GB"))
	}

	c.segmentBytes = parseBytes(getenv("ATTACKBOX_SHIP_SEGMENT_BYTES"), 16<<20)
	if c.segmentBytes < 1<<20 || c.segmentBytes > 256<<20 {
		errs = append(errs, errors.New("ATTACKBOX_SHIP_SEGMENT_BYTES must be 1MB..256MB"))
	}

	// New Relic settings
	c.nrLicenseKey = getenv("ATTACKBOX_NR_LICENSE_KEY")
	if c.nrLicenseKey == "" {
		errs = append(errs, errors.New("ATTACKBOX_NR_LICENSE_KEY is required"))
	} else if err := telemetry.ValidLicenseKey(c.nrLicenseKey); err != nil {
		errs = append(errs, err)
	}

	c.nrLogURL = getenv("ATTACKBOX_NR_LOG_URL")
	if c.nrLogURL == "" {
		c.nrLogURL = "https://log-api.newrelic.com/log/v1"
	}

	c.nrMetricURL = getenv("ATTACKBOX_NR_METRIC_URL")
	if c.nrMetricURL == "" {
		c.nrMetricURL = "https://metric-api.newrelic.com/metric/v1"
	}

	c.hostname = getenv("HOSTNAME")
	if c.hostname == "" {
		c.hostname, _ = os.Hostname()
	}
	if c.hostname == "" {
		c.hostname = "attackbox"
	}

	timeout := getenv("ATTACKBOX_SHIP_SHUTDOWN_TIMEOUT")
	if timeout == "" {
		c.shutdownTimeout = 15 * time.Second
	} else if d, err := time.ParseDuration(timeout); err != nil {
		errs = append(errs, fmt.Errorf("ATTACKBOX_SHIP_SHUTDOWN_TIMEOUT: %w", err))
	} else if d < 0 || d > time.Minute {
		errs = append(errs, errors.New("ATTACKBOX_SHIP_SHUTDOWN_TIMEOUT must be 0..1m"))
	} else {
		c.shutdownTimeout = d
	}

	// Endpoints
	baitSocket := getenv("ATTACKBOX_SPOOL_SOCKET")
	if baitSocket == "" {
		baitSocket = "/run/attackbox/spool.sock"
	}
	if err := telemetry.ValidSocketPath(baitSocket); err != nil {
		errs = append(errs, fmt.Errorf("ATTACKBOX_SPOOL_SOCKET: %w", err))
	}

	c.endpoints = []shipper.Endpoint{
		{
			Path:     baitSocket,
			Role:     shipper.RoleBait,
			Mode:     0220,
			UIDs:     []uint32{65532}, // Chainguard nonroot
			MaxConns: 4,
			Rate:     1 << 20, // 1 MB/s
			Burst:    4 << 20,
		},
	}

	// Optional runtime socket
	runtimeSocket := getenv("ATTACKBOX_RUNTIME_SOCKET")
	if runtimeSocket != "" {
		if err := telemetry.ValidSocketPath(runtimeSocket); err != nil {
			errs = append(errs, fmt.Errorf("ATTACKBOX_RUNTIME_SOCKET: %w", err))
		}
		c.endpoints = append(c.endpoints, shipper.Endpoint{
			Path:     runtimeSocket,
			Role:     shipper.RoleRuntime,
			Mode:     0220,
			UIDs:     []uint32{0}, // root (Falco)
			MaxConns: 2,
			Rate:     256 << 10, // 256 KB/s
			Burst:    1 << 20,
		})
	}

	// Optional egress socket
	egressSocket := getenv("ATTACKBOX_EGRESS_SOCKET")
	if egressSocket != "" {
		if err := telemetry.ValidSocketPath(egressSocket); err != nil {
			errs = append(errs, fmt.Errorf("ATTACKBOX_EGRESS_SOCKET: %w", err))
		}
		c.endpoints = append(c.endpoints, shipper.Endpoint{
			Path:     egressSocket,
			Role:     shipper.RoleEgress,
			Mode:     0220,
			UIDs:     []uint32{0}, // root (nft log converter)
			MaxConns: 2,
			Rate:     128 << 10, // 128 KB/s
			Burst:    512 << 10,
		})
	}

	if len(errs) > 0 {
		msg := ""
		for _, e := range errs {
			msg += e.Error() + "\n"
		}
		return config{}, errors.New(msg[:len(msg)-1])
	}
	return c, nil
}

func parseBytes(s string, def int64) int64 {
	if s == "" {
		return def
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return def
	}
	return n
}
