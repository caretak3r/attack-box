package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"attackbox/internal/observability"
	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
)

// minQueueBytes keeps the smallest role cap (20% of the queue) above one
// maximum-size frame, so no admitted record can be refused as oversize.
const minQueueBytes = 5 * (shipper.MaxData + shipper.FrameHeader)

type config struct {
	tracing         observability.Config
	endpoints       []shipper.Endpoint
	queueDir        string
	queueBytes      int64
	segmentBytes    int64
	evidenceDir     string
	hostname        string
	sensorID        string
	deploymentID    string
	shutdownTimeout time.Duration
}

// idRule is the shape of sensor and deployment IDs.
var idRule = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func loadConfig(getenv func(string) string) (config, error) {
	var c config
	var errs []error

	var traceErr error
	c.tracing, traceErr = observability.FromEnv(getenv)
	if traceErr != nil {
		errs = append(errs, traceErr)
	}

	// Queue settings
	c.queueDir = getenv("ATTACKBOX_SHIP_QUEUE_DIR")
	if c.queueDir == "" {
		c.queueDir = "/var/lib/attackbox-shipper/queue"
	}

	c.queueBytes = parseBytes(getenv("ATTACKBOX_SHIP_QUEUE_BYTES"), 256<<20)
	if c.queueBytes < minQueueBytes || c.queueBytes > 8<<30 {
		errs = append(errs, fmt.Errorf("ATTACKBOX_SHIP_QUEUE_BYTES must be %d..%d", int64(minQueueBytes), int64(8<<30)))
	}

	c.segmentBytes = parseBytes(getenv("ATTACKBOX_SHIP_SEGMENT_BYTES"), 16<<20)
	if c.segmentBytes < 1<<20 || c.segmentBytes > 256<<20 {
		errs = append(errs, errors.New("ATTACKBOX_SHIP_SEGMENT_BYTES must be 1MB..256MB"))
	}

	// Evidence directory
	c.evidenceDir = getenv("ATTACKBOX_EVIDENCE_DIR")
	if c.evidenceDir == "" {
		if stateDir := getenv("STATE_DIRECTORY"); stateDir != "" {
			c.evidenceDir = stateDir
		} else {
			c.evidenceDir = "/var/lib/attackbox-evidence/shipper"
		}
	}

	c.hostname = getenv("HOSTNAME")
	if c.hostname == "" {
		c.hostname, _ = os.Hostname()
	}
	if c.hostname == "" {
		c.hostname = "attackbox"
	}

	// ATTACKBOX_SENSOR_ID names this sensor on every New Relic log and metric.
	// Rule: idRule. Default: the host name above in lower case, or "attackbox"
	// when that does not match the rule. A set value that breaks the rule is a
	// configuration error.
	c.sensorID = strings.ToLower(c.hostname)
	if !idRule.MatchString(c.sensorID) {
		c.sensorID = "attackbox"
	}
	if v := getenv("ATTACKBOX_SENSOR_ID"); v != "" {
		if idRule.MatchString(v) {
			c.sensorID = v
		} else {
			errs = append(errs, fmt.Errorf("ATTACKBOX_SENSOR_ID must match %s", idRule))
		}
	}

	// ATTACKBOX_DEPLOYMENT_ID names the build that runs, so evidence from two
	// rebuilds can be told apart. Rule: idRule. Default: "unset". A set value
	// that breaks the rule is a configuration error.
	c.deploymentID = "unset"
	if v := getenv("ATTACKBOX_DEPLOYMENT_ID"); v != "" {
		if idRule.MatchString(v) {
			c.deploymentID = v
		} else {
			errs = append(errs, fmt.Errorf("ATTACKBOX_DEPLOYMENT_ID must match %s", idRule))
		}
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

	// Receipt mode requires the paired durable host readers. Legacy adapters
	// remain supported when this explicit migration setting is absent.
	hostReceipts := false
	if v := getenv("ATTACKBOX_HOST_RECEIPTS"); v != "" {
		var err error
		hostReceipts, err = strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, errors.New("ATTACKBOX_HOST_RECEIPTS must be a boolean"))
		}
	}

	// Optional runtime socket
	runtimeSocket := getenv("ATTACKBOX_RUNTIME_SOCKET")
	if runtimeSocket != "" {
		if err := telemetry.ValidSocketPath(runtimeSocket); err != nil {
			errs = append(errs, fmt.Errorf("ATTACKBOX_RUNTIME_SOCKET: %w", err))
		}
		c.endpoints = append(c.endpoints, shipper.Endpoint{
			Receipts: hostReceipts,
			Path:     runtimeSocket,
			Role:     shipper.RoleRuntime,
			Mode:     0220,
			UIDs:     []uint32{0}, // root (Falco)
			MaxConns: 2,
			Rate:     256 << 10, // 256 KB/s
			Burst:    4 << 20,   // above MaxLine
		})
	}

	// Optional egress socket
	egressSocket := getenv("ATTACKBOX_EGRESS_SOCKET")
	if egressSocket != "" {
		if err := telemetry.ValidSocketPath(egressSocket); err != nil {
			errs = append(errs, fmt.Errorf("ATTACKBOX_EGRESS_SOCKET: %w", err))
		}
		c.endpoints = append(c.endpoints, shipper.Endpoint{
			Receipts: hostReceipts,
			Path:     egressSocket,
			Role:     shipper.RoleEgress,
			Mode:     0220,
			UIDs:     []uint32{0}, // root (nft log converter)
			MaxConns: 2,
			Rate:     128 << 10, // 128 KB/s
			Burst:    4 << 20,   // above MaxLine
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
