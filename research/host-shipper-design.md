# Host shipper design — attackbox

Target gap: `REMAINING_WORK.md:18` ("Implement the planned isolated host shipper and bounded outage buffer") and `implementation_plan.md:273` ("Shipper. Runs on the host as a different user. It reads logs that the sandbox cannot write and keeps a bounded disk buffer when New Relic is unavailable").

Read-only investigation only; nothing was built, run or edited. Every `file:line` below was read at repo state of 2026-11-21.

## 1. Scope

In scope: moving New Relic egress out of the bait process into a host-side service, the transport between them, the bounded outage buffer, heartbeat split, shutdown ordering, and the configuration migration.

Out of scope (do not touch): `internal/responder/`, `internal/secret/`, `internal/server/` (the `Sink` injection point at `cmd/attackbox/main.go:163` already makes the server agnostic), the scrubber findings, the six-stream *producers*, the nine missing metrics. Those are separate items in `REMAINING_WORK.md` and this plan must not entangle them.

## 2. What already exists (verified)

| Fact | Location |
|---|---|
| `Sink` is a 3-method interface (`Emit`/`Count`/`Gauge`); the server only ever sees a `Sink` | `internal/telemetry/sink.go:19-23`, `cmd/attackbox/main.go:163` |
| The process picks its sink in one place: `a.sink = a.local` then optionally `Multi{local, nr}` | `cmd/attackbox/main.go:132-152` |
| `Event` carries a json tag on every field, so it round-trips through JSON as-is | `internal/telemetry/event.go:26-45` |
| `JSONLog` writes the *flattened, chunked* form (`Attributes()` + RFC3339 timestamp), which is **not** round-trippable back into an `Event` | `internal/telemetry/sink.go:111-120`, `internal/telemetry/event.go:58-85` |
| `Chunk` **overwrites** `BodySHA256` with the hash of whatever body it is given | `internal/telemetry/event.go:94-95` |
| `NewRelic.Emit` chunks then non-blocking-enqueues, counting drops | `internal/telemetry/newrelic.go:226-245` |
| `ship()` is the single consumer of `n.queue` | `internal/telemetry/newrelic.go:405-441` |
| Metrics aggregate in-process into `n.series`, label-sanitised by `SafeLabels`, capped at `maxSeries` 2000 | `internal/telemetry/newrelic.go:257-287`, `:25` |
| Heartbeat posts **directly**, bypassing the queue, so a wedged worker cannot hide a live host | `internal/telemetry/newrelic.go:353-380` |
| `Close(ctx)` drains, flushes logs+metrics, honours ctx | `internal/telemetry/newrelic.go:322-336` |
| `ValidLicenseKey` already rejects User/Insert/Query/browser keys | `internal/telemetry/newrelic.go:34-57` |
| `postAll` already drops and counts items too large for one POST | `internal/telemetry/newrelic.go:521-523` |
| Config rejects "key + disabled" and "neither" | `cmd/attackbox/config.go:190-200` |
| Max logged request body is 128 KiB | `internal/server/server.go:50,125-126` |

**Consequence that drives the whole design:** the spool must carry *unchunked* `Event` values. If the bait chunked and the shipper re-emitted the chunks, `Chunk` (`event.go:94-95`) would replace each chunk's full-body `body_sha256` with the chunk's own hash and reset `chunk_index`/`chunk_count` to `0`/`1`, silently destroying the chunk-reassembly contract required by `implementation_plan.md:284`. Spooling the whole `Event` and letting the existing `NewRelic.Emit` chunk at the last hop keeps today's output byte-identical.

## 3. Process boundaries

```
 container (gVisor, no egress, uid 65532)        host
 ┌───────────────────────────────┐    ┌──────────────────────────────────────┐
 │ attackbox                     │    │ attackbox-shipper  (user abx-ship)   │
 │  sink = Multi{JSONLog, Spool} │    │  accept() ──► validate ──► segments  │
 │  stdout ─► docker log driver ─┼────┼─► host file (root-owned, forensic)   │
 │  Spool ──► /run/attackbox/    │    │  drain ──► TryEmit ──► NewRelic ──► 443
 │            spool.sock (0220)  ├───►│  checkpoint ◄── advance on accept    │
 └───────────────────────────────┘    │  heartbeat (direct POST, no queue)   │
   NO New Relic key, NO egress        └──────────────────────────────────────┘
 falco ─► attackbox-shipper -stdin-stream runtime ─┘ (same socket)
 nft log ► attackbox-shipper -stdin-stream egress ─┘
```

Decisions and why:

- **Unix `SOCK_STREAM` socket, shipper is the listener.** Alternatives rejected: a shared spool *directory* (the sandbox could truncate, rewrite or read back its own history, and rotation/hand-off between two writers needs a rename protocol); the Docker JSON log file (root-only, needs the Docker API or root to locate — the shipper must stay unprivileged); journald (`LineMax` 48 KiB truncates an edge event whose body may reach 128 KiB per `server.go:50`).
- The socket gives the exact property the plan asks for: the sandbox can `connect()` and `write()`, and can do **nothing** else — it cannot list, read back, truncate, rewrite or even see the disk queue. Once bytes leave the sandbox they are beyond root-in-sandbox.
- **The New Relic key never enters the container.** This is the point of the whole exercise; `cmd/attackbox` loses its ability to hold one in this deployment mode (§9).
- The shipper is the only process with egress, so the host firewall rule set (`implementation_plan.md:266-267`) narrows from "the container network may reach New Relic" to "only uid `abx-ship` may reach New Relic", which `UbuntuHardening` can express as an nftables `skuid` rule.

## 4. Wire protocol

One JSON object per line, UTF-8, `\n`-terminated. New file `internal/telemetry/spool.go` (shared by both binaries — no new package):

```go
// Record is one spooled telemetry item. Exactly one of Event or Metric is set.
type Record struct {
    ID     string        `json:"id"`               // "<boot>-<seq>", unique per producer run
    Event  *Event        `json:"event,omitempty"`  // unchunked; the shipper chunks at the last hop
    Metric *MetricRecord `json:"metric,omitempty"`
}

type MetricRecord struct {
    Name  string            `json:"name"`
    Kind  string            `json:"kind"`  // "count" | "gauge"
    Value float64           `json:"value"`
    At    time.Time         `json:"at"`
    Attrs map[string]string `json:"attrs,omitempty"`
}
```

- `ID`: `boot` is 8 random bytes hex, drawn once per process with `crypto/rand`; `seq` is a monotonic `atomic.Uint64`. Not derived from `ATTACKBOX_SECRET_FILE` — a stable boot value across restarts would make two runs' IDs collide and defeat dedup.
- `seq` is also a free gap detector: the shipper tracks the last `seq` per `boot` per connection and counts a jump as `attackbox.spool_gap_total`, which proves bait-side drops independently of the bait's own counters.
- `Event.Timestamp` is `time.Time` and marshals RFC3339Nano, so it round-trips exactly.

Known limit: `Event.Attrs` is `map[string]any`, so JSON numbers return as `float64`. Integers above 2^53 would lose precision. Current `Attrs` integers are latencies, counters and byte counts — nowhere near. Record the limit in the `Record` doc comment.

## 5. Bait side — `telemetry.Spool`

New in `internal/telemetry/spool.go`, implementing `Sink` (`sink.go:19-23`):

```go
type SpoolConfig struct {
    Socket       string        // absolute path, <= 107 bytes (sun_path)
    QueueSize    int           // default 10000
    WriteTimeout time.Duration // default 5s, per write deadline
    MaxRecord    int           // default 1<<21, bytes per line
    Heartbeat    time.Duration // default 30s; <0 disables
    Now          func() time.Time
    OnError      func(error)
}

func NewSpool(cfg SpoolConfig) (*Spool, error)       // dials once, then starts the writer
func (s *Spool) Emit(Event)                           // never blocks
func (s *Spool) Count(string, float64, map[string]string)
func (s *Spool) Gauge(string, float64, map[string]string)
func (s *Spool) Stats() SpoolStats                    // Written, Dropped, Errors, Reconnects
func (s *Spool) Close(ctx context.Context) error      // drain with deadline, then close conn
```

Behaviour, mirroring `NewRelic` so there is one mental model in the codebase:

1. `Emit`/`Count`/`Gauge` build a `Record` and do a non-blocking send on a buffered `chan Record`; a full queue or a post-`Close` call increments `Dropped`. Identical shape to `newrelic.go:226-245` — copy that structure including the `closeMu sync.RWMutex` + `closed` guard, so the same race properties hold.
2. **No chunking here** (see §2).
3. One writer goroutine owns the `net.Conn`, a `bufio.Writer` and a `json.Encoder` with `SetEscapeHTML(false)` (match `sink.go:107`). It drains the channel, flushing when the channel is empty or every 100 records. Each write gets `conn.SetWriteDeadline(now+WriteTimeout)`; a deadline miss or any write error closes the conn, counts `Errors`, calls `OnError`, and redials with backoff 500 ms → 1 s → 2 s → 5 s (capped). While disconnected the channel fills and `Emit` drops — the bounded, counted, non-blocking behaviour the `Sink` contract demands.
4. A record whose marshalled length exceeds `MaxRecord` is dropped and counted rather than written, so the shipper never has to deal with an over-long line in normal operation.
5. Every `Heartbeat` interval the writer emits `Event{Stream: StreamHeartbeat, Action: "bait_heartbeat", Attrs: {queue_len, dropped_total, errors_total, reconnects}}`. This is what proves a *quiet* honeypot's bait process is still alive (see §8).
6. `NewSpool` fails if the **first** dial fails. Deliberate, and consistent with "a bind failure stops startup" (`main.go:130-131`): a missing socket at boot is a unit-ordering bug and must be loud. Later reconnects are silent and counted.

## 6. Shipper side — `cmd/attackbox-shipper`

Four small files plus tests:

```
cmd/attackbox-shipper/main.go       // cli, wiring, shutdown, -stdin-stream mode
cmd/attackbox-shipper/config.go     // ATTACKBOX_SHIP_* / ATTACKBOX_NR_* env
cmd/attackbox-shipper/listen.go     // socket, accept loop, line reader, validation
cmd/attackbox-shipper/queue.go      // bounded disk queue: segments + checkpoint
cmd/attackbox-shipper/queue_test.go
cmd/attackbox-shipper/main_test.go
```

Data path — **every record goes to disk first.** There is no fast-path bypass; that single decision removes all ordering and dual-path complexity:

```
accept ─► read line (bounded) ─► unmarshal Record ─► validate/sanitise (§7)
       ─► re-marshal ─► append to newest segment (buffered, flush ≤200ms or 64 KiB)
drain  ─► read from checkpoint forward ─► nr.TryEmit / nr.Count / nr.Gauge
       ─► advance checkpoint ─► delete fully-consumed segments
```

**Disk queue** (`queue.go`), in `ATTACKBOX_SHIP_QUEUE_DIR` (default `/var/lib/attackbox-shipper/queue`, mode 0700, never mounted into the container):

- Segments named `seg-<20-digit-zero-padded-UnixNano>.jsonl`, so lexicographic order *is* chronological order. Rolled at `ATTACKBOX_SHIP_SEGMENT_BYTES` (default 16 MiB).
- `state.json` holds `{"segment":"seg-...","offset":<int64>}`, written atomically (temp file + `os.Rename` in the same dir) after each drained batch. No `fsync`: the loss/duplicate window is one batch, and `record_id` (§7) makes duplicates detectable in NRQL. State this limit in the file's doc comment.
- **Bound:** before each append, if the sum of segment sizes exceeds `ATTACKBOX_SHIP_QUEUE_BYTES` (default 256 MiB, max 8 GiB), delete the **oldest** segment; if the checkpoint pointed into it, advance the checkpoint to the start of the new oldest. Count `attackbox.ship_queue_dropped_total` and emit one `runtime`/`queue_overflow` record (rate-limited to one per 30 s). Drop-oldest, not drop-newest: a live attack must keep flowing.
- Startup: read `state.json`, open that segment, `Seek(offset)`. A missing or corrupt state file restarts from the oldest segment — a bounded replay, deduplicable by `record_id`.
- Replay ordering is therefore trivially FIFO: one append point, one read cursor, name-ordered segments.

**Drain loop** — the only goroutine that ever touches the `NewRelic` client:

- `Event` records → `nr.TryEmit(e)` (§10). `false` means the client queue is full (New Relic is down or throttling): sleep 250 ms and retry the *same* record. The checkpoint does not move, the segments grow, the bound trims the oldest. That is the entire outage story.
- `Metric` records → `nr.Count`/`nr.Gauge`, which aggregate into `n.series` (`newrelic.go:257-287`) and cannot refuse; the cursor always advances past them.
- Batch the checkpoint write: advance after 200 records or 1 s, whichever first.

Known limit to document: `record()` stamps `s.at = now` (`newrelic.go:286`), so counters replayed after a long outage are attributed to replay time, not to when they happened. Log events keep their exact `Event.Timestamp`. The plan's alerts (`implementation_plan.md:308-315`) key on logs and on current metrics, so this is acceptable — but write it down in the operator guide.

Sizing note: the shipper should set `NRConfig.QueueSize` to 20000 rather than the 10000 default, because one 128 KiB edge event becomes ~37 chunks after `Chunk` (`event.go:90-122`) and a 10000-slot queue is only ~270 such events deep.

## 7. Trust boundary — the shipper distrusts the bait

The threat model (`implementation_plan.md:19`) assumes root on the VPS, therefore root in the sandbox, therefore a hostile producer on the socket. Validation in `listen.go`, before anything is written to a segment. None of this may be skipped.

| Check | Rule on failure |
|---|---|
| Line length | `bufio.Reader` with an explicit cap of `ATTACKBOX_SHIP_MAX_LINE` (default 2 MiB, max 16 MiB). **Do not use `bufio.Scanner`** — its 64 KiB default silently stops the connection. Over-long: discard to the next `\n`, count `ship_oversize_total`, keep the connection. |
| JSON parse | Reject the line, count `ship_invalid_total`. Three consecutive invalid lines close the connection. |
| Exactly one of `Event`/`Metric` | Reject. |
| `ID` | Non-empty, ≤128 bytes, printable ASCII. Reject otherwise. |
| `Event.Stream` | Must be one of the six constants (`event.go:15-22`). Reject otherwise — an unknown stream would pollute the operator's views. |
| Reserved attribute keys | **Delete** `instance`, `service.name`, `hostname`, `entity.guid`, `entity.name`, `entity.type`, `newrelic.source`, `plugin.type`, `timestamp`, `message` from `Event.Attrs`. New Relic lets an item's own attributes override `common.attributes`, so without this a hostile bait could re-label its records as another entity and evade every dashboard filter. `Attributes()` (`event.go:57-58`) only protects the fixed fields, not these. |
| `Event.Attrs` size | ≤128 keys, key ≤128 bytes, string value truncated to 4096 bytes on a rune boundary. |
| `Event.Timestamp` | Clamp to `[now-24h, now+5m]`; when clamped add `timestamp_clamped: true`. New Relic rejects far-future items, and a hostile timestamp could hide a record in the past. |
| `Metric.Name` | `^attackbox\.[a-z0-9_]+(\.[a-z0-9_]+)*$`, ≤64 bytes, plus a cap of 64 distinct names per producer run. The 2000-series cap (`newrelic.go:274`) otherwise lets junk names starve real metrics. |
| `Metric.Attrs` | Left alone — `record()` already runs `SafeLabels` (`newrelic.go:267`). |
| `Metric.Value` | `record()` already rejects NaN/Inf (`newrelic.go:258`). |
| Connections | `ATTACKBOX_SHIP_MAX_CLIENTS` (default 8) concurrent; beyond that, accept and immediately close, counted. |

After validation the shipper **adds** `Attrs["record_id"] = r.ID` and `Attrs["source"] = "bait" | "runtime" | "egress"` (from the connection's first record or the `-stdin-stream` flag). `record_id` is the NRQL dedup handle after a crash replay.

No re-redaction. Redaction is the bait's job (`internal/telemetry/redact.go`) and the shipper has no HMAC key — correctly, since it must not hold one.

## 8. Heartbeat independence

Two independent signals, which is what makes the "heartbeat absent > 2 minutes → power off" alert (`implementation_plan.md:313`) meaningful once the bait no longer owns the New Relic client:

1. **Host/egress liveness** — the existing `heartbeatLoop` (`newrelic.go:356-380`) now runs in the *shipper*. It posts directly, bypassing the queue, so a wedged queue or a stalled worker cannot fake it. Unchanged code.
2. **Bait liveness** — `bait_connected`, plus `last_bait_record_age_ms`. Carried on signal 1 so it is also immune to a wedged queue. This needs the one addition to `NRConfig`:

```go
// HeartbeatAttrs, if set, is called on each heartbeat and its result merged
// into the heartbeat event. It must not block.
HeartbeatAttrs func() map[string]any
```

and three lines in `heartbeatLoop` merging the result into the `Attrs` map built at `newrelic.go:366-371`. The shipper supplies `{bait_connected, last_bait_record_age_ms, spool_clients, queue_bytes, queue_backlog_bytes, ship_dropped_total}`.

Why `bait_connected` is the right primary signal: the kernel closes the socket when the bait process dies, so the shipper learns within one `read()`. `last_bait_record_age_ms` covers the case of a bait that is hung but still connected, and it works on a quiet honeypot only because of the bait-side 30 s `bait_heartbeat` record (§5.5). Both streams carry `source` so the two `heartbeat`-stream producers are distinguishable.

Resulting alert pair for the New Relic item in `REMAINING_WORK.md:28`:
- no `heartbeat` from `source=shipper` for 2 min → host or egress is down → power off;
- `bait_connected = false` or `last_bait_record_age_ms > 90000` for 2 min → bait is down, host fine → rebuild the container.

## 9. Host-sourced streams — Falco and blocked egress

No tailer, no second transport. The shipper binary gains one adapter mode:

```
attackbox-shipper -stdin-stream runtime   # reads JSONL on stdin, wraps, writes to the socket, exits on EOF
```

- Falco: `json_output: true` and `program_output.program: "/usr/local/bin/attackbox-shipper -stdin-stream runtime"`. Falco keeps the program running and writes one JSON object per line to its stdin.
- Blocked egress: `UbuntuHardening` owns the nftables→JSON converter; its contract is **one JSON object per line, ≤8 KiB, on stdout**, piped into `attackbox-shipper -stdin-stream egress`.
- The adapter wraps each stdin line as `Event{Stream: <flag>, Action: "falco"|"egress_blocked", Attrs: {"event": <the parsed object>}}` and reuses the same `telemetry.Spool` writer. ~30 lines, and it inherits the socket, the validation, the disk queue and the dedup for free.
- The adapter writes to the socket, so both producers need write access to it (Falco runs as root; the nft converter likewise). Keep Falco's own `file_output` enabled as the independent forensic copy.

This is also why §7 validation is generic rather than bait-specific: three producers share one path.

## 10. The two changes inside `internal/telemetry`

Both are additive; no existing behaviour changes.

**(a) `NewRelic.TryEmit`** in `internal/telemetry/newrelic.go`, next to `Emit`:

```go
// TryEmit queues e like Emit but reports false and queues nothing when the
// shipper is closed or the queue cannot take every chunk, so a caller with a
// durable buffer keeps the event instead of dropping it. TryEmit must not be
// called concurrently with Emit or with itself.
func (n *NewRelic) TryEmit(e Event) bool {
    if e.Timestamp.IsZero() {
        e.Timestamp = n.cfg.Now()
    }
    chunks := Chunk(e, MaxChunk)
    n.closeMu.RLock()
    defer n.closeMu.RUnlock()
    if n.closed || cap(n.queue)-len(n.queue) < len(chunks) {
        return false
    }
    for _, c := range chunks {
        n.queue <- c // room was checked; ship() only frees space
    }
    return true
}
```

The single-producer restriction is a doc comment, not a lock, because the only caller is the shipper's one drain goroutine and `ship()` (`newrelic.go:405-441`) is the only consumer. Adding a mutex would serialise the hot `Emit` path for a case that never occurs. All-or-nothing enqueue matters: a partial enqueue would duplicate the already-queued chunks on replay.

**(b) `NRConfig.HeartbeatAttrs`** — see §8.

Nothing else in `internal/telemetry` changes. `JSONLog` keeps its current output, which is why `scripts/smoke.sh:88-92` still passes.

## 11. New Relic flush and shutdown ordering

Shipper, on SIGTERM (mirror `main.go:244-292`):

1. Stop accepting; close the listener and unlink the socket.
2. Read what the open connections already buffered, with a 1 s read deadline, into the queue. Do **not** wait for producers.
3. Flush the segment writer and write the checkpoint. Nothing in RAM is lost across a restart.
4. Drain-loop **one bounded pass**: keep calling `TryEmit` until `ATTACKBOX_SHIP_SHUTDOWN_TIMEOUT` (default 15 s) is half spent. Never attempt to empty a 256 MiB backlog on shutdown — that would hang the unit.
5. `nr.Close(flushCtx)` with the remaining budget — existing semantics (`newrelic.go:322-336`).
6. Final `runtime`/`stopped` to the local JSONLog only, carrying `nr_sent/nr_dropped/nr_lost/nr_errors` plus `queue_backlog_bytes`. Reuse the `lossError` shape from `main.go:295-304` (copy the 10 lines into the shipper's `main.go`; it is not worth a shared package).

Unit ordering — the shipper must outlive the bait so the bait's `stop`/`stopped` events get shipped:

```ini
# attackbox-shipper.service
Before=attackbox.service
# attackbox.service
Requires=attackbox-shipper.service
After=attackbox-shipper.service
```

systemd stops in reverse dependency order: bait first, shipper second. `TimeoutStopSec` on the shipper ≥ `ATTACKBOX_SHIP_SHUTDOWN_TIMEOUT` + 5 s.

Bait, in `app.run` (`cmd/attackbox/main.go:273-291`) — two lines, NR path untouched:

```go
a.local.Emit(stopped)        // unchanged, authoritative local record
if a.spool != nil {
    a.spool.Emit(stopped)    // ship it before the spool closes
    spErr = a.spool.Close(flushCtx)
}
```

`stopped` must be hoisted into a local variable instead of being built inline at `main.go:290`. Join `spErr` into the returned error, and add `spool_written`/`spool_dropped`/`spool_errors` to the `attrs` map built at `main.go:273-284`.

## 12. Ownership, permissions, rotation

| Object | Owner:group | Mode | Note |
|---|---|---|---|
| `/run/attackbox` | `abx-ship:abx-bait` | `0710` | group gets `x` to traverse, **not** `r` to list. systemd `RuntimeDirectory=attackbox`, `RuntimeDirectoryMode=0710` |
| `/run/attackbox/spool.sock` | `abx-ship:abx-bait` | `0220` | write-only for the group; `chmod` immediately after `net.Listen("unix", …)`, with `umask` set so there is no readable window |
| `/var/lib/attackbox-shipper/` | `abx-ship:abx-ship` | `0700` | systemd `StateDirectory=attackbox-shipper`; **never** bind-mounted into the container |
| `/etc/attackbox/shipper.env` | `abx-ship:abx-ship` | `0600` | holds `ATTACKBOX_NR_LICENSE_KEY`; `EnvironmentFile=` on the shipper unit only |
| container mount | — | `ro` | `--mount type=bind,source=/run/attackbox,target=/run/attackbox,readonly` |

The container runs as the Chainguard static nonroot uid/gid `65532`, so the host group `abx-bait` must be created **with gid 65532**; the group bit on the socket is what authorises the bait. No `--group-add`, no supplementary groups.

A read-only bind mount still permits `connect()` to a socket inside it: `connect` does not modify the filesystem. `[INFERENCE — widely relied on, e.g. read-only `docker.sock` mounts, but not executed here.]` Verify in the deployment dry-run (§15) before relying on it; the fallback is mounting the directory read-write, which costs nothing extra because the directory itself is `0710` and the socket `0220`.

Shipper hardening in the unit: `User=abx-ship`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `CapabilityBoundingSet=` (empty), `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `SystemCallArchitectures=native`, `MemoryMax=256M`, `Restart=always`, `RestartSec=1`.

**Rotation is delegated everywhere; no rotation code is written:**

| Stream | Mechanism |
|---|---|
| Bait stdout | Docker `local` log driver, `max-size=10m`, `max-file=3`. Host root-owned, so it doubles as a sandbox-inaccessible forensic copy. |
| Shipper stdout | `StandardOutput=journal`; journald `SystemMaxUse=` caps it. |
| Spool backlog | Segment files + the `QUEUE_BYTES` bound (§6). This *is* the rotation. |
| Falco | Falco's own `file_output` + logrotate, owned by `UbuntuHardening`. |

**Backpressure chain — every stage is bounded, non-blocking and counted; nothing can stall the request path:**

| Stage | Bound | On overflow |
|---|---|---|
| server → `Sink` | — | `Emit` must not block (`sink.go:14-18`) |
| `Spool` channel | `QueueSize` 10000 | drop newest, `SpoolStats.Dropped` |
| socket write | 5 s deadline | close + redial, `SpoolStats.Errors` |
| shipper read | `MAX_LINE` 2 MiB | skip line, `ship_oversize_total` |
| disk queue | 256 MiB | delete oldest segment, `ship_queue_dropped_total` |
| `NewRelic` queue | 20000 chunks | `TryEmit` → false → backlog grows on disk (no loss) |
| NR POST | 900 KB uncompressed | existing `postAll` drop + count (`newrelic.go:521-523`) |

## 13. Configuration migration

Three mutually exclusive telemetry modes. Local development and `scripts/smoke.sh:33-39` use the first two and are untouched.

| Mode | `NR_LICENSE_KEY` | `NR_DISABLED` | `SPOOL_SOCKET` | Behaviour |
|---|---|---|---|---|
| in-process NR (today, dev against a real account) | set | unset | unset | unchanged |
| local only (smoke, unit tests) | unset | `true` | unset | unchanged |
| **spool (deployment)** | unset | unset | set | `Multi{JSONLog, Spool}`; no NR client in the bait |

New bait variables:

| Variable | Default | Meaning |
|---|---|---|
| `ATTACKBOX_SPOOL_SOCKET` | none | absolute unix socket path, ≤107 bytes; enables spool mode |
| `ATTACKBOX_SPOOL_QUEUE` | `10000` | in-memory records, cap 100000 |
| `ATTACKBOX_SPOOL_TIMEOUT` | `5s` | per-write deadline, `(0, 1h]` via the existing `dur` helper |

Exact replacement for `cmd/attackbox/config.go:190-200` (keep `telemetry.ValidLicenseKey` below it unchanged):

```go
switch {
case c.nrDisabled && c.nrKey != "":
    errs = append(errs, errors.New("ATTACKBOX_NR_DISABLED=true conflicts with ATTACKBOX_NR_LICENSE_KEY; unset one"))
case c.nrDisabled && c.spoolSocket != "":
    errs = append(errs, errors.New("ATTACKBOX_NR_DISABLED=true conflicts with ATTACKBOX_SPOOL_SOCKET; unset one"))
case c.nrKey != "" && c.spoolSocket != "":
    errs = append(errs, errors.New("ATTACKBOX_SPOOL_SOCKET conflicts with ATTACKBOX_NR_LICENSE_KEY; in the spool deployment only the host shipper holds the key"))
case !c.nrDisabled && c.nrKey == "" && c.spoolSocket == "":
    errs = append(errs, errors.New("ATTACKBOX_NR_LICENSE_KEY is required; set ATTACKBOX_SPOOL_SOCKET to ship through the host shipper, or ATTACKBOX_NR_DISABLED=true to log locally only"))
}
```

Existing test assertions this must keep satisfying — verified, all still match:

- `cmd/attackbox/main_test.go:105` expects the substring `ATTACKBOX_NR_LICENSE_KEY is required` → preserved as the message prefix.
- `main_test.go:108` expects `conflicts` → preserved.
- `main_test.go:151` expects `-check-config` stdout to contain `new relic disabled` → so **keep the `"new relic %s"` wording** at `main.go:71` and make it three-way instead of the current `map[bool]string`:

```go
mode := "enabled"
switch {
case cfg.nrDisabled:
    mode = "disabled"
case cfg.spoolSocket != "":
    mode = "off (host shipper), spool " + cfg.spoolSocket
}
fmt.Fprintf(stdout, "configuration ok: %d listener(s), new relic %s\n", len(cfg.listeners), mode)
```

- `main_test.go:155` expects stderr to name `ATTACKBOX_NR_LICENSE_KEY` on an empty env → preserved.

Add `spoolSocket string`, `spoolQueue int`, `spoolTimeout time.Duration` to the `config` struct (`config.go:39-68`), parsed with the existing `env`/`num`/`dur` closures. Validate the socket path: absolute, no NUL, `len ≤ 107`.

Shipper variables (`ATTACKBOX_NR_*` and `ATTACKBOX_INSTANCE` deliberately reuse the same names — one documented name per concept, different env files):

| Variable | Default |
|---|---|
| `ATTACKBOX_SHIP_SOCKET` | `/run/attackbox/spool.sock` |
| `ATTACKBOX_SHIP_SOCKET_MODE` | `0220` |
| `ATTACKBOX_SHIP_QUEUE_DIR` | `/var/lib/attackbox-shipper/queue` |
| `ATTACKBOX_SHIP_QUEUE_BYTES` | `268435456` (max 8 GiB) |
| `ATTACKBOX_SHIP_SEGMENT_BYTES` | `16777216` |
| `ATTACKBOX_SHIP_MAX_LINE` | `2097152` (max 16 MiB) |
| `ATTACKBOX_SHIP_MAX_CLIENTS` | `8` |
| `ATTACKBOX_SHIP_SHUTDOWN_TIMEOUT` | `15s` |
| `ATTACKBOX_NR_LICENSE_KEY`, `ATTACKBOX_NR_LOG_URL`, `ATTACKBOX_NR_METRIC_URL`, `ATTACKBOX_INSTANCE` | as the bait has today |

Copy the `env`/`num`/`dur`/`flag` closure block from `config.go:74-113` into the shipper's `config.go`. ~40 duplicated lines is cheaper than extracting a shared `internal/env` package and re-wiring the existing binary; note the duplication in a comment so a later extraction is obvious.

## 14. Change list, in order

Each step compiles and tests green on its own.

1. `internal/telemetry/newrelic.go` — add `TryEmit` (§10a) and `NRConfig.HeartbeatAttrs` + the merge in `heartbeatLoop` (§8). Additive.
2. `internal/telemetry/spool.go` (new) — `Record`, `MetricRecord`, `SpoolConfig`, `Spool` (§4, §5).
3. `internal/telemetry/spool_test.go` (new) — see §15.
4. `cmd/attackbox/config.go` — the three spool fields, the mode switch (§13).
5. `cmd/attackbox/main.go` — the spool branch in `newApp` (`main.go:132-152`), the `a.spool` field on `app` (`main.go:120-128`), the `-check-config` wording (`main.go:71`), and the shutdown hook (§11). `server.Config` construction at `main.go:158-174` is untouched.
6. `cmd/attackbox/main_test.go` — add spool-mode cases; existing cases unchanged (§13).
7. `cmd/attackbox-shipper/queue.go` + `queue_test.go` (new) — disk queue standalone, no network.
8. `cmd/attackbox-shipper/listen.go` (new) — accept loop + validation (§7).
9. `cmd/attackbox-shipper/config.go`, `main.go` (new) — wiring, shutdown, `-stdin-stream`.
10. `cmd/attackbox-shipper/main_test.go` (new).
11. `scripts/smoke.sh` — optional added step (§15), after the existing checks so the current flow stays identical.

Steps 1–6 are independent of 7–10 and can land first.

## 15. Tests and verification

New tests, all `httptest`/`t.TempDir()`/loopback only — no external host, matching the existing discipline (`implementation_plan.md:205`):

`internal/telemetry/spool_test.go`
- round-trip: `Emit` an `Event` with a 10 KiB body, non-ASCII, nested `Attrs`; read the line off a `net.Listen("unix", …)` in the test; unmarshal; assert field-for-field equality and that `BodySHA256`/`ChunkIndex`/`ChunkCount` are **zero** on the wire (proves no premature chunking, §2).
- full queue drops without blocking and counts (mirror `newrelic_test.go:280`).
- writer reconnects after the listener closes and reopens; `Reconnects` increments; no records lost while the channel has room.
- `Close` drains within the deadline; `Emit` after `Close` counts `Dropped`.
- over-size record dropped, not written.

`internal/telemetry/newrelic_test.go` (additions)
- `TryEmit` returns false on a full queue and queues **nothing** (`len(queue)` unchanged).
- `HeartbeatAttrs` values appear in the heartbeat POST; extend the existing `nrServer` harness (`newrelic_test.go:46`) and the pattern of `TestHeartbeatIndependentOfStalledWorker:642`.

`cmd/attackbox-shipper/queue_test.go`
- FIFO across a segment roll; checkpoint resume after a simulated crash mid-segment.
- overflow deletes the oldest segment and advances a checkpoint that pointed into it.
- corrupt/missing `state.json` restarts from the oldest segment without panicking.

`cmd/attackbox-shipper/main_test.go`
- end-to-end: real unix socket + `httptest` fake New Relic intake (copy `newrelic_test.go:46`); write records; assert `Api-Key`, gzip, chunking of a >3500-rune body, `record_id` present, `instance` from the shipper's `Common` and **not** overridable by a record that sets `Attrs["instance"]` (§7).
- hostile input: over-long line, invalid JSON, unknown stream, 2^31 timestamp, 100 junk metric names — assert each is counted and the connection survives (or closes only on the 3-invalid rule).
- intake returns 503 for 3 s: assert the backlog grows on disk, nothing is lost, and everything is delivered once the intake recovers.
- SIGTERM with a backlog: exits within the timeout, checkpoint is consistent, final `stopped` is logged.

`cmd/attackbox/main_test.go`
- spool mode: a test unix socket, `ATTACKBOX_SPOOL_SOCKET` set; one request produces an `edge` record on the socket; SIGTERM delivers the `stop`/`stopped` events before the socket closes.
- `NewSpool` failure (no listener) makes startup fail.
- config: each of the four error cases in §13.

`scripts/smoke.sh` (optional step 11): start `attackbox-shipper` with `ATTACKBOX_NR_DISABLED`-equivalent — not available, so instead point `ATTACKBOX_NR_LOG_URL`/`ATTACKBOX_NR_METRIC_URL` at a loopback `python3 -m http.server`-style stub, or skip the shipper entirely in smoke and cover it with `main_test.go`. **Recommended: skip it.** The Go end-to-end test already covers the path with a fake intake, and smoke.sh must keep working without extra daemons.

Commands (the implementing agent runs these; this plan ran none):

```
gofmt -l .                                   # expect: no output
go vet ./...                                 # expect: no findings
go test -race -count=1 -cover ./...          # expect: all pass; new packages covered
go build -trimpath -ldflags='-s -w' ./cmd/attackbox ./cmd/attackbox-shipper
./scripts/smoke.sh                           # expect: "smoke: PASS", unchanged from today
shellcheck -S error scripts/*.sh             # only if step 11 is taken
```

Manual, on the deployment host (`UbuntuHardening`'s dry-run):

```
systemctl show -p After -p Before attackbox.service attackbox-shipper.service
stat -c '%U %G %a' /run/attackbox /run/attackbox/spool.sock /var/lib/attackbox-shipper
docker exec <bait> sh -c 'ls /run/attackbox'     # expect: permission denied (0710, no group r)
nft list ruleset | grep -A2 skuid                # expect: only abx-ship may egress 443
```

## 16. Limits and residual risk

- **Bait-side buffering is RAM-only.** If the shipper is down longer than the 10000-record channel, the bait drops (counted, and visible as a `seq` gap at the shipper). The disk buffer is the shipper's, per `implementation_plan.md:273`. A shipper restart under systemd is ~1 s. Acceptable; upgrade path is a second disk queue inside the container, which would need a writable mount and is exactly what the sandbox design is trying to avoid.
- **Dedup is checkpoint + `record_id`, not an LRU.** A shipper crash between `TryEmit` and the checkpoint write replays at most one batch. The duplicates carry identical `record_id`, so NRQL can collapse them. No in-memory dedup set is proposed because the bait never replays. `shortcut: duplicates are detectable, not prevented; add an LRU of recent IDs only if bait-side durability is ever added.`
- **Replayed counters are timestamped at replay time** (`newrelic.go:286`). Logs are unaffected.
- `TryEmit`'s single-producer rule is documented, not enforced. A future second caller would break the all-or-nothing guarantee.
- Read-only bind mount + `connect()` is marked `[INFERENCE]` above; it is the one environmental assumption this design makes and §15 verifies it before deployment.
- The socket is the bait's only output channel in spool mode, so a shipper bug stops all telemetry. The Docker log driver copy of stdout (root-owned, host-side) is the independent backstop.
- Not designed here, by scope: the six-stream *producers*, the nine missing metrics, the Falco rule set and the nftables→JSON converter. §9 fixes only the contract those producers must meet.
