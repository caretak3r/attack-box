# Evidence collection and ingestion budget

## Architecture

The Go audit forwarder reads the original audit file and joins records by audit event time and serial. It sends retained groups to a private JSONL file. The bait, shipper, proxy, Falco, and egress evidence paths do not change.

Source: `/Users/rohit/attack-box/cmd/attackbox-auditfilter/main.go` and `/Users/rohit/attack-box/internal/auditfilter/filter.go`.

A retained group includes all observed SYSCALL, EXECVE, PATH, CWD, PROCTITLE, and SOCKADDR records. Each group has a hash and chunks of at most 3,500 Unicode characters. Join by `audit_reader_boot_id`, `audit_event_id`, and `body_sha256`; order by `chunk_index`. Require every chunk. The boot ID identifies the reader boot, not proof of the original event boot. Original audit timestamps remain in the message. Deduplicate replayed chunks by this identity. Invalid UTF-8 is hex-encoded and marked; the hash still covers the original bytes.

Only one group can be suppressed: successful x86-64 routing-netlink socket creation by the root Infrastructure process. The rule requires the expected executable, audit login identity, syscall arguments, and complete group. It checks the executable reported by the kernel audit record and the live PID, parent, start time, UID, and systemd cgroup. It does not require ptrace capability. PID reuse, unknown context, failed operations, other network operations, and incomplete records stay in the output. An attacker with host-root control can tamper with collection; local file writes do not prove source integrity.

Each batch reports input, retained, and suppressed row counts, the first and last audit event IDs, a stable batch ID, and the policy version. The cursor advances on disk only after output fsync. A crash can replay records. Rotation drains retained numeric files in order. A missing inode, changed bytes, truncated file, or oversized line stops the reader with an error. The inventory reports the reader service state. No silent cursor reset is permitted. On restart, an incomplete output line is removed before the uncommitted source batch is replayed.

Memory input is bounded to 256 KiB per batch. A normal batch flushes within about five seconds; local file arrival depends on the shipper and filesystem. Output retains four 64 MiB files. Each rotation reports the bytes retired from the oldest local file. Retired bytes are not proof of a collection loss. Original audit data retains up to 64 files of 8 MiB. These are size limits, not time guarantees. Monitor rotation, source gaps, and disk use.

The inventory worker keeps its existing systemd sandbox running and refreshes every 60 seconds. It reads all fixed service states with one systemctl call. The 90-second snapshot validity limit remains. HTTP readiness probes and metrics collection remain frequent. This removes repeated sandbox creation and inspection commands without disabling audit rules or sandbox controls.

## Setup

Build the three host binaries for Linux amd64 with CGO disabled. Place them in a private staging directory with a `SHA256SUMS.json` object that maps each basename to its SHA-256 digest:

- `attackbox-auditfilter`
- `attackbox-hostcollector`
- `attackbox-hostreader`

Run `/Users/rohit/attack-box/scripts/install-log-budget.sh --check` with the absolute staging-directory path. On the VPS, run the installed copy with `--apply` and that directory. The installer validates checksums and static ELF headers, backs up changed files, starts the reader, waits for durable output, then changes the native audit input. It restores the previous files if application fails. A short duplicate interval is possible during the cutover. Public ingress and bait containers are not changed.

For monitoring bootstrap, pass `--log-budget-binaries` and the staging-directory path to `/Users/rohit/attack-box/scripts/install-monitoring.sh`. This invokes the same validated installer after native monitoring is available. Native logging must already have exactly one managed audit route. Keep the new reader enabled after bootstrap; do not restore the raw audit input by copying an older host logging template over it.

## Keep and verify

Keep full supported attack request and response capture, follow-up attribution, proxy rejection records, authentication, Falco, blocked egress, loss counters, and service-map traces. Health-check requests also remain captured: shared routes and proxy addresses do not provide a safe discard identity. Do not add a route-only or User-Agent-only exclusion. Syslog and egress remain separate until duplicate equivalence is proved.

Host-local bounds: audit forwarder output retains four 64 MiB files (256 MiB total). Original audit data retains up to 64 files of 8 MiB (512 MiB total). Shipper events retain 30 days and 8 GiB. OTel traces and metrics retain 64 MiB each with 30-day and 60-backup rotation. Public requests retain 7 UTC days. Monitor filesystem usage separately.

Query batch accounting from local files:

```bash
# Using jq on audit-filter output
jq -c 'select(.action == "audit_budget_batch")' \
  /var/log/attackbox-audit/*.jsonl | \
  jq -s 'map({input_rows, kept_rows, suppressed_rows}) | add'
```

Batch replay can duplicate these sums. For exact reconciliation, deduplicate by `audit_batch_id`. Inspect retained events with `audit_event_id`, `chunk_index`, `chunk_count`, `body_sha256`, and `audit_decision`. A grouped message may contain several record types.

Local verification: `go test -race ./...`, `go vet ./...`, and `bash /Users/rohit/attack-box/scripts/smoke.sh`. Before rollout, also test source rotation, crash replay, malformed groups, filter bypass attempts, and exact reconstruction. After rollout, verify audit chunks, accounting, an HTTP request/response/follow-up sequence, traces, and a proxy rejection in local evidence files. Keep all live evidence and deployment state in private reports.

The installer masks `falcoctl-artifact-follow.service` after it confirms that the installed Falco rules exist. The Falco engine remains active. The rule file hash must remain unchanged during this operation. In the campaign network, the online follower cannot reach its index and otherwise restarts repeatedly. Update rules in an approved maintenance window, validate them, and record the new hash before the next campaign. Do not open an extra outbound route for this updater during a campaign.
