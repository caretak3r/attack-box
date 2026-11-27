# Read-only overnight watch

The local Go command `/Users/rohit/attack-box/cmd/attackbox-watch/main.go` observes the existing SSH target `attackbox`. It does not deploy code, change the VPS, send requests to the bait, contact observed destinations or run captured text. The source and binary stay on the operator Mac.

Default duration: eight hours. Default interval: five minutes plus collection time. Maximum duration: twelve hours. Minimum interval: one minute. Each SSH command has a 45-second deadline and two bounded 8 MiB output buffers. The remote shell program is fixed. Only integer observation timestamps are inserted.

Each snapshot collects host load, available memory, disk use, component inventory, OTel export counters, failed units, cursor modification times, bounded proxy/kernel journal rows and a bounded Falco file tail. It records known route categories, response status, public/private source counts and firewall prefixes. It does not save raw request paths, query values, headers, payloads or IP addresses. New Relic receipt is not verified by this command. Existing New Relic UI alerts remain a separate monitoring path.

`samples.jsonl` and `REPORT.md` are private files in a new output directory. The report is replaced atomically after each snapshot. It reports `running`, `complete` or `interrupted`. Read the latest snapshot time as well as the state: an abruptly terminated process cannot update its final status. The first snapshot covers the preceding five minutes. Subsequent successful windows do not overlap. Collection failures are explicit gaps; they do not trigger automatic replay or remediation. Falco tail parse-error counts can repeat old records. A bounded source can omit evidence during a flood or rotation.

Build and run from `/Users/rohit/attack-box`:

```sh
go build -o /Users/rohit/attack-box/.vultr/attackbox-watch ./cmd/attackbox-watch
/usr/bin/caffeinate -i /Users/rohit/attack-box/.vultr/attackbox-watch \
  -duration 8h -interval 5m \
  -out /Users/rohit/attack-box/reports/overnight-20261124
```

Use a new absolute output directory for each run. The directory has mode 0700; reports and the PID file have mode 0600. The current watch is launched detached with stdin disconnected and private stdout/stderr logs. `caffeinate -i` prevents idle sleep while the process runs. The Mac must remain powered on and connected; lid closure, shutdown, forced sleep and network failure can interrupt coverage. No chat notification or external message is scheduled. Findings are written to the report automatically.

Stop the current watch with SIGTERM to the numeric PID in `/Users/rohit/attack-box/reports/overnight-20261124/watch.pid`. The collector finishes or times out its current read, then writes an interrupted report. The idle-sleep assertion ends when the watch process exits.

Readiness values of -1 mean unknown. A stale Falco cursor can indicate an idle source. Egress blocks, private-source requests, synthetic labels and parse errors do not establish an attack. Before attributing activity, inspect the original evidence in New Relic and account for collection limits. Do not execute or follow captured content.

Verification: `GOTOOLCHAIN=go1.25.11 go test -race ./cmd/attackbox-watch`, matching `go vet`, independent source review, and a live read-only `-once` baseline. On 2026-11-24 the provider firewall allowed only administrator SSH; public honeypot ingress was closed. The overnight command does not change that state.

## Update daily findings

Keep one report per UTC date. Do not create a report, branch, or commit for each watch run.
Private watch snapshots remain separate. The November 24 and 25 Git publishers were time-limited jobs, not the daily reporting workflow.

Use the read-only SSH alias `attackbox`. From the repository root, run:

```sh
python3 scripts/daily-findings.py YYYY-MM-DD --own "$PRIOR_OPERATOR_IP"
```

Repeat `--own` for each additional operator address in use that day. The command excludes both ends of the SSH connection automatically.
If there are no other operator addresses, omit `--own`. Do not put actual addresses in this repository.

The command reads the retained public request capture, the current Falco log, and the kernel journal on the VPS.
Only numeric aggregates return to the Mac. The report separates HTTP requests from host signals.
Neither HTTP success nor a firewall denial establishes a compromise.

The command replaces the totals in `findings/YYYY-MM-DD/README.md`. It preserves reviewed notes below the daily totals marker.
Run it after midnight UTC for the previous day, before the seven-day capture retention expires.
For a partial day, run it again with the same date. Do not add the previous totals.
Missing capture files or failed reads leave the existing report unchanged. Log rotation can limit coverage.
The command does not install a schedule, commit, push, or change the VPS.

### Scheduled archive

The operator Mac runs `org.duckdns.attackbox-daily-findings` at 00:15 local time.
It publishes closed UTC days, not a rolling 24-hour window. It checks up to six previous dates after missed runs.
Each changed date gets one Markdown report and one public traffic map. Unchanged dates create no commit.
The [archive dashboard](https://silent.engineer/attack-box/findings/) shows all published dates. Each report links to its own view.

The job uses a fresh checkout of `main`, a private address list, signed commits, and the repository's secret checks.
The publisher stops if its collector or safety checks differ from the installed copies. Review those changes before reinstalling the publisher.
Check the job with `launchctl print gui/$(id -u)/org.duckdns.attackbox-daily-findings`.
To stop it, use `launchctl bootout gui/$(id -u)/org.duckdns.attackbox-daily-findings`.
The Mac needs a logged-in session, access to the VPS and Git remote, and a signing key that works without interaction.
