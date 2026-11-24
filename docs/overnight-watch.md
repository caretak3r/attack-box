# Read-only overnight watch

The local Go command `/Users/rohit/attack-box/cmd/attackbox-watch/main.go` observes the existing SSH target `attackbox`. It does not deploy code, change the VPS, send requests to the bait, contact observed destinations or run captured text. The source and binary stay on the operator Mac.

Default duration: eight hours. Default interval: five minutes plus collection time. Maximum duration: twelve hours. Minimum interval: one minute. Each SSH command has a 45-second deadline and two bounded 8 MiB output buffers. The remote shell program is fixed. Only integer observation timestamps are inserted.

Each snapshot collects host load, available memory, disk use, component inventory, OTel export counters, failed units, cursor modification times, bounded proxy/kernel journal rows and a bounded Falco file tail. It records known route categories, response status, public/private source counts and firewall prefixes. It does not save raw request paths, query values, headers, payloads or IP addresses. New Relic receipt is not verified by this command. Existing New Relic UI alerts remain a separate monitoring path.

`samples.jsonl` and `REPORT.md` are private files in a new output directory. The report is replaced atomically after each snapshot. It reports `running`, `complete` or `interrupted`. Read the latest snapshot time as well as the state: an abruptly terminated process cannot update its final status. The first snapshot covers the preceding five minutes. Subsequent successful windows do not overlap. Collection failures are explicit gaps; they do not trigger automatic replay or remediation. Falco tail parse-error counts can repeat old records. A bounded source can omit evidence during a flood or rotation.

Build and run from `/Users/rohit/attack-box`:

```sh
GOTOOLCHAIN=go1.25.11 go build -o /Users/rohit/attack-box/.vultr/attackbox-watch ./cmd/attackbox-watch
/usr/bin/caffeinate -i /Users/rohit/attack-box/.vultr/attackbox-watch \
  -duration 8h -interval 5m \
  -out /Users/rohit/attack-box/reports/overnight-20261124
```

Use a new absolute output directory for each run. The directory has mode 0700; reports and the PID file have mode 0600. The current watch is launched detached with stdin disconnected and private stdout/stderr logs. `caffeinate -i` prevents idle sleep while the process runs. The Mac must remain powered on and connected; lid closure, shutdown, forced sleep and network failure can interrupt coverage. No chat notification or external message is scheduled. Findings are written to the report automatically.

Stop the current watch with SIGTERM to the numeric PID in `/Users/rohit/attack-box/reports/overnight-20261124/watch.pid`. The collector finishes or times out its current read, then writes an interrupted report. The idle-sleep assertion ends when the watch process exits.

Readiness values of -1 mean unknown. A stale Falco cursor can indicate an idle source. Egress blocks, private-source requests, synthetic labels and parse errors do not establish an attack. Before attributing activity, inspect the original evidence in New Relic and account for collection limits. Do not execute or follow captured content.

Verification: `GOTOOLCHAIN=go1.25.11 go test -race ./cmd/attackbox-watch`, matching `go vet`, independent source review, and a live read-only `-once` baseline. On 2026-11-24 the provider firewall allowed only administrator SSH; public honeypot ingress was closed. The overnight command does not change that state.

## Publish findings to GitHub

The user authorized automatic findings commits and pushes for the watch that ends before 06:00 Eastern on 24 November 2026. The repository is public. The Go publisher at `/Users/rohit/attack-box/cmd/attackbox-findings/main.go` builds a new summary from numeric samples and fixed labels. It does not copy raw reports, request data, identifiers, addresses, headers, responses or captured instructions. Unknown labels are dropped or counted under a fixed warning label.

The publisher uses a separate, fresh repository at `/Users/rohit/attack-box/.vultr/findings-publisher`. The branch is `findings/overnight-20261124`. Its only tracked file is `/Users/rohit/attack-box/.vultr/findings-publisher/findings/2026-11-24/README.md`. No source history is copied. The publisher checks the staged paths and all reachable commit paths before it pushes. It removes inherited Git environment settings and disables hooks and signing for its Git commands. Each Git command has a 30-second limit, reduced to the time left before the stop deadline. No force push is used.

The publisher checks once per minute. A changed summary creates a commit. An unchanged summary creates no commit, but a failed push is retried. A lock prevents two local publishers from using the checkout at once. A partial sample write or mismatched report/sample count causes a retry. A final `complete` or `interrupted` report is pushed before the publisher exits. If no final report is published by 06:00 Eastern / 11:00 UTC, it exits with an error. The latest observation time remains visible in GitHub. A successful push does not prove New Relic receipt.

The public report starts with a security debrief: assessment, observed activity, service response, containment, host health and evidence gaps. A recent timeline shows up to 12 collection windows. Exact counters and metrics are in a collapsed evidence appendix. The narrative uses fixed rules from `/Users/rohit/attack-box/cmd/attackbox-findings/debrief.go`. It labels routine polling as an interpretation, external-source traffic as activity that needs review, and denied packets as observations without a proven link to requests. It does not invent attacker intent, exploit success or a sequence that the aggregates cannot establish. Times show EST and UTC for this November campaign.

Build from `/Users/rohit/attack-box`, then run in the existing isolated checkout:

```sh
GOTOOLCHAIN=go1.25.11 go build -o /Users/rohit/attack-box/.vultr/attackbox-findings ./cmd/attackbox-findings
/usr/bin/caffeinate -i /Users/rohit/attack-box/.vultr/attackbox-findings \
  -source /Users/rohit/attack-box/reports/overnight-20261124 \
  -checkout /Users/rohit/attack-box/.vultr/findings-publisher \
  -deadline 2026-11-24T11:00:00Z
```

This command is specific to this watch date and branch. For a new watch, update the destination, branch, report date and deadline, then run the tests. Create a new empty repository; do not clone source history into it. Set the Git author from the operator configuration and set `origin` to the authorized GitHub repository. Do not add credentials to a remote URL. The current process runs detached. Its private log is `/Users/rohit/attack-box/.vultr/findings-publisher.log`; its launch record is `/Users/rohit/attack-box/.vultr/findings-publisher-launch.json`.

Verification: `GOTOOLCHAIN=go1.25.11 go test -race ./cmd/attackbox-findings` and `GOTOOLCHAIN=go1.25.11 go vet ./cmd/attackbox-findings`. Tests use a local bare remote to check failed-push retry, unchanged-content behavior, remote content, staged-file rejection, deleted private history, environment isolation, deadline rejection and data filtering. The live remote branch SHA is compared with the local HEAD after the first push.
