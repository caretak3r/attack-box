package shipper

import (
	"context"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"attackbox/internal/telemetry"
)

const shipperBootID = "feedfacefeedface"

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

// newTestClock starts at the real time: the connection read deadlines are set
// from this clock, so a clock in the past would cut every read at once.
func newTestClock() *testClock { return &testClock{t: time.Now().Truncate(time.Millisecond)} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// rig is an Ingest on real sockets with a queue and a clock the test owns.
type rig struct {
	t     *testing.T
	in    *Ingest
	q     *Queue
	clock *testClock
	paths map[Role]string
	conns map[Role]uint64
}

func newRig(t *testing.T, qc QueueConfig, mod func(*IngestConfig), roles ...Role) *rig {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "abi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	q, _ := mustOpen(t, qc)
	r := &rig{t: t, q: q, clock: newTestClock(), paths: map[Role]string{}, conns: map[Role]uint64{}}
	cfg := IngestConfig{Queue: q, Now: r.clock.Now}
	for _, role := range roles {
		ep := Endpoint{
			Path: filepath.Join(dir, role.String()+".sock"), Role: role, Mode: 0o600,
			UIDs: []uint32{uint32(os.Getuid())}, MaxConns: 4, Rate: 1 << 20, Burst: 4 << 20,
		}
		r.paths[role] = ep.Path
		cfg.Endpoints = append(cfg.Endpoints, ep)
	}
	if mod != nil {
		mod(&cfg)
	}
	if r.in, err = NewIngest(cfg); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- r.in.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-served
	})
	return r
}

func (r *rig) until(what string, ok func(RoleStats) bool, role Role) RoleStats {
	r.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := r.in.Stats()[role]
		if ok(st) {
			return st
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("timed out waiting for %s; stats = %+v", what, st)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// open dials role and waits until the server accepted the connection, so the
// peer is still there when its credentials are read.
func (r *rig) open(role Role) net.Conn {
	r.t.Helper()
	c, err := net.Dial("unix", r.paths[role])
	if err != nil {
		r.t.Fatal(err)
	}
	r.conns[role]++
	want := r.conns[role]
	r.until("accept", func(s RoleStats) bool { return s.Accepted >= want }, role)
	return c
}

// settle waits until every connection of role is served and closed.
func (r *rig) settle(role Role) {
	r.t.Helper()
	r.until("connections served", func(s RoleStats) bool { return s.Accepted >= r.conns[role] && s.Conns == 0 }, role)
}

// send writes lines on one connection, closes it and waits for the append.
func (r *rig) send(role Role, lines ...string) {
	r.t.Helper()
	c := r.open(role)
	if _, err := c.Write([]byte(strings.Join(lines, "\n") + "\n")); err != nil {
		r.t.Fatal(err)
	}
	c.Close()
	r.settle(role)
}

func (r *rig) report() []telemetry.Event {
	return r.in.Accounting(r.clock.Now(), shipperBootID)
}

func bootID(n int) string { return fmt.Sprintf("%016x", n) }

func bl(boot string, seq int, event string) string {
	return fmt.Sprintf(`{"id":"%s-%d","v":1,"event":%s}`, boot, seq, event)
}

const edgeEv = `{"stream":"edge"}`

func beatEv(attrs string) string {
	return `{"stream":"heartbeat","action":"bait_heartbeat","attrs":` + attrs + `}`
}

func stopEv(attrs string) string {
	return `{"stream":"runtime","action":"stopped","attrs":` + attrs + `}`
}

func attr(t *testing.T, e telemetry.Event, key string) any {
	t.Helper()
	v, ok := e.Attrs[key]
	if !ok {
		t.Fatalf("%s event has no attribute %q: %v", e.Action, key, e.Attrs)
	}
	return v
}

func attrInt(t *testing.T, e telemetry.Event, key string) int64 {
	t.Helper()
	n, ok := attr(t, e, key).(int64)
	if !ok {
		t.Fatalf("attribute %q = %#v, want an int64", key, e.Attrs[key])
	}
	return n
}

func attrStr(t *testing.T, e telemetry.Event, key string) string {
	t.Helper()
	s, ok := attr(t, e, key).(string)
	if !ok {
		t.Fatalf("attribute %q = %#v, want a string", key, e.Attrs[key])
	}
	return s
}

// bootRow returns the producer_boot event of one boot; it fails when the
// report holds none or two.
func bootRow(t *testing.T, rows []telemetry.Event, role Role, boot string) telemetry.Event {
	t.Helper()
	var found []telemetry.Event
	for _, e := range rows {
		if e.Action == "producer_boot" && e.Attrs["role"] == role.String() && e.Attrs["boot"] == boot {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("got %d producer_boot rows for %s %s, want 1; rows = %d", len(found), role, boot, len(rows))
	}
	return found[0]
}

func hasBoot(rows []telemetry.Event, role Role, boot string) bool {
	return slices.ContainsFunc(rows, func(e telemetry.Event) bool {
		return e.Action == "producer_boot" && e.Attrs["role"] == role.String() && e.Attrs["boot"] == boot
	})
}

func statsRow(t *testing.T, rows []telemetry.Event, role Role) telemetry.Event {
	t.Helper()
	for _, e := range rows {
		if e.Action == "ingest_stats" && e.Attrs["role"] == role.String() {
			return e
		}
	}
	t.Fatalf("no ingest_stats row for %s", role)
	return telemetry.Event{}
}

func wantVerdict(t *testing.T, e telemetry.Event, state, loss, reason string) {
	t.Helper()
	got := [4]string{attrStr(t, e, "state"), attrStr(t, e, "loss"), attrStr(t, e, "loss_reason"), attrStr(t, e, "loss_scope")}
	if want := [4]string{state, loss, reason, "committed"}; got != want {
		t.Fatalf("boot %v: state/loss/reason/scope = %v, want %v", e.Attrs["boot"], got, want)
	}
	if _, has := e.Attrs["lost"]; has != (loss == "known") {
		t.Fatalf("boot %v: lost present = %v with loss %s", e.Attrs["boot"], has, loss)
	}
}

func wantInts(t *testing.T, e telemetry.Event, want map[string]int64) {
	t.Helper()
	for _, k := range slices.Sorted(maps.Keys(want)) {
		if got := attrInt(t, e, k); got != want[k] {
			t.Fatalf("boot %v: %s = %d, want %d", e.Attrs["boot"], k, got, want[k])
		}
	}
}

func TestAccountingCleanEnd(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	a := bootID(0xa)
	r.send(RoleBait,
		bl(a, 1, edgeEv),
		bl(a, 2, edgeEv),
		bl(a, 3, beatEv(`{"dropped_total":0}`)),
		bl(a, 4, stopEv(`{"dropped_total":0}`)))

	e := bootRow(t, r.report(), RoleBait, a)
	wantVerdict(t, e, "clean_end", "none_known", "none")
	wantInts(t, e, map[string]int64{"first_seq": 1, "last_seq": 4, "final_seq": 4, "admitted": 4, "missing": 0, "queue_refused": 0, "rejected": 0})
	if attrStr(t, e, "shipper_boot") != shipperBootID || e.Attrs["source"] != "shipper_accounting" {
		t.Fatalf("row identity = %v", e.Attrs)
	}
}

func TestAccountingKnownLoss(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	a := bootID(0xa)
	// seq 3 is refused by admission (wrong v), 4 and 5 were dropped by the bait.
	r.send(RoleBait,
		bl(a, 1, edgeEv),
		bl(a, 2, edgeEv),
		fmt.Sprintf(`{"id":"%s-3","v":2,"event":%s}`, a, edgeEv),
		bl(a, 6, beatEv(`{"dropped_total":2}`)),
		bl(a, 7, stopEv(`{"dropped_total":2}`)))

	e := bootRow(t, r.report(), RoleBait, a)
	wantVerdict(t, e, "clean_end", "known", "none")
	wantInts(t, e, map[string]int64{"admitted": 4, "missing": 3, "rejected": 1, "reported_dropped": 2, "reported_at_seq": 7, "lost": 3, "queue_refused": 0})
}

// Gaps that the claims and the refused lines do not add up to are not a loss
// the shipper can state.
func TestAccountingCounterMismatch(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	a := bootID(0xa)
	r.send(RoleBait, bl(a, 1, edgeEv), bl(a, 4, edgeEv), bl(a, 5, stopEv(`{"dropped_total":0}`)))

	e := bootRow(t, r.report(), RoleBait, a)
	wantVerdict(t, e, "clean_end", "unknown", "counter_mismatch")
	wantInts(t, e, map[string]int64{"missing": 2})
}

func TestAccountingQueueOverflow(t *testing.T) {
	a, b := bootID(0xa), bootID(0xb)
	now := time.Now()
	frame := func(l string) int64 {
		t.Helper()
		adm, err := Admit(RoleBait, []byte(l), now)
		if err != nil {
			t.Fatal(err)
		}
		return FrameHeader + int64(len(adm.Data))
	}
	fe, fs := frame(bl(a, 1, edgeEv)), frame(bl(a, 3, stopEv(`{"dropped_total":0}`)))
	qc := testConfig(queueDir(t))
	qc.MaxBytes = 2*fe + fs + fe/2 // boot a fits; no later record does

	r := newRig(t, qc, nil, RoleBait)
	r.send(RoleBait, bl(a, 1, edgeEv), bl(a, 2, edgeEv), bl(a, 3, stopEv(`{"dropped_total":0}`)))
	r.send(RoleBait, bl(b, 1, edgeEv), bl(b, 2, edgeEv), bl(b, 3, stopEv(`{"dropped_total":0}`)))

	rows := r.report()
	ea, eb := bootRow(t, rows, RoleBait, a), bootRow(t, rows, RoleBait, b)
	wantVerdict(t, ea, "clean_end", "none_known", "none")
	wantInts(t, ea, map[string]int64{"queue_refused": 0, "admitted": 3})
	wantVerdict(t, eb, "clean_end", "known", "none")
	wantInts(t, eb, map[string]int64{"queue_refused": 3, "admitted": 3, "missing": 0, "lost": 3})
	if st := statsRow(t, rows, RoleBait); attrInt(t, st, "queue_full") != 3 || attrInt(t, st, "queued") != 3 {
		t.Fatalf("stats = %v, want 3 queued and 3 queue_full", st.Attrs)
	}
}

// A boot is not final, and not admitted, before the durable append returned.
func TestAccountingPendingUntilAppend(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	a := bootID(0xa)

	r.q.mu.Lock() // Append blocks here
	locked := true
	defer func() {
		if locked {
			r.q.mu.Unlock()
		}
	}()
	c := r.open(RoleBait)
	defer c.Close()
	if _, err := c.Write([]byte(bl(a, 1, edgeEv) + "\n" + bl(a, 2, stopEv(`{"dropped_total":0}`)) + "\n")); err != nil {
		t.Fatal(err)
	}
	r.until("the first line", func(s RoleStats) bool { return s.Lines >= 1 }, RoleBait)

	e := bootRow(t, r.report(), RoleBait, a)
	wantVerdict(t, e, "open", "pending", "none")
	wantInts(t, e, map[string]int64{"admitted": 0, "queue_refused": 0, "last_seq": 0})
	if _, has := e.Attrs["final_seq"]; has {
		t.Fatalf("final_seq set before the append returned: %v", e.Attrs)
	}

	r.q.mu.Unlock()
	locked = false
	c.Close()
	r.settle(RoleBait)
	e = bootRow(t, r.report(), RoleBait, a)
	wantVerdict(t, e, "clean_end", "none_known", "none")
	wantInts(t, e, map[string]int64{"admitted": 2, "final_seq": 2})
}

func TestAccountingAppendError(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	a := bootID(0xa)
	r.send(RoleBait, bl(a, 1, edgeEv))
	r.q.Close() // every later Append fails
	r.send(RoleBait, bl(a, 2, edgeEv), bl(a, 3, stopEv(`{"dropped_total":0}`)))

	wantVerdict(t, bootRow(t, r.report(), RoleBait, a), "open", "unknown", "append_error")
}

// Drops after the last heartbeat leave a stale claim; a boot that went silent
// must not turn it into a known loss.
func TestAccountingSilentIgnoresStaleClaim(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	a := bootID(0xa)
	// seq 2 and 3 were dropped and the claim says so, then the bait dies.
	r.send(RoleBait, bl(a, 1, edgeEv), bl(a, 4, beatEv(`{"dropped_total":2}`)))

	e := bootRow(t, r.report(), RoleBait, a)
	wantVerdict(t, e, "open", "pending", "none")

	r.clock.Advance(DefaultIdleTimeout + time.Second)
	e = bootRow(t, r.report(), RoleBait, a)
	wantVerdict(t, e, "silent", "unknown", "silent")
	wantInts(t, e, map[string]int64{"reported_dropped": 2, "missing": 2})
}

func TestAccountingNewBootEndsPreviousBoot(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	a, b := bootID(0xa), bootID(0xb)
	r.send(RoleBait, bl(a, 1, edgeEv), bl(a, 2, beatEv(`{"dropped_total":0}`)))
	wantVerdict(t, bootRow(t, r.report(), RoleBait, a), "open", "pending", "none")

	r.send(RoleBait, bl(b, 1, edgeEv))
	rows := r.report()
	wantVerdict(t, bootRow(t, rows, RoleBait, a), "unclean_end", "unknown", "unclean_end")
	wantVerdict(t, bootRow(t, rows, RoleBait, b), "open", "pending", "none")
}

func TestAccountingAfterStopped(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	post, forced := bootID(0xa), bootID(0xb)
	r.send(RoleBait, bl(post, 1, edgeEv), bl(post, 2, stopEv(`{"dropped_total":0}`)))
	wantVerdict(t, bootRow(t, r.report(), RoleBait, post), "clean_end", "none_known", "none")
	r.send(RoleBait, bl(post, 3, edgeEv))

	r.send(RoleBait, bl(forced, 1, edgeEv), bl(forced, 2, stopEv(`{"dropped_total":0,"forced":true}`)))

	rows := r.report()
	wantVerdict(t, bootRow(t, rows, RoleBait, post), "unclean_end", "unknown", "post_stop")
	wantInts(t, bootRow(t, rows, RoleBait, post), map[string]int64{"final_seq": 2, "last_seq": 3})
	wantVerdict(t, bootRow(t, rows, RoleBait, forced), "unclean_end", "unknown", "forced_stop")
}

func TestAccountingPrefixUnseen(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	a := bootID(0xa)
	r.send(RoleBait, bl(a, 5, edgeEv), bl(a, 6, stopEv(`{"dropped_total":0}`)))

	e := bootRow(t, r.report(), RoleBait, a)
	wantVerdict(t, e, "clean_end", "unknown", "prefix_unseen")
	wantInts(t, e, map[string]int64{"first_seq": 5, "missing": 0})
}

// A claim that is negative, not a number or absent changes nothing, and so
// does a counter on a record that may not carry one.
func TestAccountingIgnoresBadClaims(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	a := bootID(0xa)
	r.send(RoleBait,
		bl(a, 1, beatEv(`{"dropped_total":-1}`)),
		bl(a, 2, beatEv(`{"dropped_total":"7"}`)),
		bl(a, 3, beatEv(`{}`)),
		bl(a, 4, beatEv(`{"dropped_total":null}`)),
		bl(a, 5, `{"stream":"edge","attrs":{"dropped_total":99}}`))
	wantInts(t, bootRow(t, r.report(), RoleBait, a), map[string]int64{"reported_dropped": 0, "reported_at_seq": 0, "admitted": 5})

	r.send(RoleBait, bl(a, 6, beatEv(`{"dropped_total":3}`)), bl(a, 7, beatEv(`{"dropped_total":-2}`)))
	wantInts(t, bootRow(t, r.report(), RoleBait, a), map[string]int64{"reported_dropped": 3, "reported_at_seq": 6})
}

func TestAccountingClock(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	a := bootID(0xa)
	at := func(d time.Duration) string {
		return fmt.Sprintf(`{"stream":"edge","timestamp":%q}`, r.clock.Now().Add(d).Format(time.RFC3339Nano))
	}
	r.send(RoleBait, bl(a, 1, at(-3*time.Second)), bl(a, 2, at(10*time.Second)))
	e := bootRow(t, r.report(), RoleBait, a)
	wantInts(t, e, map[string]int64{"max_skew_ms": 10000, "clamped": 0, "last_ingest_ts": r.clock.Now().UnixMilli()})

	// A day and more off is clamped; the producer time is kept for the skew.
	r.send(RoleBait, bl(a, 3, at(-48*time.Hour)), bl(a, 4, edgeEv))
	e = bootRow(t, r.report(), RoleBait, a)
	wantInts(t, e, map[string]int64{"max_skew_ms": (48 * time.Hour).Milliseconds(), "clamped": 2})
}

// The adapters send no counters and no stopped record: their boots end as
// unknown, by a new boot or by silence.
func TestAccountingAdapterBootsEndUnknown(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleRuntime)
	one, two := bootID(1), bootID(2)
	falco := `{"stream":"runtime","action":"falco"}`
	r.send(RoleRuntime, bl(one, 1, falco), bl(one, 2, falco))
	r.send(RoleRuntime, bl(two, 1, falco))

	rows := r.report()
	wantVerdict(t, bootRow(t, rows, RoleRuntime, one), "unclean_end", "unknown", "unclean_end")
	wantVerdict(t, bootRow(t, rows, RoleRuntime, two), "open", "pending", "none")

	r.clock.Advance(DefaultIdleTimeout + time.Second)
	wantVerdict(t, bootRow(t, r.report(), RoleRuntime, two), "silent", "unknown", "silent")
}

func TestAccountingShowsRejections(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait, RoleEgress)
	r.send(RoleBait, fmt.Sprintf(`{"id":"%s-1","v":2,"event":%s}`, bootID(0xa), edgeEv))

	rows := r.report()
	st := statsRow(t, rows, RoleBait)
	wantInts(t, st, map[string]int64{"rejected_schema_version": 1, "rejected_total": 1, "lines": 1, "queued": 0})
	if _, has := statsRow(t, rows, RoleEgress).Attrs["rejected_schema_version"]; has {
		t.Fatal("the egress role shows a rejection it never had")
	}
}

// A line refused on a connection of a known boot is charged to that boot.
func TestAccountingChargesRejectionsToTheBoot(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	a := bootID(0xa)
	r.send(RoleBait, bl(a, 1, edgeEv), `not json`, bl(a, 3, edgeEv))
	wantInts(t, bootRow(t, r.report(), RoleBait, a), map[string]int64{"rejected": 1, "admitted": 2, "missing": 1})
}

// The duplicate and gap counters of RoleStats behave as before the boot
// table: a resent batch is dropped and counted once, in both places.
func TestAccountingKeepsDuplicateCheck(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	a := bootID(0xa)
	r.send(RoleBait, bl(a, 1, edgeEv), bl(a, 2, edgeEv), bl(a, 3, edgeEv))
	r.send(RoleBait, bl(a, 1, edgeEv), bl(a, 2, edgeEv), bl(a, 3, edgeEv), bl(a, 4, edgeEv), bl(a, 6, edgeEv))

	st := r.in.Stats()[RoleBait]
	if st.Duplicates != 3 || st.Gaps != 1 || st.Queued != 5 || st.QueueFull != 0 {
		t.Fatalf("stats = %+v, want 3 duplicates, 1 gap, 5 queued", st)
	}
	wantInts(t, bootRow(t, r.report(), RoleBait, a), map[string]int64{"duplicates": 3, "admitted": 5, "missing": 1})

	rs := &roleState{boots: map[string]*bootMark{}, stats: RoleStats{Rejected: map[string]uint64{}}}
	for _, step := range []struct {
		seq   uint64
		fresh bool
	}{{1, true}, {1, false}, {3, true}, {2, false}} {
		if _, got := rs.track(a, step.seq, time.Now()); got != step.fresh {
			t.Fatalf("track(%d) fresh = %v, want %v", step.seq, got, step.fresh)
		}
	}
	if rs.stats.Duplicates != 2 || rs.stats.Gaps != 1 {
		t.Fatalf("stats = %+v, want 2 duplicates and 1 gap", rs.stats)
	}
}

func TestAccountingEvictionRow(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	for i := 1; i <= maxBoots+1; i++ {
		r.send(RoleBait, bl(bootID(i), 1, edgeEv))
	}
	// The ninth boot pushed the first out before any report showed it.
	for call := 1; call <= retainIntervals+1; call++ {
		rows := r.report()
		if call > retainIntervals {
			if hasBoot(rows, RoleBait, bootID(1)) {
				t.Fatalf("call %d still reports the evicted boot", call)
			}
			break
		}
		wantVerdict(t, bootRow(t, rows, RoleBait, bootID(1)), "unclean_end", "unknown", "evicted")
		wantInts(t, bootRow(t, rows, RoleBait, bootID(1)), map[string]int64{"admitted": 1})
	}
}

// A boot that was reported 3 times and then left the table keeps its verdict
// and is reported 17 more times, 20 in all.
func TestAccountingEvictionAfterPartialReportsFinishesRetention(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	for i := 1; i <= maxBoots; i++ {
		r.send(RoleBait, bl(bootID(i), 1, edgeEv))
	}
	for range 3 {
		wantVerdict(t, bootRow(t, r.report(), RoleBait, bootID(1)), "unclean_end", "unknown", "unclean_end")
	}
	r.send(RoleBait, bl(bootID(maxBoots+1), 1, edgeEv)) // boot 1 leaves the table

	for call := 4; call <= retainIntervals+1; call++ {
		rows := r.report()
		if call > retainIntervals {
			if hasBoot(rows, RoleBait, bootID(1)) {
				t.Fatalf("call %d still reports the evicted boot", call)
			}
			break
		}
		wantVerdict(t, bootRow(t, rows, RoleBait, bootID(1)), "unclean_end", "unknown", "unclean_end")
		if n := attrInt(t, statsRow(t, rows, RoleBait), "boots_unreported"); n != 0 {
			t.Fatalf("call %d: boots_unreported = %d, want 0", call, n)
		}
	}
}

// A boot that was reported for the full 20 calls leaves no row when evicted.
func TestAccountingEvictionAfterFullRetentionLeavesNoRow(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	for i := 1; i <= maxBoots; i++ {
		r.send(RoleBait, bl(bootID(i), 1, edgeEv))
	}
	for range retainIntervals {
		r.report()
	}
	r.send(RoleBait, bl(bootID(maxBoots+1), 1, edgeEv))

	rows := r.report()
	if hasBoot(rows, RoleBait, bootID(1)) {
		t.Fatal("a boot reported 20 times got a row after eviction")
	}
	if n := attrInt(t, statsRow(t, rows, RoleBait), "boots_unreported"); n != 0 {
		t.Fatalf("boots_unreported = %d, want 0", n)
	}
}

// A new verdict of a boot that was reported 20 times is reported again, for
// another 20 calls.
func TestAccountingChangedVerdictRestartsRetention(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	a := bootID(0xa)
	r.send(RoleBait, bl(a, 1, edgeEv), bl(a, 2, stopEv(`{"dropped_total":0}`)))
	for call := 1; call <= retainIntervals+1; call++ {
		rows := r.report()
		if got, want := hasBoot(rows, RoleBait, a), call <= retainIntervals; got != want {
			t.Fatalf("call %d: boot reported = %v, want %v", call, got, want)
		}
		if want := call <= retainIntervals; want {
			wantVerdict(t, bootRow(t, rows, RoleBait, a), "clean_end", "none_known", "none")
		}
	}

	r.send(RoleBait, bl(a, 3, edgeEv))
	for call := 1; call <= retainIntervals+1; call++ {
		rows := r.report()
		if got, want := hasBoot(rows, RoleBait, a), call <= retainIntervals; got != want {
			t.Fatalf("after the record, call %d: boot reported = %v, want %v", call, got, want)
		}
		if call <= retainIntervals {
			wantVerdict(t, bootRow(t, rows, RoleBait, a), "unclean_end", "unknown", "post_stop")
		}
	}
}

func TestAccountingWaitingRowsAreBounded(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	for i := 1; i <= maxBoots+3; i++ {
		r.send(RoleBait, bl(bootID(i), 1, edgeEv))
	}
	rows := r.report()
	// Boots 1 and 2 wait; boot 3 found no slot.
	wantVerdict(t, bootRow(t, rows, RoleBait, bootID(1)), "unclean_end", "unknown", "evicted")
	wantVerdict(t, bootRow(t, rows, RoleBait, bootID(2)), "unclean_end", "unknown", "evicted")
	if hasBoot(rows, RoleBait, bootID(3)) {
		t.Fatal("a third evicted boot has a row")
	}
	if n := attrInt(t, statsRow(t, rows, RoleBait), "boots_unreported"); n != 1 {
		t.Fatalf("boots_unreported = %d, want 1", n)
	}
	if len(rows) != 1+maxBoots+maxWaiting {
		t.Fatalf("got %d rows, want %d", len(rows), 1+maxBoots+maxWaiting)
	}
}

// An evicted boot that is seen again gets one fresh row. Its waiting row, with
// the stale final verdict, is gone before the table evicts another boot, so the
// other waiting rows keep their slots.
func TestAccountingRediscoveredBootReplacesWaitingRow(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	r.send(RoleBait, bl(bootID(1), 1, edgeEv), bl(bootID(1), 2, stopEv(`{"dropped_total":0}`)))
	for i := 2; i <= maxBoots+2; i++ {
		r.send(RoleBait, bl(bootID(i), 1, edgeEv)) // boots 1 and 2 leave the table
	}
	r.send(RoleBait, bl(bootID(1), 1, edgeEv))

	rows := r.report()
	back := bootRow(t, rows, RoleBait, bootID(1))
	wantVerdict(t, back, "open", "pending", "none")
	wantInts(t, back, map[string]int64{"admitted": 1, "first_seq": 1, "last_seq": 1})
	if _, has := back.Attrs["final_seq"]; has {
		t.Fatalf("the rediscovered boot kept the stale final_seq: %v", back.Attrs)
	}
	// Boot 1 gave its slot back, so boot 3 waits behind boot 2.
	for _, i := range []int{2, 3} {
		wantVerdict(t, bootRow(t, rows, RoleBait, bootID(i)), "unclean_end", "unknown", "evicted")
	}
	if n := attrInt(t, statsRow(t, rows, RoleBait), "boots_unreported"); n != 0 {
		t.Fatalf("boots_unreported = %d, want 0", n)
	}
	if len(rows) != 1+maxBoots+maxWaiting {
		t.Fatalf("got %d rows, want %d", len(rows), 1+maxBoots+maxWaiting)
	}
}

func TestAccountingEndedRowsStopAfterRetention(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	done, open := bootID(0xa), bootID(0xb)
	r.send(RoleBait, bl(done, 1, edgeEv), bl(done, 2, stopEv(`{"dropped_total":0}`)))
	r.send(RoleBait, bl(open, 1, edgeEv))

	for call := 1; call <= retainIntervals+5; call++ {
		rows := r.report()
		if got, want := hasBoot(rows, RoleBait, done), call <= retainIntervals; got != want {
			t.Fatalf("call %d: ended boot reported = %v, want %v", call, got, want)
		}
		if !hasBoot(rows, RoleBait, open) {
			t.Fatalf("call %d: the open boot is not reported", call)
		}
	}
}

func producerKeys() []string {
	return []string{
		"source", "shipper_boot", "role", "boot", "first_seq", "last_seq", "admitted", "missing", "rejected",
		"queue_refused", "duplicates", "reported_dropped", "reported_at_seq", "max_skew_ms", "clamped",
		"last_ingest_ts", "state", "loss", "loss_scope", "loss_reason",
	}
}

func statsKeys() []string {
	return []string{
		"source", "shipper_boot", "role", "lines", "oversize", "rejected_total", "duplicates", "gaps",
		"queued", "queue_full", "boots_unreported", "rows_omitted",
	}
}

func wantKeys(t *testing.T, e telemetry.Event, want []string) {
	t.Helper()
	if got := slices.Sorted(maps.Keys(e.Attrs)); !slices.Equal(got, slices.Sorted(slices.Values(want))) {
		t.Fatalf("%s attributes = %v, want %v", e.Action, got, slices.Sorted(slices.Values(want)))
	}
}

// Every role fills its table and its waiting rows: 3 + 3*(8+2) = 33 rows,
// under the limit, with the documented names and value types.
func TestAccountingFullReport(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait, RoleRuntime, RoleEgress)
	lines := map[Role]string{
		RoleBait:    edgeEv,
		RoleRuntime: `{"stream":"runtime","action":"falco"}`,
		RoleEgress:  `{"stream":"egress","action":"egress_blocked"}`,
	}
	for _, role := range Roles {
		for i := 1; i <= maxBoots+maxWaiting; i++ {
			r.send(role, bl(bootID(i), 1, lines[role]))
		}
	}

	rows := r.report()
	if len(rows) != 33 {
		t.Fatalf("got %d rows, want 33", len(rows))
	}
	stats := 0
	for _, e := range rows {
		if e.Stream != telemetry.StreamHeartbeat || e.Body != "" || e.Timestamp.IsZero() {
			t.Fatalf("row %s: stream %q body %q time %v", e.Action, e.Stream, e.Body, e.Timestamp)
		}
		if e.Attrs["source"] != "shipper_accounting" || e.Attrs["shipper_boot"] != shipperBootID {
			t.Fatalf("row %s: source/shipper_boot = %v/%v", e.Action, e.Attrs["source"], e.Attrs["shipper_boot"])
		}
		for k, v := range e.Attrs {
			switch v.(type) {
			case string, bool, int64:
			default:
				t.Fatalf("row %s: attribute %s is a %T", e.Action, k, v)
			}
		}
		switch e.Action {
		case "ingest_stats":
			stats++
			wantKeys(t, e, statsKeys())
			wantInts(t, e, map[string]int64{"rows_omitted": 0, "queued": 10, "lines": 10})
		case "producer_boot":
			wantKeys(t, e, producerKeys())
		default:
			t.Fatalf("unexpected action %q", e.Action)
		}
	}
	if stats != 3 {
		t.Fatalf("got %d ingest_stats rows, want 3", stats)
	}
}

// Over the limit, ingest_stats stays, final unknown rows come next, then other
// final rows, then open rows; the rest is counted in rows_omitted.
func TestAccountingRowLimitKeepsOrder(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), func(c *IngestConfig) { c.maxRows = 4 }, RoleBait)
	stop := stopEv(`{"dropped_total":0}`)
	r.send(RoleBait, bl(bootID(1), 1, edgeEv))                         // unclean_end, unknown
	r.send(RoleBait, bl(bootID(2), 1, edgeEv), bl(bootID(2), 2, stop)) // clean_end, none_known
	r.send(RoleBait, bl(bootID(3), 1, edgeEv))                         // unclean_end, unknown
	r.send(RoleBait, bl(bootID(4), 1, edgeEv), bl(bootID(4), 2, stop)) // clean_end, none_known
	r.send(RoleBait, bl(bootID(5), 1, edgeEv))                         // open

	rows := r.report()
	if len(rows) != 4 {
		t.Fatalf("got %d rows, want the limit of 4", len(rows))
	}
	if attrInt(t, statsRow(t, rows, RoleBait), "rows_omitted") != 2 {
		t.Fatalf("stats = %v, want rows_omitted 2", statsRow(t, rows, RoleBait).Attrs)
	}
	var got []string
	for _, e := range rows[1:] {
		got = append(got, attrStr(t, e, "boot"))
	}
	if want := []string{bootID(1), bootID(3), bootID(2)}; !slices.Equal(got, want) {
		t.Fatalf("kept boots = %v, want %v", got, want)
	}
}

// Accounting runs from the reporting loop while connections are served.
func TestAccountingWhileServing(t *testing.T) {
	r := newRig(t, testConfig(queueDir(t)), nil, RoleBait)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				r.report()
			}
		}
	}()
	for i := 1; i <= 20; i++ {
		r.send(RoleBait, bl(bootID(i), 1, edgeEv), bl(bootID(i), 2, edgeEv))
	}
	close(stop)
	wg.Wait()
	if n := r.in.Stats()[RoleBait].Queued; n != 40 {
		t.Fatalf("queued = %d, want 40", n)
	}
}
