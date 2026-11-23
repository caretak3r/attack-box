package shipper

import (
	"cmp"
	"math"
	"slices"
	"time"

	"attackbox/internal/telemetry"
)

// Accounting limits. A report is one POST, so its size is bounded: the
// largest honest report is 3 ingest_stats rows, 3*maxBoots tracked boots and
// 3*maxWaiting evicted boots, which is 33 rows.
const (
	retainIntervals = 20      // calls that report a boot after its final value
	maxWaiting      = 2       // evicted rows that wait for each role
	maxClaim        = 1 << 53 // a producer claim above this loses float precision

	accountingSource = "shipper_accounting"
	lossScope        = "committed" // version 1 reconciles up to the durable queue only
)

// Boot states and loss values, as reported.
const (
	stateOpen       = "open"
	stateCleanEnd   = "clean_end"
	stateUncleanEnd = "unclean_end"
	stateSilent     = "silent"

	lossPending   = "pending"
	lossNoneKnown = "none_known"
	lossKnown     = "known"
	lossUnknown   = "unknown"
)

// bootAcct is what the shipper counted for one producer boot in this process.
// The fields change under roleState.mu only.
type bootAcct struct {
	id   string
	born uint64 // creation order inside the role

	first, last, final uint64 // seq range of landed records; seq of stopped, 0 if none
	forced             bool   // the landed stopped said forced
	admitted           uint64 // landed records, queue-refused ones included
	refused            uint64 // landed records that the queue refused
	rejected           uint64 // lines refused on a connection of this boot
	duplicates         uint64
	dropped, droppedAt uint64 // latest dropped_total claim and the seq that carried it
	maxSkew            int64
	clamped            uint64
	lastIngest         int64
	arrived            time.Time // last record of this boot, duplicates included

	superseded bool // a record of another boot of the role landed while this one was open
	appendErr  bool
	evicted    bool      // left the table without a final row ever reported
	shown      int       // calls that reported the current final verdict of this boot
	reported   [3]string // state, loss and loss_reason of the last final row; a change restarts shown
}

// sighting is the evidence of one admitted record. It is read from the
// admitted event and held until its batch is durable.
type sighting struct {
	b       *bootMark
	seq     uint64
	ingest  int64 // ms
	skew    int64 // |ingest - producer time|, ms
	hasSkew bool
	clamped bool

	claim   bool // the record carried a usable dropped_total
	dropped uint64
	stopped bool
	forced  bool
}

func sightOf(a Admitted, b *bootMark, now time.Time) sighting {
	s := sighting{b: b, seq: a.Seq, ingest: now.UnixMilli()}
	e := a.Record.Event
	if e == nil {
		return s
	}
	if v, ok := e.Attrs["ingest_ts"].(int64); ok {
		s.ingest = v
	}
	s.clamped, _ = e.Attrs["timestamp_clamped"].(bool)
	prod, ok := e.Attrs["producer_ts"].(int64)
	if !ok && !s.clamped {
		prod, ok = e.Timestamp.UnixMilli(), true
	}
	if ok {
		s.skew, s.hasSkew = max(s.ingest-prod, prod-s.ingest), true
	}
	if a.Role != RoleBait {
		return s
	}
	switch {
	case e.Stream == telemetry.StreamHeartbeat && e.Action == "bait_heartbeat":
	case e.Stream == telemetry.StreamRuntime && e.Action == "stopped":
		s.stopped = true
		s.forced, _ = e.Attrs["forced"].(bool)
	default:
		return s
	}
	// A claim, not evidence: only a non-negative number counts.
	if v, ok := e.Attrs["dropped_total"].(float64); ok && v >= 0 {
		s.claim, s.dropped = true, uint64(min(v, maxClaim))
	}
	return s
}

// land credits a batch to its boots after the durable append returned.
// seqs[i] is 0 for an item the queue refused. The caller holds rs.mu.
func (rs *roleState) land(sights []sighting, seqs []uint64, now time.Time, idle time.Duration) {
	var landed []*bootMark
	for i, s := range sights {
		a := &s.b.acct
		a.admitted++
		if i >= len(seqs) || seqs[i] == 0 {
			a.refused++
		}
		if a.first == 0 || s.seq < a.first {
			a.first = s.seq
		}
		a.last = max(a.last, s.seq)
		if s.stopped && a.final == 0 {
			a.final, a.forced = s.seq, s.forced
		}
		if s.claim && s.seq >= a.droppedAt {
			a.dropped, a.droppedAt = s.dropped, s.seq
		}
		if s.hasSkew {
			a.maxSkew = max(a.maxSkew, s.skew)
		}
		if s.clamped {
			a.clamped++
		}
		a.lastIngest = max(a.lastIngest, s.ingest)
		if !slices.Contains(landed, s.b) {
			landed = append(landed, s.b)
		}
	}
	// Another boot of the role ended every boot that was still open, unless
	// that one was already silent.
	for _, b := range landed {
		for _, o := range rs.boots {
			if o != b && !o.acct.arrived.IsZero() && now.Sub(o.acct.arrived) < idle {
				o.acct.superseded = true
			}
		}
	}
}

// failBatch marks every boot with a record in a batch whose append failed.
func (rs *roleState) failBatch(sights []sighting) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, s := range sights {
		s.b.acct.appendErr = true
	}
}

// evict keeps a row for a boot that leaves the table before its final row was
// reported for retainIntervals calls. A boot that was never reported with a
// final value reports as evicted; one that was keeps its verdict and is
// reported until the count is complete. The caller holds rs.mu.
func (rs *roleState) evict(b *bootMark) {
	if b.acct.shown >= retainIntervals {
		return
	}
	rs.waiting = slices.DeleteFunc(rs.waiting, func(w *bootMark) bool { return w.acct.shown >= retainIntervals })
	if len(rs.waiting) >= maxWaiting {
		rs.unreported++
		return
	}
	b.acct.evicted = b.acct.shown == 0
	rs.waiting = append(rs.waiting, b)
}

type verdict struct {
	state, loss, reason string
	lost                int64
}

// missing is last-first+1-admitted. neg is set when more records landed than
// the seq range holds, which no honest producer can cause.
func (a *bootAcct) missing() (n uint64, neg bool) {
	if a.last == 0 {
		return 0, false
	}
	span := a.last - a.first + 1
	if a.admitted > span {
		return 0, true
	}
	return span - a.admitted, false
}

func (a *bootAcct) judge(now time.Time, idle time.Duration) verdict {
	v := verdict{state: stateOpen, loss: lossUnknown}
	switch {
	case a.final != 0 && !a.forced && a.last == a.final:
		v.state = stateCleanEnd
	case a.final != 0, a.superseded:
		v.state = stateUncleanEnd
	case !a.arrived.IsZero() && now.Sub(a.arrived) >= idle:
		v.state = stateSilent
	}
	switch {
	case a.appendErr:
		v.reason = "append_error"
	case a.evicted:
		v.reason = "evicted"
	case v.state == stateOpen:
		v.loss, v.reason = lossPending, "none"
	case v.state == stateSilent:
		v.reason = "silent"
	case a.final == 0:
		v.reason = "unclean_end"
	case a.forced:
		v.reason = "forced_stop"
	case a.last > a.final:
		v.reason = "post_stop"
	case a.first != 1:
		v.reason = "prefix_unseen"
	default:
		missing, neg := a.missing()
		switch {
		case neg:
			v.reason = "counter_mismatch"
		case missing == 0 && a.refused == 0 && a.dropped == 0:
			v.loss, v.reason = lossNoneKnown, "none"
		case missing == a.rejected+a.dropped:
			v.loss, v.reason, v.lost = lossKnown, "none", num(missing+a.refused)
		default:
			v.reason = "counter_mismatch"
		}
	}
	return v
}

func num(u uint64) int64 { return int64(min(u, math.MaxInt64)) }

type accountingRow struct {
	rank int // 0 final unknown, 1 other final, 2 open
	ev   telemetry.Event
}

// Accounting returns the rows of one reporting interval: an ingest_stats event
// for each role and a producer_boot event for each tracked or waiting boot,
// capped at the report limit. Each call counts as one interval: a boot with a
// final value is returned in retainIntervals calls and then no longer. It
// reads memory only and is safe to call while connections are served.
func (in *Ingest) Accounting(now time.Time, shipperBoot string) []telemetry.Event {
	var stats []telemetry.Event
	var rows []accountingRow
	for _, role := range Roles {
		rs := in.roles[role]
		if rs == nil {
			continue
		}
		rs.mu.Lock()
		stats = append(stats, in.statsEvent(rs, now, shipperBoot))
		var boots []*bootMark
		for _, b := range rs.boots {
			boots = append(boots, b)
		}
		boots = append(boots, rs.waiting...)
		slices.SortFunc(boots, func(a, b *bootMark) int { return cmp.Compare(a.acct.born, b.acct.born) })
		for _, b := range boots {
			v := b.acct.judge(now, in.cfg.IdleTimeout)
			a := &b.acct
			if v.loss == lossPending {
				a.shown = 0
			} else {
				if got := [3]string{v.state, v.loss, v.reason}; got != a.reported {
					a.reported, a.shown = got, 0
				}
				if a.shown >= retainIntervals {
					continue
				}
				a.shown++
			}
			rank := 2
			switch {
			case v.loss == lossUnknown:
				rank = 0
			case v.loss != lossPending:
				rank = 1
			}
			rows = append(rows, accountingRow{rank, bootEvent(now, shipperBoot, role, &b.acct, v)})
		}
		rs.waiting = slices.DeleteFunc(rs.waiting, func(w *bootMark) bool { return w.acct.shown >= retainIntervals })
		rs.mu.Unlock()
	}

	slices.SortStableFunc(rows, func(a, b accountingRow) int { return cmp.Compare(a.rank, b.rank) })
	room := max(in.cfg.maxRows-len(stats), 0)
	omitted := max(len(rows)-room, 0)
	out := make([]telemetry.Event, 0, len(stats)+len(rows)-omitted)
	for _, e := range stats {
		e.Attrs["rows_omitted"] = int64(omitted)
		out = append(out, e)
	}
	for _, r := range rows[:len(rows)-omitted] {
		out = append(out, r.ev)
	}
	return out
}

// statsEvent builds the ingest_stats event of a role. The caller holds rs.mu.
func (in *Ingest) statsEvent(rs *roleState, now time.Time, shipperBoot string) telemetry.Event {
	s := &rs.stats
	rejected := uint64(0)
	attrs := map[string]any{
		"source":           accountingSource,
		"shipper_boot":     shipperBoot,
		"role":             rs.ep.Role.String(),
		"lines":            num(s.Lines),
		"oversize":         num(s.Oversize),
		"duplicates":       num(s.Duplicates),
		"gaps":             num(s.Gaps),
		"queued":           num(s.Queued),
		"queue_full":       num(s.QueueFull),
		"boots_unreported": num(rs.unreported),
	}
	for reason, n := range s.Rejected {
		rejected += n
		if n > 0 {
			attrs["rejected_"+reason] = num(n)
		}
	}
	attrs["rejected_total"] = num(rejected)
	return telemetry.Event{Timestamp: now, Stream: telemetry.StreamHeartbeat, Action: "ingest_stats", Attrs: attrs}
}

func bootEvent(now time.Time, shipperBoot string, role Role, a *bootAcct, v verdict) telemetry.Event {
	missing, _ := a.missing()
	attrs := map[string]any{
		"source":           accountingSource,
		"shipper_boot":     shipperBoot,
		"role":             role.String(),
		"boot":             a.id,
		"first_seq":        num(a.first),
		"last_seq":         num(a.last),
		"admitted":         num(a.admitted),
		"missing":          num(missing),
		"rejected":         num(a.rejected),
		"queue_refused":    num(a.refused),
		"duplicates":       num(a.duplicates),
		"reported_dropped": num(a.dropped),
		"reported_at_seq":  num(a.droppedAt),
		"max_skew_ms":      a.maxSkew,
		"clamped":          num(a.clamped),
		"last_ingest_ts":   a.lastIngest,
		"state":            v.state,
		"loss":             v.loss,
		"loss_scope":       lossScope,
		"loss_reason":      v.reason,
	}
	if a.final != 0 {
		attrs["final_seq"] = num(a.final)
	}
	if v.loss == lossKnown {
		attrs["lost"] = v.lost
	}
	return telemetry.Event{Timestamp: now, Stream: telemetry.StreamHeartbeat, Action: "producer_boot", Attrs: attrs}
}
