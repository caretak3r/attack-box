package shipper

import (
	"bufio"
	"encoding/json"
	"net"
	"strconv"
	"time"
)

// Receipt confirms only a durable local append, never remote API acceptance.
// Host readers send one record per connection. Replays are deliberately kept:
// their stable record IDs allow dedup without trusting volatile boot marks.
type Receipt struct {
	ID       string `json:"id"`
	QueueSeq uint64 `json:"queue_seq"`
	Reason   string `json:"reason,omitempty"`
}

func (in *Ingest) serveReceipt(c *net.UnixConn, rs *roleState) {
	cn := &conn{in: in, rs: rs, c: c, br: bufio.NewReaderSize(c, readBuffer)}
	line, n, oversize, err := cn.readLine()
	if err != nil {
		return
	}
	if err := in.cfg.sleep(in.ctx, rs.bucket.take(int64(n)+1)); err != nil {
		return
	}
	rs.count(func(s *RoleStats) { s.Lines++ })
	response := Receipt{}
	if oversize {
		rs.count(func(s *RoleStats) { s.Oversize++ })
		response.Reason = "oversize"
	} else {
		a, err := Admit(rs.ep.Role, line, in.cfg.Now())
		if err != nil {
			response.Reason = RejectReason(err)
			rs.count(func(s *RoleStats) { s.Rejected[response.Reason]++ })
		} else {
			response.ID = a.Boot + "-" + strconv.FormatUint(a.Seq, 10)
			seqs, err := in.cfg.Queue.Append([]Item{{Role: a.Role, Data: a.Data}})
			if err != nil {
				in.setFatal(err)
				return
			}
			response.QueueSeq = seqs[0]
			if response.QueueSeq == 0 {
				response.Reason = "queue_full"
				rs.count(func(s *RoleStats) { s.QueueFull++ })
			} else {
				rs.count(func(s *RoleStats) { s.Queued++; s.LastRecord = in.cfg.Now() })
			}
		}
	}
	c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = json.NewEncoder(c).Encode(response)
}
