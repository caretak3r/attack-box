package shipper

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestHostReceiptDurableReplayAndFull(t *testing.T) {
	cfg := testConfig(queueDir(t))
	cfg.MaxBytes = 1200
	q, _ := mustOpen(t, cfg)
	ep := Endpoint{Receipts: true, Role: RoleRuntime, UIDs: []uint32{0}, Path: "/tmp/receipt.sock", Mode: 0600, MaxConns: 1, Rate: 1 << 20, Burst: 4 << 20}
	ic := IngestConfig{Queue: q, Endpoints: []Endpoint{ep}}
	if err := ic.setDefaults(); err != nil {
		t.Fatal(err)
	}
	in := &Ingest{cfg: ic, ctx: context.Background(), done: make(chan struct{})}
	rs := &roleState{ep: ep, bucket: newBucket(ep.Rate, ep.Burst, time.Now), stats: RoleStats{Rejected: map[string]uint64{}}}
	var receipts []Receipt
	for i := 0; i < 20; i++ {
		client, server := unixPair(t)
		done := make(chan struct{})
		go func() { in.serveReceipt(server, rs); server.Close(); close(done) }()
		client.SetDeadline(time.Now().Add(5 * time.Second))
		// A lost receipt must permit the same stable ID to be appended again.
		_, err := client.Write([]byte(`{"v":1,"id":"` + testBoot + `-1","event":{"stream":"runtime","action":"falco"}}` + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		var got Receipt
		if err := json.NewDecoder(client).Decode(&got); err != nil {
			t.Fatal(err)
		}
		<-done
		if got.ID != testBoot+"-1" {
			t.Fatalf("wrong receipt ID: %+v", got)
		}
		if got.Reason == "queue_full" {
			if got.QueueSeq != 0 || len(receipts) < 2 {
				t.Fatalf("bad full receipt: %+v, prior=%d", got, len(receipts))
			}
			break
		}
		if got.Reason != "" || got.QueueSeq == 0 {
			t.Fatalf("bad success receipt: %+v", got)
		}
		receipts = append(receipts, got)
	}
	if rs.stats.QueueFull != 1 {
		t.Fatal("did not exercise full queue")
	}
	q.Close()
	q, _ = mustOpen(t, cfg)
	entries, err := q.Read(100, 1<<20)
	if err != nil || len(entries) != len(receipts) {
		t.Fatalf("receipt/recovery mismatch: %d/%d: %v", len(entries), len(receipts), err)
	}
	for i, e := range entries {
		if e.Seq != receipts[i].QueueSeq || e.Role != RoleRuntime {
			t.Fatalf("receipt does not match durable record: %+v", e)
		}
	}
}

func TestReceiptsCannotBeEnabledForBaitOrNonroot(t *testing.T) {
	q, _ := mustOpen(t, testConfig(queueDir(t)))
	for _, ep := range []Endpoint{
		{Receipts: true, Role: RoleBait, UIDs: []uint32{0}},
		{Receipts: true, Role: RoleRuntime, UIDs: []uint32{1234}},
		{Receipts: true, Role: RoleEgress, UIDs: []uint32{0, 1234}},
	} {
		ep.Path, ep.Mode, ep.MaxConns, ep.Rate, ep.Burst = "/tmp/receipt.sock", 0600, 1, 1<<20, 4<<20
		cfg := IngestConfig{Queue: q, Endpoints: []Endpoint{ep}}
		if err := cfg.setDefaults(); err == nil {
			t.Fatalf("accepted unsafe receipt endpoint: %+v", ep)
		}
	}
}
