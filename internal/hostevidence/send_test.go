package hostevidence

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"attackbox/internal/shipper"
	"attackbox/internal/telemetry"
)

func TestSenderRetainsBinarySegmentsAndStableReplayIDs(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "abx-receipt-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var received []telemetry.Record
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var r telemetry.Record
			if err := json.NewDecoder(bufio.NewReader(c)).Decode(&r); err == nil {
				mu.Lock()
				received = append(received, r)
				mu.Unlock()
				json.NewEncoder(c).Encode(shipper.Receipt{ID: r.ID, QueueSeq: 1})
			}
			c.Close()
		}
	}()
	defer func() { ln.Close(); <-done }()
	data := bytes.Repeat([]byte{0xff, 0, 10, 13, 'x'}, sourceSegment)
	s := Sender{Socket: socket, Role: "runtime"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		if err := s.Send(ctx, "inode:10", data); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	records := append([]telemetry.Record(nil), received...)
	mu.Unlock()
	segments := (len(data) + sourceSegment - 1) / sourceSegment
	if len(records) != segments*2 {
		t.Fatal(len(records))
	}
	var recovered []byte
	for i := 0; i < segments; i++ {
		if records[i].ID != records[i+segments].ID {
			t.Fatal("unstable replay ID")
		}
		encoded, _ := json.Marshal(records[i])
		admitted, err := shipper.Admit(shipper.RoleRuntime, encoded, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		var record telemetry.Record
		json.Unmarshal(admitted.Data, &record)
		part, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(record.Event.Body, "base64:"))
		if err != nil {
			t.Fatal(err)
		}
		recovered = append(recovered, part...)
	}
	if !bytes.Equal(data, recovered) {
		t.Fatal("source bytes changed")
	}
}

func TestSenderRequiresMatchingDurableReceipt(t *testing.T) {
	for _, mode := range []string{"missing", "wrong", "full"} {
		t.Run(mode, func(t *testing.T) {
			dir, err := os.MkdirTemp("/tmp", "abx-r-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			socket := filepath.Join(dir, "s")
			ln, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				var r telemetry.Record
				json.NewDecoder(c).Decode(&r)
				switch mode {
				case "wrong":
					json.NewEncoder(c).Encode(shipper.Receipt{ID: "different", QueueSeq: 1})
				case "full":
					json.NewEncoder(c).Encode(shipper.Receipt{ID: r.ID, Reason: "queue_full"})
				}
			}()
			if err := (Sender{Socket: socket, Role: "egress"}).Send(context.Background(), "cursor", []byte("line")); err == nil {
				t.Fatal("accepted invalid receipt")
			}
			<-done
		})
	}
}

func TestJournalCursorAndCommandAreDataOnly(t *testing.T) {
	cursor := "s=abc;i=2;b=def"
	got, err := journalCursor([]byte(`{"__CURSOR":"` + cursor + `","MESSAGE":"synthetic"}`))
	if err != nil || got != cursor {
		t.Fatal(got, err)
	}
	if _, err := journalCursor([]byte(`{"MESSAGE":"missing"}`)); err == nil {
		t.Fatal("missing cursor")
	}
	args := JournalArgs(cursor)
	want := []string{"--output=json", "--all", "--no-pager", "--follow", "--no-tail", "_TRANSPORT=kernel", "--grep=OUTPUT-DROP|CONTAINER-EGRESS-BLOCK|METADATA-BLOCK", "--after-cursor=" + cursor}
	if !reflect.DeepEqual(args, want) {
		t.Fatal(args)
	}
}
