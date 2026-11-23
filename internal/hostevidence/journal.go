package hostevidence

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

type journalRecord struct {
	Cursor string `json:"__CURSOR"`
}

func journalCursor(line []byte) (string, error) {
	var r journalRecord
	if err := json.Unmarshal(line, &r); err != nil {
		return "", err
	}
	if len(r.Cursor) == 0 || len(r.Cursor) > 4096 {
		return "", errors.New("host evidence: missing or oversized journal cursor")
	}
	return r.Cursor, nil
}

func JournalArgs(cursor string) []string {
	args := []string{"--output=json", "--all", "--no-pager", "--follow", "--no-tail", "_TRANSPORT=kernel", "--grep=OUTPUT-DROP|CONTAINER-EGRESS-BLOCK|METADATA-BLOCK"}
	if cursor != "" {
		args = append(args, "--after-cursor="+cursor)
	}
	return args
}

// Check the saved cursor explicitly: seeking to a missing cursor must never
// silently start at a different retained journal position.
func verifyJournalCursor(ctx context.Context, cursor string) error {
	if cursor == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "journalctl", "--output=json", "--all", "--no-pager", "--lines=1", "--cursor="+cursor)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	scan := bufio.NewScanner(out)
	scan.Buffer(make([]byte, 4096), MaxSourceRecord+1)
	var got string
	if scan.Scan() {
		got, err = journalCursor(scan.Bytes())
	}
	if err == nil {
		err = scan.Err()
	}
	cancel()
	_ = cmd.Wait()
	if err != nil {
		return err
	}
	if got != cursor {
		return errors.New("host evidence: source gap: journal cursor no longer retained")
	}
	return nil
}

func RunJournal(ctx context.Context, state *State, sender Sender) error {
	if err := verifyJournalCursor(ctx, state.Position.Cursor); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, "journalctl", JournalArgs(state.Position.Cursor)...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() { cancel(); _ = cmd.Wait() }()
	type result struct {
		line []byte
		err  error
	}
	lines := make(chan result, 1)
	go func() {
		defer close(lines)
		scan := bufio.NewScanner(out)
		scan.Buffer(make([]byte, 4096), MaxSourceRecord+1)
		for scan.Scan() {
			line := append([]byte(nil), scan.Bytes()...)
			select {
			case lines <- result{line: line}:
			case <-ctx.Done():
				return
			}
		}
		select {
		case lines <- result{err: scan.Err()}:
		case <-ctx.Done():
		}
	}()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	if err := sender.Heartbeat(ctx); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := sender.Heartbeat(ctx); err != nil {
				return err
			}
		case r, ok := <-lines:
			if !ok || r.line == nil {
				return fmt.Errorf("host evidence: journal reader stopped; cursor retained: %v", r.err)
			}
			cursor, err := journalCursor(r.line)
			if err != nil {
				return err
			}
			if err := sender.Send(ctx, cursor, r.line); err != nil {
				return err
			}
			pos := state.Position
			pos.Cursor = cursor
			if err := state.Save(pos); err != nil {
				return err
			}
		}
	}
}
