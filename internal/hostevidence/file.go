package hostevidence

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type Deliver func(context.Context, string, []byte) error

type FileReader struct {
	Path    string
	State   *State
	Deliver Deliver
	file    *os.File
}

func fileID(info os.FileInfo) string {
	st := info.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino)
}

func openSource(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("host evidence: source must be a regular file")
	}
	return f, nil
}

func (r *FileReader) Close() {
	if r.file != nil {
		r.file.Close()
		r.file = nil
	}
}

func (r *FileReader) open() error {
	pos := r.State.Position
	f, err := openSource(r.Path)
	if err != nil {
		return err
	}
	info, _ := f.Stat()
	if pos.FileID != "" && fileID(info) != pos.FileID {
		f.Close()
		f = nil
		// Rotation recovery searches only this source's directory and prefix.
		d, err := os.Open(filepath.Dir(r.Path))
		if err != nil {
			return err
		}
		entries, err := d.ReadDir(1025)
		d.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if len(entries) > 1024 {
			return errors.New("host evidence: rotation directory exceeds bound")
		}
		for _, e := range entries {
			match, _ := filepath.Match(filepath.Base(r.Path)+".*", e.Name())
			if !match || !e.Type().IsRegular() {
				continue
			}
			candidate, err := openSource(filepath.Join(filepath.Dir(r.Path), e.Name()))
			if err != nil {
				continue
			}
			info, _ := candidate.Stat()
			if fileID(info) == pos.FileID {
				f = candidate
				break
			}
			candidate.Close()
		}
		if f == nil {
			return errors.New("host evidence: source gap: saved inode missing; cursor retained")
		}
	}
	r.file = f
	return nil
}

// Step processes at most one complete line. Partial lines do not advance the
// cursor. A removed inode or copy-truncate is an explicit failure, not a seek
// to the end that conceals the missing interval.
func (r *FileReader) Step(ctx context.Context) (bool, error) {
	if r.file == nil {
		if err := r.open(); err != nil {
			return false, err
		}
	}
	pos := r.State.Position
	info, err := r.file.Stat()
	if err != nil {
		return false, err
	}
	id := fileID(info)
	offset := pos.Offset
	if pos.FileID != id {
		offset = 0
	}
	if info.Size() < offset {
		return false, errors.New("host evidence: source gap: file truncated; cursor retained")
	}
	if pos.FileID == id && pos.LastHash != "" {
		n := pos.Offset - pos.LastStart
		if n < 1 || n > MaxSourceRecord {
			return false, errors.New("host evidence: invalid anchor")
		}
		prior := make([]byte, n)
		if _, err := r.file.ReadAt(prior, pos.LastStart); err != nil {
			return false, err
		}
		if fmt.Sprintf("%x", sha256.Sum256(prior)) != pos.LastHash {
			return false, errors.New("host evidence: source gap: saved bytes changed; cursor retained")
		}
	}
	if _, err := r.file.Seek(offset, io.SeekStart); err != nil {
		return false, err
	}
	br := bufio.NewReader(io.LimitReader(r.file, MaxSourceRecord+1))
	line, err := br.ReadBytes('\n')
	if len(line) > MaxSourceRecord {
		return false, errors.New("host evidence: oversized source line; cursor retained")
	}
	if errors.Is(err, io.EOF) {
		current, serr := os.Lstat(r.Path)
		if serr != nil {
			return false, serr
		}
		if !current.Mode().IsRegular() {
			return false, errors.New("host evidence: source changed type")
		}
		if fileID(current) != id {
			if len(line) > 0 {
				return false, errors.New("host evidence: incomplete line at rotation; cursor retained")
			}
			// The old inode has been drained. Keep it in source rotation until
			// the next line's receipt and cursor commit complete.
			r.Close()
			r.file, err = openSource(r.Path)
			return false, err
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !bytes.HasSuffix(line, []byte{'\n'}) {
		return false, errors.New("host evidence: incomplete source line")
	}
	key := fmt.Sprintf("%s:%s:%d", r.Path, id, offset)
	if err := r.Deliver(ctx, key, line); err != nil {
		return false, err
	}
	pos.FileID = id
	pos.LastStart = offset
	pos.Offset = offset + int64(len(line))
	pos.LastHash = fmt.Sprintf("%x", sha256.Sum256(line))
	if err := r.State.Save(pos); err != nil {
		return false, err
	}
	return true, nil
}

func RunFile(ctx context.Context, state *State, path string, sender Sender) error {
	r := FileReader{Path: path, State: state, Deliver: sender.Send}
	defer r.Close()
	lastBeat := time.Time{}
	for ctx.Err() == nil {
		if time.Since(lastBeat) >= 30*time.Second {
			if err := sender.Heartbeat(ctx); err != nil {
				return err
			}
			lastBeat = time.Now()
		}
		progress, err := r.Step(ctx)
		if err != nil {
			return err
		}
		if progress {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return ctx.Err()
}
