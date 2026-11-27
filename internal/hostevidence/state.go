// Package hostevidence reads host observations without executing their content.
package hostevidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

type Position struct {
	Version   int    `json:"version"`
	Source    string `json:"source"`
	FileID    string `json:"file_id,omitempty"`
	Offset    int64  `json:"offset,omitempty"`
	LastStart int64  `json:"last_start,omitempty"`
	LastHash  string `json:"last_hash,omitempty"`
	Cursor    string `json:"cursor,omitempty"`
}

type State struct {
	root     *os.Root
	lock     *os.File
	Position Position
}

func OpenState(dir, source string) (*State, error) {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !ok || int(st.Uid) != os.Geteuid() {
		return nil, errors.New("host evidence: state directory must be private and owned by reader")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	f, err := root.OpenFile("lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		root.Close()
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		root.Close()
		return nil, errors.New("host evidence: state already in use")
	}
	s := &State{root: root, lock: f, Position: Position{Version: 1, Source: source}}
	f, err = root.OpenFile("cursor.json", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 16<<10 {
		s.Close()
		return nil, errors.New("host evidence: cursor must be a bounded private regular file")
	}
	dec := json.NewDecoder(io.LimitReader(f, (16<<10)+1))
	err = dec.Decode(&s.Position)
	if err == nil {
		var extra any
		if dec.Decode(&extra) != io.EOF {
			err = errors.New("trailing cursor data")
		}
	}
	if err != nil || s.Position.Version != 1 || s.Position.Source != source || s.Position.Offset < 0 || s.Position.LastStart < 0 || s.Position.LastStart > s.Position.Offset {
		s.Close()
		return nil, fmt.Errorf("host evidence: invalid source cursor: %v", err)
	}
	return s, nil
}

func (s *State) Close() error { return errors.Join(s.lock.Close(), s.root.Close()) }

func (s *State) Save(p Position) error {
	if p.Version != 1 || p.Source != s.Position.Source {
		return errors.New("host evidence: cursor source mismatch")
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if len(b) > 16<<10 {
		return errors.New("host evidence: cursor exceeds bound")
	}
	// The state lock makes the fixed temporary name private to this writer.
	if _, err := s.root.Lstat("cursor.pending"); err == nil {
		if err := s.root.Remove("cursor.pending"); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := s.root.OpenFile("cursor.pending", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return err
	}
	if err := s.root.Rename("cursor.pending", "cursor.json"); err != nil {
		return err
	}
	d, err := s.root.Open(".")
	if err != nil {
		return err
	}
	err = d.Sync()
	d.Close()
	if err != nil {
		return err
	}
	s.Position = p
	return nil
}
