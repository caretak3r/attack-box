package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const findingsOrigin = "git@github.com:caretak3r/attack-box.git"

// Use existing main ancestry. Only this day's report can enter a new commit.
// Fetch, rebase and push use ordinary Git policy, hooks and signing. No force.
func publishMain(dir, target, expectedOrigin string, content []byte) error {
	name, err := git(dir, "symbolic-ref", "--short", "HEAD")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(name)), "findings/") {
		return errors.New("publisher requires an isolated findings branch")
	}
	origin, err := git(dir, "remote", "get-url", "origin")
	if err != nil || strings.TrimSpace(string(origin)) != expectedOrigin {
		return errors.New("unexpected findings remote")
	}
	status, err := git(dir, "status", "--porcelain", "--untracked-files=no")
	if err != nil || len(bytes.TrimSpace(status)) != 0 {
		return errors.New("findings checkout has tracked changes")
	}
	if _, err = git(dir, "fetch", "origin", "refs/heads/main:refs/remotes/origin/main"); err != nil {
		return err
	}
	// A retry may have an unpublished report commit. Never rebase or publish
	// unrelated local commits, including changes later deleted from the tree.
	paths, err := git(dir, "log", "--format=", "--name-only", "--no-renames", "origin/main..HEAD")
	if err != nil {
		return err
	}
	for _, p := range strings.Fields(string(paths)) {
		if p != target {
			return errors.New("unpublished non-findings commit")
		}
	}
	if _, err = git(dir, "rebase", "origin/main"); err != nil {
		_, _ = git(dir, "rebase", "--abort")
		return err
	}
	// Do not follow a symlink when writing the report or its parent directories.
	parent := dir
	for _, part := range strings.Split(target, "/") {
		parent = filepath.Join(parent, part)
		info, e := os.Lstat(parent)
		if e == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink in findings path")
		}
		if e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	path := filepath.Join(dir, target)
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err = os.WriteFile(path, content, 0600); err != nil {
		return err
	}
	if _, err = git(dir, "add", "--", target); err != nil {
		return err
	}
	staged, err := git(dir, "diff", "--cached", "--name-only")
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(staged)) != 0 {
		if strings.TrimSpace(string(staged)) != target {
			return errors.New("unexpected staged findings path")
		}
		if _, err = git(dir, "commit", "-m", "findings: update daily watch "+time.Now().UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	_, err = git(dir, "push", "origin", "HEAD:refs/heads/main")
	return err
}

func runMain(source, checkout, deadlineText, date string, once bool) error {
	day, err := time.Parse("2006-01-02", date)
	deadline, e := time.Parse(time.RFC3339, deadlineText)
	if err != nil || e != nil || !filepath.IsAbs(source) || !filepath.IsAbs(checkout) || time.Until(deadline) <= 0 || time.Until(deadline) > 12*time.Hour {
		return errors.New("invalid main findings paths, date or deadline")
	}
	operationDeadline = deadline
	lockPath, err := git(checkout, "rev-parse", "--git-path", "findings-publisher.lock")
	if err != nil {
		return err
	}
	path := strings.TrimSpace(string(lockPath))
	if !filepath.IsAbs(path) {
		path = filepath.Join(checkout, path)
	}
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("publisher already running")
	}
	for time.Now().Before(deadline) {
		data, err := readBounded(filepath.Join(source, "samples.jsonl"))
		var host, report, public []byte
		var done bool
		if err == nil {
			report, err = readBounded(filepath.Join(source, "REPORT.md"))
		}
		if err == nil {
			host, done, err = render(data, report)
		}
		if err == nil && done {
			// Let the lagged query pass the final host observation before exit.
			lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
			var last sample
			err = json.Unmarshal(lines[len(lines)-1], &last)
			done = !time.Now().Before(last.Until.Add(2 * time.Minute))
		}
		if err == nil {
			public, err = publicReport(day, time.Now().UTC().Add(-time.Minute))
		}
		if err == nil {
			content := append(public, []byte("\n---\n\n<details>\n<summary>Host and private-proxy evidence</summary>\n\n")...)
			content = append(content, host...)
			content = append(content, []byte("\n</details>\n")...)
			err = publishMain(checkout, "findings/"+date+"/README.md", findingsOrigin, content)
		}
		if err != nil {
			// Errors are fixed strings. Never print HTTP or Git response bodies.
			fmt.Fprintln(os.Stderr, time.Now().UTC().Format(time.RFC3339), "publication failed:", err)
		} else {
			fmt.Println(time.Now().UTC().Format(time.RFC3339), "published daily findings to main")
		}
		if once || (err == nil && done) {
			return err
		}
		time.Sleep(min(5*time.Minute, time.Until(deadline)))
	}
	return errors.New("publisher deadline reached before final publication")
}
