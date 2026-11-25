package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMainPublicationPreservesSourceAndRemoteUpdates(t *testing.T) {
	root := t.TempDir()
	remote, checkout, other := filepath.Join(root, "remote.git"), filepath.Join(root, "publisher"), filepath.Join(root, "other")
	rawGit(t, root, "init", "--bare", "--initial-branch=main", remote)
	rawGit(t, root, "clone", remote, checkout)
	configure := func(dir string) {
		rawGit(t, dir, "config", "user.name", "Test")
		rawGit(t, dir, "config", "user.email", "test@example.invalid")
		rawGit(t, dir, "config", "commit.gpgsign", "false")
	}
	configure(checkout)
	if err := os.WriteFile(filepath.Join(checkout, "source.go"), []byte("package example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rawGit(t, checkout, "add", "source.go")
	rawGit(t, checkout, "commit", "-m", "source fixture")
	rawGit(t, checkout, "push", "origin", "main")
	rawGit(t, checkout, "switch", "-c", "findings/test")
	target := "findings/2026-11-25/README.md"
	if err := publishMain(checkout, target, remote, []byte("First observation.\n")); err != nil {
		t.Fatal(err)
	}
	first := rawGit(t, checkout, "rev-parse", "HEAD")
	if err := publishMain(checkout, target, remote, []byte("First observation.\n")); err != nil {
		t.Fatal(err)
	}
	if got := rawGit(t, checkout, "rev-parse", "HEAD"); got != first {
		t.Fatal("duplicate observation commit")
	}
	rawGit(t, root, "clone", remote, other)
	configure(other)
	if err := os.WriteFile(filepath.Join(other, "source.go"), []byte("package changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rawGit(t, other, "commit", "-am", "concurrent source edit")
	rawGit(t, other, "push", "origin", "main")
	if err := publishMain(checkout, target, remote, []byte("Second observation.\n")); err != nil {
		t.Fatal(err)
	}
	if got := rawGit(t, root, "--git-dir="+remote, "show", "main:source.go"); got != "package changed" {
		t.Fatal("source history lost")
	}
	if got := rawGit(t, checkout, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"); got != target {
		t.Fatal("unrelated path committed", got)
	}
	// An unpublished findings commit is rebased on a concurrent source update.
	if err := os.WriteFile(filepath.Join(checkout, target), []byte("Pending report.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rawGit(t, checkout, "commit", "-am", "pending findings")
	rawGit(t, other, "pull", "--ff-only", "origin", "main")
	if err := os.WriteFile(filepath.Join(other, "source.go"), []byte("package newer\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rawGit(t, other, "commit", "-am", "next source edit")
	rawGit(t, other, "push", "origin", "main")
	if err := publishMain(checkout, target, remote, []byte("Third observation.\n")); err != nil {
		t.Fatal(err)
	}
	if got := rawGit(t, root, "--git-dir="+remote, "show", "main:source.go"); got != "package newer" {
		t.Fatal("retry lost source")
	}
	// A normal policy hook must be honored, never bypassed by the publisher.
	hooks := filepath.Join(root, "hooks")
	if err := os.Mkdir(hooks, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooks, "pre-commit"), []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	rawGit(t, checkout, "config", "core.hooksPath", hooks)
	if err := publishMain(checkout, target, remote, []byte("Rejected observation.\n")); err == nil {
		t.Fatal("hook bypassed")
	}
	if got := rawGit(t, root, "--git-dir="+remote, "show", "main:"+target); got != "Third observation." {
		t.Fatal("rejected report pushed")
	}
	// Clear only the known test fixture staging before checking history policy.
	rawGit(t, checkout, "restore", "--staged", target)
	rawGit(t, checkout, "restore", target)
	rawGit(t, checkout, "config", "--unset", "core.hooksPath")
	if err := os.WriteFile(filepath.Join(checkout, "private.txt"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	rawGit(t, checkout, "add", "private.txt")
	if err := publishMain(checkout, target, remote, []byte("Rejected.\n")); err == nil {
		t.Fatal("unrelated staged file accepted")
	}
	rawGit(t, checkout, "commit", "-m", "unpublished private fixture")
	rawGit(t, checkout, "rm", "private.txt")
	rawGit(t, checkout, "commit", "-m", "delete private fixture")
	if err := publishMain(checkout, target, remote, []byte("Rejected.\n")); err == nil || !strings.Contains(err.Error(), "non-findings") {
		t.Fatal("private ancestry accepted", err)
	}
}
