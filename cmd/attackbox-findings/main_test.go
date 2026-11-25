package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	s := sample{From: time.Date(2026, 11, 24, 3, 0, 0, 0, time.UTC), Until: time.Date(2026, 11, 24, 3, 5, 0, 0, time.UTC), Counts: map[string]int64{"http_total": 3, "route:/v1/models": 3, "raw-secret-password": 42, "failed_unit_samples:private-name.service": 1}, Metrics: map[string]float64{"load_1m": 0.5, "raw-secret-metric": 1, `attackbox_component_running{component="private-secret-name"}`: 1, `attackbox_component_running{component="attackbox-bait"}`: 1}, Warnings: []string{"falco_1000_row_tail_bound", "<script>private-secret</script>"}}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n'), []byte("State: running. Start: 2026-11-24T03:00:00Z. Deadline: 2026-11-24T10:58:16Z. Samples: 1.\n")
}

func TestRenderPrivacyAndCoherence(t *testing.T) {
	data, report := fixture(t)
	b, done, err := render(data, report)
	if err != nil || done {
		t.Fatalf("%v %v", done, err)
	}
	for _, forbidden := range []string{"secret", "private-name", "<script>"} {
		if bytes.Contains(b, []byte(forbidden)) {
			t.Fatalf("leaked %q", forbidden)
		}
	}
	for _, wanted := range []string{"`http_total`: 3", "`failed_service_sample_occurrences`: 1", "`unrecognized_warning`: 1", "attackbox-bait"} {
		if !bytes.Contains(b, []byte(wanted)) {
			t.Fatalf("missing %q", wanted)
		}
	}
	if _, _, err = render(data[:len(data)-1], report); err == nil {
		t.Fatal("partial write accepted")
	}
	if _, _, err = render(data, bytes.ReplaceAll(report, []byte("Samples: 1"), []byte("Samples: 2"))); err == nil {
		t.Fatal("torn report accepted")
	}
	_, done, err = render(data, bytes.ReplaceAll(report, []byte("running"), []byte("complete")))
	if err != nil || !done {
		t.Fatal("final state missing")
	}
}

func rawGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestPublishIsolationRetryAndNoop(t *testing.T) {
	root := t.TempDir()
	checkout := filepath.Join(root, "checkout")
	remote := filepath.Join(root, "remote.git")
	if err := os.Mkdir(checkout, 0700); err != nil {
		t.Fatal(err)
	}
	rawGit(t, checkout, "init", "-b", branch)
	rawGit(t, checkout, "config", "user.name", "Test")
	rawGit(t, checkout, "config", "user.email", "test@example.invalid")
	rawGit(t, checkout, "config", "commit.gpgsign", "false")
	rawGit(t, checkout, "remote", "add", "origin", remote)
	data, report := fixture(t)
	content, _, err := render(data, report)
	if err != nil {
		t.Fatal(err)
	}
	// First push fails after a local commit. The unchanged retry must push it.
	if err = publish(checkout, content); err == nil {
		t.Fatal("missing remote accepted")
	}
	first := rawGit(t, checkout, "rev-parse", "HEAD")
	rawGit(t, root, "init", "--bare", remote)
	if err = publish(checkout, content); err != nil {
		t.Fatal(err)
	}
	if first != rawGit(t, checkout, "rev-parse", "HEAD") {
		t.Fatal("duplicate commit")
	}
	if first != rawGit(t, root, "--git-dir="+remote, "rev-parse", "refs/heads/"+branch) {
		t.Fatal("retry did not push")
	}
	if got := rawGit(t, checkout, "ls-tree", "-r", "--name-only", "HEAD"); got != destination {
		t.Fatalf("unexpected paths %s", got)
	}
	if got := rawGit(t, root, "--git-dir="+remote, "show", branch+":"+destination); got != strings.TrimSpace(string(content)) {
		t.Fatal("remote content mismatch")
	}
	if err = publish(checkout, append(content, []byte("\nNew observation.\n")...)); err != nil {
		t.Fatal(err)
	}
	if rawGit(t, checkout, "rev-list", "--count", "HEAD") != "2" {
		t.Fatal("new observation not committed")
	}
	if err = os.WriteFile(filepath.Join(checkout, "secret.txt"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	rawGit(t, checkout, "add", "secret.txt")
	if err = publish(checkout, content); err == nil {
		t.Fatal("unrelated staged file accepted")
	}
	// Deleting a secret later does not make the ancestry safe to publish.
	rawGit(t, checkout, "commit", "-m", "private fixture")
	rawGit(t, checkout, "rm", "secret.txt")
	rawGit(t, checkout, "commit", "-m", "remove fixture")
	if err = publish(checkout, content); err == nil {
		t.Fatal("private history accepted")
	}
}

func TestGitEnvironmentIsolationAndDeadline(t *testing.T) {
	dir := t.TempDir()
	rawGit(t, dir, "init")
	t.Setenv("GIT_DIR", "/does/not/exist")
	t.Setenv("GIT_WORK_TREE", "/does/not/exist")
	t.Setenv("GIT_INDEX_FILE", "/does/not/exist")
	if _, err := git(dir, "status", "--porcelain"); err != nil {
		t.Fatal(err)
	}
	operationDeadline = time.Now().Add(-time.Second)
	t.Cleanup(func() { operationDeadline = time.Time{} })
	if _, err := git(dir, "status", "--porcelain"); err == nil {
		t.Fatal("expired deadline accepted")
	}
}

func TestSecurityDebriefUsesEvidenceAndExplainsGaps(t *testing.T) {
	data, report := fixture(t)
	var s sample
	if err := json.Unmarshal(bytes.TrimSpace(data), &s); err != nil {
		t.Fatal(err)
	}
	s.Counts["http_private_source"] = 3
	s.Counts["http_status:200"] = 3
	s.Counts["kernel:OUTPUT-DROP:"] = 40
	encode := func() []byte {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return append(b, '\n')
	}
	b, _, err := render(encode(), report)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## Assessment", "consistent with routine service polling", "3 successful responses (2xx)", "40 host-output deny records", "not unique sessions or attackers", "## Recent observation timeline", "<details>"} {
		if !bytes.Contains(b, []byte(want)) {
			t.Fatalf("missing debrief context %q", want)
		}
	}
	s.Counts = map[string]int64{"http_total": 3, "http_public_source": 3, "route:/v1/chat/completions": 3, "http_status:500": 3, "falco_events": 2}
	b, _, err = render(encode(), report)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"External-source activity needs review", "3 server-error responses (5xx)", "does not identify an attacker", "2 timestamped Falco events"} {
		if !bytes.Contains(b, []byte(want)) {
			t.Fatalf("missing external context %q", want)
		}
	}
	if bytes.Contains(b, []byte("consistent with routine service polling")) {
		t.Fatal("external activity mislabeled as polling")
	}
	s.Counts = map[string]int64{}
	s.Metrics = map[string]float64{}
	s.Warnings = []string{"ssh_collect_failed"}
	b, _, err = render(encode(), report)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"no traffic or incomplete collection", "Collection failed in 1 snapshots", "running-state values were available for 0", "SSH collection failed; partial evidence"} {
		if !bytes.Contains(b, []byte(want)) {
			t.Fatalf("missing failure context %q", want)
		}
	}
}
