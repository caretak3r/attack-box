// Package auditfilter compacts complete audit events without interpreting
// payloads.
package auditfilter

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const Policy = "audit-budget-v1"
const MaxBatch = 256 << 10

var prefix = regexp.MustCompile(`^type=([A-Z0-9_]+) msg=audit\(([0-9]+\.[0-9]+:[0-9]+)\): ?`)
var fieldKey = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

type Record struct {
	ID, Kind, Raw string
	Fields        map[string]string
	Valid         bool
}

// Parse rejects ambiguous fields. Original bytes are always retained on failure.
func Parse(line string) Record {
	r := Record{Raw: line}
	m := prefix.FindStringSubmatch(line)
	if m == nil {
		return r
	}
	r.Kind, r.ID = m[1], m[2]
	s := strings.SplitN(line[len(m[0]):], "\x1d", 2)[0]
	r.Fields = map[string]string{}
	for s = strings.TrimSpace(s); s != ""; s = strings.TrimSpace(s) {
		k, rest, ok := strings.Cut(s, "=")
		if !ok || !fieldKey.MatchString(k) || rest == "" {
			return r
		}
		if _, exists := r.Fields[k]; exists {
			return r
		}
		var v string
		if rest[0] == '"' {
			end := strings.IndexByte(rest[1:], '"')
			if end < 0 {
				return r
			}
			end++
			v, s = rest[1:end], rest[end+1:]
			if s != "" && s[0] != ' ' {
				return r
			}
		} else {
			v, s, _ = strings.Cut(rest, " ")
		}
		r.Fields[k] = v
	}
	r.Valid = true
	return r
}

type Entry struct {
	Message    string `json:"message"`
	Policy     string `json:"audit_policy"`
	EventID    string `json:"audit_event_id"`
	Boot       string `json:"audit_reader_boot_id"`
	SHA256     string `json:"body_sha256"`
	ChunkIndex int    `json:"chunk_index"`
	ChunkCount int    `json:"chunk_count"`
	Rows       int    `json:"audit_source_rows"`
	Reason     string `json:"audit_decision"`
}
type Stats struct{ InputRows, KeptRows, KeptEvents int }

// Batch is bounded by the caller. Split or malformed groups pass through in full.
// Suppression requires a complete group and independently verified live process identity.
func Batch(lines []string, boot string) ([]Entry, Stats) {
	groups := map[string][]Record{}
	var order []string
	for i, line := range lines {
		r := Parse(line)
		key := r.ID
		if key == "" {
			key = fmt.Sprintf("unparsed-%d", i)
		}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], r)
	}
	var out []Entry
	stats := Stats{InputRows: len(lines)}
	for _, key := range order {
		g := groups[key]
		reason := "retained"
		if !complete(g) {
			reason = "retained_incomplete_or_unknown"
		}
		var b strings.Builder
		for _, r := range g {
			b.WriteString(r.Raw)
			b.WriteByte('\n')
		}
		body := b.String()
		sum := sha256.Sum256([]byte(body))
		hash := hex.EncodeToString(sum[:])
		// Valid audit text is ASCII. Preserve arbitrary bytes with hex if necessary.
		if !utf8.ValidString(body) {
			body = hex.EncodeToString([]byte(body))
			reason = "retained_hex_invalid_utf8"
		}
		runes := []rune(body)
		count := (len(runes) + 3499) / 3500
		for i := 0; i < count; i++ {
			end := min((i+1)*3500, len(runes))
			out = append(out, Entry{string(runes[i*3500 : end]), Policy, g[0].ID, boot, hash, i, count, len(g), reason})
		}
		stats.KeptRows += len(g)
		stats.KeptEvents++
	}
	return out, stats
}
func complete(g []Record) bool {
	syscall, title, paths := 0, 0, 0
	expected := -1
	pathIDs := map[string]bool{}
	for _, r := range g {
		if !r.Valid {
			return false
		}
		switch r.Kind {
		case "SYSCALL":
			syscall++
			n, err := strconv.Atoi(r.Fields["items"])
			if err != nil || n < 0 || n > 128 {
				return false
			}
			expected = n
		case "PROCTITLE":
			title++
		case "PATH":
			paths++
			id := r.Fields["item"]
			n, err := strconv.Atoi(id)
			if err != nil || n < 0 || pathIDs[id] {
				return false
			}
			pathIDs[id] = true
		case "SOCKADDR", "CWD", "EXECVE", "EOE":
		default:
			return false
		}
	}
	return syscall == 1 && title == 1 && paths == expected
}
