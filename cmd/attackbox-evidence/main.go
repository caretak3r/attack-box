// Command attackbox-evidence reconstructs one complete capture from a local
// New Relic NDJSON/JSON-array export. Hashes verify consistency, not provenance.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	maxInput  = 64 << 20
	maxBody   = 16 << 20
	maxRecord = 1 << 20
	maxParts  = 32768
)

type fields map[string]json.RawMessage
type metadata struct {
	kind, target, hash, reason      string
	segment, offset, size, segments int
	complete                        bool
}
type record struct {
	meta   metadata
	hash   string
	count  int
	chunks map[int]string
}
type segment struct {
	offset int
	data   []byte
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stderr)) }

func run(args []string, stdin io.Reader, stderr io.Writer) int {
	fs := flag.NewFlagSet("attackbox-evidence", flag.ContinueOnError)
	fs.SetOutput(stderr)
	input := fs.String("input", "-", "local NDJSON or JSON array; - reads stdin (64 MiB maximum)")
	output := fs.String("output", "", "new output file, exclusively created with mode 0600")
	request := fs.String("request-id", "", "required exact server-assigned request ID")
	kind := fs.String("kind", "", "request_body, response_body, request_metadata, response_metadata, or request_trailers")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	validKind := map[string]bool{"request_body": true, "response_body": true, "request_metadata": true, "response_metadata": true, "request_trailers": true}
	if fs.NArg() != 0 || *request == "" || !validKind[*kind] || *output == "" || *output == "-" {
		fmt.Fprintln(stderr, "required: -request-id ID -kind KIND -output NEW_FILE; output cannot be stdout")
		return 2
	}
	reader := stdin
	if *input != "-" {
		f, err := os.Open(*input)
		if err != nil {
			fmt.Fprintln(stderr, "cannot open input")
			return 1
		}
		defer f.Close()
		reader = f
	}
	data, err := reconstruct(reader, *request, *kind)
	if err == nil {
		err = writeOutput(*output, data)
	}
	if err != nil {
		fmt.Fprintln(stderr, "attackbox-evidence:", err)
		return 1
	}
	fmt.Fprintf(stderr, "verified and wrote %d bytes\n", len(data))
	return 0
}

func writeOutput(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot exclusively create output")
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.New("output write failed; incomplete file removed")
	}
	return nil
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Parse only a bounded record at a time. Unknown nested values stay raw JSON.
// Reject duplicate field names instead of choosing one ambiguous interpretation.
func object(raw []byte) (fields, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, errors.New("expected JSON object")
	}
	m := fields{}
	for d.More() {
		t, err = d.Token()
		if err != nil {
			return nil, errors.New("invalid object field")
		}
		key, ok := t.(string)
		if !ok || len(key) > 256 || len(m) >= 128 || m[key] != nil {
			return nil, errors.New("duplicate or excessive object fields")
		}
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return nil, errors.New("invalid object value")
		}
		m[key] = v
	}
	if _, err = d.Token(); err != nil {
		return nil, errors.New("unterminated object")
	}
	return m, nil
}

func (m fields) str(key string) string {
	var s string
	_ = json.Unmarshal(m[key], &s)
	return s
}

func (m fields) number(key string, limit int) (int, error) {
	s := string(m[key])
	if s == "" || strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, errors.New("missing or non-integer evidence number")
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n > uint64(limit) {
		return 0, errors.New("evidence number exceeds limit")
	}
	return int(n), nil
}

func attributes(raw []byte) (fields, error) {
	m, err := object(raw)
	if err != nil {
		return nil, err
	}
	if nested := m["attributes"]; nested != nil {
		a, err := object(nested)
		if err != nil {
			return nil, err
		}
		for k, v := range a {
			if old := m[k]; old != nil && !bytes.Equal(bytes.TrimSpace(old), bytes.TrimSpace(v)) {
				return nil, errors.New("conflicting nested attributes")
			}
			m[k] = v
		}
	}
	return m, nil
}

func reconstruct(input io.Reader, request, kind string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(input, maxInput+1))
	if err != nil || len(data) > maxInput {
		return nil, errors.New("input unreadable or exceeds 64 MiB")
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("empty input")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	array := data[0] == '['
	if array {
		_, _ = d.Token()
	}
	records := map[string]*record{}
	for seen := 0; ; seen++ {
		if array && !d.More() {
			break
		}
		var raw json.RawMessage
		err = d.Decode(&raw)
		if err == io.EOF && !array {
			break
		}
		if err != nil || len(raw) > maxRecord || seen >= maxParts {
			return nil, errors.New("invalid JSON or export record limit exceeded")
		}
		m, err := attributes(raw)
		if err != nil {
			return nil, err
		}
		if m.str("source") != "bait" || m.str("stream") != "edge" || m.str("action") != "capture" || m.str("request_id") != request {
			continue
		}
		k := m.str("evidence_kind")
		if k != kind && !(k == "manifest" && m.str("evidence_target") == kind) {
			continue
		}
		if err := addRecord(records, m); err != nil {
			return nil, err
		}
	}
	if array {
		if t, err := d.Token(); err != nil || t != json.Delim(']') {
			return nil, errors.New("unterminated export array")
		}
		var extra json.RawMessage
		if d.Decode(&extra) != io.EOF {
			return nil, errors.New("trailing export data")
		}
	}
	return assemble(records)
}

func addRecord(records map[string]*record, m fields) error {
	version, err := m.number("evidence_version", 1)
	if err != nil || version != 1 || m.str("evidence_encoding") != "base64" || m.str("evidence_scope") != "application" {
		return errors.New("unsupported or missing capture schema: require version 1, base64, application")
	}
	meta := metadata{kind: m.str("evidence_kind"), target: m.str("evidence_target"), hash: m.str("evidence_sha256"), reason: m.str("evidence_reason")}
	if meta.size, err = m.number("evidence_bytes", maxBody); err != nil {
		return err
	}
	if meta.kind == "manifest" {
		if meta.segments, err = m.number("evidence_segments", maxParts); err != nil {
			return err
		}
		if string(m["evidence_complete"]) != "true" {
			return errors.New("capture manifest is incomplete")
		}
		meta.complete = true
	} else {
		if meta.segment, err = m.number("evidence_segment", maxParts-1); err != nil {
			return err
		}
		if meta.offset, err = m.number("evidence_offset", maxBody); err != nil {
			return err
		}
	}
	count, err := m.number("chunk_count", maxParts)
	if err != nil || count == 0 {
		return errors.New("invalid chunk count")
	}
	index, err := m.number("chunk_index", count-1)
	if err != nil {
		return err
	}
	id, hash, chunk := m.str("record_id"), m.str("body_sha256"), m.str("body_chunk")
	if raw := m["body_chunk"]; raw != nil && (bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &chunk) != nil) {
		return errors.New("body_chunk must be a string")
	}
	if id == "" || len(id) > 256 || len(hash) != 64 || len(meta.hash) != 64 || len(meta.reason) > 256 {
		return errors.New("missing or invalid evidence identity/hash")
	}
	if meta.kind != "manifest" && m["body_chunk"] == nil {
		return errors.New("missing body_chunk")
	}
	r := records[id]
	if r == nil {
		r = &record{meta: meta, hash: hash, count: count, chunks: map[int]string{}}
		records[id] = r
	}
	if r.meta != meta || r.hash != hash || r.count != count {
		return errors.New("conflicting record metadata")
	}
	if previous, ok := r.chunks[index]; ok && previous != chunk {
		return errors.New("conflicting replayed chunk")
	}
	r.chunks[index] = chunk
	return nil
}

func assemble(records map[string]*record) ([]byte, error) {
	var manifest *metadata
	segments := map[int]segment{}
	retained := 0
	for _, r := range records {
		if len(r.chunks) != r.count {
			return nil, errors.New("missing record chunk")
		}
		var body strings.Builder
		for i := 0; i < r.count; i++ {
			body.WriteString(r.chunks[i])
		}
		text := body.String()
		if digest([]byte(text)) != r.hash {
			return nil, errors.New("record body hash mismatch")
		}
		if r.meta.kind == "manifest" {
			if text != "" || r.count != 1 {
				return nil, errors.New("invalid manifest body")
			}
			if manifest != nil && *manifest != r.meta {
				return nil, errors.New("conflicting manifests")
			}
			meta := r.meta
			manifest = &meta
			continue
		}
		if !strings.HasPrefix(text, "base64:") || base64.StdEncoding.DecodedLen(len(text)-7) > maxBody+2 {
			return nil, errors.New("invalid base64 evidence encoding or size")
		}
		b, err := base64.StdEncoding.Strict().DecodeString(text[7:])
		if err != nil || len(b) != r.meta.size || digest(b) != r.meta.hash {
			return nil, errors.New("segment encoding, length or hash mismatch")
		}
		if old, ok := segments[r.meta.segment]; ok {
			if old.offset != r.meta.offset || !bytes.Equal(old.data, b) {
				return nil, errors.New("conflicting logical segments")
			}
			continue
		}
		retained += len(b)
		if retained > maxBody {
			return nil, errors.New("decoded evidence exceeds 16 MiB")
		}
		segments[r.meta.segment] = segment{r.meta.offset, b}
	}
	if manifest == nil {
		return nil, errors.New("missing complete manifest")
	}
	if len(segments) != manifest.segments || retained != manifest.size {
		return nil, errors.New("manifest segment count or length mismatch")
	}
	out := make([]byte, 0, retained)
	for i := 0; i < manifest.segments; i++ {
		s, ok := segments[i]
		if !ok || s.offset != len(out) {
			return nil, errors.New("missing, overlapping or discontinuous segment")
		}
		out = append(out, s.data...)
	}
	if digest(out) != manifest.hash {
		return nil, errors.New("complete evidence hash mismatch")
	}
	return out, nil
}
