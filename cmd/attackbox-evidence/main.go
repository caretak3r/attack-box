// Command attackbox-evidence reconstructs one complete capture from local
// shipper evidence JSONL. Hashes verify consistency, not provenance.
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
	"strings"
)

const (
	maxInput  = 64 << 20
	maxBody   = 16 << 20
	maxRecord = 1 << 20
	maxParts  = 32768
)

type metadata struct {
	kind, target, hash, reason      string
	segment, offset, size, segments int
	complete                        bool
}
type record struct {
	meta metadata
	data []byte
}
type segment struct {
	offset int
	data   []byte
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stderr)) }

func run(args []string, stdin io.Reader, stderr io.Writer) int {
	fs := flag.NewFlagSet("attackbox-evidence", flag.ContinueOnError)
	fs.SetOutput(stderr)
	input := fs.String("input", "-", "local JSONL; - reads stdin (64 MiB maximum)")
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
	records := map[string]*record{}
	for seen := 0; d.More(); seen++ {
		var envelope struct {
			Record struct {
				ID    string `json:"id"`
				Event *struct {
					Stream    string         `json:"stream"`
					Action    string         `json:"action"`
					RequestID string         `json:"request_id"`
					Attrs     map[string]any `json:"attrs"`
					Body      string         `json:"body"`
				} `json:"event"`
			} `json:"record"`
		}
		err = d.Decode(&envelope)
		if err == io.EOF {
			break
		}
		if err != nil || seen >= maxParts {
			return nil, errors.New("invalid JSON or export record limit exceeded")
		}
		evt := envelope.Record.Event
		if evt == nil || evt.Stream != "edge" || evt.Action != "capture" || evt.RequestID != request {
			continue
		}
		getStr := func(key string) string {
			if v, ok := evt.Attrs[key].(string); ok {
				return v
			}
			return ""
		}
		getNum := func(key string) (float64, bool) {
			v, ok := evt.Attrs[key].(float64)
			return v, ok
		}
		getBool := func(key string) (bool, bool) {
			v, ok := evt.Attrs[key].(bool)
			return v, ok
		}
		if getStr("source") != "bait" {
			continue
		}
		evidenceKind := getStr("evidence_kind")
		if evidenceKind != kind && !(evidenceKind == "manifest" && getStr("evidence_target") == kind) {
			continue
		}
		if err := addRecord(records, envelope.Record.ID, evt.Attrs, evt.Body, getStr, getNum, getBool); err != nil {
			return nil, err
		}
	}
	return assemble(records)
}

func addRecord(records map[string]*record, id string, attrs map[string]any, body string, getStr func(string) string, getNum func(string) (float64, bool), getBool func(string) (bool, bool)) error {
	versionF, ok := getNum("evidence_version")
	if !ok || versionF != 1 || getStr("evidence_encoding") != "base64" || getStr("evidence_scope") != "application" {
		return errors.New("unsupported or missing capture schema: require version 1, base64, application")
	}
	meta := metadata{kind: getStr("evidence_kind"), target: getStr("evidence_target"), hash: getStr("evidence_sha256"), reason: getStr("evidence_reason")}
	bytesF, ok := getNum("evidence_bytes")
	if !ok || bytesF < 0 || bytesF > maxBody {
		return errors.New("invalid evidence_bytes")
	}
	meta.size = int(bytesF)

	if meta.kind == "manifest" {
		segsF, ok := getNum("evidence_segments")
		if !ok || segsF < 0 || segsF > maxParts {
			return errors.New("invalid evidence_segments")
		}
		meta.segments = int(segsF)
		complete, ok := getBool("evidence_complete")
		if !ok {
			return errors.New("manifest missing evidence_complete")
		}
		if !complete && meta.reason == "" {
			return errors.New("incomplete manifest missing reason")
		}
		if !complete {
			return errors.New("capture manifest is incomplete")
		}
		meta.complete = true
	} else {
		segF, ok := getNum("evidence_segment")
		if !ok || segF < 0 || segF > maxParts-1 {
			return errors.New("invalid evidence_segment")
		}
		meta.segment = int(segF)
		offsetF, ok := getNum("evidence_offset")
		if !ok || offsetF < 0 || offsetF > maxBody {
			return errors.New("invalid evidence_offset")
		}
		meta.offset = int(offsetF)
	}

	if id == "" || len(id) > 256 || len(meta.hash) != 64 || len(meta.reason) > 256 {
		return errors.New("missing or invalid evidence identity/hash")
	}
	if meta.kind != "manifest" && body == "" {
		return errors.New("missing body")
	}

	r := records[id]
	if r != nil {
		return errors.New("duplicate record ID")
	}

	var data []byte
	if body != "" {
		if !strings.HasPrefix(body, "base64:") || base64.StdEncoding.DecodedLen(len(body)-7) > maxBody+2 {
			return errors.New("invalid base64 evidence encoding or size")
		}
		b, err := base64.StdEncoding.Strict().DecodeString(body[7:])
		if err != nil {
			return errors.New("segment encoding invalid")
		}
		if len(b) != meta.size || digest(b) != meta.hash {
			return errors.New("segment length or hash mismatch")
		}
		data = b
	}

	records[id] = &record{meta: meta, data: data}
	return nil
}

func assemble(records map[string]*record) ([]byte, error) {
	var manifest *metadata
	segments := map[int]segment{}
	retained := 0
	for _, r := range records {
		if r.meta.kind == "manifest" {
			if len(r.data) != 0 {
				return nil, errors.New("invalid manifest body")
			}
			if manifest != nil {
				return nil, errors.New("duplicate manifest")
			}
			meta := r.meta
			manifest = &meta
			continue
		}
		if old, ok := segments[r.meta.segment]; ok {
			if old.offset != r.meta.offset || !bytes.Equal(old.data, r.data) {
				return nil, errors.New("conflicting logical segments")
			}
			continue
		}
		retained += len(r.data)
		if retained > maxBody {
			return nil, errors.New("decoded evidence exceeds 16 MiB")
		}
		segments[r.meta.segment] = segment{r.meta.offset, r.data}
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
