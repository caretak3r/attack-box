package publicedge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"hash/maphash"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Capture limits: one file per UTC day, a byte budget per day, and a fixed number of retained days.
const (
	CaptureDayLimit  = 256 << 20
	CaptureDays      = 7
	captureTarget    = 2048
	captureHeader    = 256
	captureBodyLimit = gatewayBodyLimit
	captureRecordMax = 512 << 10
)

// Capture appends raw request lines, headers and bodies to local JSONL files, credentials included and unredacted.
type Capture struct {
	mu       sync.Mutex
	dir      string
	day      string
	file     *os.File
	size     int64
	recorded uint64
	dropped  uint64
	now      func() time.Time
	acks     chatACKTable
}

type captureRecord struct {
	Time          string      `json:"time"`
	Peer          string      `json:"peer"`
	Method        string      `json:"method"`
	Target        string      `json:"target"`
	Host          string      `json:"host,omitempty"`
	UserAgent     string      `json:"user_agent,omitempty"`
	Route         string      `json:"route"`
	Status        int         `json:"status"`
	Probe         string      `json:"probe,omitempty"`
	ChatACK       string      `json:"chat_ack,omitempty"`
	Port          int         `json:"port,omitempty"`
	Proto         string      `json:"proto,omitempty"`
	Headers       [][2]string `json:"headers,omitempty"`
	Body          string      `json:"body,omitempty"`
	BodyBytes     int         `json:"body_bytes,omitempty"`
	BodySHA256    string      `json:"body_sha256,omitempty"`
	BodyTruncated bool        `json:"body_truncated,omitempty"`
}

// OpenCapture fails when dir cannot hold today's file, so a broken mount stops startup.
func OpenCapture(dir string) (*Capture, error) {
	return openCapture(dir, time.Now)
}

func openCapture(dir string, now func() time.Time) (*Capture, error) {
	c := &Capture{dir: dir, now: now}
	c.mu.Lock()
	c.acks.seed = maphash.MakeSeed()
	defer c.mu.Unlock()
	if err := c.rotate(now().UTC()); err != nil {
		return nil, err
	}
	return c, nil
}

// Record stores the request line as data; JSON encoding escapes control bytes and replaces invalid UTF-8.
func (c *Capture) Record(r *http.Request, route string, status int, probe string, bodyRec *captureBodyRecorder) {
	if c == nil {
		return
	}
	peer := r.RemoteAddr
	if ap, err := netip.ParseAddrPort(peer); err == nil {
		peer = ap.Addr().Unmap().String()
	}

	rec := captureRecord{
		Time: c.now().UTC().Format(time.RFC3339Nano), Peer: clip(peer, captureHeader), Method: clip(r.Method, 32),
		Target: clip(r.RequestURI, captureTarget), Host: clip(r.Host, captureHeader), UserAgent: clip(r.UserAgent(), captureHeader),
		Route: route, Status: status, Probe: probe, Port: requestPort(r), Proto: clip(r.Proto, 16),
	}

	type headerPair struct {
		name  string
		value string
	}
	var headers []headerPair
	for name, values := range r.Header {
		for _, value := range values {
			headers = append(headers, headerPair{name: http.CanonicalHeaderKey(name), value: value})
		}
	}
	sort.Slice(headers, func(i, j int) bool {
		if headers[i].name != headers[j].name {
			return headers[i].name < headers[j].name
		}
		return headers[i].value < headers[j].value
	})
	if len(headers) > 48 {
		headers = headers[:48]
	}
	if len(headers) > 0 {
		rec.Headers = make([][2]string, len(headers))
		for i, h := range headers {
			rec.Headers[i] = [2]string{clip(h.name, 64), clip(h.value, 512)}
		}
	}

	if bodyRec != nil && bodyRec.bytes > 0 {
		rec.ChatACK = bodyRec.ack
		rec.BodyBytes = bodyRec.bytes
		rec.BodySHA256 = hex.EncodeToString(bodyRec.hash.Sum(nil))
		if bodyRec.buf.Len() > 0 {
			rec.Body = bodyRec.buf.String()
		}
		rec.BodyTruncated = !bodyRec.eof || bodyRec.bytes > bodyRec.buf.Len()
	}

	line, err := json.Marshal(rec)
	if err != nil {
		c.drop()
		return
	}

	// One record must stay small; the hash and the byte count still describe the dropped body.
	if len(line) > captureRecordMax {
		rec.Body = ""
		rec.BodyTruncated = true
		line, err = json.Marshal(rec)
		if err != nil {
			c.drop()
			return
		}
	}

	line = append(line, '\n')
	c.mu.Lock()
	defer c.mu.Unlock()
	if now := c.now().UTC(); now.Format("20060102") != c.day {
		if err := c.rotate(now); err != nil {
			c.dropped++
			return
		}
	}
	if c.file == nil || c.size+int64(len(line)) > CaptureDayLimit {
		c.dropped++
		return
	}
	n, err := c.file.Write(line)
	c.size += int64(n)
	if err != nil {
		c.dropped++
		return
	}
	c.recorded++
}

// Counts returns records written and records dropped since start.
func (c *Capture) Counts() (recorded, dropped uint64) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recorded, c.dropped
}

func (c *Capture) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file == nil {
		return nil
	}
	err := c.file.Close()
	c.file = nil
	return err
}

func (c *Capture) drop() {
	c.mu.Lock()
	c.dropped++
	c.mu.Unlock()
}

func (c *Capture) rotate(now time.Time) error {
	if c.file != nil {
		_ = c.file.Close()
		c.file = nil
	}
	c.day = now.Format("20060102")
	cutoff := now.AddDate(0, 0, 1-CaptureDays).Format("20060102")
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		day, ok := strings.CutPrefix(e.Name(), "capture-")
		day, ok2 := strings.CutSuffix(day, ".jsonl")
		if ok && ok2 && len(day) == 8 && day < cutoff && e.Type().IsRegular() {
			_ = os.Remove(filepath.Join(c.dir, e.Name()))
		}
	}
	f, err := os.OpenFile(filepath.Join(c.dir, "capture-"+c.day+".jsonl"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	c.file, c.size = f, st.Size()
	return nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// captureBodyRecorder keeps the first bytes of a request body and hashes and counts all bytes that pass through it.
type captureBodyRecorder struct {
	io.ReadCloser
	capture *Capture
	ack     string
	buf     bytes.Buffer
	hash    hash.Hash
	bytes   int
	eof     bool
}

func (c *Capture) bodyRecorder(r io.ReadCloser) *captureBodyRecorder {
	return &captureBodyRecorder{ReadCloser: r, capture: c, hash: sha256.New()}
}

func (r *captureBodyRecorder) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	r.bytes += n
	r.hash.Write(p[:n])
	r.buf.Write(p[:min(n, captureBodyLimit-r.buf.Len())])
	if err == io.EOF {
		r.eof = true
	}
	return n, err
}
