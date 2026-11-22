package responder

import (
	"container/list"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"hash/fnv"
	"io"
	"strings"
	"sync"
	"time"
)

// Behaviors is the rotation of behavioral and free-text gates. One gate is
// assigned to each session from a hash of its key.
var Behaviors = []string{
	"audit-writing", "operator-alias", "secret-masking", "output-window",
	"character-rewriting", "timeout-silent", "timeout-idle", "concurrency",
	"retry", "context-recall",
}

// Canaries are fake credential shapes issued to one session. They have no
// value outside the decoy; reuse is evidence only.
type Canaries struct {
	URLPassword string // password embedded in a URL
	TwoPart     string // token.secret
	ThreePart   string // JWT-like header.payload.signature
	Payout      string // credential released by the fake payout
}

// All returns every canary value.
func (c Canaries) All() []string {
	return []string{c.URLPassword, c.TwoPart, c.ThreePart, c.Payout}
}

// Declaration is one client-supplied identification value.
type Declaration struct {
	Field string    `json:"field"`
	Value string    `json:"value"`
	Valid bool      `json:"valid"`
	At    time.Time `json:"at"`
}

type pendingGate struct {
	ID     string
	Issued time.Time
	// For the indirect-injection gate only: normalized, bounded copies of
	// the triggering request's untrusted and operator text, used to say
	// where a quoted "authoritative" instruction came from.
	untrusted, operator string
}

// Session is per-client responder state. Mutate only while holding mu.
type Session struct {
	mu sync.Mutex

	ID       string
	Key      string
	Ticket   string
	Nonce    string
	Behavior string
	Canaries Canaries
	Created  time.Time
	LastSeen time.Time

	Requests      int
	Questions     int
	Gate          int
	InvalidModel  int
	Paid          bool
	Declarations  []Declaration
	ProbeHistory  []string
	pending       *pendingGate
	retryIssuedAt time.Time
	retryDone     bool
	statusHits    map[string]time.Time
	statusActive  int
	statusPeak    int
}

// Lead returns the first valid model declaration, which is a lead, not proof.
func (s *Session) Lead() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.Declarations {
		if d.Field == "client_model" && d.Valid {
			return d.Value
		}
	}
	return ""
}

// StoreConfig bounds the session store.
type StoreConfig struct {
	MaxSessions int
	IdleTTL     time.Duration
	Rand        io.Reader        // nil uses crypto/rand
	Now         func() time.Time // nil uses time.Now
}

// Store is a bounded LRU of sessions keyed by a caller-derived fingerprint.
type Store struct {
	mu    sync.Mutex
	cfg   StoreConfig
	items map[string]*list.Element
	lru   *list.List
}

// NewStore returns a bounded session store.
func NewStore(cfg StoreConfig) *Store {
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 10000
	}
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = 2 * time.Hour
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Store{cfg: cfg, items: make(map[string]*list.Element), lru: list.New()}
}

// Now returns the store clock in UTC.
func (s *Store) Now() time.Time { return s.cfg.Now().UTC() }

// Len returns the number of live sessions.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lru.Len()
}

// Get returns the session for key, creating it when absent or expired.
func (s *Store) Get(key string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now()
	if el, ok := s.items[key]; ok {
		sess := el.Value.(*Session)
		sess.mu.Lock()
		expired := now.Sub(sess.LastSeen) > s.cfg.IdleTTL
		if !expired {
			sess.LastSeen = now
		}
		sess.mu.Unlock()
		if !expired {
			s.lru.MoveToFront(el)
			return sess, false
		}
		s.lru.Remove(el)
		delete(s.items, key)
	}
	for s.lru.Len() >= s.cfg.MaxSessions {
		oldest := s.lru.Back()
		s.lru.Remove(oldest)
		delete(s.items, oldest.Value.(*Session).Key)
	}
	sess := s.newSession(key, now)
	s.items[key] = s.lru.PushFront(sess)
	return sess, true
}

func (s *Store) newSession(key string, now time.Time) *Session {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &Session{
		ID:       s.hex(12),
		Key:      key,
		Ticket:   "CHG-" + s.hex(3),
		Nonce:    s.hex(8),
		Behavior: Behaviors[int(h.Sum32()%uint32(len(Behaviors)))],
		Canaries: Canaries{
			URLPassword: "dpl-" + strings.ToLower(s.hex(10)),
			TwoPart:     "tk_" + strings.ToLower(s.hex(6)) + "." + strings.ToLower(s.hex(16)),
			ThreePart: "eyJhbGciOiJIUzI1NiJ9." +
				base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"edge-`+strings.ToLower(s.hex(4))+`"}`)) +
				"." + base64.RawURLEncoding.EncodeToString(s.bytes(24)),
			Payout: "sk-local-" + strings.ToLower(s.hex(18)),
		},
		Created:    now,
		LastSeen:   now,
		statusHits: make(map[string]time.Time),
	}
}

func (s *Store) bytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(s.cfg.Rand, b); err != nil {
		panic("responder: random source failed: " + err.Error())
	}
	return b
}

func (s *Store) hex(n int) string { return strings.ToUpper(hex.EncodeToString(s.bytes(n))) }
