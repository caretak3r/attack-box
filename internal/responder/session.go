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

type namedCanary struct{ name, value string }

// named returns every canary with its result-key name.
func (c Canaries) named() []namedCanary {
	return []namedCanary{
		{"url_password", c.URLPassword}, {"two_part", c.TwoPart},
		{"three_part", c.ThreePart}, {"payout", c.Payout},
	}
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
	// LastSeen belongs to Store and is guarded by Store.mu, not mu, so a busy
	// session never stalls the store.
	LastSeen time.Time

	Requests        int
	Questions       int
	Gate            int
	InvalidModel    int
	Paid            bool
	Declarations    []Declaration
	ProbeHistory    []string
	diagnosticsDone bool // Invitation attempted, valid claim supplied, or declined.

	// Reply attribution, all bounded (see issuance.go): the newest probe
	// issuances, digests of messages already seen, and per-canary delivery.
	issuances       []*Issuance
	issSeq          int
	seen            []digest
	issued          []digest          // digests of the responses sent, kept after their records are evicted
	canaryIssued    map[string]bool   // canary name -> carried by some probe
	canaryDelivered map[string]uint64 // canary name -> tick it was fully sent
	canaryLatch     map[string]uint8  // canary name -> states already reported
	// The history of the last chat request, as a count and rolling digest: the
	// next request that still starts with it has only its tail to inspect.
	prefixN    int
	prefixRoll digest
	// The one indirect-injection snapshot a session keeps: the newest gate's
	// triggering text. A newer gate supersedes the older issuance.
	snap snapshot
	// Registry losses: records dropped to stay bounded, and the open ones among
	// them. A loss lowers confidence and never verifies anything.
	evicted, lost int
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
		if now.Sub(sess.LastSeen) <= s.cfg.IdleTTL {
			sess.LastSeen = now
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
		Created:         now,
		LastSeen:        now,
		canaryIssued:    make(map[string]bool),
		canaryDelivered: make(map[string]uint64),
		canaryLatch:     make(map[string]uint8),
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
