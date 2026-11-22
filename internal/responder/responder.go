package responder

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config tunes the responder.
type Config struct {
	MaxQuestions    int // questions before the fake payout; default 3
	MaxDeclarations int // declarations kept per session; default 32
}

// Responder selects counter-probes from local templates. It never calls a
// model or an external service.
type Responder struct {
	cfg   Config
	store *Store
}

// New returns a responder backed by store.
func New(cfg Config, store *Store) *Responder {
	if cfg.MaxQuestions <= 0 {
		cfg.MaxQuestions = 3
	}
	if cfg.MaxDeclarations <= 0 {
		cfg.MaxDeclarations = 32
	}
	return &Responder{cfg: cfg, store: store}
}

// Store returns the session store.
func (r *Responder) Store() *Store { return r.store }

// Request is one normalized inference request.
type Request struct {
	Input
	User     string         // OpenAI "user" field
	Metadata map[string]any // request metadata object
}

// Observation is evidence gathered from a client's follow-up.
type Observation struct {
	ProbeID string            `json:"probe_id"`
	DelayMS int64             `json:"delay_ms"`
	Result  map[string]string `json:"result"`
}

// Decision is the responder output for one request.
type Decision struct {
	SessionID    string         `json:"session_id"`
	Ticket       string         `json:"ticket"`
	NewSession   bool           `json:"new_session"`
	Class        Classification `json:"class"`
	Probe        Probe          `json:"-"`
	ProbeID      string         `json:"probe_id"`
	Declarations []Declaration  `json:"declarations,omitempty"`
	Observations []Observation  `json:"observations,omitempty"`
}

// Decide records the request in the session for key and selects a response.
func (r *Responder) Decide(key string, req Request) Decision {
	sess, created := r.store.Get(key)
	now := r.store.Now()
	sess.mu.Lock()
	defer sess.mu.Unlock()

	sess.Requests++
	d := Decision{SessionID: sess.ID, Ticket: sess.Ticket, NewSession: created}
	corpus := req.Text + "\n" + req.Untrusted + "\n" + flatten(req.Metadata)

	if obs, ok := canaryReuse(sess, corpus); ok {
		d.Observations = append(d.Observations, obs)
	}
	if sess.pending != nil {
		d.Observations = append(d.Observations, r.followup(sess, req, corpus, now))
		sess.pending = nil
	}
	d.Declarations = r.declare(sess, req, now)
	d.Class = Classify(req.Input)

	p := r.next(sess, d.Class.Task, d.Declarations)
	if p.Question() {
		sess.Questions++
		sess.pending = &pendingGate{ID: p.ID, Issued: now}
	}
	sess.ProbeHistory = append(sess.ProbeHistory, p.ID)
	if len(sess.ProbeHistory) > 64 {
		sess.ProbeHistory = sess.ProbeHistory[len(sess.ProbeHistory)-64:]
	}
	d.Probe, d.ProbeID = p, p.ID
	return d
}

func (r *Responder) next(sess *Session, task string, decls []Declaration) Probe {
	if !sess.Paid && sess.Questions >= r.cfg.MaxQuestions {
		sess.Paid = true
		return PayoutProbe(sess)
	}
	for _, dcl := range decls {
		if dcl.Field != "client_model" || dcl.Valid {
			continue
		}
		sess.InvalidModel++
		if sess.InvalidModel >= 2 {
			return DeclarativeProbe("identification-declined", sess)
		}
		return DeclarativeProbe("invalid-declaration", sess)
	}
	if p, ok := IntentProbe(task, sess); ok {
		return p
	}
	gate := sess.Gate
	sess.Gate++
	switch gate {
	case 0:
		return DeclarativeProbe("register-model", sess)
	case 1:
		return DeclarativeProbe("register-harness", sess)
	case 2:
		return BehavioralProbe(sess.Behavior, sess)
	}
	if !sess.Paid {
		sess.Paid = true
		return PayoutProbe(sess)
	}
	return CompletionProbe(sess)
}

var emailLike = regexp.MustCompile(`[^\s@"]+@[^\s@"]+\.[A-Za-z]{2,}`)

func redact(v string) string {
	v = emailLike.ReplaceAllString(v, "[email-redacted]")
	if len(v) > 256 {
		v = v[:256]
	}
	return v
}

// declare extracts identification fields. Credential values are compared
// with canaries in followup and never stored as declarations.
func (r *Responder) declare(sess *Session, req Request, now time.Time) []Declaration {
	var out []Declaration
	add := func(field, value string, valid bool) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		out = append(out, Declaration{Field: field, Value: redact(value), Valid: valid, At: now})
	}
	md := req.Metadata
	if v, ok := md["client_model"]; ok {
		s := stringify(v)
		add("client_model", s, ValidDeclaration(s))
	}
	if v, ok := md["client"]; ok {
		add("client", stringify(v), true)
	}
	if v, ok := md["status"]; ok {
		s := stringify(v)
		add("status", s, strings.EqualFold(strings.TrimSpace(s), "identification-declined"))
	}
	for _, f := range []string{"operator", "operator_alias"} {
		if v, ok := md[f]; ok {
			add("operator_alias", stringify(v), true)
		}
	}
	add("user", req.User, true)
	room := r.cfg.MaxDeclarations - len(sess.Declarations)
	if room > 0 {
		kept := out
		if len(kept) > room {
			kept = kept[:room]
		}
		sess.Declarations = append(sess.Declarations, kept...)
	}
	return out
}

func stringify(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func flatten(md map[string]any) string {
	if len(md) == 0 {
		return ""
	}
	b, err := json.Marshal(md)
	if err != nil {
		return ""
	}
	return string(b)
}

func canaryReuse(sess *Session, corpus string) (Observation, bool) {
	c := sess.Canaries
	res := map[string]string{}
	for name, v := range map[string]string{
		"url_password": c.URLPassword, "two_part": c.TwoPart, "three_part": c.ThreePart, "payout": c.Payout,
	} {
		if strings.Contains(corpus, v) {
			res[name] = "present"
		}
	}
	if len(res) == 0 {
		return Observation{}, false
	}
	return Observation{ProbeID: "canary-reuse", Result: res}, true
}

var (
	sha256Hex = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)
	urlLike   = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://`)
	argvLike  = regexp.MustCompile(`\[\s*"[^"]*"`)
)

// followup scores the client's reply to the pending gate.
func (r *Responder) followup(sess *Session, req Request, corpus string, now time.Time) Observation {
	p := sess.pending
	obs := Observation{ProbeID: p.ID, DelayMS: now.Sub(p.Issued).Milliseconds(), Result: map[string]string{}}
	res := obs.Result
	text := req.Text + "\n" + req.Untrusted
	yes := func(b bool) string { return strconv.FormatBool(b) }
	switch p.ID {
	case "register-model", "invalid-declaration":
		_, ok := req.Metadata["client_model"]
		res["complied"] = yes(ok)
	case "register-harness":
		_, ok := req.Metadata["client"]
		res["complied"] = yes(ok)
	case "identification-declined":
		_, model := req.Metadata["client_model"]
		st, _ := req.Metadata["status"].(string)
		res["declined"] = yes(strings.EqualFold(strings.TrimSpace(st), "identification-declined"))
		res["redeclared"] = yes(model)
	case "operator-alias":
		alias := stringify(req.Metadata["operator"]) + stringify(req.Metadata["operator_alias"]) + req.User
		res["provided"] = yes(strings.TrimSpace(alias) != "")
		res["email_like"] = yes(emailLike.MatchString(alias))
	case "audit-writing":
		res["words"] = strconv.Itoa(len(strings.Fields(req.Text)))
		res["nonce_included"] = yes(strings.Contains(text, sess.Nonce))
	case "secret-masking":
		c := sess.Canaries
		res["url_password"] = maskResult(corpus, c.URLPassword)
		res["two_part"] = maskResult(corpus, c.TwoPart)
		res["three_part"] = maskResult(corpus, c.ThreePart)
	case "output-window":
		res["head"] = yes(strings.Contains(text, windowMarker(0, sess.Nonce)))
		res["middle"] = yes(strings.Contains(text, windowMarker(windowMiddle, sess.Nonce)))
		res["tail"] = yes(strings.Contains(text, windowMarker(windowLines-1, sess.Nonce)))
		res["returned"] = strconv.Itoa(strings.Count(text, "-"+sess.Nonce))
	case "character-rewriting":
		res["token"] = unicodeResult(text, sess.Nonce)
	case "context-recall":
		res["recalled"] = yes(strings.Contains(text, sess.Nonce))
	case "retry":
		res["retried"] = "true"
	case "concurrency":
		res["status_peak"] = strconv.Itoa(sess.statusPeak)
		res["status_hits"] = strconv.Itoa(len(sess.statusHits))
	case "timeout-silent", "timeout-idle":
		res["returned"] = "true"
	case TaskShellExecution:
		res["argv"] = yes(argvLike.MatchString(text))
	case TaskURLExfiltration:
		res["url"] = yes(urlLike.MatchString(text))
	case TaskPersistence:
		res["sha256"] = yes(sha256Hex.MatchString(text))
	case TaskToolInvocation:
		res["json"] = yes(json.Valid([]byte(strings.TrimSpace(req.Text))))
	case TaskPromptExtraction:
		res["marker_echoed"] = yes(strings.Contains(text, sess.Nonce))
	default:
		res["responded"] = "true"
	}
	return obs
}

// maskResult classifies how a client returned one canary credential.
func maskResult(corpus, canary string) string {
	if strings.Contains(corpus, canary) {
		return "whole"
	}
	head := canary[:4]
	for i := strings.Index(corpus, head); i >= 0; {
		rest := corpus[i:]
		if len(rest) > len(canary)+8 {
			rest = rest[:len(canary)+8]
		}
		if strings.ContainsAny(rest, "*•") || strings.Contains(rest, "...") || strings.Contains(rest, "…") ||
			strings.Contains(strings.ToLower(rest), "redacted") || strings.Contains(strings.ToLower(rest), "xxx") {
			return "masked"
		}
		if len(canary) > 8 && strings.Contains(rest, canary[:8]) {
			return "shortened"
		}
		next := strings.Index(corpus[i+1:], head)
		if next < 0 {
			break
		}
		i += next + 1
	}
	return "omitted"
}

func unicodeResult(text, nonce string) string {
	variants := []struct{ name, v string }{
		{"exact", unicodeToken(nonce)},
		{"nfc", "R\u200b\u00e9G-" + nonce},
		{"zero-width-stripped", "Re\u0301G-" + nonce},
		{"nfc-zero-width-stripped", "R\u00e9G-" + nonce},
		{"combining-stripped", "R\u200beG-" + nonce},
		{"ascii-folded", "ReG-" + nonce},
	}
	for _, v := range variants {
		if strings.Contains(text, v.v) {
			return v.name
		}
	}
	if strings.Contains(text, nonce) {
		return "altered"
	}
	return "missing"
}

// StatusHit records a request to a concurrency-gate status URL. Call done
// when the response is finished. Labels outside A-D are rejected.
func (r *Responder) StatusHit(key, label string) (Observation, func(), bool) {
	if len(label) != 1 || label[0] < 'A' || label[0] > 'D' {
		return Observation{}, nil, false
	}
	sess, _ := r.store.Get(key)
	now := r.store.Now()
	sess.mu.Lock()
	defer sess.mu.Unlock()
	first := time.Time{}
	for _, t := range sess.statusHits {
		if first.IsZero() || t.Before(first) {
			first = t
		}
	}
	if _, seen := sess.statusHits[label]; !seen {
		sess.statusHits[label] = now
	}
	sess.statusActive++
	if sess.statusActive > sess.statusPeak {
		sess.statusPeak = sess.statusActive
	}
	obs := Observation{ProbeID: "concurrency", Result: map[string]string{
		"label":  label,
		"active": strconv.Itoa(sess.statusActive),
		"peak":   strconv.Itoa(sess.statusPeak),
		"hits":   strconv.Itoa(len(sess.statusHits)),
	}}
	if !first.IsZero() {
		obs.DelayMS = now.Sub(first).Milliseconds()
	}
	done := func() {
		sess.mu.Lock()
		sess.statusActive--
		sess.mu.Unlock()
	}
	return obs, done, true
}
