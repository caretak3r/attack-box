package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	mrand "math/rand/v2"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Personas. One Server serves one persona.
const (
	PersonaOpenAI = "openai"
	PersonaVLLM   = "vllm"
	PersonaOllama = "ollama"
)

var defaultVersions = map[string]string{
	PersonaOpenAI: "1.0.0",
	PersonaVLLM:   "0.11.0",
	PersonaOllama: "0.12.6",
}

var defaultModels = []string{"qwen3:8b", "gpt-oss:20b", "llama3.1:8b"}

// Embedding widths per fake model. They are smaller than the real hidden
// sizes so that a 256-input request stays cheap to answer.
const defaultEmbedDims = 1024

var embedDims = map[string]int{
	"qwen3:8b":    1024,
	"gpt-oss:20b": 768,
	"llama3.1:8b": 2048,
}

// maxEmbedInputs caps the inputs of one embeddings request.
const maxEmbedInputs = 256

var jsonNull = json.RawMessage("null")

// modelMeta is the fake model card.
type modelMeta struct {
	family string
	params string
	quant  string
	size   int64
	ctx    int
}

var knownMeta = map[string]modelMeta{
	"qwen3:8b":    {"qwen3", "8.2B", "Q4_K_M", 5225376047, 40960},
	"gpt-oss:20b": {"gptoss", "20.9B", "MXFP4", 13780173724, 131072},
	"llama3.1:8b": {"llama", "8.0B", "Q4_K_M", 4920753328, 131072},
}

func nameHash(name string) [32]byte { return sha256.Sum256([]byte("model:" + name)) }

// metaFor returns the card for name. Unknown names get a stable derived card.
func metaFor(name string) modelMeta {
	if m, ok := knownMeta[name]; ok {
		return m
	}
	h := nameHash(name)
	family := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, strings.ToLower(strings.SplitN(name, ":", 2)[0]))
	if family == "" {
		family = "llama"
	}
	return modelMeta{
		family: family,
		params: "7B",
		quant:  "Q4_K_M",
		size:   2_000_000_000 + int64(binary.BigEndian.Uint32(h[:4]))%6_000_000_000,
		ctx:    8192,
	}
}

func modelDigest(name string) string {
	h := nameHash(name)
	return hex.EncodeToString(h[:])
}

// modelCreated is a fixed per-model Unix time in late 2025.
func modelCreated(name string) int64 {
	h := nameHash(name)
	return 1758000000 + int64(binary.BigEndian.Uint32(h[4:8]))%20_000_000
}

func modelModified(name string) string {
	h := nameHash(name)
	return time.Unix(modelCreated(name), int64(binary.BigEndian.Uint32(h[8:12]))%1_000_000_000).UTC().Format(time.RFC3339Nano)
}

func embedDimsFor(model string) int {
	if d, ok := embedDims[model]; ok {
		return d
	}
	return defaultEmbedDims
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("server: random source failed: " + err.Error())
	}
	return b
}

func randHex(n int) string { return hex.EncodeToString(randBytes(n)) }

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func randBase62(n int) string {
	b := randBytes(n)
	for i := range b {
		b[i] = base62[int(b[i])%len(base62)]
	}
	return string(b)
}

// newID returns a persona-shaped identifier such as chatcmpl-... or resp_....
func (s *Server) newID(prefix string) string {
	switch {
	case prefix == "resp_" || prefix == "msg_":
		if s.persona == PersonaVLLM {
			return prefix + randHex(16)
		}
		return prefix + randHex(24)
	case s.persona == PersonaVLLM:
		return prefix + randHex(16)
	case s.persona == PersonaOllama:
		// Ollama's OpenAI layer numbers ids: chatcmpl-<rand.Intn(999)>.
		return prefix + strconv.Itoa(mrand.IntN(999))
	}
	return prefix + randBase62(29)
}

// fingerprint is the stable system_fingerprint for a model.
func (s *Server) fingerprint(model string) string {
	if s.persona == PersonaOllama {
		return "fp_ollama"
	}
	h := nameHash(model)
	return "fp_" + hex.EncodeToString(h[16:21])
}

// cleanEcho makes a client string safe to repeat in an error message: no
// control or format characters, at most max runes.
func cleanEcho(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if n == max {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

func truncRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}

// truncBytes cuts s to at most n bytes without splitting a rune.
func truncBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func wordCount(s string) int { return len(strings.Fields(s)) }

// wordChunks splits s into pieces of per words each, keeping the whitespace
// that follows a word with that word. The pieces always join back into s.
func wordChunks(s string, per int) []string {
	var out []string
	start, words := 0, 0
	inWord := false
	for i, r := range s {
		space := unicode.IsSpace(r)
		switch {
		case !space && !inWord:
			if words == per {
				out = append(out, s[start:i])
				start, words = i, 0
			}
			inWord = true
		case space && inWord:
			words++
			inWord = false
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
