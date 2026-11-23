package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// personaDigests maps PersonaVersion to the digest of personaTranscript.
var personaDigests = map[int]string{
	1: "9967be06817ce8854290d6d010c85fa67352cafdd88598b02cd4c1b54fbe92f1",
}

// personaTranscript records the status, headers and body of requests that
// every persona answers without a session: model cards, version and health,
// the ollama document routes, the vLLM schema and page, an embedding, and the
// error bodies. One entry per request and persona. The rig fixes the clock and
// the embedding seed.
func personaTranscript(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, persona := range []string{PersonaOpenAI, PersonaVLLM, PersonaOllama} {
		rg := newRig(t, persona)
		for _, q := range []struct{ method, path, body string }{
			{"GET", "/v1/models", ""},
			{"GET", "/v1/models/qwen3:8b", ""},
			{"GET", "/v1/models/no-such-model", ""},
			{"GET", "/version", ""},
			{"GET", "/health", ""},
			{"GET", "/metrics", ""},
			{"GET", "/docs", ""},
			{"GET", "/openapi.json", ""},
			{"GET", "/", ""},
			{"GET", "/api/version", ""},
			{"GET", "/api/tags", ""},
			{"GET", "/api/ps", ""},
			{"GET", "/v1/responses/resp_abc", ""},
			{"POST", "/api/show", `{"model":"qwen3:8b"}`},
			{"POST", "/api/show", `{"model":"gpt-oss:20b"}`},
			{"POST", "/v1/embeddings", `{"model":"qwen3:8b","input":"pin"}`},
			{"POST", "/v1/embeddings", `{"model":"gpt-oss:20b","input":["a","b"]}`},
			{"POST", "/v1/chat/completions", `{`},
			{"POST", "/v1/chat/completions", `{"model":"qwen3:8b"}`},
			{"GET", "/no/such/path", ""},
			{"DELETE", "/v1/models", ""},
		} {
			rec := rg.do(q.method, q.path, q.body)
			var names []string
			for k := range rec.Header() {
				if k != "X-Request-Id" { // random per request
					names = append(names, k)
				}
			}
			sort.Strings(names)
			var b strings.Builder
			fmt.Fprintf(&b, "%s %s %s %q -> %d\n", persona, q.method, q.path, q.body, rec.Code)
			for _, k := range names {
				fmt.Fprintf(&b, "%s: %q\n", k, rec.Header().Values(k))
			}
			fmt.Fprintf(&b, "%q\n", rec.Body.String())
			out = append(out, b.String())
		}
	}
	return out
}

func TestPersonaVersionPin(t *testing.T) {
	want, ok := personaDigests[PersonaVersion]
	if !ok {
		t.Fatalf("PersonaVersion %d has no digest in personaDigests; add it", PersonaVersion)
	}
	sum := sha256.Sum256([]byte(strings.Join(personaTranscript(t), "")))
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("a persona's static answer changed, and PersonaVersion is still %d.\n"+
			"Raise PersonaVersion and add this digest for the new number:\n\t%d: %q,\n(old digest %q)",
			PersonaVersion, PersonaVersion+1, got, want)
	}
}
