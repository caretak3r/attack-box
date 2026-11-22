package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
)

// maxEmbedDims caps a client-chosen "dimensions" value.
const maxEmbedDims = 4096

// vector returns the unit-length embedding of text. It is a pure function of
// the seed, the model name and the text: HMAC-SHA256 keys a SHA-256 counter
// stream that becomes the components.
func (s *Server) vector(model, text string, dims int) []float32 {
	m := hmac.New(sha256.New, s.cfg.EmbedSeed)
	m.Write([]byte(model))
	m.Write([]byte{0})
	m.Write([]byte(text))
	seed := m.Sum(nil)

	v := make([]float32, dims)
	block := make([]byte, len(seed)+4)
	copy(block, seed)
	var sum float64
	for i, ctr := 0, uint32(0); i < dims; ctr++ {
		binary.BigEndian.PutUint32(block[len(seed):], ctr)
		h := sha256.Sum256(block)
		for j := 0; j+4 <= len(h) && i < dims; j, i = j+4, i+1 {
			f := float32(int32(binary.BigEndian.Uint32(h[j:]))) / (1 << 31)
			v[i] = f
			sum += float64(f) * float64(f)
		}
	}
	if sum == 0 {
		return v
	}
	inv := float32(1 / math.Sqrt(sum))
	for i := range v {
		v[i] *= inv
	}
	return v
}

// appendVector appends v as a JSON array of numbers, or as the base64 of its
// little-endian float32 bytes when b64 is set.
func appendVector(dst []byte, v []float32, b64 bool) []byte {
	if b64 {
		raw := make([]byte, 4*len(v))
		for i, f := range v {
			binary.LittleEndian.PutUint32(raw[4*i:], math.Float32bits(f))
		}
		dst = append(dst, '"')
		dst = base64.StdEncoding.AppendEncode(dst, raw)
		return append(dst, '"')
	}
	dst = append(dst, '[')
	for i, f := range v {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = strconv.AppendFloat(dst, float64(f), 'g', -1, 32)
	}
	return append(dst, ']')
}

// embedRequest is a parsed embeddings call.
type embedRequest struct {
	model  string
	inputs []embedInput
	dims   int
	b64    bool
	words  int
}

// parseEmbed reads the body of any embeddings endpoint. field names the input
// field: "input" or, for the legacy Ollama call, "prompt".
func (c *call) parseEmbed(field string) (*embedRequest, bool) {
	s := c.s
	raw, err := decodeObject(c.body)
	if err != nil {
		c.failParse(err)
		return nil, false
	}
	model, ok := c.checkModel(str(raw["model"]))
	if !ok {
		return nil, false
	}
	c.model = model
	inputs, err := s.embedInputs(raw[field])
	if err != nil {
		c.failParse(err)
		return nil, false
	}
	if len(inputs) == 0 {
		c.fail(http.StatusBadRequest, fmt.Sprintf("'%s' is a required property", field), field, "")
		return nil, false
	}
	req := &embedRequest{model: model, inputs: inputs, dims: embedDimsFor(model)}
	for _, in := range inputs {
		if in.tokens > 0 {
			req.words += in.tokens
			continue
		}
		if in.text == "" && c.style != styleOllama {
			c.fail(http.StatusBadRequest, "Invalid 'input': empty string. Expected a string with minimum length 1, but got an empty string instead.", "input", "")
			return nil, false
		}
		req.words += max(1, wordCount(in.text))
	}
	if d, ok := intOf(raw["dimensions"]); ok {
		if d < 1 || d > maxEmbedDims {
			c.fail(http.StatusBadRequest, fmt.Sprintf("Invalid 'dimensions': integer must be between 1 and %d.", maxEmbedDims), "dimensions", "")
			return nil, false
		}
		req.dims = d
	}
	req.b64 = str(raw["encoding_format"]) == "base64"
	return req, true
}

func intOf(raw json.RawMessage) (int, bool) {
	var n int
	if json.Unmarshal(raw, &n) != nil {
		return 0, false
	}
	return n, true
}

// embeddings serves the OpenAI-shaped POST /v1/embeddings. The vectors are
// streamed out one at a time so a full request never builds one large buffer.
func (s *Server) embeddings(c *call) {
	req, ok := c.parseEmbed("input")
	if !ok {
		return
	}
	w := c.w
	w.Header().Set("Content-Type", c.contentType())
	w.WriteHeader(http.StatusOK)
	var buf []byte
	buf = append(buf, `{"object":"list","data":[`...)
	for i, in := range req.inputs {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, `{"object":"embedding","index":`...)
		buf = strconv.AppendInt(buf, int64(i), 10)
		buf = append(buf, `,"embedding":`...)
		buf = appendVector(buf, s.vector(req.model, in.text, req.dims), req.b64)
		buf = append(buf, '}')
		if _, err := w.Write(buf); err != nil {
			return
		}
		buf = buf[:0]
	}
	buf = append(buf, `],"model":`...)
	buf = append(buf, marshalNoNL(req.model)...)
	buf = append(buf, `,"usage":{"prompt_tokens":`...)
	buf = strconv.AppendInt(buf, int64(req.words), 10)
	buf = append(buf, `,"total_tokens":`...)
	buf = strconv.AppendInt(buf, int64(req.words), 10)
	buf = append(buf, "}}\n"...)
	_, _ = w.Write(buf)
}

func marshalNoNL(v any) []byte {
	b := marshal(v)
	return b[:len(b)-1]
}

// ollamaEmbed serves POST /api/embed.
func (s *Server) ollamaEmbed(c *call) {
	req, ok := c.parseEmbed("input")
	if !ok {
		return
	}
	w := c.w
	w.Header().Set("Content-Type", c.contentType())
	w.WriteHeader(http.StatusOK)
	buf := append([]byte(nil), `{"model":`...)
	buf = append(buf, marshalNoNL(req.model)...)
	buf = append(buf, `,"embeddings":[`...)
	for i, in := range req.inputs {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = appendVector(buf, s.vector(req.model, in.text, req.dims), false)
		if _, err := w.Write(buf); err != nil {
			return
		}
		buf = buf[:0]
	}
	d := s.durations(req.model, req.words, 0)
	buf = append(buf, fmt.Sprintf(`],"total_duration":%d,"load_duration":%d,"prompt_eval_count":%d}`+"\n",
		d.total, d.load, req.words)...)
	_, _ = w.Write(buf)
}

// ollamaEmbeddings serves the legacy POST /api/embeddings, one prompt.
func (s *Server) ollamaEmbeddings(c *call) {
	req, ok := c.parseEmbed("prompt")
	if !ok {
		return
	}
	buf := append([]byte(nil), `{"embedding":`...)
	buf = appendVector(buf, s.vector(req.model, req.inputs[0].text, req.dims), false)
	buf = append(buf, "}\n"...)
	c.w.Header().Set("Content-Type", c.contentType())
	c.w.WriteHeader(http.StatusOK)
	_, _ = c.w.Write(buf)
}
