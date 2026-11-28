package publicedge

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The answers in this file were compared with Ollama 0.40.11: status, headers, member order and error text.
const gatewayOllamaVersion = "0.40.11"

type gatewayOllamaModel struct {
	tag, family, params, quant        string
	count, size                       int64 // parameters, bytes on disk
	context, embedding, blocks, heads int
	caps                              string // JSON list
}

// gatewayOllamaModels describes each local-style name of gatewayModelList the way Ollama reports a pulled model.
// Hosted API names are not Ollama models and do not resolve on Ollama routes.
var gatewayOllamaModels = [...]gatewayOllamaModel{
	{"llama3.3:70b", "llama", "70.6B", "Q4_K_M", 70553706560, 42520413916, 131072, 8192, 80, 64, `["completion","tools"]`},
	{"deepseek-r1:70b", "llama", "70.6B", "Q4_K_M", 70553706560, 42520397704, 131072, 8192, 80, 64, `["completion","thinking"]`},
	{"qwen2.5-coder:32b", "qwen2", "32.8B", "Q4_K_M", 32763876352, 19851349856, 32768, 5120, 64, 40, `["completion","tools","insert"]`},
	{"qwen3:32b", "qwen2", "32B", "Q4_K_M", 32000000000, 20000000000, 40960, 3584, 48, 48, `["completion","tools"]`},
	{"qwen3-coder:30b", "qwen2", "30B", "Q4_K_M", 30000000000, 18000000000, 40960, 3584, 48, 48, `["completion","tools"]`},
	{"gemma3:27b", "gemma3", "27B", "Q4_K_M", 27000000000, 16200000000, 8192, 4096, 42, 42, `["completion"]`},
	{"phi4:14b", "phi3", "14B", "Q4_K_M", 14000000000, 9100000000, 16384, 5120, 40, 40, `["completion"]`},
	{"gemma3:12b", "gemma3", "12B", "Q4_K_M", 12000000000, 7200000000, 8192, 4096, 40, 40, `["completion"]`},
	{"llama3.1:8b", "llama", "8.0B", "Q4_K_M", 8030261312, 4920753328, 131072, 4096, 32, 32, `["completion","tools"]`},
	{"deepseek-r1:8b", "llama", "8.0B", "Q4_K_M", 8030261248, 4920738407, 131072, 4096, 32, 32, `["completion","thinking"]`},
	{"qwen3:8b", "qwen2", "8B", "Q4_K_M", 8000000000, 5200000000, 40960, 4096, 32, 32, `["completion","tools"]`},
	{"qwen2.5:7b", "qwen2", "7.6B", "Q4_K_M", 7615616512, 4683087332, 32768, 3584, 28, 28, `["completion","tools"]`},
	{"mistral:7b", "llama", "7.2B", "Q4_K_M", 7248023552, 4372824384, 32768, 4096, 32, 32, `["completion","tools"]`},
	{"gemma3:4b", "gemma3", "4B", "Q4_K_M", 4000000000, 2400000000, 8192, 4096, 32, 32, `["completion"]`},
	{"gemma3:1b", "gemma3", "1B", "Q4_K_M", 1000000000, 600000000, 8192, 2048, 18, 18, `["completion"]`},
	{"deepseek-v3:671b", "llama", "671B", "MXFP4", 671000000000, 404000000000, 163840, 8192, 160, 128, `["completion","tools"]`},
	{"qwen3-coder:480b", "qwen2", "480B", "Q4_K_M", 480000000000, 290000000000, 40960, 3584, 160, 160, `["completion","tools"]`},
	{"llama4:128x17b", "llama", "403B", "Q4_K_M", 403000000000, 242000000000, 131072, 8192, 128, 128, `["completion","tools"]`},
	{"gpt-oss:120b", "llama", "120B", "MXFP4", 120000000000, 72000000000, 131072, 8192, 96, 80, `["completion","thinking"]`},
	{"llama4:16x17b", "llama", "50B", "Q4_K_M", 50000000000, 30000000000, 131072, 8192, 80, 64, `["completion","tools"]`},
	{"gpt-oss:20b", "llama", "20B", "MXFP4", 20000000000, 12000000000, 131072, 8192, 48, 40, `["completion","thinking"]`},
	{"local-instruct-8b:latest", "llama", "8.0B", "Q4_K_M", 8030261312, 4920738912, 131072, 4096, 32, 32, `["completion","tools"]`},
	{"nomic-embed-text:latest", "nomic-bert", "137M", "F16", 136727040, 274302450, 2048, 768, 12, 12, `["embedding"]`},
}

// gatewayOllamaTag gives a model the tag form Ollama reports.
func gatewayOllamaTag(m string) string {
	if strings.Contains(m, ":") {
		return m
	}
	return m + ":latest"
}

func gatewayOllamaLookup(name string) *gatewayOllamaModel {
	tag := gatewayOllamaTag(name)
	for i := range gatewayOllamaModels {
		if gatewayOllamaModels[i].tag == tag {
			return &gatewayOllamaModels[i]
		}
	}
	return nil
}

// listed is the name in gatewayModelList, which is the only form the span carries.
func (m *gatewayOllamaModel) listed() string { return strings.TrimSuffix(m.tag, ":latest") }

func (m *gatewayOllamaModel) digest() string { return fmt.Sprintf("%x", sha256.Sum256([]byte(m.tag))) }

// modified is a fixed pull time for each tag, between August and November 2026.
func (m *gatewayOllamaModel) modified() string {
	sum := sha256.Sum256([]byte(m.tag))
	return time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC).Add(time.Duration(binary.BigEndian.Uint32(sum[:4])) * 1900 * time.Microsecond).Format(time.RFC3339Nano)
}

// details is the "details" object; /api/tags also reports the runner members.
func (m *gatewayOllamaModel) details(runner bool) string {
	s := fmt.Sprintf(`{"parent_model":"","format":"gguf","family":"%[1]s","families":["%[1]s"],"parameter_size":"%s","quantization_level":"%s"`, m.family, m.params, m.quant)
	if runner {
		s += fmt.Sprintf(`,"context_length":%d,"embedding_length":%d,"runner":"llamacpp"`, m.context, m.embedding)
	}
	return s + "}"
}

func gatewayOllamaTags(w http.ResponseWriter, _ *http.Request) {
	entries := make([]string, len(gatewayOllamaModels))
	for i := range gatewayOllamaModels {
		m := &gatewayOllamaModels[i]
		entries[i] = fmt.Sprintf(`{"name":"%[1]s","model":"%[1]s","modified_at":"%s","size":%d,"digest":"%s","details":%s,"capabilities":%s}`,
			m.tag, m.modified(), m.size, m.digest(), m.details(true), m.caps)
	}
	gatewayReply(w, 200, gatewayJSONUTF8, `{"models":[`+strings.Join(entries, ",")+`]}`)
}

// gatewayOllamaPS shows the largest model as loaded in GPU memory.
func gatewayOllamaPS(w http.ResponseWriter, _ *http.Request) {
	m := &gatewayOllamaModels[0]
	vram := m.size + m.size/16 + 1<<30
	gatewayReply(w, 200, gatewayJSONUTF8, fmt.Sprintf(`{"models":[{"name":"%[1]s","model":"%[1]s","size":%[2]d,"digest":"%s","details":%s,"expires_at":"%s","size_vram":%[2]d,"context_length":8192,"runner":"llamacpp"}]}`,
		m.tag, vram, m.digest(), m.details(false), time.Now().UTC().Add(4*time.Minute).Format(time.RFC3339Nano)))
}

func gatewayOllamaError(w http.ResponseWriter, status int, msg string) {
	gatewayReply(w, status, gatewayJSONUTF8, `{"error":`+gatewayQ(msg)+`}`)
}

// gatewayOllamaRead decodes a request body and answers an error in Ollama's words. Ollama is a Go program too, so
// the text of a JSON syntax error is the same.
func gatewayOllamaRead(w http.ResponseWriter, r *http.Request) (map[string]json.RawMessage, bool) {
	var obj map[string]json.RawMessage
	err := json.NewDecoder(r.Body).Decode(&obj)
	var limit *http.MaxBytesError
	var kind *json.UnmarshalTypeError
	switch {
	case err == nil:
		if obj == nil {
			obj = map[string]json.RawMessage{}
		}
		return obj, true
	case errors.As(err, &limit):
		gatewayOllamaError(w, http.StatusRequestEntityTooLarge, "request body too large")
	case errors.Is(err, io.EOF):
		gatewayOllamaError(w, 400, "missing request body")
	case errors.As(err, &kind):
		gatewayOllamaError(w, 400, "invalid request body")
	default:
		gatewayOllamaError(w, 400, err.Error())
	}
	return nil, false
}

// gatewayOllamaStream follows Ollama's default: a stream unless the client sets "stream": false.
func gatewayOllamaStream(w http.ResponseWriter, obj map[string]json.RawMessage) (stream, ok bool) {
	if stream, ok = gatewayStream(obj["stream"]); !ok {
		gatewayOllamaError(w, 400, "json: cannot unmarshal string into Go struct field .stream of type bool")
	}
	return stream || obj["stream"] == nil, ok
}

// gatewayOllamaName reads the model of a request; older clients send it as "name".
func gatewayOllamaName(obj map[string]json.RawMessage) string {
	raw := obj["model"]
	if raw == nil {
		raw = obj["name"]
	}
	var name string
	_ = json.Unmarshal(raw, &name)
	return name[:min(len(name), 128)]
}

type gatewayOllamaReply func(w http.ResponseWriter, m *gatewayOllamaModel, stream bool, obj map[string]json.RawMessage)

// gatewayOllamaManage serves a management route. reply gets the model; when listed is false it gets nil for a name
// that is not in the table. The gateway stores nothing: a created model does not list and a deleted one stays.
func gatewayOllamaManage(listed bool, reply gatewayOllamaReply) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		obj, ok := gatewayOllamaRead(w, r)
		if !ok {
			return
		}
		stream, ok := gatewayOllamaStream(w, obj)
		if !ok {
			return
		}
		name := gatewayOllamaName(obj)
		if name == "" {
			gatewayOllamaError(w, 400, "model is required")
			return
		}
		m := gatewayOllamaLookup(name)
		if m == nil && listed {
			gatewayOllamaError(w, 404, "model '"+name+"' not found")
			return
		}
		if m != nil {
			gatewayTrace(r, obj, m.listed(), stream)
		}
		reply(w, m, stream, obj)
	}
}

// gatewayOllamaSteps sends progress lines and a last line as NDJSON, or only the last line when the client set "stream": false.
func gatewayOllamaSteps(w http.ResponseWriter, stream bool, status int, steps, last string) {
	if stream {
		gatewayReply(w, 200, "application/x-ndjson", steps+last+"\n")
		return
	}
	gatewayReply(w, status, gatewayJSONUTF8, last)
}

func gatewayOllamaCreate(w http.ResponseWriter, _ *gatewayOllamaModel, stream bool, _ map[string]json.RawMessage) {
	gatewayOllamaSteps(w, stream, 200, "", `{"status":"success"}`)
}

func gatewayOllamaDelete(w http.ResponseWriter, _ *gatewayOllamaModel, _ bool, _ map[string]json.RawMessage) {
	w.WriteHeader(200)
}

// gatewayOllamaPull reports a listed model as present. Another name fails as it does when the registry does not have it;
// without a stream Ollama answers 500 there, and the gateway answers 404 so that the span is not an error.
func gatewayOllamaPull(w http.ResponseWriter, m *gatewayOllamaModel, stream bool, _ map[string]json.RawMessage) {
	const start = `{"status":"pulling manifest"}` + "\n"
	if m == nil {
		gatewayOllamaSteps(w, stream, 404, start, `{"error":"pull model manifest: file does not exist"}`)
		return
	}
	d := m.digest()
	gatewayOllamaSteps(w, stream, 200, start+fmt.Sprintf(`{"status":"pulling %s","digest":"sha256:%s","total":%d,"completed":%[3]d}`, d[:12], d, m.size)+"\n"+
		`{"status":"verifying sha256 digest"}`+"\n"+`{"status":"writing manifest"}`+"\n", `{"status":"success"}`)
}

func gatewayOllamaShow(w http.ResponseWriter, m *gatewayOllamaModel, _ bool, _ map[string]json.RawMessage) {
	license := "\n                                 Apache License\n                           Version 2.0, January 2004\n                        http://www.apache.org/licenses/\n"
	template := "{{ .Prompt }}"
	parameters := ""
	switch {
	case strings.HasPrefix(m.tag, "deepseek"):
		license = "MIT License\n\nCopyright (c) 2023 DeepSeek\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the \"Software\"), to deal\nin the Software without restriction.\n"
	case strings.HasPrefix(m.tag, "llama"), strings.HasPrefix(m.tag, "local"):
		license = "META LLAMA 3 COMMUNITY LICENSE AGREEMENT\n\nMeta Llama 3 Version Release Date: April 18, 2024\n"
	}
	switch m.family {
	case "llama":
		template = "{{- range .Messages }}<|start_header_id|>{{ .Role }}<|end_header_id|>\n\n{{ .Content }}<|eot_id|>\n{{- end }}<|start_header_id|>assistant<|end_header_id|>\n\n"
		parameters = "stop                           \"<|start_header_id|>\"\nstop                           \"<|end_header_id|>\"\nstop                           \"<|eot_id|>\""
	case "qwen2":
		template = "{{- range .Messages }}<|im_start|>{{ .Role }}\n{{ .Content }}<|im_end|>\n{{ end }}<|im_start|>assistant\n"
	}
	fileType := 15
	if m.quant == "F16" {
		fileType = 1
	}
	body, _ := json.Marshal(struct {
		License        string          `json:"license"`
		Modelfile      string          `json:"modelfile"`
		Parameters     string          `json:"parameters,omitempty"`
		Template       string          `json:"template"`
		TemplateSource string          `json:"template_source"`
		Details        json.RawMessage `json:"details"`
		ModelInfo      json.RawMessage `json:"model_info"`
		Capabilities   json.RawMessage `json:"capabilities"`
		ModifiedAt     string          `json:"modified_at"`
	}{license, "# Modelfile generated by \"ollama show\"\n# To build a new Modelfile based on this, replace FROM with:\n# FROM " + m.tag + "\n\nFROM /usr/share/ollama/.ollama/models/blobs/sha256-" + m.digest() + "\nTEMPLATE \"\"\"" + template + "\"\"\"\n",
		parameters, template, "go_template", json.RawMessage(m.details(false)),
		json.RawMessage(fmt.Sprintf(`{"general.architecture":"%[1]s","general.file_type":%[2]d,"general.parameter_count":%[3]d,"general.quantization_version":2,"general.type":"model","%[1]s.attention.head_count":%[4]d,"%[1]s.block_count":%[5]d,"%[1]s.context_length":%[6]d,"%[1]s.embedding_length":%[7]d,"tokenizer.ggml.merges":null,"tokenizer.ggml.model":"gpt2","tokenizer.ggml.token_type":null,"tokenizer.ggml.tokens":null}`,
			m.family, fileType, m.count, m.heads, m.blocks, m.context, m.embedding)),
		json.RawMessage(m.caps), m.modified()})
	gatewayReply(w, 200, gatewayJSONUTF8, string(body))
}

// gatewayOllamaEmbed serves /api/embed, or the older /api/embeddings when legacy is set.
func gatewayOllamaEmbed(legacy bool) gatewayOllamaReply {
	return func(w http.ResponseWriter, m *gatewayOllamaModel, _ bool, obj map[string]json.RawMessage) {
		if legacy {
			gatewayReply(w, 200, gatewayJSONUTF8, `{"embedding":`+gatewayVector(768, obj["prompt"])+`}`)
			return
		}
		inputs := gatewayInputs(obj["input"])
		vectors := make([]string, len(inputs))
		for i, in := range inputs {
			vectors[i] = gatewayVector(768, in)
		}
		gatewayReply(w, 200, gatewayJSONUTF8, fmt.Sprintf(`{"model":"%s","embeddings":[%s],"total_duration":%d,"load_duration":%d,"prompt_eval_count":%d}`,
			m.tag, strings.Join(vectors, ","), 14000000+rand.N(4000000), 900000+rand.N(400000), 2*len(inputs)))
	}
}

// gatewayInputs returns the inputs of an embedding request: one string, or at most 32 members of a list.
func gatewayInputs(raw json.RawMessage) []json.RawMessage {
	if gatewayText(raw) {
		return []json.RawMessage{raw}
	}
	var list []json.RawMessage
	_ = json.Unmarshal(raw, &list)
	return list[:min(len(list), 32)]
}

// gatewayVector is a unit vector of n values that depends only on seed, so one input always gets one embedding.
func gatewayVector(n int, seed []byte) string {
	h := fnv.New32a()
	_, _ = h.Write(seed)
	x := h.Sum32() | 1
	values := make([]float64, n)
	var sum float64
	for i := range values {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		values[i] = float64(int32(x)) / (1 << 31)
		sum += values[i] * values[i]
	}
	norm := math.Sqrt(sum)
	b := append(make([]byte, 0, n*13), '[')
	for i, v := range values {
		if i > 0 {
			b = append(b, ',')
		}
		b = strconv.AppendFloat(b, v/norm, 'f', -1, 32)
	}
	return string(append(b, ']'))
}

// gatewayOllamaContext stands for the token list that /api/generate returns for a follow-up request.
func gatewayOllamaContext(n int) string {
	b := []byte{'['}
	x := uint32(n)*2654435761 | 1
	for i := range n {
		if i > 0 {
			b = append(b, ',')
		}
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b = strconv.AppendUint(b, uint64(x%128000), 10)
	}
	return string(append(b, ']'))
}

// gatewayOllama serves /api/generate and /api/chat with a rule-based reply; see answer.go.
func gatewayOllama(chat bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		obj, ok := gatewayOllamaRead(w, r)
		if !ok {
			return
		}
		stream, ok := gatewayOllamaStream(w, obj)
		if !ok {
			return
		}
		name := gatewayOllamaName(obj)
		m := gatewayOllamaLookup(name)
		if m == nil || name == "" {
			gatewayOllamaError(w, 404, "model '"+name+"' not found")
			return
		}
		gatewayTrace(r, obj, m.listed(), stream)
		if !strings.Contains(m.caps, "completion") {
			kind := "generate"
			if chat {
				kind = "chat"
			}
			gatewayOllamaError(w, 400, `"`+m.tag+`" does not support `+kind)
			return
		}
		// line is one answer object; tail closes it.
		line := func(text, thinking, tail string) string {
			if thinking != "" {
				thinking = `,"thinking":` + gatewayQ(thinking)
			}
			content := `"response":` + gatewayQ(text) + thinking
			if chat {
				content = `"message":{"role":"assistant","content":` + gatewayQ(text) + thinking + `}`
			}
			return `{"model":"` + m.tag + `","created_at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `",` + content + tail
		}
		contentType := gatewayJSONUTF8
		if stream {
			contentType = "application/x-ndjson"
		}
		var prompt string
		if !chat {
			prompt = gatewayContentText(obj["prompt"])
		}
		if chat && !gatewayArray(obj["messages"]) || !chat && prompt == "" {
			// A request without a prompt only loads the model.
			gatewayOllamaSteps(w, stream, 200, "", line("", "", `,"done":true,"done_reason":"load"}`))
			return
		}
		var options map[string]json.RawMessage
		_ = json.Unmarshal(obj["options"], &options)
		think := strings.Contains(m.caps, "thinking") && string(bytes.TrimSpace(obj["think"])) != "false"
		limit := gatewayLimit(options, "num_predict")
		var a gatewayAnswerText
		if chat {
			a = gatewayChatAnswer(r, m.listed(), obj["messages"], limit, think)
		} else {
			a = gatewayCompose(m.listed(), prompt, limit, think)
		}

		// A larger model is slower: about 9 ms for each token at 8B and 32 ms at 70B.
		tokenTime := 6*time.Millisecond + time.Duration(m.size/1600)
		load := 12*time.Millisecond + rand.N(30*time.Millisecond)
		promptEval := time.Duration(a.promptTokens) * tokenTime / 8
		eval := time.Duration(a.count)*tokenTime + rand.N(tokenTime)
		context := ""
		if !chat {
			context = `,"context":` + gatewayOllamaContext(a.promptTokens+a.count)
		}
		tail := fmt.Sprintf(`,"done":true,"done_reason":"%s"%s,"total_duration":%d,"load_duration":%d,"prompt_eval_count":%d,"prompt_eval_cached_count":0,"prompt_eval_duration":%d,"eval_count":%d,"eval_duration":%d}`,
			a.reason, context, load+promptEval+eval+rand.N(time.Millisecond), load, a.promptTokens, promptEval, a.count, eval)
		if !stream {
			gatewaySleep(r.Context(), eval)
			gatewayReply(w, 200, contentType, line(strings.Join(a.text, ""), strings.Join(a.thinking, ""), tail))
			return
		}
		w.Header().Set("Content-Type", contentType)
		for _, token := range a.thinking {
			gatewaySleep(r.Context(), tokenTime)
			if !gatewayFlush(w, line("", token, `,"done":false}`)+"\n") {
				return
			}
		}
		for _, token := range a.text {
			gatewaySleep(r.Context(), tokenTime)
			if !gatewayFlush(w, line(token, "", `,"done":false}`)+"\n") {
				return
			}
		}
		gatewayFlush(w, line("", "", tail)+"\n")
	}
}
