package publicedge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The gateway runs no model. gatewayAnswer picks a fixed reply by rule, so that a client that checks a model with a
// short prompt gets the reply a model usually gives. The rules read the prompt; they never run it or send it on.

const gatewayGreeting = "Hello! How can I assist you today?"
const gatewayFallback = "I'm here to help! Could you please provide more details about what you'd like to know or discuss?"
const gatewayThought = "Okay, the user sent a short message. I should respond in a friendly way and offer my help."

// gatewayExact maps a whole prompt, in lower case and without end punctuation, to its reply.
var gatewayExact = map[string]string{
	"hi": gatewayGreeting, "hello": gatewayGreeting, "hey": gatewayGreeting, "hi there": gatewayGreeting, "hello there": gatewayGreeting,
	"hey there": gatewayGreeting, "yo": gatewayGreeting, "hola": gatewayGreeting, "good morning": gatewayGreeting, "test": gatewayGreeting,
	"testing": gatewayGreeting, "hello world": gatewayGreeting, "ping": "Pong! How can I help you today?", "say hello": "Hello!", "say hi": "Hi!",
}

// gatewayAnswers gives a reply to a prompt that holds every part.
var gatewayAnswers = [...]struct {
	parts []string
	reply string
}{
	{[]string{"hello", "one word"}, "Hello."},
	{[]string{"capital", "france"}, "The capital of France is Paris."},
	{[]string{"sky", "blue"}, "The sky appears blue because of a phenomenon called Rayleigh scattering. Sunlight contains all the colors of the rainbow, and as it passes through Earth's atmosphere, the shorter blue wavelengths are scattered in all directions by gas molecules far more than the longer red wavelengths. That scattered blue light reaches your eyes from every part of the sky."},
	{[]string{"joke"}, "Why don't scientists trust atoms? Because they make up everything!"},
}

var gatewaySayRE = regexp.MustCompile(`(?i)^(?:please )?(?:just )?(?:say|reply with|respond with|answer with|repeat after me|repeat|output|print|echo|return)\b[ :,]*(?:(?:only|exactly|just|back|the word|the words|the phrase|the following|this)\b[ :,]*)*(.+)$`)
var gatewaySayEndRE = regexp.MustCompile(`(?i)[ ,]+(?:and nothing else|only|exactly|please)$`)
var gatewaySayTextRE = regexp.MustCompile(`^[A-Za-z0-9 ,.!?'_-]{1,60}$`)
var gatewaySayOpenRE = regexp.MustCompile(`(?i)^(?:something|anything|what|how|why|a|an|me|more|it|that)\b`)
var gatewaySumRE = regexp.MustCompile(`(\d{1,6}) ?([-+*x/]) ?(\d{1,6})`)
var gatewayTokenRE = regexp.MustCompile(`\s*(?:[\pL\pN]+(?:'\pL+)?|[^\s\pL\pN])`)

func gatewayAnswer(model, prompt string) string {
	p := strings.Join(strings.Fields(prompt), " ")
	if len(p) > 200 {
		return gatewayFallback
	}
	const punctuation = " .!?,;:\"'`"
	low := strings.Trim(strings.ToLower(p), punctuation)
	if low == "" {
		return gatewayGreeting
	}
	if reply, ok := gatewayExact[low]; ok {
		return reply
	}
answers:
	for _, a := range gatewayAnswers {
		for _, part := range a.parts {
			if !strings.Contains(low, part) {
				continue answers
			}
		}
		return a.reply
	}
	for _, part := range [...]string{"who are you", "what are you", "which model", "what model", "your name"} {
		if strings.Contains(low, part) {
			return gatewayIdentity(model)
		}
	}
	if m := gatewaySayRE.FindStringSubmatch(p); m != nil {
		text := strings.Trim(gatewaySayEndRE.ReplaceAllString(strings.TrimRight(m[1], " ."), ""), punctuation)
		if gatewaySayTextRE.MatchString(text) && !gatewaySayOpenRE.MatchString(text) {
			return text
		}
	}
	if m := gatewaySumRE.FindStringSubmatch(low); m != nil && len(low) <= 60 {
		a, _ := strconv.Atoi(m[1])
		b, _ := strconv.Atoi(m[3])
		var sum int
		switch m[2] {
		case "+":
			sum = a + b
		case "-":
			sum = a - b
		case "/":
			if b == 0 || a%b != 0 {
				return gatewayFallback
			}
			sum = a / b
		default:
			m[2], sum = "*", a*b
		}
		if strings.Contains(low, "only") || strings.Contains(low, "just") {
			return strconv.Itoa(sum)
		}
		return fmt.Sprintf("%d %s %d = %d", a, m[2], b, sum)
	}
	return gatewayFallback
}

// gatewayIdentity is how the model family of a name usually describes itself.
func gatewayIdentity(model string) string {
	switch {
	case strings.HasPrefix(model, "gpt-"), strings.HasPrefix(model, "o3-"):
		return "I'm ChatGPT, a large language model trained by OpenAI. How can I help you today?"
	case strings.HasPrefix(model, "claude-"):
		return "I'm Claude, an AI assistant made by Anthropic. How can I help you today?"
	case strings.HasPrefix(model, "qwen"):
		return "I am Qwen, a large language model created by Alibaba Cloud. I can answer questions, write text and help with code."
	case strings.HasPrefix(model, "deepseek"):
		return "Greetings! I'm DeepSeek-R1, an artificial intelligence assistant created by DeepSeek. I'm at your service and would be delighted to assist you with any inquiries or tasks you may have."
	case strings.HasPrefix(model, "mistral"):
		return "I'm a large language model trained by Mistral AI. How can I help you today?"
	case strings.HasPrefix(model, "llama"):
		return `I'm an artificial intelligence model known as Llama. Llama stands for "Large Language Model Meta AI."`
	}
	return "I'm an AI assistant. How can I help you today?"
}

// gatewayAnswerText is a reply cut into token-like pieces, as a model sends it.
type gatewayAnswerText struct {
	thinking, text []string
	reason         string // "stop", or "length" when the client's token limit ended the reply
	count          int    // output tokens; a full reply counts one end token
	promptTokens   int
}

// gatewayCompose builds the reply to a prompt. limit > 0 is the client's output token limit; think adds the
// reasoning text that a reasoning model sends first.
func gatewayCompose(model, prompt string, limit int, think bool) gatewayAnswerText {
	a := gatewayAnswerText{reason: "stop", promptTokens: 9 + min(len(strings.Fields(prompt)), 4000)}
	if think {
		a.thinking = gatewayTokenRE.FindAllString(gatewayThought, -1)
	}
	a.text = gatewayTokenRE.FindAllString(gatewayAnswer(model, prompt), -1)
	a.count = len(a.thinking) + len(a.text) + 1
	if limit > 0 && limit < a.count {
		a.reason, a.count = "length", limit
		a.thinking = a.thinking[:min(limit, len(a.thinking))]
		a.text = a.text[:limit-len(a.thinking)]
	}
	return a
}

// gatewayLimit returns the first positive integer member of obj among names, or 0.
func gatewayLimit(obj map[string]json.RawMessage, names ...string) int {
	for _, name := range names {
		var n int
		if json.Unmarshal(obj[name], &n) == nil && n > 0 {
			return n
		}
	}
	return 0
}

func gatewayChatAnswer(r *http.Request, model string, raw json.RawMessage, limit int, think bool) gatewayAnswerText {
	var messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	}
	valid := json.Unmarshal(raw, &messages) == nil
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "user" {
			content := messages[i].Content
			prompt := gatewayContentText(content)
			a := gatewayCompose(model, prompt, limit, think)
			if rec, ok := r.Body.(*captureBodyRecorder); ok && valid && i == len(messages)-1 && prompt != "" {
				rec.chatACK(r, content, prompt, limit, &a)
			}
			return a
		}
	}
	return gatewayCompose(model, "", limit, think)
}

// gatewayContentText reads a string, or the text parts of a content list.
func gatewayContentText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Text string `json:"text"`
	}
	_ = json.Unmarshal(raw, &parts)
	for _, p := range parts {
		s += p.Text + " "
	}
	return s
}

// gatewayQ is s as a JSON string.
func gatewayQ(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// gatewayPace scales the wait that stands for model work; tests set it to 0.
var gatewayPace = 1.0

func gatewaySleep(ctx context.Context, d time.Duration) {
	d = time.Duration(float64(d) * gatewayPace)
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
