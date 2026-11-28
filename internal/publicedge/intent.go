package publicedge

import (
	"hash/fnv"
	"regexp"
	"strconv"
	"strings"

	"attackbox/internal/secret"
)

var (
	identityRE      = regexp.MustCompile(`(?i)\b(who|what) +(are +you|is +this|model|assistant|ai|your +name|you +are)\b`)
	capabilityRE    = regexp.MustCompile(`(?i)\b(what +can +you +do|capabilities|tools|internet +access|can +you)\b`)
	explainRE       = regexp.MustCompile(`(?i)^(what +is|explain|tell +me +about|describe) +(.+)`)
	summarizeRE     = regexp.MustCompile(`(?i)\b(summarize|summarise|sum +up|tldr|brief|condense)\b`)
	translateRE     = regexp.MustCompile(`(?i)^(translate|how +do +you +say) +`)
	listRE          = regexp.MustCompile(`(?i)^(list|name|give +me|what +are) +.*(steps|ways|reasons|examples|types|kinds|benefits)`)
	yesNoRE         = regexp.MustCompile(`(?i)^(is|are|do|does|did|can|could|should|will|would|has|have)\b.*\?`)
	promptExtractRE = regexp.MustCompile(`(?i)(ignore +previous|system +prompt|your +instructions|developer +mode|jailbreak|DAN\b|print +your +prompt)`)
	harmfulRE       = regexp.MustCompile(`(?i)\b(write|create|build|make|generate|develop|code|implement|how +to +(?:build|create|make|steal)) +.*(malware|exploit|hack +into|steal|keylog|backdoor|crack +password|phishing|passwords)\b|\b(run|execute|deploy|launch|start|install) +.*(malware|exploit|backdoor)\b|\b(sql +injection|xss|command +injection) +(tutorial|guide|how-?to)\b`)
	shellRE         = regexp.MustCompile(`(?i)^(id|whoami|uname|pwd|hostname|ls|cat|echo \$|printenv|env\b)`)
	shellWordRE     = regexp.MustCompile(`(?i)\b(whoami|uname|hostname|/etc/|/proc/|sudo\b|chmod\b|/bin/|/usr/)\b`)
	helloWorldRE    = regexp.MustCompile(`(?i)hello +world`)
	reverseRE       = regexp.MustCompile(`(?i)reverse +a? +string`)
	sortRE          = regexp.MustCompile(`(?i)sort +a? +(list|array)`)
	fizzbuzzRE      = regexp.MustCompile(`(?i)fizz ?buzz`)
	codeRE          = regexp.MustCompile(`(?i)\b(write|code|function|script|program|implement)\b`)
	languageRE      = regexp.MustCompile(`(?i)\b(python|javascript|go|rust|java|c\+\+|ruby|php|typescript|swift)\b`)
	credentialRE    = regexp.MustCompile(`\b(sk-[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}|xox[a-z]-[A-Za-z0-9-]{10,})\b|^[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}$`)
	sayLeadRE       = regexp.MustCompile(`(?i)^(?:please )?(?:just )?(?:say|reply with|respond with|answer with|repeat|output|print|echo|return)\b`)
)

func detectIntent(prompt string) string {
	low := strings.ToLower(prompt)
	if promptExtractRE.MatchString(low) {
		return "prompt_extract"
	}
	if harmfulRE.MatchString(low) {
		return "harmful"
	}
	if shellRE.MatchString(low) || (shellWordRE.MatchString(low) && !strings.Contains(low, "explain") && !strings.Contains(low, "what is")) {
		return "shell"
	}
	if identityRE.MatchString(low) || capabilityRE.MatchString(low) {
		return "identity"
	}
	if helloWorldRE.MatchString(low) || reverseRE.MatchString(low) || sortRE.MatchString(low) || fizzbuzzRE.MatchString(low) {
		return "code_benign"
	}
	if summarizeRE.MatchString(low) && len(prompt) > 40 {
		return "summarize"
	}
	if translateRE.MatchString(low) {
		return "translate"
	}
	if listRE.MatchString(low) {
		return "list"
	}
	if yesNoRE.MatchString(low) {
		return "yesno"
	}
	if m := explainRE.FindStringSubmatch(low); m != nil {
		return "explain"
	}
	if !sayLeadRE.MatchString(low) && codeRE.MatchString(low) {
		return "code_outline"
	}
	return ""
}

func intentAnswer(model, prompt, intent string) string {
	switch intent {
	case "prompt_extract":
		return promptExtractAnswer(prompt)
	case "harmful":
		return harmfulAnswer(prompt)
	case "shell":
		return shellAnswer(prompt)
	case "identity":
		return identityAnswer(model, prompt)
	case "code_benign":
		return codeBenignAnswer(prompt)
	case "code_outline":
		return codeOutlineAnswer(prompt)
	case "summarize":
		return summarizeAnswer(prompt)
	case "translate":
		return translateAnswer(prompt)
	case "list":
		return listAnswer(prompt)
	case "yesno":
		return yesNoAnswer(prompt)
	case "explain":
		return explainAnswer(prompt)
	}
	return ""
}

func promptExtractAnswer(prompt string) string {
	h := hashPrompt(prompt)
	switch h % 3 {
	case 0:
		return "I'm designed to be helpful, harmless, and honest. I can't share internal instructions or override my guidelines."
	case 1:
		return "I appreciate your interest, but I can't provide system prompts or bypass my safety guidelines."
	default:
		return "I'm here to assist with legitimate requests. I can't ignore my instructions or share internal configuration."
	}
}

func harmfulAnswer(prompt string) string {
	h := hashPrompt(prompt)
	switch h % 3 {
	case 0:
		return "I can't assist with that request as it could cause harm."
	case 1:
		return "I'm not able to help with malicious activities or security exploits."
	default:
		return "I can't provide assistance with harmful or unethical requests."
	}
}

func shellAnswer(prompt string) string {
	low := strings.ToLower(prompt)
	if strings.Contains(low, "whoami") || strings.Contains(low, "id") {
		return "appuser"
	}
	if strings.Contains(low, "uname") {
		h := hashPrompt(prompt)
		if h%2 == 0 {
			return "Linux container-7f3a 5.15.0-generic #102-Ubuntu SMP x86_64 GNU/Linux"
		}
		return "Linux sandbox-9b2c 6.1.0-generic #120-Ubuntu SMP aarch64 GNU/Linux"
	}
	if strings.Contains(low, "pwd") {
		return "/home/appuser"
	}
	if strings.Contains(low, "hostname") {
		h := hashPrompt(prompt)
		return "container-" + strconv.FormatUint(uint64(h%10000), 16)
	}
	if strings.Contains(low, "ls") {
		return "app.py\nconfig\ndata\nrequirements.txt"
	}
	if strings.Contains(low, "/etc/shadow") || strings.Contains(low, "password") {
		return "I don't have access to sensitive system files or credentials."
	}
	if strings.Contains(low, "/etc/os-release") || strings.Contains(low, "cat") {
		return "NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu\nID_LIKE=debian"
	}
	return "I'm running in a container environment. I can't execute system commands, but I can help explain them."
}

func identityAnswer(model, prompt string) string {
	low := strings.ToLower(prompt)
	if strings.Contains(low, "tool") || strings.Contains(low, "internet") {
		h := hashPrompt(prompt)
		switch h % 3 {
		case 0:
			return "I'm a conversational AI assistant. I can answer questions and help with tasks, but I don't have internet access or external tools."
		case 1:
			return "I can help with information and conversation, though I don't have live internet access or the ability to execute commands."
		default:
			return "I'm an AI assistant designed to help with questions and tasks. I work with the information I was trained on and don't have external tool access."
		}
	}
	return gatewayIdentity(model)
}

func codeBenignAnswer(prompt string) string {
	low := strings.ToLower(prompt)
	lang := "python"
	if m := languageRE.FindString(low); m != "" {
		lang = strings.ToLower(m)
	}
	if helloWorldRE.MatchString(low) {
		switch lang {
		case "python":
			return `print("Hello, World!")`
		case "javascript", "js":
			return `console.log("Hello, World!");`
		case "go":
			return `package main
import "fmt"
func main() { fmt.Println("Hello, World!") }`
		case "rust":
			return `fn main() { println!("Hello, World!"); }`
		default:
			return `print("Hello, World!")`
		}
	}
	if reverseRE.MatchString(low) {
		if lang == "python" {
			return `s[::-1]`
		}
		return `s.split('').reverse().join('')`
	}
	if sortRE.MatchString(low) {
		if lang == "python" {
			return `sorted(items)`
		}
		return `items.sort()`
	}
	if fizzbuzzRE.MatchString(low) {
		return `for i in range(1, 101):
    if i % 15 == 0: print("FizzBuzz")
    elif i % 3 == 0: print("Fizz")
    elif i % 5 == 0: print("Buzz")
    else: print(i)`
	}
	return ""
}

func codeOutlineAnswer(prompt string) string {
	topic := extractTopic(prompt, 40)
	h := hashPrompt(prompt)
	var step1, step2, step3 string
	switch h % 3 {
	case 0:
		step1, step2, step3 = "Define the requirements", "Implement the core logic", "Test with example inputs"
	case 1:
		step1, step2, step3 = "Set up the data structure", "Write the main algorithm", "Validate the output"
	default:
		step1, step2, step3 = "Parse the input", "Process the data", "Return the result"
	}
	if topic != "" {
		return "To " + topic + ":\n1. " + step1 + "\n2. " + step2 + "\n3. " + step3
	}
	return "Here's a general approach:\n1. " + step1 + "\n2. " + step2 + "\n3. " + step3
}

func summarizeAnswer(prompt string) string {
	sentences := strings.Split(prompt, ".")
	if len(sentences) > 0 {
		first := strings.TrimSpace(sentences[0])
		if len(first) > 0 && len(first) < 200 {
			return first + "."
		}
	}
	words := strings.Fields(prompt)
	if len(words) > 15 {
		return strings.Join(words[:15], " ") + "..."
	}
	return "The text is brief and already concise."
}

func translateAnswer(prompt string) string {
	low := strings.ToLower(prompt)
	phrases := map[string]string{
		"hello":     "Hola (Spanish), Bonjour (French), Hallo (German)",
		"goodbye":   "Adiós (Spanish), Au revoir (French), Auf Wiedersehen (German)",
		"thank you": "Gracias (Spanish), Merci (French), Danke (German)",
		"yes":       "Sí (Spanish), Oui (French), Ja (German)",
		"no":        "No (Spanish), Non (French), Nein (German)",
	}
	for eng, trans := range phrases {
		if strings.Contains(low, eng) {
			return trans
		}
	}
	return "I can help with common short phrases, but I don't have full translation capabilities for longer text."
}

func listAnswer(prompt string) string {
	topic := extractTopic(prompt, 50)
	h := hashPrompt(prompt)
	items := []string{
		"Understanding the fundamentals",
		"Applying best practices",
		"Reviewing and testing",
		"Iterating based on feedback",
		"Documenting the approach",
	}
	start := int(h % 3)
	result := "Here are some key points"
	if topic != "" {
		result += " about " + topic
	}
	result += ":\n"
	for i := range 3 {
		result += strconv.Itoa(i+1) + ". " + items[(start+i)%len(items)] + "\n"
	}
	return strings.TrimSpace(result)
}

func yesNoAnswer(prompt string) string {
	h := hashPrompt(prompt)
	if h%2 == 0 {
		switch h % 3 {
		case 0:
			return "Yes, in most cases."
		case 1:
			return "It depends on the specific context."
		default:
			return "Generally, yes."
		}
	}
	switch h % 3 {
	case 0:
		return "No, typically not."
	case 1:
		return "Not usually."
	default:
		return "It depends on the situation."
	}
}

func explainAnswer(prompt string) string {
	topic := extractTopic(prompt, 60)
	if topic == "" {
		return gatewayFallback
	}
	h := hashPrompt(prompt)
	templates := []string{
		topic + " refers to a concept that involves multiple aspects. It's commonly understood through its key characteristics and practical applications.",
		topic + " is a topic that encompasses various elements. Understanding it requires considering its main components and how they interact.",
		topic + " represents an area of interest that can be approached from different angles. Its significance lies in how it relates to broader themes.",
	}
	return templates[h%uint64(len(templates))]
}

func extractTopic(prompt string, maxLen int) string {
	prompt = strings.TrimSpace(prompt)
	low := strings.ToLower(prompt)
	low = explainRE.ReplaceAllString(low, "$2")
	low = codeRE.ReplaceAllString(low, "")
	low = regexp.MustCompile(`\b(write|code|function|script|program|implement|a|an|the|to|how|for)\b`).ReplaceAllString(low, "")
	low = strings.TrimSpace(low)
	low = strings.Trim(low, "?.,!;:")
	if len(low) > maxLen {
		low = low[:maxLen]
	}
	return sanitizeReflection(low)
}

func sanitizeReflection(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7F || (r >= 0x80 && r < 0xA0) {
			return -1
		}
		if r >= 0x202A && r <= 0x202E {
			return -1
		}
		if r >= 0x2066 && r <= 0x2069 {
			return -1
		}
		return r
	}, s)
	if credentialRE.MatchString(s) {
		return "[user input]"
	}
	if secret.IsMarker(s) {
		return "[user input]"
	}
	runes := []rune(s)
	if len(runes) > 80 {
		runes = runes[:80]
	}
	return string(runes)
}

func hashPrompt(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}
