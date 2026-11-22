package responder

import "strings"

// Task labels. Responses use these safe labels instead of reflecting the
// attacker's prompt.
const (
	TaskGeneral             = "general-inference"
	TaskPromptExtraction    = "prompt-extraction"
	TaskCredentialAccess    = "credential-access"
	TaskShellExecution      = "shell-execution"
	TaskURLExfiltration     = "url-exfiltration"
	TaskToolInvocation      = "tool-invocation"
	TaskInstructionOverride = "instruction-override"
	TaskIndirectInjection   = "indirect-injection"
	TaskPersistence         = "persistence"
)

// maxScan bounds classifier work per request.
const maxScan = 64 << 10

type rule struct {
	task  string
	terms []string
}

// Order is priority: the first matching rule is the primary task.
var rules = []rule{
	{TaskPromptExtraction, []string{
		"system prompt", "developer message", "initial instructions", "your instructions",
		"initial prompt", "repeat the words above", "print your prompt", "reveal your prompt",
		"hidden prompt", "text above", "everything above",
	}},
	{TaskPersistence, []string{
		"crontab", "cron job", "systemd", "shell-rc", ".bashrc", ".zshrc", ".profile",
		"authorized_keys", "launchd", "persistence", "persist across", "rc.local", "startup script",
	}},
	{TaskCredentialAccess, []string{
		"credential", "secret", "api key", "api_key", "apikey", ".env", "password", "passwd",
		"/etc/shadow", "id_rsa", "id_ed25519", "ssh key", "private key", "aws_access", "kubeconfig",
		".aws/", ".ssh/", "access token", "bearer token", "auth token", "cookie",
	}},
	{TaskShellExecution, []string{
		"argv", "bash", " sh -c", "/bin/sh", "shell", "execute", "run the command", "run command",
		"terminal", "powershell", "cmd.exe", "rm -rf", "chmod ", "sudo ", "subprocess", "os.system",
		"wget ", "curl ", "nc -e", "reverse shell",
	}},
	{TaskURLExfiltration, []string{
		"http://", "https://", "exfil", "webhook", "fetch ", "fetch(", "upload to", "send it to",
		"post it to", "ngrok", "pastebin", "dns lookup",
	}},
	{TaskInstructionOverride, []string{
		"ignore previous", "ignore all previous", "ignore the above", "ignore your", "disregard",
		"forget your instructions", "forget all previous", "override", "jailbreak", "you are now",
		"dan mode", "developer mode", "no restrictions", "new instructions",
	}},
}

// toolTerms mark a request that asks the server-side model to call a tool.
var toolTerms = []string{
	"call the", "invoke", "use the tool", "use your tool", "function call", "tool call",
	"call function", "run the tool", "use the function",
}

// injectionTerms mark instructions addressed to a model inside untrusted
// content such as tool output or retrieved documents.
var injectionTerms = []string{
	"ignore previous", "ignore all", "ignore the above", "disregard", "you are now",
	"new instructions", "system:", "assistant:", "important instruction", "do not tell the user",
	"instructions to the ai", "ai assistant must", "as an ai", "override",
}

// Input is the normalized content of one inference request.
type Input struct {
	Text      string // operator-authored text: user/system/developer messages, prompt
	Untrusted string // tool results, function outputs and other third-party content
	HasTools  bool   // the request declares tools or functions
	ToolForce bool   // tool_choice forces a function
}

// Classification is the primary task and every matched label.
type Classification struct {
	Task   string   `json:"task"`
	Labels []string `json:"labels,omitempty"`
}

// Classify assigns a safe task label. It never returns request text.
func Classify(in Input) Classification {
	text := normalize(in.Text)
	untrusted := normalize(in.Untrusted)
	var c Classification
	add := func(t string) {
		for _, l := range c.Labels {
			if l == t {
				return
			}
		}
		c.Labels = append(c.Labels, t)
	}
	if containsAny(untrusted, injectionTerms) {
		add(TaskIndirectInjection)
	}
	for _, r := range rules {
		if containsAny(text, r.terms) {
			add(r.task)
		}
	}
	if in.ToolForce || (in.HasTools && containsAny(text, toolTerms)) {
		add(TaskToolInvocation)
	}
	if len(c.Labels) == 0 {
		c.Task = TaskGeneral
		return c
	}
	c.Task = c.Labels[0]
	return c
}

func containsAny(s string, terms []string) bool {
	for _, t := range terms {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}

// normalize lowercases, drops invisible format characters and collapses
// whitespace so trivial obfuscation does not hide a task.
func normalize(s string) string {
	if len(s) > maxScan {
		s = s[:maxScan]
	}
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r == '\u200b' || r == '\u200c' || r == '\u200d' || r == '\u2060' || r == '\ufeff' || r == '\u00ad':
			continue
		case r == '\n' || r == '\t' || r == '\r' || r == ' ':
			if !space {
				b.WriteByte(' ')
			}
			space = true
			continue
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}
