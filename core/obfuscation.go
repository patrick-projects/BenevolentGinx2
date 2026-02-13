package core

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"time"
)

const (
	JS_OBFUSCATION_OFF    = "off"
	JS_OBFUSCATION_LOW    = "low"
	JS_OBFUSCATION_MEDIUM = "medium"
	JS_OBFUSCATION_HIGH   = "high"
)

var JS_OBFUSCATION_LEVELS = []string{JS_OBFUSCATION_OFF, JS_OBFUSCATION_LOW, JS_OBFUSCATION_MEDIUM, JS_OBFUSCATION_HIGH}

type Obfuscator struct {
	rng *rand.Rand
}

func NewObfuscator() *Obfuscator {
	return &Obfuscator{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// ObfuscateJS obfuscates JavaScript code based on the given level
func (o *Obfuscator) ObfuscateJS(code string, level string) string {
	if level == JS_OBFUSCATION_OFF || level == "" {
		return code
	}

	// Fresh RNG seed for each call to produce unique output every time
	o.rng = rand.New(rand.NewSource(time.Now().UnixNano()))

	switch level {
	case JS_OBFUSCATION_LOW:
		code = o.randomizeWhitespace(code)
		code = o.encodeStringLiterals(code)
	case JS_OBFUSCATION_MEDIUM:
		code = o.randomizeWhitespace(code)
		code = o.encodeStringLiterals(code)
		code = o.renameVariables(code)
		code = o.injectDeadCode(code)
	case JS_OBFUSCATION_HIGH:
		code = o.randomizeWhitespace(code)
		code = o.encodeStringLiterals(code)
		code = o.renameVariables(code)
		code = o.injectDeadCode(code)
		code = o.wrapInIIFE(code)
	}

	return code
}

// ObfuscateHTML obfuscates HTML content by base64 encoding the body and adding a JS decoder
func (o *Obfuscator) ObfuscateHTML(html []byte) []byte {
	htmlStr := string(html)

	// Only obfuscate if it contains proper HTML structure
	bodyStartRe := regexp.MustCompile(`(?i)(<body[^>]*>)`)
	bodyEndRe := regexp.MustCompile(`(?i)(</\s*body\s*>)`)

	bodyStartMatch := bodyStartRe.FindStringIndex(htmlStr)
	bodyEndMatch := bodyEndRe.FindStringIndex(htmlStr)

	if bodyStartMatch == nil || bodyEndMatch == nil {
		return html
	}

	// Extract the body content
	bodyContent := htmlStr[bodyStartMatch[1]:bodyEndMatch[0]]

	// Base64 encode the body content
	encoded := base64.StdEncoding.EncodeToString([]byte(bodyContent))

	// Generate random variable names for the decoder
	varData := o.randomVarName(8)
	varDecoded := o.randomVarName(8)
	varContainer := o.randomVarName(8)

	// Create the decoder script
	decoder := fmt.Sprintf(`<div id="%s"></div><script>var %s="%s";var %s=atob(%s);document.getElementById("%s").innerHTML=%s;</script>`,
		varContainer, varData, encoded, varDecoded, varData, varContainer, varDecoded)

	// Replace body content with decoder
	result := htmlStr[:bodyStartMatch[1]] + decoder + htmlStr[bodyEndMatch[0]:]

	return []byte(result)
}

// randomizeWhitespace adds random whitespace and newlines
func (o *Obfuscator) randomizeWhitespace(code string) string {
	lines := strings.Split(code, "\n")
	var result []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// Add random indentation
		indent := strings.Repeat(" ", o.rng.Intn(4))
		result = append(result, indent+trimmed)

		// Randomly add blank lines
		if o.rng.Intn(3) == 0 {
			result = append(result, "")
		}
	}
	return strings.Join(result, "\n")
}

// encodeStringLiterals encodes string literals using various techniques
func (o *Obfuscator) encodeStringLiterals(code string) string {
	// Match single and double quoted strings, but skip template literals and regex
	re := regexp.MustCompile(`"([^"\\]{2,})"`)

	return re.ReplaceAllStringFunc(code, func(match string) string {
		// Extract the string content (remove quotes)
		content := match[1 : len(match)-1]

		// Skip very short strings or strings that look like they could break things
		if len(content) < 3 || strings.ContainsAny(content, "{}()[]") {
			return match
		}

		// Only encode ~40% of eligible strings to keep code functional
		if o.rng.Intn(10) > 3 {
			return match
		}

		switch o.rng.Intn(3) {
		case 0:
			// Hex escape encoding
			return o.hexEncodeString(content)
		case 1:
			// String.fromCharCode encoding
			return o.charCodeEncodeString(content)
		case 2:
			// atob (base64) encoding
			return o.atobEncodeString(content)
		}
		return match
	})
}

// hexEncodeString converts a string to hex escape sequence
func (o *Obfuscator) hexEncodeString(s string) string {
	var result strings.Builder
	result.WriteString("\"")
	for _, c := range s {
		if o.rng.Intn(3) == 0 && c >= 32 && c <= 126 {
			// Randomly hex-encode some characters
			result.WriteString(fmt.Sprintf("\\x%02x", c))
		} else {
			result.WriteRune(c)
		}
	}
	result.WriteString("\"")
	return result.String()
}

// charCodeEncodeString converts a string to String.fromCharCode()
func (o *Obfuscator) charCodeEncodeString(s string) string {
	var codes []string
	for _, c := range s {
		codes = append(codes, fmt.Sprintf("%d", c))
	}
	return fmt.Sprintf("String.fromCharCode(%s)", strings.Join(codes, ","))
}

// atobEncodeString converts a string to atob()
func (o *Obfuscator) atobEncodeString(s string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(s))
	return fmt.Sprintf("atob(\"%s\")", encoded)
}

// renameVariables renames local variable declarations to random names
func (o *Obfuscator) renameVariables(code string) string {
	// Find var/let/const declarations
	re := regexp.MustCompile(`\b(var|let|const)\s+([a-zA-Z_][a-zA-Z0-9_]*)\b`)
	matches := re.FindAllStringSubmatch(code, -1)

	// Build a rename map, avoiding keywords
	reserved := map[string]bool{
		"if": true, "else": true, "for": true, "while": true, "do": true,
		"switch": true, "case": true, "break": true, "continue": true, "return": true,
		"function": true, "var": true, "let": true, "const": true, "new": true,
		"this": true, "typeof": true, "instanceof": true, "void": true, "delete": true,
		"true": true, "false": true, "null": true, "undefined": true,
		"try": true, "catch": true, "finally": true, "throw": true,
		"class": true, "extends": true, "super": true, "import": true, "export": true,
		"default": true, "async": true, "await": true, "yield": true,
		"console": true, "document": true, "window": true, "fetch": true,
		"top": true, "location": true, "setTimeout": true, "setInterval": true,
		"response": true, "data": true, "error": true, "url": true, "sid": true,
	}

	renameMap := make(map[string]string)
	for _, m := range matches {
		varName := m[2]
		if _, ok := renameMap[varName]; !ok && !reserved[varName] {
			renameMap[varName] = o.randomVarName(6)
		}
	}

	// Apply renames
	for oldName, newName := range renameMap {
		// Use word boundary replacement
		varRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(oldName) + `\b`)
		code = varRe.ReplaceAllString(code, newName)
	}

	return code
}

// injectDeadCode inserts random no-op statements
func (o *Obfuscator) injectDeadCode(code string) string {
	deadCodeSnippets := []string{
		fmt.Sprintf("var %s=%d;", o.randomVarName(6), o.rng.Intn(99999)),
		fmt.Sprintf("if(false){%s=%d;}", o.randomVarName(5), o.rng.Intn(99999)),
		fmt.Sprintf("void(%d);", o.rng.Intn(99999)),
		fmt.Sprintf("var %s=![];", o.randomVarName(6)),
		fmt.Sprintf("var %s=!![];", o.randomVarName(6)),
		fmt.Sprintf("var %s=[%d,%d,%d];", o.randomVarName(6), o.rng.Intn(100), o.rng.Intn(100), o.rng.Intn(100)),
	}

	lines := strings.Split(code, "\n")
	var result []string
	for _, line := range lines {
		result = append(result, line)
		// ~20% chance to inject dead code after each line
		if o.rng.Intn(5) == 0 {
			snippet := deadCodeSnippets[o.rng.Intn(len(deadCodeSnippets))]
			result = append(result, snippet)
		}
	}
	return strings.Join(result, "\n")
}

// wrapInIIFE wraps code in an Immediately Invoked Function Expression
func (o *Obfuscator) wrapInIIFE(code string) string {
	funcName := o.randomVarName(8)
	return fmt.Sprintf("(function %s(){%s})();", funcName, code)
}

// randomVarName generates a random variable name
func (o *Obfuscator) randomVarName(length int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz"
	const allChars = "abcdefghijklmnopqrstuvwxyz0123456789"

	result := make([]byte, length)
	// First character must be a letter or underscore
	prefix := []byte{'_'}
	result[0] = prefix[0]
	result[1] = chars[o.rng.Intn(len(chars))]
	for i := 2; i < length; i++ {
		result[i] = allChars[o.rng.Intn(len(allChars))]
	}
	return string(result)
}
