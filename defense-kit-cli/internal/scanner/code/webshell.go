package code

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nunenuh/defense-kit/defense-kit-cli/internal/scanner"
)

const (
	webshellMaxFileSize      = 1 * 1024 * 1024 // 1 MB
	webshellRecentDays       = 7
	webshellHighEntropyThreshold = 5.0
)

// webshellExtensions are file extensions associated with server-side scripting.
var webshellExtensions = map[string]bool{
	".php": true,
	".jsp": true,
	".py":  true,
	".pl":  true,
	".cgi": true,
	".asp": true,
}

// defaultWebDirs are common web server root directories to scan.
var defaultWebDirs = []string{
	"/var/www",
	"/srv/www",
	"/usr/share/nginx/html",
	"/var/www/html",
}

// webshellIndicator describes a pattern that indicates webshell activity.
type webshellIndicator struct {
	substr      string
	extensions  map[string]bool // nil means any extension
	title       string
	severity    scanner.Severity
	detail      string
	remediation string
}

// phpWebshellIndicators are patterns specific to PHP webshells.
var phpWebshellIndicators = []webshellIndicator{
	{
		substr:     "eval(",
		extensions: map[string]bool{".php": true},
		title:      "PHP eval() in web file",
		severity:   scanner.SevHigh,
		detail:     "The PHP eval() function executes arbitrary code. Its presence in a web-accessible file is a strong indicator of a webshell or malicious code injection.",
		remediation: "Remove the file if it is not part of a legitimate application. If it is, replace eval() with safer alternatives and review the code for tampering.",
	},
	{
		substr:     "base64_decode(",
		extensions: map[string]bool{".php": true},
		title:      "PHP base64_decode() in web file",
		severity:   scanner.SevHigh,
		detail:     "Combining base64_decode() with code execution (eval, system, etc.) is a common webshell obfuscation technique.",
		remediation: "Audit the file for combined use of base64_decode() and execution functions. Remove if malicious.",
	},
	{
		substr:     "system(",
		extensions: map[string]bool{".php": true},
		title:      "PHP system() in web file",
		severity:   scanner.SevHigh,
		detail:     "The PHP system() function executes OS commands. Its presence in a web-accessible file may indicate a webshell.",
		remediation: "Remove the file or audit it carefully. Disable dangerous PHP functions in php.ini (disable_functions = system,exec,passthru,shell_exec).",
	},
	{
		substr:     "exec(",
		extensions: map[string]bool{".php": true},
		title:      "PHP exec() in web file",
		severity:   scanner.SevHigh,
		detail:     "The PHP exec() function executes OS commands and is commonly used in PHP webshells.",
		remediation: "Remove the file or audit it carefully. Disable dangerous PHP functions in php.ini.",
	},
	{
		substr:     "passthru(",
		extensions: map[string]bool{".php": true},
		title:      "PHP passthru() in web file",
		severity:   scanner.SevHigh,
		detail:     "The PHP passthru() function executes OS commands and passes raw output to the browser, commonly used in webshells.",
		remediation: "Remove the file or audit it carefully. Disable dangerous PHP functions in php.ini.",
	},
	{
		substr:     "shell_exec(",
		extensions: map[string]bool{".php": true},
		title:      "PHP shell_exec() in web file",
		severity:   scanner.SevHigh,
		detail:     "The PHP shell_exec() function executes OS commands via the shell. It is frequently abused in webshells.",
		remediation: "Remove the file or audit it carefully. Disable dangerous PHP functions in php.ini.",
	},
	{
		substr:     "assert(",
		extensions: map[string]bool{".php": true},
		title:      "PHP assert() in web file",
		severity:   scanner.SevHigh,
		detail:     "PHP assert() can evaluate a string as PHP code when passed a string argument, making it an alternative to eval() in webshells.",
		remediation: "Audit the use of assert() in this file. Remove if malicious, or replace with strict type assertions.",
	},
}

// jspWebshellIndicators are patterns specific to JSP webshells.
var jspWebshellIndicators = []webshellIndicator{
	{
		substr:     "Runtime.getRuntime().exec(",
		extensions: map[string]bool{".jsp": true},
		title:      "JSP Runtime.exec() in web file",
		severity:   scanner.SevHigh,
		detail:     "Calling Runtime.getRuntime().exec() in a JSP file allows executing OS commands and is a classic JSP webshell technique.",
		remediation: "Remove the file if it is not part of a legitimate application. Implement Java security policies to restrict Runtime.exec().",
	},
}

// universalWebshellIndicators match any web script extension.
var universalWebshellIndicators = []webshellIndicator{
	{
		substr:     "cmd=",
		extensions: nil,
		title:      "Command parameter in web file",
		severity:   scanner.SevHigh,
		detail:     "The string 'cmd=' is commonly used in webshells as a URL parameter to pass OS commands to the server.",
		remediation: "Audit the file for shell command execution. Remove if malicious.",
	},
	{
		substr:     "command=",
		extensions: nil,
		title:      "Command parameter in web file",
		severity:   scanner.SevHigh,
		detail:     "The string 'command=' is commonly used in webshells as a URL parameter to pass OS commands to the server.",
		remediation: "Audit the file for shell command execution. Remove if malicious.",
	},
	{
		substr:     "shell=",
		extensions: nil,
		title:      "Shell parameter in web file",
		severity:   scanner.SevHigh,
		detail:     "The string 'shell=' is commonly used in webshells as a URL parameter to select or pass a shell command.",
		remediation: "Audit the file for shell command execution. Remove if malicious.",
	},
}

// WebshellScanner scans web server directories for webshell indicators.
type WebshellScanner struct{}

// NewWebshellScanner creates a new WebshellScanner.
func NewWebshellScanner() *WebshellScanner {
	return &WebshellScanner{}
}

func (s *WebshellScanner) Name() string            { return "webshell" }
func (s *WebshellScanner) Category() string        { return "code" }
func (s *WebshellScanner) RequiresRoot() bool      { return false }
func (s *WebshellScanner) RequiredTools() []string { return nil }
func (s *WebshellScanner) OptionalTools() []string { return nil }
func (s *WebshellScanner) Available() bool         { return true }
func (s *WebshellScanner) Description() string {
	return "Scans web server directories (/var/www, /srv/www, /usr/share/nginx/html) for webshell indicators including PHP execution functions (eval, system, exec), JSP Runtime.exec(), command parameters, high-entropy obfuscated content, and recently modified web scripts."
}

// Scan searches web directories and any provided TargetPaths for webshells.
func (s *WebshellScanner) Scan(_ context.Context, opts scanner.ScanOptions) ([]scanner.Finding, error) {
	// Combine default web dirs with caller-provided target paths.
	dirs := make([]string, 0, len(defaultWebDirs)+len(opts.TargetPaths))
	dirs = append(dirs, defaultWebDirs...)
	dirs = append(dirs, opts.TargetPaths...)

	seenIDs := make(map[string]bool)
	var findings []scanner.Finding

	addFinding := func(f scanner.Finding) {
		if !seenIDs[f.ID] {
			seenIDs[f.ID] = true
			findings = append(findings, f)
		}
	}

	seenPaths := make(map[string]bool)

	for _, dir := range dirs {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			if seenPaths[path] {
				return nil
			}
			seenPaths[path] = true

			ext := strings.ToLower(filepath.Ext(path))
			if !webshellExtensions[ext] {
				return nil
			}
			if info.Size() > webshellMaxFileSize {
				return nil
			}

			ff := scanWebFile(path, info)
			for _, f := range ff {
				addFinding(f)
			}
			return nil
		})
	}

	return findings, nil
}

// scanWebFile inspects a single web script file for webshell indicators.
func scanWebFile(path string, info os.FileInfo) []scanner.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	content := string(data)
	ext := strings.ToLower(filepath.Ext(path))
	var findings []scanner.Finding

	isRecent := time.Since(info.ModTime()) < webshellRecentDays*24*time.Hour

	// Collect all matching indicators.
	allIndicators := make([]webshellIndicator, 0,
		len(phpWebshellIndicators)+len(jspWebshellIndicators)+len(universalWebshellIndicators))
	allIndicators = append(allIndicators, phpWebshellIndicators...)
	allIndicators = append(allIndicators, jspWebshellIndicators...)
	allIndicators = append(allIndicators, universalWebshellIndicators...)

	matched := false
	for _, ind := range allIndicators {
		// Check extension filter.
		if ind.extensions != nil && !ind.extensions[ext] {
			continue
		}
		if !strings.Contains(content, ind.substr) {
			continue
		}

		sev := ind.severity
		if isRecent && sev < scanner.SevCritical {
			sev = scanner.SevCritical
		}
		matched = true
		findings = append(findings, scanner.Finding{
			ID:          scanner.GenerateFindingID("webshell", path, ind.title),
			Scanner:     "webshell",
			Severity:    sev,
			Title:       ind.title,
			Detail:      ind.detail,
			Evidence:    fmt.Sprintf("path: %s, pattern: %q, recently_modified: %v", path, ind.substr, isRecent),
			Location:    path,
			Remediation: ind.remediation,
		})
	}

	// Check for high entropy (obfuscated content).
	ent := shannonEntropy(content)
	if ent >= webshellHighEntropyThreshold && !matched {
		sev := scanner.SevMedium
		if isRecent {
			sev = scanner.SevCritical
		}
		findings = append(findings, scanner.Finding{
			ID:      scanner.GenerateFindingID("webshell", path, "high entropy web file"),
			Scanner: "webshell",
			Severity: sev,
			Title:   "High-entropy web file (possible obfuscated webshell)",
			Detail:  fmt.Sprintf("The file %q has an unusually high Shannon entropy of %.2f bits/byte, which may indicate base64-encoded or otherwise obfuscated content typical of webshell payloads.", path, ent),
			Evidence: fmt.Sprintf("entropy: %.2f, path: %s, recently_modified: %v", ent, path, isRecent),
			Location: path,
			Remediation: "Inspect the file content manually. If it is obfuscated without a legitimate reason, remove it and investigate how it was placed there.",
		})
	}

	return findings
}

// shannonEntropy computes the Shannon entropy (bits per byte) of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	total := float64(len([]rune(s)))
	var entropy float64
	for _, count := range freq {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}
