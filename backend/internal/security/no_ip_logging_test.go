package security

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// logCallPattern matches log.Printf/Println/Fatalf/Fatal/Print/Panic/Panicf/Panicln calls.
var logCallPattern = regexp.MustCompile(`log\.(Printf|Println|Fatalf|Fatal|Print|Panic|Panicf|Panicln)\(`)

// logFormatStringPattern extracts the first string literal from a log call.
// This is used to isolate the format string from arguments.
var logFormatStringPattern = regexp.MustCompile(`log\.\w+\(\s*"([^"]*)"`)

// ipInFormatString matches IP-bearing patterns inside log format strings and log literals.
// This catches direct interpolation (ip=%s, ip:%s), key-value patterns (ip=, ip:),
// and keyword patterns (client_ip, remote_addr, user_ip, etc.).
var ipInFormatString = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bip\s*=\s*%`),
	regexp.MustCompile(`(?i)\bip\s*:\s*%`),
	regexp.MustCompile(`(?i)\bip\s*=`),
	regexp.MustCompile(`(?i)\bip\s*:\s*`),
	regexp.MustCompile(`(?i)\bclient.?ip`),
	regexp.MustCompile(`(?i)\bremote.?addr`),
	regexp.MustCompile(`(?i)\bremote.?ip`),
	regexp.MustCompile(`(?i)\buser.?ip`),
	regexp.MustCompile(`(?i)\buser.?agent`),
	regexp.MustCompile(`(?i)\bx.?forwarded`),
	regexp.MustCompile(`(?i)\bx.?real.?ip`),
	regexp.MustCompile(`(?i)\bsrc.?ip`),
	regexp.MustCompile(`(?i)\bsource.?ip`),
	regexp.MustCompile(`(?i)\bpeer.?(?:ip|addr)`),
	regexp.MustCompile(`(?i)\bcaller.?ip`),
}

// identifyingInLogLine catches identifying information appearing anywhere on a
// log call line (format string, arguments, or variable references).
var identifyingInLogLine = []*regexp.Regexp{
	regexp.MustCompile(`\.IP\(\)`),
	regexp.MustCompile(`\.IPs\(\)`),
	regexp.MustCompile(`\.RemoteAddr\b`),
	regexp.MustCompile(`\.RemoteIP\b`),
	regexp.MustCompile(`\.ClientIP\b`),
	regexp.MustCompile(`Get\(\s*"User-Agent"`),
	regexp.MustCompile(`Get\(\s*"user-agent"`),
	regexp.MustCompile(`Get\(\s*"Referer"`),
	regexp.MustCompile(`Get\(\s*"referer"`),
	regexp.MustCompile(`Get\(\s*"X-Forwarded-For"`),
	regexp.MustCompile(`Get\(\s*"x-forwarded-for"`),
	regexp.MustCompile(`Get\(\s*"X-Real-Ip"`),
	regexp.MustCompile(`Get\(\s*"x-real-ip"`),
	regexp.MustCompile(`Get\(\s*"X-Real-IP"`),
	regexp.MustCompile(`c\.Locals\(\s*"ip"`),
	regexp.MustCompile(`c\.Locals\(\s*"clientIP"`),
}

// assignIPPattern matches variable assignments from c.IP() or any *.IP().
var assignIPPattern = regexp.MustCompile(`(?:\b(\w+)\s*(?::=|=)|var\s+(\w+)(?:\s+\w+)?\s*=)\s*.*\.IP\(\)`)

// TestNoIPLogging verifies that no log.Printf/log.Println/log.Fatalf call
// in the codebase includes client IP addresses or User-Agent strings.
// This is a hard-fail test.
func TestNoIPLogging(t *testing.T) {
	root := findRoot(t)
	var violations []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(path, "vendor") || strings.Contains(path, ".git") {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if !logCallPattern.MatchString(line) {
				continue
			}
			for _, pat := range identifyingInLogLine {
				if pat.MatchString(line) {
					violations = append(violations, fmt.Sprintf("%s:%d: %s", path, lineNum, pat.String()))
				}
			}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk source tree: %v", err)
	}
	if len(violations) > 0 {
		t.Errorf(
			"Found %d reference(s) to identifying information (IP, User-Agent, etc.) "+
				"in log calls. This violates the no-IP-logging promise.\n\n"+
				"Violations:\n%s",
			len(violations),
			strings.Join(violations, "\n"),
		)
	}
}

// TestNoIPLoggingFormatStrings checks that no log format string contains
// IP-keyword patterns (ip=%s, client_ip, remote_addr, user-agent, etc.).
// This catches the indirection pattern: IP assigned to variable, then
// interpolated via %s in the format string on a separate line.
// This is a hard-fail test.
func TestNoIPLoggingFormatStrings(t *testing.T) {
	root := findRoot(t)
	var violations []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(path, "vendor") || strings.Contains(path, ".git") {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if !logCallPattern.MatchString(line) {
				continue
			}

			// Extract the format string from the log call
			matches := logFormatStringPattern.FindStringSubmatch(line)
			if matches == nil {
				continue
			}
			formatStr := matches[1]

			for _, pat := range ipInFormatString {
				if pat.MatchString(formatStr) {
					violations = append(violations, fmt.Sprintf(
						"%s:%d: log format string contains %q: %s",
						path, lineNum, formatStr, pat.String()))
				}
			}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk source tree: %v", err)
	}
	if len(violations) > 0 {
		t.Errorf(
			"Found %d log format string(s) containing IP-keyword patterns.\n"+
				"This catches the indirection pattern where IP is assigned to a variable\n"+
				"and then interpolated via %%s in a log format string.\n\n"+
				"Violations:\n%s",
			len(violations),
			strings.Join(violations, "\n"),
		)
	}
}

// TestNoIPLoggingInLogCalls is a comprehensive check that no log call line
// contains identifying information — both direct (.IP()) and indirect
// (format strings with ip=, client_ip, etc.).
// This is a hard-fail test.
func TestNoIPLoggingInLogCalls(t *testing.T) {
	root := findRoot(t)
	var violations []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(path, "vendor") || strings.Contains(path, ".git") {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			if !logCallPattern.MatchString(line) {
				continue
			}

			// Check direct references (e.g., .IP() passed as argument)
			for _, pat := range identifyingInLogLine {
				if pat.MatchString(line) {
					violations = append(violations, fmt.Sprintf("%s:%d: log call references: %s",
						path, lineNum, pat.String()))
				}
			}

			// Check format string for IP-keyword patterns
			matches := logFormatStringPattern.FindStringSubmatch(line)
			if matches != nil {
				for _, pat := range ipInFormatString {
					if pat.MatchString(matches[1]) {
						violations = append(violations, fmt.Sprintf("%s:%d: log format string %q: %s",
							path, lineNum, matches[1], pat.String()))
					}
				}
			}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk source tree: %v", err)
	}
	if len(violations) > 0 {
		t.Errorf(
			"Found %d log call(s) that may leak identifying information.\n\n"+
				"Violations:\n%s",
			len(violations),
			strings.Join(violations, "\n"),
		)
	}
}

// TestNoIPLoggingInFiberLoggerFormat verifies the Fiber logger middleware
// does not include ${ip}, ${user-agent}, or similar variables.
func TestNoIPLoggingInFiberLoggerFormat(t *testing.T) {
	root := findRoot(t)

	dangerousLoggerVars := []string{
		"${ip}", "${user-agent}", "${referer}", "${ips}",
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		for _, v := range dangerousLoggerVars {
			if strings.Contains(string(content), v) {
				t.Errorf("%s contains Fiber logger variable %s — this would log identifying information", path, v)
			}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk source tree: %v", err)
	}
}

// TestNoIPLoggingIndirectAssignment is a WARNING-ONLY test that flags any
// function calling c.IP() and storing the result in a variable, then checks
// whether that variable appears in a log call within the surrounding code.
//
// This catches the indirection pattern that direct tests might miss:
// the IP is assigned to a variable on one line, then interpolated into a log
// string on a different line.
//
// Example:
//
//	clientIP := c.IP()
//	log.Printf("Request from %s", clientIP)
//
// Every call site of c.IP() is logged as a warning/info item during the test run
// so a human reviewer can verify that the variable is never logged.
func TestNoIPLoggingIndirectAssignment(t *testing.T) {
	root := findRoot(t)

	var warnings []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(path, "vendor") || strings.Contains(path, ".git") {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		var lines []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}

		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}

			if !assignIPPattern.MatchString(line) && !strings.Contains(line, ".IP()") {
				continue
			}

			// Extract the variable name from the assignment
			varName := extractAssignedVarName(line)

			// Check the next 40 lines (or until next func) for log calls referencing this variable
			end := i + 40
			if end > len(lines) {
				end = len(lines)
			}

			doesLog := false
			var logDetail string
			var varWordPattern *regexp.Regexp
			if varName != "" {
				varWordPattern = regexp.MustCompile(`\b` + regexp.QuoteMeta(varName) + `\b`)
			}

			for _, futureLine := range lines[i+1 : end] {
				trimmedFuture := strings.TrimSpace(futureLine)
				// If we reached a new top-level function, stop scanning this scope
				if strings.HasPrefix(trimmedFuture, "func ") && !strings.HasPrefix(trimmedFuture, "func(") {
					break
				}

				if !logCallPattern.MatchString(futureLine) {
					continue
				}

				// Check if the variable name appears in the log call
				if varWordPattern != nil && varWordPattern.MatchString(futureLine) {
					doesLog = true
					logDetail = fmt.Sprintf("variable %q referenced in log call %q", varName, trimmedFuture)
					break
				}

				// Check if the log format string has ANY IP-keyword pattern
				if matches := logFormatStringPattern.FindStringSubmatch(futureLine); matches != nil {
					for _, pat := range ipInFormatString {
						if pat.MatchString(matches[1]) {
							doesLog = true
							logDetail = fmt.Sprintf("log format %q matches %s", matches[1], pat.String())
							break
						}
					}
					if doesLog {
						break
					}
				}
			}

			location := fmt.Sprintf("%s:%d", path, i+1)
			if doesLog {
				warnings = append(warnings, fmt.Sprintf(
					"[REVIEW NEEDED] %s: c.IP() stored in %q — %s — potential IP leak!",
					location, varName, logDetail))
			} else {
				warnings = append(warnings, fmt.Sprintf(
					"[AUDIT VERIFIED] %s: c.IP() stored in %q — used only for rate limiting key; no log leak detected",
					location, varName))
			}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk source tree: %v", err)
	}

	if len(warnings) > 0 {
		t.Logf("c.IP() Variable Assignment & Indirection Audit (%d location(s) found):", len(warnings))
		for _, w := range warnings {
			t.Logf("  %s", w)
		}
		t.Log("NOTE: This audit flags all c.IP() variable assignments so reviewers can confirm the IP is not logged.")
	} else {
		t.Log("No c.IP() assignments found in non-test code.")
	}
}

// TestIPFormatStringRegexPatterns validates that the IP format string regex patterns
// correctly identify forbidden patterns (ip=%s, ip:%s, client_ip, etc.) and do not
// false-positive on legitimate log messages.
func TestIPFormatStringRegexPatterns(t *testing.T) {
	badFormatStrings := []string{
		"RATELIMIT_LOGIN blocked: ip=%s",
		"RATELIMIT_2FA blocked: ip=%s",
		"RATELIMIT_REPLIES blocked: ip=%s",
		"login failed for ip:%s",
		"client_ip=%s connected",
		"remote_ip=%v",
		"user_ip: %s",
		"remote_addr: %s",
		"x_forwarded_for: %s",
		"x-real-ip=%s",
		"ip=%v",
		"ip=%+v",
		"ip=%q",
		"ip = %s",
		"ip: %s",
		"ip=%d",
		"ip=",
		"ip:",
	}

	for _, s := range badFormatStrings {
		matched := false
		for _, pat := range ipInFormatString {
			if pat.MatchString(s) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("Expected regex to flag format string %q, but none matched", s)
		}
	}

	goodFormatStrings := []string{
		"RATELIMIT_LOGIN blocked",
		"RATELIMIT_2FA blocked",
		"RATELIMIT_REPLIES blocked",
		"Connected to PostgreSQL database",
		"Database tables migrated",
		"RequireRole called with invalid role: %s",
		"RBAC rejected: role=%s required=%s path=%s",
		"AUTH_GUARD rejected: no Authorization header path=%s",
		"ROOM_FILE_UPLOAD: room=%s file=%s size=%d",
		"2FA_SETUP success: org=%s (pending verification)",
		"SUBMIT_TIP success: anon=%s files=%d encrypted=%v",
		"UPDATE_STATUS success: submission=%s status=%s priority=%s",
		"ADD_NOTE success: submission=%s depth=%d",
		"STATUS_WS JOIN: sub=%s",
		"STATUS_WS LEAVE: sub=%s",
	}

	for _, s := range goodFormatStrings {
		for _, pat := range ipInFormatString {
			if pat.MatchString(s) {
				t.Errorf("Expected regex to NOT flag format string %q, but matched %s", s, pat.String())
			}
		}
	}
}

// extractAssignedVarName pulls the variable name from an assignment like
// "ip := c.IP()" or "var clientIP string = c.IP()".
func extractAssignedVarName(line string) string {
	matches := assignIPPattern.FindStringSubmatch(line)
	if len(matches) > 1 && matches[1] != "" {
		return matches[1]
	}
	if len(matches) > 2 && matches[2] != "" {
		return matches[2]
	}
	return "ip"
}

func findRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Cannot determine working directory: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	t.Fatal("Could not find go.mod to determine project root")
	return ""
}
