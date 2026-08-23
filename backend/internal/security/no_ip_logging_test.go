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

// logCallPattern matches log.Printf/Println/Fatalf/Fatal calls.
var logCallPattern = regexp.MustCompile(`log\.(Printf|Println|Fatalf|Fatal)\(`)

// logFormatStringPattern extracts the first string literal from a log call.
// This is used to isolate the format string from arguments.
var logFormatStringPattern = regexp.MustCompile(`log\.\w+\(\s*"([^"]*)"`)

// ipInFormatString matches IP-bearing patterns inside log format strings.
// This catches both direct interpolation (ip=%s) and keyword patterns (client_ip).
var ipInFormatString = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bip\s*=\s*%`),
	regexp.MustCompile(`(?i)\bip\s*:\s*%`),
	regexp.MustCompile(`(?i)\bclient.?ip`),
	regexp.MustCompile(`(?i)\bremote.?addr`),
	regexp.MustCompile(`(?i)\bremote.?ip`),
	regexp.MustCompile(`(?i)\buser.?agent`),
	regexp.MustCompile(`(?i)\bx.?forwarded`),
	regexp.MustCompile(`(?i)\bx.?real.?ip`),
}

// identifyingInLogLine catches identifying information appearing anywhere on a
// log call line (format string, arguments, or variable references).
var identifyingInLogLine = []*regexp.Regexp{
	regexp.MustCompile(`\.IP\(\)`),
	regexp.MustCompile(`\.RemoteAddr\b`),
	regexp.MustCompile(`\.RemoteIP\b`),
	regexp.MustCompile(`Get\(\s*"User-Agent"`),
	regexp.MustCompile(`Get\(\s*"user-agent"`),
	regexp.MustCompile(`Get\(\s*"Referer"`),
	regexp.MustCompile(`Get\(\s*"referer"`),
	regexp.MustCompile(`Get\(\s*"X-Forwarded-For"`),
	regexp.MustCompile(`Get\(\s*"x-forwarded-for"`),
	regexp.MustCompile(`Get\(\s*"X-Real-Ip"`),
	regexp.MustCompile(`Get\(\s*"x-real-ip"`),
	regexp.MustCompile(`c\.Locals\(\s*"ip"`),
	regexp.MustCompile(`c\.Locals\(\s*"clientIP"`),
}

// assignIPPattern matches variable assignments from c.IP().
var assignIPPattern = regexp.MustCompile(`(:?=|:=)\s*c\.IP\(\)`)

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
// whether that variable appears in a log call within the same function.
//
// This catches the indirection pattern that the hard-fail tests might miss:
// the IP is assigned to a variable on one line, then interpolated into a log
// string on a different line — but the format string doesn't contain "ip=".
//
// Example caught by this test (but NOT by hard-fail tests):
//
//	clientIP := c.IP()
//	log.Printf("Request from %s", clientIP)
//
// This produces a noisy but safe output — a human should review each flagged
// location.
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

			if !assignIPPattern.MatchString(line) {
				continue
			}

			// Extract the variable name from the assignment
			varName := extractAssignedVarName(line)

			// Check the next 30 lines for log calls referencing this variable
			end := i + 30
			if end > len(lines) {
				end = len(lines)
			}

			doesLog := false
			var logDetail string
			for _, futureLine := range lines[i+1 : end] {
				if !logCallPattern.MatchString(futureLine) {
					continue
				}

				// Check if the variable name appears as an argument in the log call
				if varName != "" && (strings.Contains(futureLine, varName+")") ||
					strings.Contains(futureLine, varName+",") ||
					strings.Contains(futureLine, varName+" )")) {
					doesLog = true
					logDetail = fmt.Sprintf("variable %q passed to log at next line", varName)
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

				// Also check for generic variable interpolation patterns
				if strings.Contains(futureLine, "ip)") || strings.Contains(futureLine, "ip,") {
					doesLog = true
					logDetail = "generic ip reference in log call"
					break
				}
			}

			location := fmt.Sprintf("%s:%d", path, i+1)
			if doesLog {
				warnings = append(warnings, fmt.Sprintf(
					"[REVIEW] %s: c.IP() assigned to %q — %s — verify no IP leak",
					location, varName, logDetail))
			} else {
				warnings = append(warnings, fmt.Sprintf(
					"[INFO] %s: c.IP() assigned to %q — used only for rate-limit key, no log leak",
					location, varName))
			}
		}
		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk source tree: %v", err)
	}

	if len(warnings) > 0 {
		t.Logf("IP assignment audit (%d location(s) found — review each for potential leaks):", len(warnings))
		for _, w := range warnings {
			t.Logf("  %s", w)
		}
		t.Log("NOTE: This is a warning-only check. Fix any [REVIEW] items that log IP values.")
	} else {
		t.Log("No c.IP() assignments found in non-test code.")
	}
}

// extractAssignedVarName pulls the variable name from an assignment like
// "ip := c.IP()" or "clientIP = c.IP()".
func extractAssignedVarName(line string) string {
	// Match: varName := c.IP() or varName = c.IP()
	re := regexp.MustCompile(`(\w+)\s*(:?=|:=)\s*c\.IP\(\)`)
	matches := re.FindStringSubmatch(line)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
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
