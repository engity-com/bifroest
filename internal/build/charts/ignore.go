// SPDX-FileCopyrightText: The Helm Authors
// SPDX-FileCopyrightText: 2026 Engity GmbH
// SPDX-License-Identifier: Apache-2.0

package charts

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
)

const maxIgnoreFileSize = 64 << 10
const maxIgnoreRules = 256

type chartIgnoreRule struct {
	pattern   string
	basename  bool
	directory bool
	negated   bool
}

// Matching follows Helm 4's pkg/ignore rules, including its first-match and
// negation behavior. Chart paths use POSIX separators on every build host.
// https://github.com/helm/helm/blob/v4.3.2/pkg/ignore/rules.go
func readChartIgnore(source fs.FS) ([]chartIgnoreRule, []byte, error) {
	entries, err := fs.ReadDir(source, ".")
	if err != nil {
		return nil, nil, err
	}
	var raw []byte
	for _, entry := range entries {
		if entry.Name() != ".helmignore" {
			continue
		}
		if !entry.Type().IsRegular() {
			return nil, nil, fmt.Errorf(".helmignore must be a regular, unlinked file")
		}
		raw, err = readChartFile(source, ".helmignore", maxIgnoreFileSize)
		if err != nil {
			return nil, nil, err
		}
		break
	}
	rules, err := parseChartIgnore(raw)
	return rules, raw, err
}

func parseChartIgnore(raw []byte) ([]chartIgnoreRule, error) {
	var rules []chartIgnoreRule
	scanner := bufio.NewScanner(bytes.NewReader(bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})))
	for line := 1; scanner.Scan(); line++ {
		pattern := strings.TrimSpace(scanner.Text())
		if pattern == "" || strings.HasPrefix(pattern, "#") {
			continue
		}
		if len(rules) >= maxIgnoreRules {
			return nil, fmt.Errorf(".helmignore exceeds rule limit")
		}
		if strings.Contains(pattern, "**") {
			return nil, fmt.Errorf(".helmignore:%d: double-star patterns are not supported", line)
		}
		if _, err := path.Match(pattern, "validate-pattern"); err != nil {
			return nil, fmt.Errorf(".helmignore:%d: %w", line, err)
		}
		rule := chartIgnoreRule{}
		pattern, rule.negated = strings.CutPrefix(pattern, "!")
		pattern, rule.directory = strings.CutSuffix(pattern, "/")
		pattern, rooted := strings.CutPrefix(pattern, "/")
		rule.pattern = pattern
		rule.basename = !rooted && !strings.Contains(pattern, "/")
		rules = append(rules, rule)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("invalid .helmignore: %w", err)
	}
	return append(rules, chartIgnoreRule{pattern: "templates/.?*"}), nil
}

func chartInputIgnored(rules []chartIgnoreRule, name string, directory bool) bool {
	if name == "." {
		return false
	}
	for _, rule := range rules {
		candidate := name
		if rule.basename {
			candidate = path.Base(name)
		}
		matched, _ := path.Match(rule.pattern, candidate) // Validated while parsing.
		if rule.negated {
			if rule.directory && !directory || !matched {
				return true
			}
			continue
		}
		if (!rule.directory || directory) && matched {
			return true
		}
	}
	return false
}

func readChartFile(source fs.FS, name string, maxSize int64) ([]byte, error) {
	file, err := source.Open(name)
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxSize+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(raw)) > maxSize {
		return nil, fmt.Errorf("chart input %q exceeds size limit", name)
	}
	return raw, nil
}
