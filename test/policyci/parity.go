package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
)

// Only observed durations and the exact fixture workspace prefix differ. Never
// rewrite assertion values/reasons, categories, counters, names or decisions.
func normalizedSource(source, workspace string) string {
	plain, root := filepath.ToSlash(source), filepath.ToSlash(workspace)
	if plain == root {
		return "/workspace"
	}
	if strings.HasPrefix(plain, root+"/") {
		return "/workspace" + strings.TrimPrefix(plain, root)
	}
	return source
}

func normalizeJSON(document jsonReport, workspace string) jsonReport {
	document.DurationSeconds = 0
	for i := range document.Packages {
		document.Packages[i].DurationSeconds = 0
		document.Packages[i].Directory = normalizedSource(document.Packages[i].Directory, workspace)
	}
	for i := range document.Suites {
		document.Suites[i].DurationSeconds = 0
		document.Suites[i].Source = normalizedSource(document.Suites[i].Source, workspace)
	}
	for i := range document.Results {
		document.Results[i].DurationSeconds = 0
		document.Results[i].Source = normalizedSource(document.Results[i].Source, workspace)
	}
	for i := range document.SkippedSuites {
		document.SkippedSuites[i].Source = normalizedSource(document.SkippedSuites[i].Source, workspace)
	}
	return document
}

func normalizeXML(document xmlReport, workspace string) xmlReport {
	document.Time = ""
	for i := range document.Suites {
		suite := &document.Suites[i]
		suite.Time = ""
		for j := range suite.Properties {
			if suite.Properties[j].Name == "source" {
				suite.Properties[j].Value = normalizedSource(suite.Properties[j].Value, workspace)
			}
		}
		for j := range suite.Cases {
			item := &suite.Cases[j]
			item.Time = ""
			original := item.File
			item.File = normalizedSource(item.File, workspace)
			for _, problems := range [][]xmlProblem{item.Failures, item.Errors} {
				for k := range problems {
					lines := strings.Split(problems[k].Body, "\n")
					for n, line := range lines {
						if original != "" && strings.HasPrefix(line, original+":") {
							lines[n] = item.File + strings.TrimPrefix(line, original)
						}
					}
					problems[k].Body = strings.Join(lines, "\n")
				}
			}
		}
	}
	return document
}

var textDuration = regexp.MustCompile(`\(([0-9]+\.[0-9]{3})s, (?:[0-9]+ assertions?|assertions: [0-9]+, passed: [0-9]+, failed: [0-9]+, skipped: [0-9]+(?:, errors: [0-9]+)?)\)$`)

func normalizeText(text, workspace string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "=== RUN   ") || strings.HasPrefix(trimmed, "--- ") {
			// The workspace prefix occurs only in a synthetic load-error name.
			line = strings.ReplaceAll(line, workspace+string(filepath.Separator), "/workspace/")
		}
		if strings.HasPrefix(trimmed, "--- ") || strings.HasPrefix(line, "PASS    ") || strings.HasPrefix(line, "FAIL    ") || strings.HasPrefix(line, "SKIP    ") {
			if location := textDuration.FindStringSubmatchIndex(line); location != nil {
				line = line[:location[2]] + "<duration>" + line[location[3]:]
			}
		}
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}

func equalJSON(a, b any) bool { return reflect.DeepEqual(a, b) }

func compareExecutions(native, container, workspace string, test policyScenario) error {
	jsonFile := filepath.Join("created", "nested", "report.json")
	xmlFile := filepath.Join("created", "nested", "report.xml")
	if !test.nested {
		jsonFile, xmlFile = "report.json", "report.xml"
	}
	a, err := readJSON(filepath.Join(native, jsonFile))
	if err != nil {
		return err
	}
	b, err := readJSON(filepath.Join(container, jsonFile))
	if err != nil {
		return err
	}
	if !equalJSON(normalizeJSON(a, workspace), normalizeJSON(b, workspace)) {
		return fmt.Errorf("native/OCI JSON outcomes differ after path/duration normalization")
	}
	if !test.blocked {
		var documents [2]xmlReport
		for i, folder := range []string{native, container} {
			raw, err := os.ReadFile(filepath.Join(folder, xmlFile))
			if err != nil {
				return err
			}
			if err := xml.Unmarshal(raw, &documents[i]); err != nil {
				return err
			}
		}
		if !reflect.DeepEqual(normalizeXML(documents[0], workspace), normalizeXML(documents[1], workspace)) {
			return fmt.Errorf("native/OCI JUnit outcomes differ after path/duration normalization")
		}
	}
	var texts [2]string
	for i, folder := range []string{native, container} {
		raw, err := os.ReadFile(filepath.Join(folder, "cli.stdout.txt"))
		if err != nil {
			return err
		}
		texts[i] = normalizeText(string(raw), workspace)
	}
	if texts[0] != texts[1] {
		return fmt.Errorf("native/OCI text outcomes differ after path/duration normalization")
	}
	return nil
}
