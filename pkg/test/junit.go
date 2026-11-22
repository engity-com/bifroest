package test

import (
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

type junitReport struct {
	XMLName  xml.Name      `xml:"testsuites"`
	Name     string        `xml:"name,attr"`
	Tests    int           `xml:"tests,attr"`
	Failures int           `xml:"failures,attr"`
	Errors   int           `xml:"errors,attr"`
	Skipped  int           `xml:"skipped,attr"`
	Time     string        `xml:"time,attr,omitempty"`
	Suites   []*junitSuite `xml:"testsuite"`
}
type junitSuite struct {
	Name       string          `xml:"name,attr"`
	ID         int             `xml:"id,attr"`
	Tests      int             `xml:"tests,attr"`
	Failures   int             `xml:"failures,attr"`
	Errors     int             `xml:"errors,attr"`
	Skipped    int             `xml:"skipped,attr"`
	Time       string          `xml:"time,attr,omitempty"`
	Properties []junitProperty `xml:"properties>property"`
	Cases      []junitCase     `xml:"testcase"`
	Warnings   string          `xml:"system-err,omitempty"`
}
type junitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}
type junitCase struct {
	Name       string        `xml:"name,attr"`
	ClassName  string        `xml:"classname,attr"`
	File       string        `xml:"file,attr,omitempty"`
	Line       int32         `xml:"line,attr,omitempty"`
	Assertions int           `xml:"assertions,attr"`
	Time       string        `xml:"time,attr,omitempty"`
	Failure    *junitProblem `xml:"failure,omitempty"`
	Error      *junitProblem `xml:"error,omitempty"`
	Skip       *junitSkip    `xml:"skipped,omitempty"`
}
type junitProblem struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}
type junitSkip struct {
	Message string `xml:"message,attr"`
}

// WriteJUnit serializes the same outcomes/Summary used by text and JSON. It does
// not rerun tests or invent timing observations. Skipped suites must retain their
// actual test names; an incomplete externally constructed Report is an error.
func (this Report) WriteJUnit(out io.Writer) error {
	root, err := this.junit()
	if err != nil {
		return err
	}
	if n, err := io.WriteString(out, xml.Header); err != nil {
		return err
	} else if n != len(xml.Header) {
		return io.ErrShortWrite
	}
	encoder := xml.NewEncoder(out)
	encoder.Indent("", "  ")
	if err := encoder.Encode(root); err != nil {
		return err
	}
	if n, err := io.WriteString(out, "\n"); err != nil {
		return err
	} else if n != 1 {
		return io.ErrShortWrite
	}
	return nil
}

func (this Report) junit() (junitReport, error) {
	root := junitReport{Name: "bifroest-policy-tests", Time: junitTime(this.DurationSeconds)}
	validDuration := func(seconds float64) bool { return seconds >= 0 && !math.IsNaN(seconds) && !math.IsInf(seconds, 0) }
	if !validDuration(this.DurationSeconds) {
		return root, invalid("invalid JUnit run duration")
	}
	type key struct{ source, suite string }
	groups := map[key]*junitSuite{}
	suiteFor := func(source, name string) *junitSuite {
		id := key{source, name}
		if group := groups[id]; group != nil {
			return group
		}
		if name == "" {
			name = "bifroest.policytest.runner"
		}
		group := &junitSuite{Name: junitText(name), ID: len(root.Suites), Properties: []junitProperty{
			{Name: "apiVersion", Value: junitText(this.APIVersion)},
			{Name: "scope", Value: junitText(this.Scope)},
			{Name: "authenticationAssumed", Value: "true"},
		}}
		if source != "" {
			group.Properties = append(group.Properties, junitProperty{Name: "source", Value: junitText(source)})
		}
		root.Suites = append(root.Suites, group)
		groups[id] = group
		return group
	}
	setPackage := func(group *junitSuite, name string) error {
		if name == "" {
			return nil
		}
		name = junitText(name)
		for _, property := range group.Properties {
			if property.Name == "package" {
				if property.Value != name {
					return invalid("conflicting JUnit package identity")
				}
				return nil
			}
		}
		group.Properties = append(group.Properties, junitProperty{Name: "package", Value: name})
		return nil
	}
	for _, suite := range this.Suites {
		if !validDuration(suite.DurationSeconds) {
			return root, invalid("invalid JUnit suite duration")
		}
		group := suiteFor(suite.Source, suite.Name)
		group.Time = junitTime(suite.DurationSeconds)
		if err := setPackage(group, suite.Package); err != nil {
			return root, err
		}
	}
	for _, skipped := range this.SkippedSuites {
		if skipped.Tests < 0 || len(skipped.TestNames) != skipped.Tests {
			return root, invalid("JUnit requires the declared names of every platform-excluded test")
		}
		seen := map[string]bool{}
		for _, name := range skipped.TestNames {
			if name == "" || seen[name] {
				return root, invalid("invalid skipped test name in JUnit report")
			}
			seen[name] = true
		}
		group := suiteFor(skipped.Source, skipped.Suite)
		if err := setPackage(group, skipped.Package); err != nil {
			return root, err
		}
		for _, name := range skipped.TestNames {
			group.Cases = append(group.Cases, junitCase{Name: junitText(name), ClassName: group.Name, File: junitText(skipped.Source), Skip: &junitSkip{Message: junitText(skipped.Reason)}})
			group.Tests++
			group.Skipped++
		}
	}
	for _, result := range this.Results {
		if result.Assertions < 0 || result.Status == "passed" && len(result.Failures) > 0 || !validDuration(result.DurationSeconds) {
			return root, invalid("inconsistent test outcome in JUnit report")
		}
		group := suiteFor(result.Source, result.Suite)
		if err := setPackage(group, result.Package); err != nil {
			return root, err
		}
		item := junitCase{Name: junitText(result.Name), ClassName: group.Name, File: junitText(result.Source), Assertions: result.Assertions, Time: junitTime(result.DurationSeconds)}
		for _, failure := range result.Failures {
			if failure.Line > 0 {
				item.Line = failure.Line
				break
			}
		}
		body := junitFailures(result.Source, result.Failures)
		switch result.Status {
		case "passed":
		case "failed":
			message := "test assertions failed"
			if n := len(result.Failures); n > 0 {
				noun := "assertions"
				if n == 1 {
					noun = "assertion"
				}
				message = fmt.Sprintf("%d %s failed", n, noun)
			}
			item.Failure = &junitProblem{Type: "assertion", Message: message, Body: junitText(body)}
			group.Failures++
		default:
			category := result.Category
			if category == "" {
				category = "system"
			}
			message := result.Message
			if result.Status != "error" {
				message = fmt.Sprintf("unsupported result status %q", result.Status)
			}
			if message == "" {
				message = "test execution failed"
			}
			item.Error = &junitProblem{Type: junitText(category), Message: junitText(message), Body: junitText(body)}
			group.Errors++
		}
		group.Cases = append(group.Cases, item)
		group.Tests++
	}
	if len(this.Results) == 0 {
		group := suiteFor("", "")
		group.Cases = append(group.Cases, junitCase{Name: "no-tests-selected", ClassName: group.Name, Error: &junitProblem{Type: "system", Message: "no tests selected"}})
		group.Tests++
		group.Errors++
	}
	for _, warning := range this.Warnings {
		group := suiteFor(warning.Source, "")
		group.Warnings += junitText(fmt.Sprintf("%q: %s\n", warning.Source, warning.Message))
	}
	for _, group := range root.Suites {
		root.Tests += group.Tests
		root.Failures += group.Failures
		root.Errors += group.Errors
		root.Skipped += group.Skipped
	}
	summary := this.Summary()
	if root.Tests != summary.Passed+summary.Failed+summary.Errors+summary.Skipped || root.Failures != summary.Failed || root.Errors != summary.Errors || root.Skipped != summary.Skipped {
		return root, invalid("JUnit outcome counts differ from the policy report summary")
	}
	return root, nil
}

func junitTime(seconds float64) string {
	if seconds == 0 {
		return ""
	}
	return strconv.FormatFloat(seconds, 'f', 9, 64)
}

func junitFailures(source string, failures []Failure) string {
	if source == "" {
		source = "<memory>"
	}
	var body strings.Builder
	for _, failure := range failures {
		location := source
		if failure.Line > 0 {
			location = fmt.Sprintf("%s:%d", source, failure.Line)
		}
		fmt.Fprintf(&body, "%s: expected %s, actual %s; reason %q\n", location, failure.Expected, failure.Actual, failure.Reason)
	}
	return body.String()
}

// XML 1.0 cannot represent every Lua/Go string. Keep legal text unchanged and
// spell out forbidden codepoints/invalid UTF-8 bytes instead of silently letting
// encoding/xml replace them with U+FFFD or producing an unreadable document.
func junitText(text string) string {
	var out strings.Builder
	for len(text) > 0 {
		r, size := utf8.DecodeRuneInString(text)
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&out, "\\x%02x", text[0])
		} else if r == '\t' || r == '\n' || r == '\r' || r >= 0x20 && r <= 0xd7ff || r >= 0xe000 && r <= 0xfffd || r >= 0x10000 && r <= utf8.MaxRune {
			out.WriteRune(r)
		} else {
			out.WriteString("\\u")
			digits := strconv.FormatInt(int64(r), 16)
			out.WriteString(strings.Repeat("0", max(0, 4-len(digits))))
			out.WriteString(digits)
		}
		text = text[size:]
	}
	return out.String()
}
