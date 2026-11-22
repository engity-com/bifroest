// Package test implements an explicit offline, post-authentication policy
// test boundary. It never initializes the service or registered runtime providers.
package test

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/errors"
)

// APIVersion identifies serialized reports, not Lua suite declarations.
const APIVersion = "bifroest.engity.org/testing/v1alpha1"

const (
	maxSource     = 64 << 10
	maxTests      = 64
	maxNodes      = 2048
	maxDepth      = 16
	maxString     = 4096
	maxAssertions = 128
)

type Failure struct {
	Line     int32  `json:"line"`
	Reason   string `json:"reason,omitempty"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
}

type Result struct {
	Package         string    `json:"package,omitempty"`
	DurationSeconds float64   `json:"durationSeconds,omitempty"`
	Suite           string    `json:"suite,omitempty"`
	Source          string    `json:"source,omitempty"`
	Name            string    `json:"name"`
	Status          string    `json:"status"`
	Category        string    `json:"category,omitempty"`
	Message         string    `json:"message,omitempty"`
	Assertions      int       `json:"assertions"`
	Failures        []Failure `json:"failures,omitempty"`
}

type Report struct {
	DurationSeconds float64        `json:"durationSeconds,omitempty"`
	Packages        []PackageRun   `json:"packages,omitempty"`
	Suites          []SuiteRun     `json:"suites,omitempty"`
	APIVersion      string         `json:"apiVersion"`
	Suite           string         `json:"suite,omitempty"`
	Scope           string         `json:"scope"`
	Results         []Result       `json:"results"`
	Warnings        []Warning      `json:"warnings,omitempty"`
	SkippedSuites   []SkippedSuite `json:"skippedSuites,omitempty"`
	// InputFiles is output-protection metadata, not policy result data.
	InputFiles []string `json:"-"`
}

// PackageRun identifies a physical directory, including explicitly selected
// empty directories. Package time is time spent processing its own source files,
// not its descendants or report serialization; run time also includes discovery.
type PackageRun struct {
	Name            string  `json:"name"`
	Directory       string  `json:"directory,omitempty"`
	DurationSeconds float64 `json:"durationSeconds,omitempty"`
}

type SuiteRun struct {
	Package         string  `json:"package,omitempty"`
	Name            string  `json:"name"`
	Source          string  `json:"source,omitempty"`
	DeclaredTests   int     `json:"declaredTests"`
	DurationSeconds float64 `json:"durationSeconds,omitempty"`
}

// SkippedSuite is a selector exclusion, never a passing test result. A report
// containing only excluded suites still has no selected tests and exits with 2.
// TestNames retains declaration order before name filters, for named JUnit skips.
type SkippedSuite struct {
	Package   string   `json:"package,omitempty"`
	Suite     string   `json:"suite"`
	Source    string   `json:"source,omitempty"`
	Reason    string   `json:"reason"`
	Tests     int      `json:"tests"`
	TestNames []string `json:"testNames,omitempty"`
}

type Summary struct {
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
	Errors  int `json:"errors"`
}

// Summary counts test outcomes and tests in platform-excluded suites.
// Errors include synthetic load/execution failures and an empty selection.
func (this Report) Summary() Summary {
	var result Summary
	for _, test := range this.Results {
		switch test.Status {
		case "passed":
			result.Passed++
		case "failed":
			result.Failed++
		default:
			result.Errors++
		}
	}
	for _, suite := range this.SkippedSuites {
		result.Skipped += suite.Tests
	}
	if len(this.Results) == 0 {
		result.Errors++
	}
	return result
}

type Warning struct {
	Source  string `json:"source"`
	Message string `json:"message"`
}

func (this Result) qualifiedName() string {
	if this.Suite != "" {
		return this.Suite + "/" + this.Name
	}
	if this.Source != "" {
		return this.Source + ":" + this.Name
	}
	return this.Name
}

func (this Report) WriteWarnings(out io.Writer) error {
	for _, warning := range this.Warnings {
		if _, err := fmt.Fprintf(out, "%-6s %q: %s\n", "WARN", warning.Source, warning.Message); err != nil {
			return err
		}
	}
	return nil
}

func (this Report) ExitCode() int {
	code := 0
	if len(this.Results) == 0 {
		return 2
	}
	for _, result := range this.Results {
		switch result.Status {
		case "error":
			return 2
		case "failed":
			code = 1
		case "passed":
		default:
			return 2
		}
	}
	return code
}

// CommandError carries only this command's process status, not a new error category.
type CommandError struct {
	Code  int
	Cause error
	// Reported is set only after the CLI successfully wrote its result reports.
	// Unreported invocation/output errors must still reach executable diagnostics.
	Reported bool
}

func (this *CommandError) Error() string { return this.Cause.Error() }
func (this *CommandError) Unwrap() error { return this.Cause }

func (this Report) Err() error {
	if code := this.ExitCode(); code != 0 {
		category := errors.Config
		if code == 2 {
			category = errors.System
			for _, result := range this.Results {
				if result.Status == "error" {
					var reported errors.Type
					if reported.Set(result.Category) == nil {
						category = reported
					}
					break
				}
			}
		}
		return &CommandError{Code: code, Cause: category.Newf("offline policy tests did not pass")}
	}
	return nil
}

func (this Report) WriteJSON(out io.Writer) error {
	type report Report
	return json.NewEncoder(out).Encode(struct {
		report
		Summary Summary `json:"summary"`
	}{report: report(this), Summary: this.Summary()})
}

func failureResult(name string, err error, message string) Result {
	category := errors.System
	if typed, ok := errors.IsError(err); ok {
		category = typed.Type
	}
	return Result{Name: name, Status: "error", Category: category.String(), Message: message}
}

func invalid(message string) error { return errors.Config.Newf("%s", message) }

type input struct {
	Request        requestInput          `json:"request"`
	Authentication map[string]assumption `json:"authentication"`
}
type requestInput struct {
	RequestingName *string               `json:"requestingName"`
	Method         string                `json:"method,omitempty"`
	Transport      *connection.Transport `json:"transport,omitempty"`
	Host           *string               `json:"host,omitempty"`
	Slug           *string               `json:"slug,omitempty"`
}
type assumption struct {
	Outcome string                          `json:"outcome"`
	Account string                          `json:"account,omitempty"`
	Mode    string                          `json:"mode,omitempty"`
	Oidc    *authorization.AssumedOidcFacts `json:"oidc,omitempty"`
}
type facts struct {
	Accounts         []account    `json:"accounts"`
	AbsentNames      []string     `json:"absentNames,omitempty"`
	AbsentUIDs       []uint32     `json:"absentUIDs,omitempty"`
	AbsentSIDs       []string     `json:"absentSIDs,omitempty"`
	LocalGroups      []localGroup `json:"localGroups,omitempty"`
	AbsentGroupNames []string     `json:"absentGroupNames,omitempty"`
}
type account struct {
	Name        string          `json:"name"`
	UID         *uint32         `json:"uid,omitempty"`
	SID         string          `json:"sid,omitempty"`
	DisplayName *string         `json:"displayName,omitempty"`
	HomeDir     *string         `json:"homeDir,omitempty"`
	Shell       *string         `json:"shell,omitempty"`
	Group       *accountGroup   `json:"group,omitempty"`
	Groups      *[]accountGroup `json:"groups,omitempty"`
}

type accountGroup struct {
	Name string  `json:"name"`
	GID  *uint32 `json:"gid,omitempty"`
	SID  string  `json:"sid,omitempty"`
}

type localGroup struct {
	Name    string    `json:"name"`
	SID     string    `json:"sid"`
	Members *[]string `json:"members,omitempty"`
}

func decodeData(data any, target any) error {
	if !validDataEncoding(data) {
		return invalid("fixture strings and property names require valid UTF-8")
	}
	if !matchesDataProperties(data, reflect.TypeOf(target)) {
		return invalid("fixture does not match the supported schema")
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return invalid("invalid fixture value")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return invalid("fixture does not match the supported schema")
	}
	return nil
}
