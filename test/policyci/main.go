// Command policyci checks the real offline CLI on the current native platform.
// It is a CI harness, not another policy evaluator or an integration-test mode.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type processResult struct {
	Arguments []string `json:"arguments"`
	ExitCode  int      `json:"exitCode"`
	Error     string   `json:"error,omitempty"`
}

type caseResult struct {
	Name     string        `json:"name"`
	Expected int           `json:"expectedExitCode"`
	Process  processResult `json:"process"`
	Passed   bool          `json:"passed"`
	Error    string        `json:"error,omitempty"`
}

type manifest struct {
	OS        string        `json:"os"`
	Arch      string        `json:"arch"`
	GoVersion string        `json:"goVersion"`
	Build     processResult `json:"build"`
	Cases     []caseResult  `json:"cases"`
	Passed    bool          `json:"passed"`
	Error     string        `json:"error,omitempty"`
}

func main() {
	output := flag.String("output", "var/policy-ci", "New output directory; existing paths are never reused.")
	oci := flag.Bool("oci", false, "Check native/OCI parity using the regular Generic Linux image layout.")
	engine := flag.String("runtime", "docker", "Local OCI runtime executable (docker or podman).")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "policyci does not accept positional arguments")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	var err error
	if *oci {
		err = runOCI(ctx, *output, *engine)
	} else {
		err = run(ctx, *output)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	mode := "native"
	if *oci {
		mode = "native/OCI parity"
	}
	fmt.Printf("Offline policy CLI %s checks passed on %s/%s; reports: %s/reports\n", mode, runtime.GOOS, runtime.GOARCH, *output)
}

func run(ctx context.Context, output string) (resultErr error) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		return fmt.Errorf("unsupported native platform: %s", runtime.GOOS)
	}
	if _, err := os.Stat("pkg/test/examples/ssh/green-unix_bftest.lua"); err != nil {
		return fmt.Errorf("run policyci from the repository root: %w", err)
	}
	root, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(root), 0700); err != nil {
		return err
	}
	if err := os.Mkdir(root, 0700); err != nil {
		return fmt.Errorf("output must be a new directory: %w", err)
	}
	reports, private := filepath.Join(root, "reports"), filepath.Join(root, "private")
	if err := os.Mkdir(reports, 0700); err != nil {
		return err
	}
	record := manifest{OS: runtime.GOOS, Arch: runtime.GOARCH, GoVersion: runtime.Version()}
	defer func() {
		record.Passed = resultErr == nil
		if resultErr != nil {
			record.Error = resultErr.Error()
		}
		raw, err := json.MarshalIndent(record, "", "  ")
		if err == nil {
			err = createFile(filepath.Join(reports, "manifest.json"), append(raw, '\n'))
		}
		resultErr = errors.Join(resultErr, err)
	}()
	if err := os.Mkdir(private, 0700); err != nil {
		return err
	}
	binary := filepath.Join(private, "bifroest")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build, err := runProcess(ctx, reports, "build", "go", []string{"build", "-p=1", "-trimpath", "-o", binary, "./cmd/bifroest"}, processEnvironment(true))
	record.Build = build
	if err != nil {
		return fmt.Errorf("native CLI build failed: %w", err)
	}
	if build.ExitCode != 0 {
		return fmt.Errorf("native CLI build exited %d; see build.stderr.txt", build.ExitCode)
	}
	invalid := filepath.Join(private, "invalid_bftest.lua")
	if err := createFile(invalid, []byte("suite {\n")); err != nil {
		return err
	}
	variant := "unix"
	if runtime.GOOS == "windows" {
		variant = "windows"
	}
	for _, test := range policyScenarios(invalid, variant) {
		outcome, err := runPolicyCase(reports, test, func(folder string, args []string) (processResult, error) {
			return runProcess(ctx, folder, "cli", binary, args, processEnvironment(false))
		})
		record.Cases = append(record.Cases, outcome)
		if err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("%s: %w", test.name, err))
		}
	}
	return resultErr
}

type policyScenario struct {
	name            string
	args            []string
	code            int
	want            counts
	overwrite       string
	nested, blocked bool
}

func policyScenarios(invalid, variant string) []policyScenario {
	green := filepath.Join("pkg", "test", "examples", "ssh", "green-"+variant+"_bftest.lua")
	return []policyScenario{
		{name: "green", args: []string{"pkg/test/examples/ssh", "pkg/test/examples/oidc", "pkg/test/examples/http", "--excludes", "^deliberately-red-"}, want: counts{Passed: 11, Skipped: 3}, nested: true},
		{name: "verbose", args: []string{"pkg/test/examples/oidc", "--verbose"}, want: counts{Passed: 2}},
		{name: "assertion-failure", args: []string{"pkg/test/examples/ssh", "--includes", "^deliberately-red-"}, code: 1, want: counts{Failed: 1, Skipped: 3}},
		{name: "empty-selection", args: []string{"pkg/test/examples/ssh", "--includes", "^no-matching-suite/"}, code: 2, want: counts{Skipped: 3, Errors: 1}},
		{name: "invalid-input", args: []string{invalid}, code: 2, want: counts{Errors: 1}},
		{name: "overwrite-json", args: []string{green}, want: counts{Passed: 1}, overwrite: "json"},
		{name: "overwrite-junit", args: []string{green}, want: counts{Passed: 1}, overwrite: "xml"},
		{name: "report-error", args: []string{green}, code: 2, blocked: true},
	}
}

func runPolicyCase(reports string, test policyScenario, execute func(string, []string) (processResult, error)) (outcome caseResult, checkErr error) {
	outcome = caseResult{Name: test.name, Expected: test.code, Process: processResult{ExitCode: -1}}
	defer func() {
		outcome.Passed = checkErr == nil
		if checkErr != nil {
			outcome.Error = checkErr.Error()
		}
	}()
	folder := filepath.Join(reports, test.name)
	if err := os.Mkdir(folder, 0700); err != nil {
		return outcome, err
	}
	jsonPath, xmlPath := filepath.Join(folder, "report.json"), filepath.Join(folder, "report.xml")
	if test.nested {
		jsonPath = filepath.Join(folder, "created", "nested", "report.json")
		xmlPath = filepath.Join(folder, "created", "nested", "report.xml")
	}
	sentinel := []byte("old report or blocking-file content\n")
	if test.blocked {
		barrier := filepath.Join(folder, "blocked")
		if err := createFile(barrier, sentinel); err != nil {
			return outcome, err
		}
		xmlPath = filepath.Join(barrier, "report.xml")
	}
	if test.overwrite != "" {
		path := jsonPath
		if test.overwrite == "xml" {
			path = xmlPath
		}
		if err := createFile(path, sentinel); err != nil {
			return outcome, err
		}
	}
	args := append([]string{"test"}, test.args...)
	args = append(args, "--json", jsonPath, "--junit", xmlPath)
	process, checkErr := execute(folder, args)
	outcome.Process = process
	if process.ExitCode != test.code {
		checkErr = errors.Join(checkErr, fmt.Errorf("expected exit %d, got %d", test.code, process.ExitCode))
	}
	if !test.blocked {
		checkErr = errors.Join(checkErr, validateReports(jsonPath, xmlPath, test.want))
		checkErr = errors.Join(checkErr, validateMeasurements(jsonPath, xmlPath))
		checkErr = errors.Join(checkErr, validateText(folder, test.want))
		if test.name == "assertion-failure" {
			checkErr = errors.Join(checkErr, validateRed(jsonPath))
		}
		stderr, err := os.ReadFile(filepath.Join(folder, "cli.stderr.txt"))
		checkErr = errors.Join(checkErr, err)
		if len(stderr) != 0 {
			checkErr = errors.Join(checkErr, fmt.Errorf("completed report has unexpected stderr diagnostics"))
		}
	} else {
		checkErr = errors.Join(checkErr, validateReportFailure(folder, sentinel))
	}
	return outcome, checkErr
}

func createFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, writeErr := file.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	return errors.Join(writeErr, file.Close())
}

func runProcess(ctx context.Context, folder, prefix, executable string, args, env []string) (processResult, error) {
	return runProcessIn(ctx, "", folder, prefix, executable, args, env)
}

func runProcessIn(ctx context.Context, directory, folder, prefix, executable string, args, env []string) (processResult, error) {
	result := processResult{Arguments: args, ExitCode: -1}
	out, err := os.OpenFile(filepath.Join(folder, prefix+".stdout.txt"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return result, err
	}
	diagnostics, err := os.OpenFile(filepath.Join(folder, prefix+".stderr.txt"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return result, errors.Join(err, out.Close())
	}
	command := exec.CommandContext(ctx, executable, args...)
	command.Dir = directory
	command.Env, command.Stdout, command.Stderr = env, out, diagnostics
	runErr := command.Run()
	var exit *exec.ExitError
	if runErr == nil {
		result.ExitCode = 0
	} else if errors.As(runErr, &exit) {
		result.ExitCode = exit.ExitCode()
		runErr = nil // Expected negative cases are checked by their caller.
	}
	err = errors.Join(runErr, ctx.Err(), out.Close(), diagnostics.Close())
	if err != nil {
		result.Error = err.Error()
	}
	return result, err
}

// Never forward the CI environment wholesale to the build or CLI. In particular,
// GitHub/cloud tokens and arbitrary caller secrets are not test-process inputs.
func processEnvironment(build bool) []string {
	allowed := "|PATH|HOME|USERPROFILE|SYSTEMROOT|WINDIR|COMSPEC|PATHEXT|APPDATA|LOCALAPPDATA|PROGRAMDATA|TEMP|TMP|TMPDIR|"
	if build {
		allowed += "GOROOT|GOPATH|GOCACHE|GOMODCACHE|GOTMPDIR|CGO_ENABLED|CC|CXX|PKG_CONFIG_PATH|"
	}
	var result []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.Contains(allowed, "|"+strings.ToUpper(key)+"|") {
			result = append(result, entry)
		}
	}
	if build {
		result = append(result, "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH, "GOTOOLCHAIN=local")
	}
	return result
}
