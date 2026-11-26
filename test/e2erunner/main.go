// Command e2erunner runs mandatory browser E2E tests and checks their Go JSON
// results. It is invoked by the test:e2e:*:browser MISE tasks, not embedded in CI.
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
	"os/signal"
	"path/filepath"
	"strings"
)

const e2ePackage = "github.com/engity-com/bifroest/test/e2e"

type browserSuite struct {
	name     string
	timeout  string
	required []string
}

func selectSuite(name string) (browserSuite, error) {
	suite := browserSuite{
		name: name,
		required: []string{
			"TestSharedBrowserNetworkArguments",
			"TestSharedBrowserNetworkIsolation",
		},
	}
	switch name {
	case "docker-browser":
		suite.timeout = "15m"
		suite.required = append(suite.required, "TestOpenSSHDockerBrowserSharedWorkload")
	case "kubernetes-browser":
		suite.timeout = "30m"
		suite.required = append(suite.required, "TestOpenSSHKubernetesBrowserSharedWorkload")
	default:
		return browserSuite{}, fmt.Errorf("unknown browser suite %q; use docker-browser or kubernetes-browser", name)
	}
	return suite, nil
}

func (s browserSuite) arguments() []string {
	return []string{
		"test", "-json", "-count=1", "-tags=e2e", "-timeout=" + s.timeout,
		"-run", "^(" + strings.Join(s.required, "|") + ")$", "./test/e2e",
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil && !errors.Is(err, flag.ErrHelp) {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("e2erunner", flag.ContinueOnError)
	flags.SetOutput(stderr)
	name := flags.String("suite", "", "Required browser suite: docker-browser or kubernetes-browser.")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("e2erunner does not accept positional arguments")
	}
	suite, err := selectSuite(*name)
	if err != nil {
		return err
	}
	runtime := os.Getenv("BIFROEST_E2E_RUNTIME")
	if runtime != "docker" && runtime != "podman" {
		return errors.New("BIFROEST_E2E_RUNTIME must explicitly select docker or podman")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		return err
	}
	node, err := browserNodeTool()
	if err != nil {
		return fmt.Errorf("resolve pinned browser Node runtime: %w", err)
	}
	return runSuite(ctx, suite, runtime, node, root, goTool, stdout, stderr, exec.CommandContext)
}

func browserNodeTool() (string, error) {
	if node := os.Getenv("BIFROEST_TEST_NODE"); node != "" {
		return node, nil
	}
	// The invoking MISE task puts its pinned runtime on PATH. A separate
	// `mise which` cannot see task-local tools as global selections.
	return exec.LookPath("node")
}

type commandFactory func(context.Context, string, ...string) *exec.Cmd

func runSuite(ctx context.Context, suite browserSuite, runtime, node, root, goTool string, stdout, stderr io.Writer, command commandFactory) error {
	logDir := filepath.Join(root, "var", "e2e", runtime)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}
	logPath := filepath.Join(logDir, suite.name+".json")
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	child := command(ctx, goTool, suite.arguments()...)
	child.Dir = root
	child.Env = append(os.Environ(), "BIFROEST_E2E_RUNTIME="+runtime, "BIFROEST_TEST_BROWSER_UI=1", "BIFROEST_TEST_NODE="+node)
	child.Stdout, child.Stderr = io.MultiWriter(stdout, log), stderr
	runErr := child.Run()
	closeErr := log.Close()
	if runErr != nil {
		runErr = fmt.Errorf("run %s: %w", suite.name, runErr)
	}
	results, err := os.Open(logPath)
	if err != nil {
		return errors.Join(runErr, closeErr, err, ctx.Err())
	}
	verifyErr := verifyResults(results, suite.required)
	readCloseErr := results.Close()
	if verifyErr != nil {
		verifyErr = fmt.Errorf("verify %s results in %s: %w", suite.name, logPath, verifyErr)
	}
	return errors.Join(runErr, closeErr, verifyErr, readCloseErr, ctx.Err())
}

// Test selection is not proof of execution: go test can succeed with no matching
// tests or with skipped tests. Require each named test and the package to pass.
func verifyResults(input io.Reader, required []string) error {
	decoder := json.NewDecoder(input)
	passed := make(map[string]int)
	packagePassed := false
	for {
		var event struct {
			Action  string
			Package string
			Test    string
		}
		if err := decoder.Decode(&event); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("decode Go test JSON: %w", err)
		}
		switch event.Action {
		case "skip", "fail", "build-fail":
			return fmt.Errorf("mandatory browser tests reported %s: package=%s test=%s", event.Action, event.Package, event.Test)
		case "pass":
			if event.Package == e2ePackage {
				if event.Test == "" {
					packagePassed = true
				} else {
					passed[event.Test]++
				}
			}
		}
	}
	for _, test := range required {
		if passed[test] != 1 {
			return fmt.Errorf("required test %s passed %d times, want exactly once", test, passed[test])
		}
	}
	if !packagePassed {
		return errors.New("mandatory browser test package did not complete successfully")
	}
	return nil
}
