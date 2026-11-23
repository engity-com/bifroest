package test

import (
	"context"
	goerrors "errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
	bftest "github.com/engity-com/bifroest/pkg/test"
)

type opts struct {
	Suites        []string `argument:"suites" required:"true" description:"Suite files (*_bftest.lua) or directories searched recursively, following symlinks."`
	Includes      []string `flag:"includes" description:"Include tests matching any regex on suite.name/test.name; repeatable, default all."`
	Excludes      []string `flag:"excludes" description:"Exclude tests matching any regex on suite.name/test.name; repeatable."`
	Configuration string   `flag:"configuration" short:"c" description:"Fallback YAML file for suites without configuration; otherwise use the system default."`
	JSON          string   `flag:"json" description:"Write a JSON report, replacing an existing report and creating parent directories."`
	JUnit         string   `flag:"junit" description:"Write a JUnit XML report, replacing an existing report and creating parent directories."`
	Verbose       bool     `flag:"verbose" short:"v" description:"Show every package, suite and test, including passing and skipped tests."`
}

func CreateCommands(version sys.Version) []cli.CommandRequirementLike {
	var binary bftest.Platform
	if version != nil {
		binary = bftest.Platform{OS: version.Os().String(), Arch: version.Arch().String(), Version: version.Version()}
	}
	return []cli.CommandRequirementLike{cli.NewCommand[opts]("test", "Run bounded offline post-authentication policy tests.").
		WithProfiles(common.ProfileExecutable).WithHandler(func(ctx context.Context, opts opts) error { return handle(ctx, opts, binary) })}
}

func handle(ctx context.Context, opts opts, binary bftest.Platform) error {
	report := bftest.RunPaths(ctx, opts.Suites, bftest.Options{Includes: opts.Includes, Excludes: opts.Excludes, Configuration: opts.Configuration, Platform: binary})
	if len(report.Warnings) > 0 {
		if err := report.WriteWarnings(cli.StderrOfContext(ctx)); err != nil {
			return reportError("stderr", err)
		}
	}
	if err := report.WriteTextWithOptions(cli.StdoutOfContext(ctx), bftest.TextOptions{Verbose: opts.Verbose}); err != nil {
		return reportError("stdout", err)
	}
	protected := append(append([]string{}, opts.Suites...), report.InputFiles...)
	protected = append(protected, opts.Configuration)
	if err := writeReport(opts.JSON, report.WriteJSON, protected...); err != nil {
		return err
	}
	if err := writeReport(opts.JUnit, report.WriteJUnit, append(protected, opts.JSON)...); err != nil {
		return err
	}
	err := report.Err()
	if reported, ok := err.(*bftest.CommandError); ok {
		reported.Reported = true
	}
	return err
}

func writeReport(path string, write func(io.Writer) error, protected ...string) (resultErr error) {
	if path == "" {
		return nil
	}
	defer func() {
		if resultErr != nil {
			resultErr = reportError(path, resultErr)
		}
	}()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if err := checkReportTarget(path, protected); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".bifroest-policy-report-*")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(file.Name()); err != nil && !os.IsNotExist(err) {
			resultErr = goerrors.Join(resultErr, err)
		}
	}()
	writeErr := write(file)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return goerrors.Join(writeErr, closeErr)
	}
	// Recheck after serialization; never truncate a live input or follow a final
	// symlink. Staging also leaves the old report intact if serialization fails.
	if err := checkReportTarget(path, protected); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func checkReportTarget(path string, protected []string) error {
	if strings.HasSuffix(filepath.Base(path), "_bftest.lua") {
		return fmt.Errorf("report destination %q uses the reserved suite filename suffix", path)
	}
	info, err := os.Lstat(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if info != nil && !info.Mode().IsRegular() {
		return fmt.Errorf("report destination %q is not a regular file (directories and symlinks are not replaced)", path)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for _, input := range protected {
		if input == "" {
			continue
		}
		other, err := filepath.Abs(input)
		if err != nil {
			return err
		}
		inputInfo, statErr := os.Stat(input)
		if absolute == other || info != nil && statErr == nil && os.SameFile(info, inputInfo) {
			return fmt.Errorf("report destination %q would replace input or another report %q", path, input)
		}
	}
	return nil
}

func reportError(target string, cause error) error {
	return &bftest.CommandError{Code: 2, Cause: errors.System.Newf("cannot write offline policy test report %q: %w", target, cause)}
}
