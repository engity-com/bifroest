package binary

import (
	"context"
	"fmt"
	gos "os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

type BuildRequest struct {
	Platform build.Platform
	Time     time.Time
	Version  string
	Vendor   string
	Revision string

	TargetFile string

	WslBuildDistribution string
	AssumedBuildOs       sys.Os
	AssumedBuildArch     sys.Arch
}

func Build(ctx context.Context, req BuildRequest) error {
	fail := func(err error) error {
		return err
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.System.Newf(msg, args...))
	}

	ldFlags := " -s -w " + req.toLdFlags()
	req.Platform.ToLdFlags()

	var buildEnvPath string

	var err error
	outputFilePath := req.TargetFile
	if req.WslBuildDistribution != "" {
		outputFilePath, err = translateToWslPath(outputFilePath)
		if err != nil {
			return fail(err)
		}
	}

	env := sys.EnvVars{}
	env.Add(gos.Environ()...)
	program := "go"
	args := []string{"build", "-ldflags", ldFlags, "-o", outputFilePath, "./cmd/bifroest"}
	if req.WslBuildDistribution != "" {
		wd, err := gos.Getwd()
		if err != nil {
			return fail(err)
		}
		wd, err = translateToWslPath(wd)
		if err != nil {
			return fail(err)
		}

		f, err := gos.CreateTemp("", "bifroest-go-build-*.env")
		if err != nil {
			return fail(err)
		}
		_ = f.Close()

		buildEnvPath = f.Name()
		wslBuildEnvPath, err := translateToWslPath(buildEnvPath)
		if err != nil {
			return fail(err)
		}

		qargs := make([]string, len(args)+1)
		qargs[0] = strconv.Quote(program)
		for i, arg := range args {
			qargs[i+1] = strconv.Quote(arg)
		}

		program = "wsl"
		env = sys.EnvVars{}
		args = []string{
			"-d", req.WslBuildDistribution,
			"--cd", wd,
			"bash",
			"-c", "source " + strconv.Quote(wslBuildEnvPath) + "; " + strings.Join(qargs, " "),
		}
	}

	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Stderr = gos.Stderr
	cmd.Stdout = gos.Stdout
	req.Platform.SetToEnv(req.assumedBuildOs(), req.assumedBuildArch(), env)

	if req.WslBuildDistribution != "" {
		f, err := gos.OpenFile(buildEnvPath, gos.O_WRONLY|gos.O_TRUNC, 0)
		if err != nil {
			return fail(err)
		}
		defer func() { _ = gos.Remove(f.Name()) }()
		defer common.IgnoreCloseError(f)

		for k, v := range env {
			if _, err := fmt.Fprintf(f, "export %s=%q\n", k, v); err != nil {
				return fail(err)
			}
		}
		if err := f.Close(); err != nil {
			return fail(err)
		}
	}

	cmd.Env = env.Strings()

	var eErr *exec.ExitError
	if err := cmd.Run(); errors.As(err, &eErr) {
		return failf("%v: build failed with %d", cmd, eErr.ExitCode())
	} else if err != nil {
		return fail(err)
	}

	return nil
}

func translateToWslPath(in string) (string, error) {
	if build.Goos != sys.OsWindows {
		return "", fmt.Errorf("can only translate %q to wsl path if os is: %v; but is: %v", in, sys.OsWindows, build.Goos)
	}
	abs, err := filepath.Abs(in)
	if err != nil {
		return "", err
	}

	return "/mnt/" + strings.ToLower(abs[0:1]) + filepath.ToSlash(abs[2:]), nil
}

func (this BuildRequest) toLdFlags() string {
	testPrefix := ""
	testSuffix := ""
	if this.Platform.Testing {
		testPrefix = "TEST"
		testSuffix = "TEST"
	}

	vendor := this.Vendor
	if vendor == "" {
		vendor = "unknown"
	}

	version := this.Version
	if version == "" {
		version = "development"
	}

	revision := this.Revision
	if revision == "" {
		revision = "development"
	}

	t := this.Time
	if t.IsZero() {
		t = time.Now()
	}

	return this.Platform.ToLdFlags() +
		" -X main.version=" + testPrefix + version + testSuffix +
		" -X main.revision=" + revision +
		" -X " + strconv.Quote("main.vendor="+vendor) +
		" -X main.buildAt=" + t.Format(time.RFC3339)
}

func (this BuildRequest) assumedBuildOs() sys.Os {
	if v := this.AssumedBuildOs; !v.IsZero() {
		return v
	}
	if this.WslBuildDistribution != "" {
		return sys.OsLinux
	}
	return build.Goos
}

func (this BuildRequest) assumedBuildArch() sys.Arch {
	if v := this.AssumedBuildArch; !v.IsZero() {
		return v
	}
	return build.Goarch
}
