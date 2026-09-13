package binary

import (
	"context"
	"fmt"
	"io"
	gos "os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/debug"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

type BuildRequest struct {
	Platform build.Platform
	Time     time.Time
	Version  string
	Vendor   string
	Revision string
	Tags     []string

	TargetFile string

	WslBuildDistribution string
	AssumedBuildOs       sys.Os
	AssumedBuildArch     sys.Arch
}

func Build(ctx context.Context, req BuildRequest) error {
	cFlags := ""
	ldFlags := req.toLdFlags()
	if !debug.IsEmbeddedDlvEnabled() {
		ldFlags = "-w -s " + ldFlags
		if req.Platform.Os != sys.OsWindows || req.Platform.Arch != sys.ArchArm64 {
			cFlags = "all=-N -l"
		}
	}

	outputFilePath, err := req.TargetPath(req.TargetFile)
	if err != nil {
		return err
	}
	args := []string{"build", "-o", outputFilePath}
	args = append(args, "-trimpath", "-buildvcs=false")
	if ldFlags != "" {
		args = append(args, "-ldflags", ldFlags)
	}
	if cFlags != "" {
		args = append(args, "-gcflags", cFlags)
	}
	if vs := req.Tags; len(vs) > 0 {
		args = append(args, "-tags", strings.Join(vs, " "))
	}
	args = append(args, "./cmd/bifroest")
	return req.RunGo(ctx, gos.Stdout, gos.Stderr, args...)
}

func (this BuildRequest) TargetPath(filename string) (string, error) {
	if this.WslBuildDistribution == "" {
		return filename, nil
	}
	return translateToWslPath(filename)
}

func (this BuildRequest) RunGo(ctx context.Context, stdout, stderr io.Writer, goArgs ...string) error {
	var buildEnvPath string
	goEnv := this.Environment()

	program := "go"
	args := goArgs
	commandEnv := goEnv
	if this.WslBuildDistribution != "" {
		wd, err := gos.Getwd()
		if err != nil {
			return err
		}
		wd, err = translateToWslPath(wd)
		if err != nil {
			return err
		}

		f, err := gos.CreateTemp("", "bifroest-go-build-*.env")
		if err != nil {
			return err
		}
		_ = f.Close()

		buildEnvPath = f.Name()
		wslBuildEnvPath, err := translateToWslPath(buildEnvPath)
		if err != nil {
			return err
		}

		qargs := make([]string, len(args)+1)
		qargs[0] = strconv.Quote(program)
		for i, arg := range args {
			qargs[i+1] = strconv.Quote(arg)
		}

		program = "wsl"
		commandEnv = nil
		args = []string{
			"-d", this.WslBuildDistribution,
			"--cd", wd,
			"bash",
			"-c", "source " + strconv.Quote(wslBuildEnvPath) + "; " + strings.Join(qargs, " "),
		}
	}

	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Stderr = stderr
	cmd.Stdout = stdout

	if this.WslBuildDistribution != "" {
		f, err := gos.OpenFile(buildEnvPath, gos.O_WRONLY|gos.O_TRUNC, 0)
		if err != nil {
			return err
		}
		defer func() { _ = gos.Remove(f.Name()) }()
		defer common.IgnoreCloseError(f)

		for k, v := range goEnv {
			if _, err := fmt.Fprintf(f, "export %s=%q\n", k, v); err != nil {
				return err
			}
		}
		if err := f.Close(); err != nil {
			return err
		}
	}

	cmd.Env = commandEnv.Strings()

	var eErr *exec.ExitError
	if err := cmd.Run(); errors.As(err, &eErr) {
		return errors.System.Newf("%v: Go command failed with %d", cmd, eErr.ExitCode())
	} else if err != nil {
		return err
	}

	return nil
}

func (this BuildRequest) Environment() sys.EnvVars {
	result := sys.EnvVars{}
	result.Add(gos.Environ()...)
	result.SetCanonical("GOENV", "off", "GOFLAGS", "-mod=readonly", "GOWORK", "off")
	this.Platform.SetToEnv(this.assumedBuildOs(), this.assumedBuildArch(), result)
	if len(this.Tags) > 0 {
		result.SetCanonical("GOFLAGS", "-mod=readonly -tags="+strings.Join(this.Tags, ","))
	}
	return result
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
