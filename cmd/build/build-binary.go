package main

import (
	"context"
	"fmt"
	gos "os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kingpin"
	"github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/common"
)

func newBuildBinary(b *build) *buildBinary {
	return &buildBinary{
		build: b,
	}
}

type buildBinary struct {
	*build
}

func (this *buildBinary) attach(_ *kingpin.CmdClause) {}

func (this *buildBinary) compile(ctx context.Context, p *platform) (*buildArtifact, error) {
	fail := func(err error) (*buildArtifact, error) {
		return nil, fmt.Errorf("cannot build %v: %w", *p, err)
	}

	if err := p.assertBinarySupported(this.assumedBuildOs(), this.assumedBuildArch()); err != nil {
		return fail(err)
	}

	fn := p.filenamePrefix(this.prefix) + p.os.execExt()

	success := false
	a, err := this.newBuildFileArtifact(ctx, p, buildArtifactTypeBinary, fn)
	if err != nil {
		return fail(err)
	}
	defer common.IgnoreCloseErrorIfFalse(&success, a)

	l := log.With("platform", p).
		With("stage", buildStageBinary).
		With("file", a.filepath)

	ldFlags := "-s -w " + a.toLdFlags(a.os)

	start := time.Now()
	l.Debug("building binary...")

	var buildEnvPath string
	createExec := func(cmd string, args ...string) (*execCmd, error) {
		if this.wslBuildDistribution == "" {
			return this.build.execute(ctx, cmd, args...), nil
		}
		wd, err := gos.Getwd()
		if err != nil {
			return nil, err
		}
		wd, err = this.translateToWslPath(wd)
		if err != nil {
			return nil, err
		}

		f, err := gos.CreateTemp("", "bifroest-go-build-*.env")
		if err != nil {
			return nil, err
		}
		_ = f.Close()

		buildEnvPath = f.Name()
		wslBuildEnvPath, err := this.translateToWslPath(buildEnvPath)
		if err != nil {
			return nil, err
		}

		qargs := make([]string, len(args)+1)
		qargs[0] = strconv.Quote(cmd)
		for i, arg := range args {
			qargs[i+1] = strconv.Quote(arg)
		}

		result := this.build.execute(ctx, "wsl",
			"-d", this.wslBuildDistribution,
			"--cd", wd,
			"bash",
			"-c", "source "+strconv.Quote(wslBuildEnvPath)+"; "+strings.Join(qargs, " "),
		)
		result.env = map[string]string{}
		return result, nil
	}

	outputFilePath := a.filepath
	if this.wslBuildDistribution != "" {
		outputFilePath, err = this.translateToWslPath(outputFilePath)
		if err != nil {
			return fail(err)
		}
	}

	ec, err := createExec("go", "build", "-ldflags", ldFlags, "-o", outputFilePath, "./cmd/bifroest")
	if err != nil {
		return fail(err)
	}
	ec.attachStd()
	a.setToEnv(this.assumedBuildOs(), this.assumedBuildArch(), ec)

	if this.wslBuildDistribution != "" {
		f, err := gos.OpenFile(buildEnvPath, gos.O_WRONLY|gos.O_TRUNC, 0)
		if err != nil {
			return fail(err)
		}
		defer func() { _ = gos.Remove(f.Name()) }()
		defer common.IgnoreCloseError(f)

		for k, v := range ec.env {
			if _, err := fmt.Fprintf(f, "export %s=%q\n", k, v); err != nil {
				return fail(err)
			}
		}
		if err := f.Close(); err != nil {
			return fail(err)
		}
	}
	if err := ec.do(); err != nil {
		return fail(err)
	}

	ld := l.With("duration", time.Since(start).Truncate(time.Millisecond))
	if l.IsDebugEnabled() {
		ld.Debug("building binary... DONE!")
	} else {
		ld.Info("binary built")
	}

	success = true
	return a, nil
}

func (this *buildBinary) buildLdFlags(ctx context.Context, _ os, _ arch, e edition, forTesting bool, version string) (string, error) {
	fail := func(err error) (string, error) {
		return "", err
	}

	testPrefix := ""
	testSuffix := ""
	if forTesting {
		testPrefix = "TEST"
		testSuffix = "TEST"
	}
	commit, err := this.build.commit(ctx)
	if err != nil {
		return fail(err)
	}

	return "-s -w" +
		fmt.Sprintf(" -X main.edition=%v", e) +
		fmt.Sprintf(" -X main.version=%s%s%s", testPrefix, version, testSuffix) +
		fmt.Sprintf(" -X main.revision=%s", commit) +
		fmt.Sprintf(" -X main.vendor=%s", this.build.vendor) +
		fmt.Sprintf(" -X main.buildAt=%s", this.build.timeFormatted()), nil
}

func (this *buildBinary) outputName(o os, a arch, e edition, forTesting bool, version string) string {
	dir := filepath.Join(this.build.dest, version)
	_ = gos.MkdirAll(dir, 0755)

	fn := fmt.Sprintf("%s-%v-%v-%v", this.prefix, o, a, e)
	if forTesting {
		fn += "-test"
	}
	fn += o.execExt()

	return filepath.Join(dir, fn)
}
