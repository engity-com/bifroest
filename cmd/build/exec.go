package main

import (
	"bytes"
	"context"
	"fmt"
	gos "os"
	gexec "os/exec"
	"strings"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/errors"
)

func newExec(b *base) *exec {
	return &exec{
		base: b,
	}
}

type exec struct {
	base *base
}

func (this *exec) init(_ context.Context, _ *kingpin.Application) {}

func (this *exec) execute(ctx context.Context, cmd string, args ...string) *execCmd {
	result := execCmd{
		parent: this,
		cmd:    gexec.CommandContext(ctx, cmd, args...),
	}

	env := gos.Environ()
	result.env = make(map[string]string, len(env))
	for _, kv := range env {
		parts := strings.SplitN(kv, "=", 2)
		result.env[parts[0]] = parts[1]
	}
	result.cmd.Stdout = &result.stdout
	result.cmd.Stderr = &result.stderr

	return &result
}

type execCmd struct {
	parent *exec
	cmd    *gexec.Cmd

	env    map[string]string
	stdout bytes.Buffer
	stderr bytes.Buffer
}

func (this *execCmd) wrapError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%v: %s", this, err)
}

func (this *execCmd) String() string {
	return this.cmd.String()
}

func (this *execCmd) SetEnv(key, val string) {
	this.env[key] = val
}

func (this *execCmd) do() error {
	this.cmd.Env = make([]string, len(this.env))
	var i int
	for k, v := range this.env {
		this.cmd.Env[i] = k + "=" + v
		i++
	}

	var eErr *gexec.ExitError
	err := this.cmd.Run()
	if errors.As(err, &eErr) {
		return this.wrapError(fmt.Errorf("%v\n%s", eErr, this.stderr.String()))
	}
	return err
}

func (this *execCmd) doAndGet() (string, error) {
	if err := this.do(); err != nil {
		return "", err
	}
	return strings.TrimSpace(this.stdout.String()), nil
}
