package environment

import (
	"crypto/tls"
	"path/filepath"
	"runtime"

	"github.com/docker/go-connections/tlsconfig"

	"github.com/engity-com/bifroest/pkg/errors"
)

type dockerToken struct {
	Host       string `json:"host,omitempty"`
	ApiVersion string `json:"apiVersion,omitempty"`
	CertPath   string `json:"certPath,omitempty"`
	TlsVerify  bool   `json:"tlsVerify,omitempty"`

	Id string `json:"id"`

	ShellCommand          []string `json:"shellCommand"`
	ExecCommand           []string `json:"execCommand"`
	SftpCommand           []string `json:"sftpCommand,omitempty"`
	Directory             string   `json:"directory,omitempty"`
	User                  string   `json:"user,omitempty"`
	PortForwardingAllowed bool     `json:"portForwardingAllowed,omitempty"`
}

func (this *DockerRepository) newDockerToken(req Request) (_ *dockerToken, err error) {
	fail := func(err error) (*dockerToken, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*dockerToken, error) {
		return fail(errors.Config.Newf(msg, args...))
	}
	var result dockerToken

	if result.Host, err = this.conf.Host.Render(req); err != nil {
		return failf("cannot evaluate host: %w", err)
	}
	if result.ApiVersion, err = this.conf.ApiVersion.Render(req); err != nil {
		return failf("cannot evaluate apiVersion: %w", err)
	}
	if result.CertPath, err = this.conf.CertPath.Render(req); err != nil {
		return failf("cannot evaluate certPath: %w", err)
	}
	if result.TlsVerify, err = this.conf.TlsVerify.Render(req); err != nil {
		return failf("cannot evaluate tlsVerify: %w", err)
	}

	if result.ShellCommand, err = this.conf.ShellCommand.Render(req); err != nil {
		return failf("cannot evaluate shellCommand: %w", err)
	}
	if result.ExecCommand, err = this.conf.ExecCommand.Render(req); err != nil {
		return failf("cannot evaluate execCommand: %w", err)
	}
	if result.SftpCommand, err = this.conf.SftpCommand.Render(req); err != nil {
		return failf("cannot evaluate sftpCommand: %w", err)
	}
	if result.User, err = this.conf.User.Render(req); err != nil {
		return failf("cannot evaluate user: %w", err)
	}
	if result.Directory, err = this.conf.Directory.Render(req); err != nil {
		return failf("cannot evaluate directory: %w", err)
	}
	if result.PortForwardingAllowed, err = this.conf.PortForwardingAllowed.Render(req); err != nil {
		return failf("cannot evaluate portForwardingAllowed: %w", err)
	}

	return &result, nil
}

func (this *dockerToken) toTlsConfig() (*tls.Config, error) {
	if v := this.CertPath; v != "" {
		return tlsconfig.Client(tlsconfig.Options{
			CAFile:             filepath.Join(v, "ca.pem"),
			CertFile:           filepath.Join(v, "cert.pem"),
			KeyFile:            filepath.Join(v, "key.pem"),
			InsecureSkipVerify: !this.TlsVerify,
		})
	}
	return nil, nil
}

func (this *dockerToken) enrichWithHostDetails(_ Request, hostOs, hostArch string) (err error) {
	fail := func(err error) error {
		return err
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.Config.Newf(msg, args...))
	}

	if len(this.SftpCommand) == 0 && hostOs == runtime.GOOS && hostArch == runtime.GOARCH {
		this.SftpCommand = []string{BifroestBinaryMountTarget, `sftp-server`}
	}

	if len(this.ShellCommand) == 0 {
		switch hostOs {
		case "windows":
			this.ShellCommand = []string{`C:\WINDOWS\system32\cmd.exe`}
		case "linux":
			this.ShellCommand = []string{`/bin/sh`}
		default:
			return failf("shellCommand was not defined for docker environment and default cannot be resolved for %s/%s", hostOs, hostArch)
		}
	}

	if len(this.ExecCommand) == 0 {
		switch hostOs {
		case "windows":
			this.ExecCommand = []string{`C:\WINDOWS\system32\cmd.exe`, `/C`}
		case "linux":
			this.ExecCommand = []string{`/bin/sh`, `-c`}
		default:
			return failf("execCommand was not defined for docker environment and default cannot be resolved for %s/%s", hostOs, hostArch)
		}
	}

	return nil
}
