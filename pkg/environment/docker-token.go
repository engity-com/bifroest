package environment

import (
	"encoding/json"
	"strings"

	"github.com/docker/docker/api/types"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
)

type dockerToken struct {
	containerId        string
	containerAddresses []net.Host

	remoteUser string
	remoteHost net.Host

	shellCommand []string
	execCommand  []string
	sftpCommand  []string
	user         string
	directory    string

	portForwardingAllowed bool
}

func (this *DockerRepository) requestToToken(req Request, hostOs, hostArch string) (_ *dockerToken, err error) {
	fail := func(err error) (*dockerToken, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (_ *dockerToken, err error) {
		return fail(errors.Config.Newf(msg, args...))
	}

	var result dockerToken

	result.remoteUser = req.Remote().User()
	result.remoteHost = req.Remote().Host().Clone()

	if result.shellCommand, err = this.conf.ShellCommand.Render(req); err != nil {
		return failf("cannot evaluate shellCommand: %w", err)
	}
	if len(result.shellCommand) == 0 {
		switch hostOs {
		case "windows":
			result.shellCommand = []string{`C:\WINDOWS\system32\cmd.exe`}
		case "linux":
			result.shellCommand = []string{`/bin/sh`}
		default:
			return failf("shellCommand was not defined for docker environment and default cannot be resolved for %s/%s", hostOs, hostArch)
		}
	}

	if result.execCommand, err = this.conf.ExecCommand.Render(req); err != nil {
		return failf("cannot evaluate execCommand: %w", err)
	}
	if len(result.execCommand) == 0 {
		switch hostOs {
		case "windows":
			result.execCommand = []string{`C:\WINDOWS\system32\cmd.exe`, `/C`}
		case "linux":
			result.execCommand = []string{`/bin/sh`, `-c`}
		default:
			return failf("execCommand was not defined for docker environment and default cannot be resolved for %s/%s", hostOs, hostArch)
		}
	}

	if result.sftpCommand, err = this.conf.SftpCommand.Render(req); err != nil {
		return failf("cannot evaluate sftpCommand: %w", err)
	}
	if len(result.sftpCommand) == 0 {
		switch hostOs {
		case "windows":
			result.sftpCommand = []string{BifroestWindowsBinaryMountTarget, `sftp-server`}
		default:
			result.sftpCommand = []string{BifroestUnixBinaryMountTarget, `sftp-server`}
		}
	}

	if result.user, err = this.conf.User.Render(req); err != nil {
		return failf("cannot evaluate user: %w", err)
	}
	if result.directory, err = this.conf.Directory.Render(req); err != nil {
		return failf("cannot evaluate directory: %w", err)
	}
	if result.portForwardingAllowed, err = this.conf.PortForwardingAllowed.Render(req); err != nil {
		return failf("cannot evaluate portForwardingAllowed: %w", err)
	}

	return &result, nil
}

func (this *DockerRepository) containerToToken(container *types.Container, expected session.Session) (_ *dockerToken, err error) {
	fail := func(err error) (*dockerToken, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (_ *dockerToken, err error) {
		return fail(errors.Config.Newf(msg, args...))
	}
	decodeStrings := func(in string) (result []string, err error) {
		err = json.Unmarshal([]byte(in), &result)
		return result, err
	}

	var result dockerToken

	labels := container.Labels
	if v := labels[DockerLabelSessionId]; v == "" {
		return failf("missing %s label", DockerLabelSessionId)
	} else if v != expected.Id().String() {
		return failf("%s label contains session id: %q; but expected was: %q", DockerLabelSessionId, v, expected.Id().String())
	}

	result.remoteUser = labels[DockerLabelCreatedRemoteUser]
	if v := labels[DockerLabelCreatedRemoteHost]; v == "" {
		return failf("missing %s label", DockerLabelCreatedRemoteHost)
	} else if err = result.remoteHost.Set(v); err != nil {
		return failf("cannot decode remoteHost: %w", err)
	}

	if v := labels[DockerAnnotationShellCommand]; v == "" {
		return failf("missing %s label", DockerAnnotationShellCommand)
	} else if result.shellCommand, err = decodeStrings(v); err != nil {
		return failf("cannot decode shellCommand: %w", err)
	}
	if v := labels[DockerAnnotationExecCommand]; v == "" {
		return failf("missing %s label", DockerAnnotationExecCommand)
	} else if result.execCommand, err = decodeStrings(v); err != nil {
		return failf("cannot decode execCommand: %w", err)
	}
	if v := labels[DockerAnnotationSftpCommand]; v == "" {
		result.sftpCommand = nil
	} else if result.sftpCommand, err = decodeStrings(v); err != nil {
		return failf("cannot decode sftpCommand: %w", err)
	}

	result.user = labels[DockerAnnotationUser]
	result.directory = labels[DockerAnnotationDirectory]
	result.portForwardingAllowed = labels[DockerAnnotationPortForwardingAllowed] == "true"

	if netSettings := container.NetworkSettings; netSettings != nil && netSettings.Networks != nil {
		result.containerAddresses = make([]net.Host, len(netSettings.Networks))
		var i int
		for _, v := range netSettings.Networks {
			if err := result.containerAddresses[i].Set(v.IPAddress); err != nil {
				return failf("cannot decode network address of network %q: %w", v.NetworkID, err)
			}
			i++
		}
	}

	return &result, nil
}

func (this dockerToken) toLabels(using session.Session) map[string]string {
	mustEncodeJson := func(what any) string {
		bytes, err := json.Marshal(what)
		common.Must(err)
		return string(bytes)
	}

	return map[string]string{
		DockerLabelSessionId: strings.Clone(using.Id().String()),

		DockerLabelCreatedRemoteUser: this.User(),
		DockerLabelCreatedRemoteHost: this.Host().String(),

		DockerAnnotationShellCommand:          mustEncodeJson(this.shellCommand),
		DockerAnnotationExecCommand:           mustEncodeJson(this.execCommand),
		DockerAnnotationSftpCommand:           mustEncodeJson(this.sftpCommand),
		DockerAnnotationUser:                  strings.Clone(this.user),
		DockerAnnotationDirectory:             strings.Clone(this.directory),
		DockerAnnotationPortForwardingAllowed: mustEncodeJson(this.portForwardingAllowed),
	}
}

func (this dockerToken) User() string {
	return strings.Clone(this.remoteUser)
}

func (this dockerToken) Host() net.Host {
	return this.remoteHost.Clone()
}

func (this dockerToken) String() string {
	return this.User() + "@" + this.Host().String()
}
