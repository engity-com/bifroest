package environment

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/strslice"
	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/sys"
)

type dockerImp struct {
	repository *DockerRepository

	containerId string
	sessionId   uuid.UUID
	accessToken []byte

	remoteUser string
	remoteHost net.Host

	shellCommand []string
	execCommand  []string
	sftpCommand  []string
	user         string
	directory    string

	portForwardingAllowed bool
}

func (this *DockerRepository) populateImpFrom(req Request, hostOs, hostArch string) (_ *dockerImp, err error) {
	fail := func(err error) (*dockerImp, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (_ *dockerImp, err error) {
		return fail(errors.Config.Newf(msg, args...))
	}

	buf := dockerImp{
		repository: this,
	}

	buf.remoteUser = req.Remote().User()
	buf.remoteHost = req.Remote().Host().Clone()

	if buf.shellCommand, err = this.conf.ShellCommand.Render(req); err != nil {
		return failf("cannot evaluate shellCommand: %w", err)
	}
	if len(buf.shellCommand) == 0 {
		switch hostOs {
		case "windows":
			buf.shellCommand = []string{`C:\WINDOWS\system32\cmd.exe`}
		case "linux":
			buf.shellCommand = []string{`/bin/sh`}
		default:
			return failf("shellCommand was not defined for docker environment and default cannot be resolved for %s/%s", hostOs, hostArch)
		}
	}

	if buf.execCommand, err = this.conf.ExecCommand.Render(req); err != nil {
		return failf("cannot evaluate execCommand: %w", err)
	}
	if len(buf.execCommand) == 0 {
		switch hostOs {
		case "windows":
			buf.execCommand = []string{`C:\WINDOWS\system32\cmd.exe`, `/C`}
		case "linux":
			buf.execCommand = []string{`/bin/sh`, `-c`}
		default:
			return failf("execCommand was not defined for docker environment and default cannot be resolved for %s/%s", hostOs, hostArch)
		}
	}

	if buf.sftpCommand, err = this.conf.SftpCommand.Render(req); err != nil {
		return failf("cannot evaluate sftpCommand: %w", err)
	}
	if len(buf.sftpCommand) == 0 {
		switch hostOs {
		case "windows":
			buf.sftpCommand = []string{BifroestWindowsBinaryMountTarget, `sftp-server`}
		default:
			buf.sftpCommand = []string{BifroestUnixBinaryMountTarget, `sftp-server`}
		}
	}

	if buf.user, err = this.conf.User.Render(req); err != nil {
		return failf("cannot evaluate user: %w", err)
	}
	if buf.directory, err = this.conf.Directory.Render(req); err != nil {
		return failf("cannot evaluate directory: %w", err)
	}
	if buf.portForwardingAllowed, err = this.conf.PortForwardingAllowed.Render(req); err != nil {
		return failf("cannot evaluate portForwardingAllowed: %w", err)
	}

	return &buf, nil
}

func (this *DockerRepository) attachExisting(ctx context.Context, container *types.Container) error {
	fail := func(err error) error {
		return errors.System.Newf("cannot recover dangling containers of flow %v: %w", this.flow, err)
	}
	failf := func(msg string, args ...any) error {
		return fail(fmt.Errorf(msg, args...))
	}

	buf := dockerImp{
		repository: this,
	}
	if err := buf.parseExistingContainer(container); err != nil {
		return fail(err)
	}
	if err := this.apiClient.ContainerKill(ctx, buf.containerId, sys.SIGINT.String()); err != nil {
		return failf("cannot interrupt existing container %v: %w", buf.containerId, err)
	}
	if err := buf.doAttach(ctx); err != nil {
		return fail(err)
	}

	return nil
}

func (this *dockerImp) doAttach(_ context.Context) error {
	fail := func(err error) error {
		return errors.System.Newf("cannot attach to container %v of flow %v: %w", this.containerId, this.repository.flow, err)
	}
	failf := func(msg string, args ...any) error {
		return fail(fmt.Errorf(msg, args...))
	}

	if !this.repository.imps.CompareAndSwap(this.sessionId, nil, this) {
		return failf("cannot attach, because there is already an active attachment!?")
	}
	go this.observe()

	return nil
}

func (this *dockerImp) observe() {
	defer this.repository.imps.CompareAndSwap(this.sessionId, this, nil)

	// TODO! Do the observe
}

func (this *dockerImp) parseExistingContainer(container *types.Container) (err error) {
	fail := func(err error) error {
		return err
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.Config.Newf(msg, args...))
	}
	decodeStrings := func(in string) (result []string, err error) {
		err = json.Unmarshal([]byte(in), &result)
		return result, err
	}

	this.containerId = container.ID

	labels := container.Labels
	if v := labels[DockerLabelSessionId]; v == "" {
		return failf("missing %s label", DockerLabelSessionId)
	} else if err = this.sessionId.UnmarshalText([]byte(v)); err != nil {
		return failf("cannot decode sessionId: %w", err)
	}

	this.remoteUser = labels[DockerLabelCreatedRemoteUser]
	if v := labels[DockerLabelCreatedRemoteHost]; v == "" {
		return failf("missing %s label", DockerLabelCreatedRemoteHost)
	} else if err = this.remoteHost.Set(v); err != nil {
		return failf("cannot decode remoteHost: %w", err)
	}

	annotations := container.HostConfig.Annotations
	if v := annotations[DockerAnnotationShellCommand]; v == "" {
		return failf("missing %s label", DockerAnnotationShellCommand)
	} else if this.shellCommand, err = decodeStrings(v); err != nil {
		return failf("cannot decode shellCommand: %w", err)
	}
	if v := annotations[DockerAnnotationExecCommand]; v == "" {
		return failf("missing %s label", DockerAnnotationExecCommand)
	} else if this.execCommand, err = decodeStrings(v); err != nil {
		return failf("cannot decode execCommand: %w", err)
	}
	if v := annotations[DockerAnnotationSftpCommand]; v == "" {
		this.sftpCommand = nil
	} else if this.sftpCommand, err = decodeStrings(v); err != nil {
		return failf("cannot decode sftpCommand: %w", err)
	}

	this.user = annotations[DockerAnnotationUser]
	this.directory = annotations[DockerAnnotationDirectory]
	this.portForwardingAllowed = annotations[DockerAnnotationPortForwardingAllowed] == "true"

	return nil
}

func (this *dockerImp) resolveContainerConfig(req Request) (_ *container.Config, err error) {
	fail := func(err error) (*container.Config, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (_ *container.Config, err error) {
		return fail(errors.Config.Newf(msg, args...))
	}

	var result container.Config

	result.Labels = this.toLabels()

	if result.Image, err = this.repository.conf.Image.Render(req); err != nil {
		return failf("cannot evaluate image: %w", err)
	}
	result.Entrypoint = strslice.StrSlice{}
	if result.Cmd, err = this.repository.conf.BlockCommand.Render(req); err != nil {
		return failf("cannot evaluate mainCommand: %w", err)
	}
	result.Env = []string{
		"BIFROEST_IMP_ACCESS_TOKEN=" + hex.EncodeToString(this.accessToken),
		"BIFROEST_SESSION_ID=" + this.sessionId.String(),
	}
	if len(result.Cmd) == 0 {
		switch this.repository.hostOs {
		case "windows":
			result.Cmd = []string{BifroestWindowsBinaryMountTarget, `imp`}
		default:
			result.Cmd = []string{BifroestUnixBinaryMountTarget, `imp`}
		}
	}

	return &result, nil
}

func (this *dockerImp) resolveHostConfig(req Request, hostOs, hostArch string) (_ *container.HostConfig, err error) {
	fail := func(err error) (*container.HostConfig, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (_ *container.HostConfig, err error) {
		return fail(errors.Config.Newf(msg, args...))
	}

	var result container.HostConfig

	result.Annotations = this.toAnnotations()
	result.AutoRemove = true
	if result.Binds, err = this.repository.conf.Volumes.Render(req); err != nil {
		return failf("cannot evaluate volumes: %w", err)
	}
	if result.CapAdd, err = this.repository.conf.Capabilities.Render(req); err != nil {
		return failf("cannot evaluate capabilities: %w", err)
	}
	if result.Privileged, err = this.repository.conf.Privileged.Render(req); err != nil {
		return failf("cannot evaluate capabilities: %w", err)
	}
	if result.DNS, err = this.repository.conf.DnsServers.Render(req); err != nil {
		return failf("cannot evaluate dnsServer: %w", err)
	}
	if result.DNSSearch, err = this.repository.conf.DnsSearch.Render(req); err != nil {
		return failf("cannot evaluate dnsSearch: %w", err)
	}

	impBinaryPath, err := this.repository.impBinaries.FindBinaryFor(req.Context(), hostOs, hostArch)
	if err != nil {
		return failf("cannot resolve imp binary path: %w", err)
	}
	if impBinaryPath != "" {
		impBinaryPath, err = filepath.Abs(impBinaryPath)
		if err != nil {
			return failf("cannot resolve full imp binary path: %w", err)
		}
		var targetPath string
		switch hostOs {
		case "windows":
			targetPath = BifroestWindowsBinaryMountTarget
		default:
			targetPath = BifroestUnixBinaryMountTarget
		}
		result.Mounts = append(result.Mounts, mount.Mount{
			Type:     mount.TypeBind,
			Source:   impBinaryPath,
			Target:   targetPath,
			ReadOnly: true,
			BindOptions: &mount.BindOptions{
				NonRecursive:     true,
				CreateMountpoint: true,
			},
		})
	}

	return &result, nil
}

func (this *dockerImp) resolveNetworkingConfig(req Request) (*network.NetworkingConfig, error) {
	fail := func(err error) (*network.NetworkingConfig, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (_ *network.NetworkingConfig, err error) {
		return fail(errors.Config.Newf(msg, args...))
	}

	var result network.NetworkingConfig

	if v, err := this.repository.conf.Network.Render(req); err != nil {
		return failf("cannot evaluate network: %w", err)
	} else {
		result.EndpointsConfig = map[string]*network.EndpointSettings{
			v: {},
		}
	}

	return &result, nil
}

func (this dockerImp) toLabels() map[string]string {
	return map[string]string{
		DockerLabelSessionId: this.sessionId.String(),

		DockerLabelCreatedRemoteUser: this.remoteUser,
		DockerLabelCreatedRemoteHost: this.remoteHost.String(),
	}
}

func (this dockerImp) toAnnotations() map[string]string {
	mustEncodeJson := func(what any) string {
		bytes, err := json.Marshal(what)
		common.Must(err)
		return string(bytes)
	}

	return map[string]string{
		DockerAnnotationShellCommand:          mustEncodeJson(this.shellCommand),
		DockerAnnotationExecCommand:           mustEncodeJson(this.execCommand),
		DockerAnnotationSftpCommand:           mustEncodeJson(this.sftpCommand),
		DockerAnnotationUser:                  strings.Clone(this.user),
		DockerAnnotationDirectory:             strings.Clone(this.directory),
		DockerAnnotationPortForwardingAllowed: mustEncodeJson(this.portForwardingAllowed),
		DockerAnnotationAccessToken:           hex.EncodeToString(this.accessToken),
	}
}
