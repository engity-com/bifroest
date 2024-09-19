package environment

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/echocat/slf4g"
	"github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
)

var (
	_ = RegisterRepository(NewDockerRepository)
)

const (
	BifroestUnixBinaryMountTarget    = `/usr/bin/bifroest`
	BifroestWindowsBinaryMountTarget = `C:\Program Files\Engity\Bifroest\bifroest.exe`

	DockerLabelPrefix            = "org.engity.bifroest/"
	DockerLabelFlow              = DockerLabelPrefix + "flow"
	DockerLabelSessionId         = DockerLabelPrefix + "session-id"
	DockerLabelCreatedRemoteUser = DockerLabelPrefix + "created-remote-user"
	DockerLabelCreatedRemoteHost = DockerLabelPrefix + "created-remote-host"

	DockerAnnotationPrefix                = DockerLabelPrefix
	DockerAnnotationShellCommand          = DockerAnnotationPrefix + "shellCommand"
	DockerAnnotationExecCommand           = DockerAnnotationPrefix + "execCommand"
	DockerAnnotationSftpCommand           = DockerAnnotationPrefix + "sftpCommand"
	DockerAnnotationUser                  = DockerAnnotationPrefix + "user"
	DockerAnnotationDirectory             = DockerAnnotationPrefix + "directory"
	DockerAnnotationPortForwardingAllowed = DockerAnnotationPrefix + "portForwardingAllowed"
	DockerAnnotationAccessToken           = DockerAnnotationPrefix + "accessToken"
)

type DockerRepository struct {
	flow configuration.FlowName
	conf *configuration.EnvironmentDocker
	imp  imp.Imp

	apiClient   client.APIClient
	hostVersion *types.Version

	Logger log.Logger

	instances sync.Map
}

func NewDockerRepository(ctx context.Context, flow configuration.FlowName, conf *configuration.EnvironmentDocker, i imp.Imp) (*DockerRepository, error) {
	fail := func(err error) (*DockerRepository, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*DockerRepository, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	if conf == nil {
		return failf("nil configuration")
	}

	apiClient, err := newDockerApiClient(conf)
	if err != nil {
		return fail(err)
	}

	hostVersion, err := apiClient.ServerVersion(ctx)
	if err != nil {
		return failf("cannot retrieve docker host's version: %w", err)
	}

	result := DockerRepository{
		flow:        flow,
		conf:        conf,
		imp:         i,
		apiClient:   apiClient,
		hostVersion: &hostVersion,
	}

	if err := result.recoverDangling(ctx); err != nil {
		return fail(err)
	}

	return &result, nil
}

func (this *DockerRepository) WillBeAccepted(req Request) (ok bool, err error) {
	fail := func(err error) (bool, error) {
		return false, err
	}

	if ok, err = this.conf.LoginAllowed.Render(req); err != nil {
		return fail(fmt.Errorf("cannot evaluate if user is allowed to login or not: %w", err))
	}

	return ok, nil
}

func (this *DockerRepository) DoesSupportPty(Request, ssh.Pty) (bool, error) {
	return true, nil
}

func (this *DockerRepository) Ensure(req Request) (Environment, error) {
	fail := func(err error) (Environment, error) {
		return nil, err
	}
	failf := func(t errors.Type, msg string, args ...any) (Environment, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	success := false

	if ok, err := this.WillBeAccepted(req); err != nil {
		return fail(err)
	} else if !ok {
		return fail(ErrNotAcceptable)
	}

	sess := req.Authorization().FindSession()
	if sess == nil {
		return failf(errors.System, "authorization without session")
	}

	for {
		instance, ok := this.instances.Load(sess.Id())
		if ok {
			return instance.(*docker), nil
		}

		accessToken := make([]byte, 12)
		if _, err := rand.Read(accessToken); err != nil {
			return failf(errors.System, "cannot generate access token: %w", err)
		}

		config, err := this.resolveContainerConfig(req, sess, accessToken)
		if err != nil {
			return fail(err)
		}
		hostConfig, err := this.resolveHostConfig(req, accessToken)
		if err != nil {
			return fail(err)
		}
		networkingConfig, err := this.resolveNetworkingConfig(req)
		if err != nil {
			return fail(err)
		}

		cr, err := this.apiClient.ContainerCreate(req.Context(), config, hostConfig, networkingConfig, nil, "")
		if err != nil {
			return failf(errors.System, "cannot create container: %w", err)
		}
		containerId := cr.ID
		defer func() {
			if !success {
				if _, err := this.removeContainer(req.Context(), containerId); err != nil {
					req.Logger().
						WithError(err).
						Warn("cannot remove orphan container within emergency cleanup; container could still be there")
				}
			}
		}()

		if err := this.apiClient.ContainerStart(req.Context(), containerId, container.StartOptions{}); err != nil {
			return failf(errors.System, "cannot start container #%s: %w", containerId, err)
		}
		c, _, err := this.findContainerById(req.Context(), containerId)

		result, err := this.new(req.Context(), c)
		if errors.Is(err, errDockerEnvironmentDuplicate) {
			// Ok, new try....
			continue
		}
		if err != nil {
			return fail(err)
		}

		success = true
		return result, nil
	}
}

func (this *DockerRepository) resolveContainerConfig(req Request, sess session.Session, accessToken []byte) (_ *container.Config, err error) {
	fail := func(err error) (*container.Config, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (_ *container.Config, err error) {
		return fail(errors.Config.Newf(msg, args...))
	}

	var result container.Config

	result.Labels = map[string]string{
		DockerLabelFlow:      this.flow.String(),
		DockerLabelSessionId: sess.Id().String(),

		DockerLabelCreatedRemoteUser: req.Remote().User(),
		DockerLabelCreatedRemoteHost: req.Remote().Host().String(),
	}

	if result.Image, err = this.conf.Image.Render(req); err != nil {
		return failf("cannot evaluate image: %w", err)
	}
	result.Entrypoint = strslice.StrSlice{}
	if result.Cmd, err = this.conf.BlockCommand.Render(req); err != nil {
		return failf("cannot evaluate mainCommand: %w", err)
	}
	result.Env = []string{
		"BIFROEST_IMP_ACCESS_TOKEN=" + hex.EncodeToString(accessToken),
		"BIFROEST_SESSION_ID=" + sess.Id().String(),
	}
	if len(result.Cmd) == 0 {
		switch this.hostVersion.Os {
		case sys.OsWindows:
			result.Cmd = []string{BifroestWindowsBinaryMountTarget, `imp`}
		case sys.OsLinux:
			result.Cmd = []string{BifroestUnixBinaryMountTarget, `imp`}
		default:
			return failf("cannot resolve target path for host %s/%s", this.hostVersion.Os, this.hostVersion.Arch)
		}
	}

	return &result, nil
}

func (this *DockerRepository) resolveHostConfig(req Request, accessToken []byte) (_ *container.HostConfig, err error) {
	fail := func(err error) (*container.HostConfig, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (_ *container.HostConfig, err error) {
		return fail(errors.Config.Newf(msg, args...))
	}

	var result container.HostConfig

	result.AutoRemove = true
	if result.Binds, err = this.conf.Volumes.Render(req); err != nil {
		return failf("cannot evaluate volumes: %w", err)
	}
	if result.CapAdd, err = this.conf.Capabilities.Render(req); err != nil {
		return failf("cannot evaluate capabilities: %w", err)
	}
	if result.Privileged, err = this.conf.Privileged.Render(req); err != nil {
		return failf("cannot evaluate capabilities: %w", err)
	}
	if result.DNS, err = this.conf.DnsServers.Render(req); err != nil {
		return failf("cannot evaluate dnsServer: %w", err)
	}
	if result.DNSSearch, err = this.conf.DnsSearch.Render(req); err != nil {
		return failf("cannot evaluate dnsSearch: %w", err)
	}

	impBinaryPath, err := this.imp.FindBinaryFor(req.Context(), this.hostVersion.Os, this.hostVersion.Arch)
	if err != nil {
		return failf("cannot resolve imp binary path: %w", err)
	}
	if impBinaryPath != "" {
		impBinaryPath, err = filepath.Abs(impBinaryPath)
		if err != nil {
			return failf("cannot resolve full imp binary path: %w", err)
		}
		var targetPath string
		switch this.hostVersion.Os {
		case sys.OsWindows:
			targetPath = BifroestWindowsBinaryMountTarget
		case sys.OsLinux:
			targetPath = BifroestUnixBinaryMountTarget
		default:
			return failf("cannot resolve target path for host %s/%s", this.hostVersion.Os, this.hostVersion.Arch)
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

	result.Annotations = make(map[string]string)
	if result.Annotations[DockerAnnotationShellCommand], err = this.resolveEncodedShellCommand(req); err != nil {
		return fail(err)
	}
	if result.Annotations[DockerAnnotationExecCommand], err = this.resolveEncodedExecCommand(req); err != nil {
		return fail(err)
	}
	if result.Annotations[DockerAnnotationSftpCommand], err = this.resolveEncodedSftpCommand(req); err != nil {
		return fail(err)
	}
	if result.Annotations[DockerAnnotationUser], err = this.conf.User.Render(req); err != nil {
		return failf("cannot evaluate user: %w", err)
	}
	if result.Annotations[DockerAnnotationDirectory], err = this.conf.Directory.Render(req); err != nil {
		return failf("cannot evaluate directory: %w", err)
	}
	if v, err := this.conf.PortForwardingAllowed.Render(req); err != nil {
		return failf("cannot evaluate portForwardingAllowed: %w", err)
	} else if v {
		result.Annotations[DockerAnnotationPortForwardingAllowed] = "true"
	}
	result.Annotations[DockerAnnotationAccessToken] = hex.EncodeToString(accessToken)

	return &result, nil
}

func (this *DockerRepository) resolveEncodedShellCommand(req Request) (string, error) {
	failf := func(msg string, args ...any) (string, error) {
		return "", errors.Config.Newf(msg, args...)
	}

	v, err := this.conf.ShellCommand.Render(req)
	if err != nil {
		return failf("cannot evaluate shellCommand: %w", err)
	}
	if len(v) == 0 {
		switch this.hostVersion.Os {
		case sys.OsWindows:
			v = []string{`C:\WINDOWS\system32\cmd.exe`}
		case sys.OsLinux:
			v = []string{`/bin/sh`}
		default:
			return failf("shellCommand was not defined for docker environment and default cannot be resolved for %s/%s", this.hostVersion.Os, this.hostVersion.Arch)
		}
	}
	b, err := json.Marshal(v)
	return string(b), err
}

func (this *DockerRepository) resolveEncodedExecCommand(req Request) (string, error) {
	failf := func(msg string, args ...any) (string, error) {
		return "", errors.Config.Newf(msg, args...)
	}

	v, err := this.conf.ExecCommand.Render(req)
	if err != nil {
		return failf("cannot evaluate execCommand: %w", err)
	}
	if len(v) == 0 {
		switch this.hostVersion.Os {
		case sys.OsWindows:
			v = []string{`C:\WINDOWS\system32\cmd.exe`, `/C`}
		case sys.OsLinux:
			v = []string{`/bin/sh`, `-c`}
		default:
			return failf("execCommand was not defined for docker environment and default cannot be resolved for %s/%s", this.hostVersion.Os, this.hostVersion.Arch)
		}
	}
	b, err := json.Marshal(v)
	return string(b), err
}

func (this *DockerRepository) resolveEncodedSftpCommand(req Request) (string, error) {
	failf := func(msg string, args ...any) (string, error) {
		return "", errors.Config.Newf(msg, args...)
	}

	v, err := this.conf.SftpCommand.Render(req)
	if err != nil {
		return failf("cannot evaluate sftpCommand: %w", err)
	}
	if len(v) == 0 {
		switch this.hostVersion.Os {
		case sys.OsWindows:
			v = []string{BifroestWindowsBinaryMountTarget, `sftp-server`}
		case sys.OsLinux:
			v = []string{BifroestUnixBinaryMountTarget, `sftp-server`}
		default:
			return failf("sftpCommand was not defined for docker environment and default cannot be resolved for %s/%s", this.hostVersion.Os, this.hostVersion.Arch)
		}
	}
	b, err := json.Marshal(v)
	return string(b), err
}

func (this *DockerRepository) resolveNetworkingConfig(req Request) (*network.NetworkingConfig, error) {
	fail := func(err error) (*network.NetworkingConfig, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (_ *network.NetworkingConfig, err error) {
		return fail(errors.Config.Newf(msg, args...))
	}

	var result network.NetworkingConfig

	if v, err := this.conf.Network.Render(req); err != nil {
		return failf("cannot evaluate network: %w", err)
	} else {
		result.EndpointsConfig = map[string]*network.EndpointSettings{
			v: {},
		}
	}

	return &result, nil
}

func (this *DockerRepository) FindBySession(_ context.Context, sess session.Session, opts *FindOpts) (Environment, error) {
	fail := func(err error) (Environment, error) {
		return nil, err
	}

	instance, ok := this.instances.Load(sess.Id())
	if !ok {
		return fail(ErrNoSuchEnvironment)
	}

	return instance.(*docker), nil
}

func (this *DockerRepository) removeContainer(ctx context.Context, id string) (bool, error) {
	if err := this.apiClient.ContainerRemove(ctx, id, container.RemoveOptions{
		RemoveVolumes: true,
		Force:         true,
	}); errdefs.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, errors.System.Newf("cannot remove container #%s: %w", id, err)
	}
	return true, nil
}

func (this *DockerRepository) findContainers(ctx context.Context) ([]types.Container, error) {
	list, err := this.apiClient.ContainerList(ctx, container.ListOptions{
		All: true,
		Filters: filters.NewArgs(
			filters.Arg("label="+DockerLabelFlow, this.flow.String()),
			filters.Arg("status", "running"),
		),
	})
	if err != nil {
		return nil, errors.System.Newf("cannot list container of flow %v: %w", this.flow, err)
	}
	return list, nil
}

func (this *DockerRepository) findContainerBySession(ctx context.Context, sess session.Session) (*types.Container, int, error) {
	return this.findContainerBy(ctx, filters.NewArgs(
		filters.Arg("label="+DockerLabelSessionId, sess.Id().String()),
	))
}
func (this *DockerRepository) findContainerById(ctx context.Context, id string) (*types.Container, int, error) {
	return this.findContainerBy(ctx, filters.NewArgs(
		filters.Arg("id", id),
	))
}

func (this *DockerRepository) findContainerBy(ctx context.Context, filters filters.Args) (*types.Container, int, error) {
	list, err := this.apiClient.ContainerList(ctx, container.ListOptions{
		Limit:   1,
		Filters: filters,
	})
	if err != nil {
		return nil, -1, errors.System.Newf("cannot list container by %v: %w", filters, err)
	}
	if len(list) == 0 {
		return nil, -1, nil
	}

	c := list[0]
	exitCode := -1
	if strings.HasPrefix(c.Status, "Exited (") {
		status := strings.TrimPrefix(c.Status, "Exited (")
		if i := strings.IndexRune(status, ')'); i > 0 {
			v, err := strconv.Atoi(status[:i])
			if err == nil {
				exitCode = v
			}
		}
	}

	return &list[0], exitCode, nil
}

func (this *DockerRepository) recoverDangling(ctx context.Context) error {
	fail := func(err error) error {
		return errors.System.Newf("cannot recover dangling containers of flow %v: %w", this.flow, err)
	}
	failf := func(msg string, args ...any) error {
		return fail(fmt.Errorf(msg, args...))
	}

	candidates, err := this.findContainers(ctx)
	if err != nil {
		return fail(err)
	}
	for _, candidate := range candidates {
		if _, err := this.new(ctx, &candidate); err != nil {
			return failf("cannot attach container %v: %w", candidate.ID, err)
		}
	}

	return nil
}

func (this *DockerRepository) Close() error {
	return nil
}

func (this *DockerRepository) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("authorizer")
}
