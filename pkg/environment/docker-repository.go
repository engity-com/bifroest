package environment

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/docker/cli/opts"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/docker/go-connections/nat"
	"github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	"github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/alternatives"
	"github.com/engity-com/bifroest/pkg/common"
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

	DockerLabelShellCommand          = DockerLabelPrefix + "shellCommand"
	DockerLabelExecCommand           = DockerLabelPrefix + "execCommand"
	DockerLabelSftpCommand           = DockerLabelPrefix + "sftpCommand"
	DockerLabelUser                  = DockerLabelPrefix + "user"
	DockerLabelDirectory             = DockerLabelPrefix + "directory"
	DockerLabelPortForwardingAllowed = DockerLabelPrefix + "portForwardingAllowed"
)

type DockerRepository struct {
	flow         configuration.FlowName
	conf         *configuration.EnvironmentDocker
	alternatives alternatives.Provider
	imp          imp.Imp

	apiClient   client.APIClient
	hostOs      sys.Os
	hostArch    sys.Arch
	hostVersion *types.Version

	Logger              log.Logger
	defaultLogLevelName string

	sessionIdMutex  common.KeyedMutex[session.Id]
	activeInstances sync.Map
}

func NewDockerRepository(ctx context.Context, flow configuration.FlowName, conf *configuration.EnvironmentDocker, ap alternatives.Provider, i imp.Imp) (*DockerRepository, error) {
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
		flow:         flow,
		conf:         conf,
		alternatives: ap,
		imp:          i,
		apiClient:    apiClient,
		hostVersion:  &hostVersion,
	}

	if err = result.hostOs.SetOci(result.hostVersion.Os); err != nil {
		return failf("cannot parse docker host's os: %w", err)
	}
	if err = result.hostArch.SetOci(result.hostVersion.Arch); err != nil {
		return failf("cannot parse docker host's os: %w", err)
	}

	lp := result.logger().GetProvider()
	if la, ok := lp.(level.Aware); ok {
		if lna, ok := lp.(level.NamesAware); ok {
			lvl := la.GetLevel()
			if result.defaultLogLevelName, err = lna.GetLevelNames().ToName(lvl); err != nil {
				return failf("cannot transform to name of level %v: %w", lvl, err)
			}
		}
	}

	return &result, nil
}

func (this *DockerRepository) WillBeAccepted(ctx Context) (ok bool, err error) {
	fail := func(err error) (bool, error) {
		return false, err
	}

	if ok, err = this.conf.LoginAllowed.Render(ctx); err != nil {
		return fail(fmt.Errorf("cannot evaluate if user is allowed to login or not: %w", err))
	}

	return ok, nil
}

func (this *DockerRepository) DoesSupportPty(Context, ssh.Pty) (bool, error) {
	return true, nil
}

func (this *DockerRepository) Ensure(req Request) (Environment, error) {
	fail := func(err error) (Environment, error) {
		return nil, err
	}
	failf := func(t errors.Type, msg string, args ...any) (Environment, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	if ok, err := this.WillBeAccepted(req); err != nil {
		return fail(err)
	} else if !ok {
		return fail(ErrNotAcceptable)
	}

	sess := req.Authorization().FindSession()
	if sess == nil {
		return failf(errors.System, "authorization without session")
	}

	return this.findOrEnsureBySession(req.Context(), sess, nil, req, true)
}

func (this *DockerRepository) createContainerBy(req Request, sess session.Session) (*types.Container, error) {
	fail := func(err error) (*types.Container, error) {
		return nil, err
	}
	failf := func(t errors.Type, msg string, args ...any) (*types.Container, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	config, err := this.resolveContainerConfig(req, sess)
	if err != nil {
		return fail(err)
	}
	hostConfig, err := this.resolveHostConfig(req)
	if err != nil {
		return fail(err)
	}
	networkingConfig, err := this.resolveNetworkingConfig(req)
	if err != nil {
		return fail(err)
	}

	if this.conf.ImagePullPolicy == configuration.PullPolicyAlways {
		if err := this.pullImage(req, config.Image); err != nil {
			return failf(errors.System, "cannot pull container image %s: %w", config.Image, err)
		}
	}
	success := false
	cr, err := this.apiClient.ContainerCreate(req.Context(), config, hostConfig, networkingConfig, nil, "")
	if this.isNoSuchImageError(err) && this.conf.ImagePullPolicy != configuration.PullPolicyAlways {
		if err := this.pullImage(req, config.Image); err != nil {
			return failf(errors.System, "cannot pull container image %s: %w", config.Image, err)
		}
		cr, err = this.apiClient.ContainerCreate(req.Context(), config, hostConfig, networkingConfig, nil, "")
	}
	if err != nil {
		return failf(errors.System, "cannot create container: %w", err)
	}
	containerId := cr.ID
	defer func() {
		if !success {
			if _, err := this.removeContainer(req.Context(), containerId); err != nil {
				req.Connection().Logger().
					WithError(err).
					Warn("cannot remove orphan container within emergency cleanup; container could still be there")
			}
		}
	}()

	if err := this.apiClient.ContainerStart(req.Context(), containerId, container.StartOptions{}); err != nil {
		return failf(errors.System, "cannot start container #%s: %w", containerId, err)
	}
	c, _, err := this.findContainerById(req.Context(), containerId)
	if err != nil {
		return fail(err)
	}

	success = true
	return c, nil

}

func (this *DockerRepository) pullImage(req Request, ref string) error {
	var progress PreparationProgress
	fail := func(err error) error {
		if progress != nil {
			_ = progress.Error(err)
		}
		return err
	}

	var err error
	progress, err = req.StartPreparation(
		"pull-image",
		fmt.Sprintf("Pulling image %s", ref),
		PreparationProgressAttributes{
			"image": ref,
		},
	)
	if err != nil {
		return fail(err)
	}

	var pOpts image.PullOptions

	if pOpts.RegistryAuth, err = this.resolvePullCredentials(req, ref); err != nil {
		return fail(err)
	}

	rc, err := this.apiClient.ImagePull(req.Context(), ref, pOpts)
	if err != nil {
		return fail(err)
	}
	defer common.IgnoreCloseError(rc)

	if progress == nil {
		return nil
	}

	l := req.Connection().Logger().
		With("image", ref)
	if err := handleImagePullProgress(rc, progress, l); err != nil {
		return fail(err)
	}
	return err
}

func (this *DockerRepository) resolvePullCredentials(req Request, _ string) (string, error) {
	fail := func(err error) (string, error) {
		return "", errors.Config.Newf("cannot resolve image pull credentials: %w", err)
	}

	plain, err := this.conf.ImagePullCredentials.Render(req)
	if err != nil {
		return fail(err)
	}

	if plain == "" {
		return "", nil
	}

	if buf, err := registry.DecodeAuthConfig(plain); err == nil && (buf.Auth != "" || buf.Username != "" || buf.Password != "") {
		// We can take it as it is, because it is in fully valid format.
		return plain, nil
	}

	var buf registry.AuthConfig
	if err := json.Unmarshal([]byte(plain), &buf); err == nil && (buf.Auth != "" || buf.Username != "" || buf.Password != "") {
		// Ok, is close to be perfect, just encode it base64 url based...
		return base64.URLEncoding.EncodeToString([]byte(plain)), nil
	}

	// Seems to be direct auth string...
	buf.Auth = plain
	result, err := registry.EncodeAuthConfig(buf)
	if err != nil {
		return fail(err)
	}
	return result, nil
}

func (this *DockerRepository) resolveContainerConfig(req Request, sess session.Session) (_ *container.Config, err error) {
	fail := func(err error) (*container.Config, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (_ *container.Config, err error) {
		return fail(errors.Config.Newf(msg, args...))
	}

	var result container.Config

	remote := req.Connection().Remote()
	result.Labels = map[string]string{
		DockerLabelFlow:      this.flow.String(),
		DockerLabelSessionId: sess.Id().String(),

		DockerLabelCreatedRemoteUser: remote.User(),
		DockerLabelCreatedRemoteHost: remote.Host().String(),
	}
	if result.Labels[DockerLabelShellCommand], err = this.resolveEncodedShellCommand(req); err != nil {
		return fail(err)
	}
	if result.Labels[DockerLabelExecCommand], err = this.resolveEncodedExecCommand(req); err != nil {
		return fail(err)
	}
	if result.Labels[DockerLabelSftpCommand], err = this.resolveEncodedSftpCommand(req); err != nil {
		return fail(err)
	}
	if result.Labels[DockerLabelUser], err = this.conf.User.Render(req); err != nil {
		return failf("cannot evaluate user: %w", err)
	}
	if result.Labels[DockerLabelDirectory], err = this.conf.Directory.Render(req); err != nil {
		return failf("cannot evaluate directory: %w", err)
	}
	if v, err := this.conf.PortForwardingAllowed.Render(req); err != nil {
		return failf("cannot evaluate portForwardingAllowed: %w", err)
	} else if v {
		result.Labels[DockerLabelPortForwardingAllowed] = "true"
	}

	result.ExposedPorts = map[nat.Port]struct{}{
		nat.Port(fmt.Sprintf("%d/tcp", imp.ServicePort)): {},
	}

	if result.Image, err = this.conf.Image.Render(req); err != nil {
		return failf("cannot evaluate image: %w", err)
	}
	result.Entrypoint = strslice.StrSlice{}
	switch this.hostOs {
	case sys.OsWindows:
		result.Cmd = []string{BifroestWindowsBinaryMountTarget}
	case sys.OsLinux:
		result.User = "root"
		result.Cmd = []string{BifroestUnixBinaryMountTarget}
	default:
		return failf("cannot resolve target path for host %s/%s", this.hostOs, this.hostArch)
	}

	result.Cmd = append(result.Cmd, `imp`, `--log.colorMode=always`)
	if this.defaultLogLevelName != "" {
		result.Cmd = append(result.Cmd, `--log.level=`+this.defaultLogLevelName)
	}

	masterPub, err := this.imp.GetMasterPublicKey()
	if err != nil {
		return fail(err)
	}

	result.Env = []string{
		imp.EnvVarMasterPublicKey + "=" + base64.RawStdEncoding.EncodeToString(masterPub.Marshal()),
		session.EnvName + "=" + sess.Id().String(),
	}

	return &result, nil
}

func (this *DockerRepository) resolveHostConfig(req Request) (_ *container.HostConfig, err error) {
	fail := func(err error) (*container.HostConfig, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (_ *container.HostConfig, err error) {
		return fail(errors.Config.Newf(msg, args...))
	}

	var result container.HostConfig

	result.AutoRemove = true
	if !this.conf.ImpPublishHost.IsZero() {
		result.PublishAllPorts = true
	}
	if result.Binds, err = this.conf.Volumes.Render(req); err != nil {
		return failf("cannot evaluate volumes: %w", err)
	}
	if raws, err := this.conf.Mounts.Render(req); err != nil {
		return failf("cannot evaluate mounts: %w", err)
	} else {
		var buf opts.MountOpt
		for i, raw := range raws {
			if err := buf.Set(raw); err != nil {
				return failf("cannot evaluate mount %d: %w", i, err)
			}
		}
		result.Mounts = buf.Value()
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

	// result.PortBindings = nat.PortMap{nat.Port(fmt.Sprintf("%d/tcp", imp.ServicePort)): {{
	// 	HostIP:   impBinding.Host.String(),
	// 	HostPort: strconv.FormatUint(uint64(impBinding.Port), 10),
	// }}}

	impBinaryPath, err := this.alternatives.FindBinaryFor(req.Context(), this.hostOs, this.hostArch)
	if err != nil {
		return failf("cannot resolve imp binary path: %w", err)
	}
	if impBinaryPath != "" {
		impBinaryPath, err = filepath.Abs(impBinaryPath)
		if err != nil {
			return failf("cannot resolve full imp binary path: %w", err)
		}
		var targetPath string
		switch this.hostOs {
		case sys.OsWindows:
			targetPath = BifroestWindowsBinaryMountTarget
		case sys.OsLinux:
			targetPath = BifroestUnixBinaryMountTarget
		default:
			return failf("cannot resolve target path for host %s/%s", this.hostOs, this.hostArch)
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

func (this *DockerRepository) resolveEncodedShellCommand(req Request) (string, error) {
	failf := func(msg string, args ...any) (string, error) {
		return "", errors.Config.Newf(msg, args...)
	}

	v, err := this.conf.ShellCommand.Render(req)
	if err != nil {
		return failf("cannot evaluate shellCommand: %w", err)
	}
	if len(v) == 0 {
		switch this.hostOs {
		case sys.OsWindows:
			v = []string{`C:\WINDOWS\system32\cmd.exe`}
		case sys.OsLinux:
			v = []string{`/bin/sh`}
		default:
			return failf("shellCommand was not defined for docker environment and default cannot be resolved for %s/%s", this.hostOs, this.hostArch)
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
		switch this.hostOs {
		case sys.OsWindows:
			v = []string{`C:\WINDOWS\system32\cmd.exe`, `/C`}
		case sys.OsLinux:
			v = []string{`/bin/sh`, `-c`}
		default:
			return failf("execCommand was not defined for docker environment and default cannot be resolved for %s/%s", this.hostOs, this.hostArch)
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
		switch this.hostOs {
		case sys.OsWindows:
			v = []string{BifroestWindowsBinaryMountTarget, `sftp-server`}
		case sys.OsLinux:
			v = []string{BifroestUnixBinaryMountTarget, `sftp-server`}
		default:
			return failf("sftpCommand was not defined for docker environment and default cannot be resolved for %s/%s", this.hostOs, this.hostArch)
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

	if vs, err := this.conf.Networks.Render(req); err != nil {
		return failf("cannot evaluate network: %w", err)
	} else {
		result.EndpointsConfig = make(map[string]*network.EndpointSettings, len(vs))
		for _, v := range vs {
			result.EndpointsConfig[v] = &network.EndpointSettings{}
		}
	}

	return &result, nil
}

func (this *DockerRepository) FindBySession(ctx context.Context, sess session.Session, opts *FindOpts) (Environment, error) {
	return this.findOrEnsureBySession(ctx, sess, opts, nil, false)
}

func (this *DockerRepository) findOrEnsureBySession(ctx context.Context, sess session.Session, opts *FindOpts, createUsing Request, retryAllowed bool) (Environment, error) {
	fail := func(err error) (Environment, error) {
		return nil, err
	}

	sessId := sess.Id()
	rUnlocker := this.sessionIdMutex.RLock(sessId)
	rUnlock := func() {
		if rUnlocker != nil {
			rUnlocker()
		}
		rUnlocker = nil
	}
	defer rUnlock()

	ip, ok := this.activeInstances.Load(sessId)
	if ok {
		instance := ip.(*docker)
		instance.owners.Add(1)
		return instance, nil
	}

	c, exitCode, err := this.findContainerBySession(ctx, sess)
	if err != nil {
		return nil, err
	}
	if c == nil && createUsing == nil {
		return fail(ErrNoSuchEnvironment)
	}
	rUnlock()

	defer this.sessionIdMutex.Lock(sessId)()

	ip, ok = this.activeInstances.Load(sessId)
	if ok {
		instance := ip.(*docker)
		instance.owners.Add(1)
		return instance, nil
	}

	if c != nil && exitCode >= 0 {
		if opts.IsAutoCleanUpAllowed() {
			if _, err := this.removeContainer(ctx, c.ID); err != nil {
				return fail(err)
			}
		}
		if createUsing == nil {
			return fail(ErrNoSuchEnvironment)
		}
	}

	if c == nil {
		c, err = this.createContainerBy(createUsing, sess)
		if err != nil {
			return fail(err)
		}
	}

	logger := this.logger().
		With("containerId", c.ID).
		With("sessionId", sessId)

	removeContainerUnchecked := func() {
		if _, err := this.removeContainer(ctx, c.ID); err != nil {
			logger.
				WithError(err).
				Warnf("cannot broken container; need to be done manually")
		}
	}

	instance, err := this.new(ctx, c, logger)
	if err != nil {
		if errors.Is(err, containerContainsProblemsErr) {
			if createUsing != nil {
				removeContainerUnchecked()
				if !retryAllowed {
					return fail(err)
				}
				return this.findOrEnsureBySession(ctx, sess, opts, createUsing, false)
			} else if opts.IsAutoCleanUpAllowed() {
				removeContainerUnchecked()
				return fail(ErrNoSuchEnvironment)
			}
		}
		return fail(err)
	}

	this.activeInstances.Store(sessId, instance)

	return instance, nil
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

func (this *DockerRepository) findContainerBySession(ctx context.Context, sess session.Session) (c *types.Container, exitCode int, err error) {
	return this.findContainerBy(ctx, filters.NewArgs(
		filters.Arg("label", DockerLabelSessionId+"="+sess.Id().String()),
	))
}
func (this *DockerRepository) findContainerById(ctx context.Context, id string) (c *types.Container, exitCode int, err error) {
	return this.findContainerBy(ctx, filters.NewArgs(
		filters.Arg("id", id),
	))
}

func (this *DockerRepository) findContainerBy(ctx context.Context, filters filters.Args) (c *types.Container, exitCode int, err error) {
	list, err := this.apiClient.ContainerList(ctx, container.ListOptions{
		Limit:   1,
		All:     true,
		Filters: filters,
	})
	if err != nil {
		return nil, -1, errors.System.Newf("cannot list container by %v: %w", filters, err)
	}
	if len(list) == 0 {
		return nil, -1, nil
	}

	c = &list[0]
	exitCode = -1
	if strings.HasPrefix(c.Status, "Exited (") {
		status := strings.TrimPrefix(c.Status, "Exited (")
		if i := strings.IndexRune(status, ')'); i > 0 {
			v, err := strconv.Atoi(status[:i])
			if err == nil {
				exitCode = v
			}
		}
	}

	return c, exitCode, nil
}

func (this *DockerRepository) Close() error {
	return nil
}

func (this *DockerRepository) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("docker-repository")
}

func (this *DockerRepository) isNoSuchImageError(err error) bool {
	for {
		if err == nil {
			return false
		}
		if msg := err.Error(); strings.HasPrefix(msg, "No such image:") {
			return true
		}
		ue, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = ue.Unwrap()
	}
}
