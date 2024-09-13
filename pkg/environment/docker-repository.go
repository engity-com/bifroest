package environment

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	log "github.com/echocat/slf4g"
	"github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/session"
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
	flow        configuration.FlowName
	conf        *configuration.EnvironmentDocker
	impBinaries imp.BinaryProvider
	apiClient   client.APIClient
	hostOs      string
	hostArch    string

	imps sync.Map

	Logger log.Logger
}

func NewDockerRepository(ctx context.Context, flow configuration.FlowName, conf *configuration.EnvironmentDocker, ibp imp.BinaryProvider) (*DockerRepository, error) {
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

	si, err := apiClient.ServerVersion(ctx)
	if err != nil {
		return failf("cannot retrieve docker host's version: %w", err)
	}

	result := DockerRepository{
		flow:        flow,
		conf:        conf,
		impBinaries: ibp,
		apiClient:   apiClient,
		hostOs:      si.Os,
		hostArch:    si.Arch,
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

	if existing, err := this.FindBySession(req.Context(), sess, nil); err != nil {
		if !errors.Is(err, ErrNoSuchEnvironment) {
			req.Logger().
				WithError(err).
				Warn("cannot restore environment from existing session; will create a new one")
		}
	} else {
		return existing, nil
	}

	apiClient, err := this.newDockerApiClient(sess)
	if err != nil {
		return fail(err)
	}
	defer common.DoOnFailureIgnore(&success, apiClient.Close)

	si, err := apiClient.ServerVersion(req.Context())
	if err != nil {
		return failf(errors.System, "cannot retrieve docker host's version: %w", err)
	}
	hostOs, hostArch := si.Os, si.Arch

	t, err := this.requestToToken(req, hostOs, hostArch)
	if err != nil {
		return fail(err)
	}

	config, err := this.resolveContainerConfig(req, t, sess, hostOs, hostArch)
	if err != nil {
		return fail(err)
	}
	hostConfig, err := this.resolveHostConfig(req, hostOs, hostArch)
	if err != nil {
		return fail(err)
	}
	networkingConfig, err := this.resolveNetworkingConfig(req)
	if err != nil {
		return fail(err)
	}

	c, err := this.createContainer(req.Context(), apiClient, config, hostConfig, networkingConfig, sess, true)
	if err != nil {
		return failf(errors.System, "cannot create container: %w", err)
	}
	defer func() {
		if !success {
			if _, err := this.removeContainer(req.Context(), apiClient, c.ID); err != nil {
				req.Logger().
					WithError(err).
					Warn("cannot remove orphan container within emergency cleanup; container could still be there")
			}
		}
	}()
	t.containerId = c.ID

	if err := apiClient.ContainerStart(req.Context(), t.containerId, container.StartOptions{}); err != nil {
		return failf(errors.System, "cannot start container #%s: %w", t.containerId, err)
	}

	result := docker{
		repository: this,
		session:    sess,
		token:      t,
		apiClient:  apiClient,
	}

	success = true
	return &result, nil
}

func (this *DockerRepository) createContainer(ctx context.Context, apiClient client.APIClient, config *container.Config, hostConfig *container.HostConfig, networkingConfig *network.NetworkingConfig, sess session.Session, retryAllowed bool) (container.CreateResponse, error) {
	name := fmt.Sprintf("bifroest-%v", sess.Id())
	c, err := apiClient.ContainerCreate(ctx, config, hostConfig, networkingConfig, nil, name)
	if err != nil {
		other, _, fErr := this.findContainerBy(ctx, apiClient, filters.NewArgs(
			filters.Arg("name", name),
		))
		if fErr == nil && other != nil {
			if other.State == "running" {
				// There is another one running with the same name. We use this one instead.
				return container.CreateResponse{ID: other.ID}, nil
			}
			if retryAllowed {
				// Every other state is not acceptable. Remove this contain and try again...
				if _, rErr := this.removeContainer(ctx, apiClient, other.ID); rErr == nil {
					return this.createContainer(ctx, apiClient, config, hostConfig, networkingConfig, sess, false)
				}
			}
		}
		return container.CreateResponse{}, err
	}
	return c, nil
}

func (this *DockerRepository) FindBySession(ctx context.Context, sess session.Session, opts *FindOpts) (Environment, error) {
	fail := func(err error) (Environment, error) {
		return nil, err
	}
	failf := func(t errors.Type, msg string, args ...any) (Environment, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	success := false

	apiClient, err := this.newDockerApiClient(sess)
	if err != nil {
		return fail(err)
	}
	common.DoOnFailureIgnore(&success, apiClient.Close)

	containerInWrongState := func(containerId string, cause error) (Environment, error) {
		if !opts.IsAutoCleanUpAllowed() {
			if cause != nil {
				return failf(errors.Expired, "container (#%s) of session #%v is in a wrong state; treat as expired: %w", containerId, sess.Id(), cause)
			}
			return failf(errors.Expired, "container (#%s) of session #%v is in a wrong state; treat as expired", containerId, sess.Id())
		}

		if _, err := this.removeContainer(ctx, apiClient, containerId); err != nil {
			return failf(errors.System, "cannot clear existing environment token of session #%v after its container (#%s) does not seem to exist any longer: %w", sess.Id(), containerId, err)
		}

		l := opts.GetLogger(this.logger).
			With("session", sess).
			With("container", containerId)
		if err != nil {
			l = l.WithError(err)
		}
		l.Debug("session's container is in a wrong state; treat environment as expired; therefore this container was removed")
		return fail(ErrNoSuchEnvironment)
	}

	c, _, err := this.findContainerBySession(ctx, sess)
	if err != nil {
		return fail(err)
	}
	if c == nil {
		return fail(ErrNoSuchEnvironment)
	}
	if c.State != "running" {
		return containerInWrongState(c.ID, nil)
	}

	t, err := this.containerToToken(c, sess)
	if err != nil {
		return containerInWrongState(c.ID, err)
	}
	t.containerId = c.ID

	result := docker{
		repository: this,
		session:    sess,
		token:      t,
		apiClient:  apiClient,
	}
	success = true
	return &result, nil
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
		if err := this.attachExisting(ctx, &candidate); err != nil {
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
