package environment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/docker/go-connections/sockets"
	log "github.com/echocat/slf4g"
	"github.com/gliderlabs/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

var (
	_ = RegisterRepository(NewDockerRepository)

	LinuxRunForeverCommand   = []string{`/bin/sh`, `-c`, `while true; do sleep 10; done`}
	WindowsRunForeverCommand = []string{`powershell.exe`, `-Command`, `while ($true) { sleep 10 }`}
)

type DockerRepository struct {
	flow configuration.FlowName
	conf *configuration.EnvironmentDocker

	Logger log.Logger
}

func NewDockerRepository(ctx context.Context, flow configuration.FlowName, conf *configuration.EnvironmentDocker) (*DockerRepository, error) {
	fail := func(err error) (*DockerRepository, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*DockerRepository, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	if conf == nil {
		return failf("nil configuration")
	}

	result := DockerRepository{
		flow: flow,
		conf: conf,
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

	t, err := this.newDockerToken(req)
	if err != nil {
		return fail(err)
	}

	apiClient, err := this.toApiClient(t)
	if err != nil {
		return fail(err)
	}
	defer common.DoOnFailureIgnore(&success, apiClient.Close)

	hostOs, hostArch, err := this.resolveEnvironment(req, apiClient)
	if err != nil {
		return fail(err)
	}
	if err := t.enrichWithHostDetails(req, hostOs, hostArch); err != nil {
		return fail(err)
	}
	config, err := this.resolveContainerConfig(req, sess, hostOs, hostArch)
	if err != nil {
		return fail(err)
	}
	hostConfig, err := this.resolveHostConfig(req, hostOs, hostArch)
	if err != nil {
		return fail(err)
	}
	name, err := this.conf.Name.Render(req)
	if err != nil {
		return fail(err)
	}

	c, err := this.createContainer(req.Context(), apiClient, config, hostConfig, name, true)
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
	t.Id = c.ID

	if err := apiClient.ContainerStart(req.Context(), t.Id, container.StartOptions{}); err != nil {
		return failf(errors.System, "cannot start container #%s: %w", t.Id, err)
	}

	if tb, err := json.Marshal(t); err != nil {
		return failf(errors.System, "cannot marshal environment token: %w", err)
	} else if err := sess.SetEnvironmentToken(req.Context(), tb); err != nil {
		return failf(errors.System, "cannot store environment token at session: %w", err)
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

func (this *DockerRepository) createContainer(ctx context.Context, apiClient *client.Client, config *container.Config, hostConfig *container.HostConfig, name string, retryAllowed bool) (container.CreateResponse, error) {
	c, err := apiClient.ContainerCreate(ctx, config, hostConfig, nil, nil, name)
	if err != nil {
		other, _, fErr := this.findContainerByName(ctx, apiClient, name)
		if fErr == nil {
			if other.State == "running" {
				// There is another one running with the same name. We use this one instead.
				return container.CreateResponse{ID: other.ID}, nil
			}
			if retryAllowed {
				// Every other state is not acceptable. Remove this contain and try again...
				if _, rErr := this.removeContainer(ctx, apiClient, other.ID); rErr == nil {
					return this.createContainer(ctx, apiClient, config, hostConfig, name, false)
				}
			}
		}
		return container.CreateResponse{}, err
	}
	return c, nil
}

func (this *DockerRepository) resolveEnvironment(req Request, apiClient client.APIClient) (os, arch string, _ error) {
	fail := func(err error) (string, string, error) {
		return "", "", err
	}
	failf := func(msg string, args ...any) (string, string, error) {
		return fail(errors.Config.Newf(msg, args...))
	}

	si, err := apiClient.Info(req.Context())
	if err != nil {
		return failf("cannot retrieve docker host's system information: %w", err)
	}

	return si.OSType, si.Architecture, nil
}

func (this *DockerRepository) resolveContainerConfig(req Request, sess session.Session, hostOs, hostArch string) (_ *container.Config, err error) {
	fail := func(err error) (*container.Config, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (_ *container.Config, err error) {
		return fail(errors.Config.Newf(msg, args...))
	}

	var result container.Config

	result.Labels = map[string]string{
		"org.engity.bifroest/session-id":          sess.Id().String(),
		"org.engity.bifroest/created-remote-user": req.Remote().User(),
		"org.engity.bifroest/created-remote-host": req.Remote().Host().String(),
	}

	if result.Image, err = this.conf.Image.Render(req); err != nil {
		return failf("cannot evaluate image: %w", err)
	}
	result.Entrypoint = strslice.StrSlice{}
	if result.Cmd, err = this.conf.BlockCommand.Render(req); err != nil {
		return failf("cannot evaluate mainCommand: %w", err)
	}

	if err := this.enrichContainerConfigOsSpecific(req, hostOs, hostArch, &result); err != nil {
		return fail(err)
	}

	return &result, nil
}

func (this *DockerRepository) resolveHostConfig(req Request, hostOs, hostArch string) (_ *container.HostConfig, err error) {
	fail := func(err error) (*container.HostConfig, error) {
		return nil, err
	}
	var result container.HostConfig

	if err := this.enrichHostConfigOsSpecific(req, hostOs, hostArch, &result); err != nil {
		return fail(err)
	}

	return &result, nil
}

func (this *DockerRepository) FindBySession(ctx context.Context, sess session.Session, opts *FindOpts) (Environment, error) {
	fail := func(err error) (Environment, error) {
		return nil, err
	}
	failf := func(t errors.Type, msg string, args ...any) (Environment, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	success := false

	containerNotFound := func(id string) (Environment, error) {
		if !opts.IsAutoCleanUpAllowed() {
			return failf(errors.Expired, "container #%s of session cannot longer be found; treat as expired", id)
		}
		// Clear the stored token.
		if err := sess.SetEnvironmentToken(ctx, nil); err != nil {
			return failf(errors.System, "cannot clear existing environment token of session after its container (#%s) does not seem to exist any longer: %w", id, err)
		}
		opts.GetLogger(this.logger).
			With("session", sess).
			With("container", id).
			Debug("session's user does not longer seem to exist; treat environment as expired; therefore according environment token was removed from session")
		return fail(ErrNoSuchEnvironment)
	}

	tb, err := sess.EnvironmentToken(ctx)
	if err != nil {
		return failf(errors.System, "cannot get environment token: %w", err)
	}
	if len(tb) == 0 {
		return fail(ErrNoSuchEnvironment)
	}
	var t dockerToken
	if err := json.Unmarshal(tb, &t); err != nil {
		return failf(errors.System, "cannot decode environment token: %w", err)
	}

	apiClient, err := this.toApiClient(&t)
	if err != nil {
		return fail(err)
	}
	common.DoOnFailureIgnore(&success, apiClient.Close)

	c, _, err := this.findContainerById(ctx, apiClient, t.Id)
	if err != nil {
		return fail(err)
	}
	if c == nil {
		return containerNotFound(t.Id)
	}
	if c.State != "running" {
		return containerNotFound(t.Id)
	}

	result := docker{
		repository: this,
		session:    sess,
		token:      &t,
		apiClient:  apiClient,
	}
	success = true
	return &result, nil
}

func (this *DockerRepository) toApiClient(t *dockerToken) (_ *client.Client, err error) {
	fail := func(err error) (*client.Client, error) {
		return nil, err
	}

	hostURL, err := client.ParseHostURL(client.DefaultDockerHost)
	if err != nil {
		return fail(err)
	}

	httpTransport := http.Transport{}
	if err := sockets.ConfigureTransport(&httpTransport, hostURL.Scheme, hostURL.Host); err != nil {
		return fail(err)
	}
	httpClient := http.Client{
		Transport:     &httpTransport,
		CheckRedirect: client.CheckRedirect,
	}

	clientOpts := []client.Opt{client.WithHTTPClient(&httpClient)}
	if v := t.Host; v != "" {
		clientOpts = append(clientOpts, client.WithHost(v))
	}
	if v := t.ApiVersion; v != "" {
		clientOpts = append(clientOpts, client.WithVersion(v))
	}
	if httpTransport.TLSClientConfig, err = t.toTlsConfig(); err != nil {
		return fail(err)
	}

	apiClient, err := client.NewClientWithOpts(clientOpts...)
	if err != nil {
		return fail(err)
	}

	return apiClient, nil
}

func (this *DockerRepository) removeContainer(ctx context.Context, apiClient client.APIClient, id string) (bool, error) {
	if err := apiClient.ContainerRemove(ctx, id, container.RemoveOptions{
		RemoveVolumes: true,
		Force:         true,
	}); errdefs.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, errors.System.Newf("cannot remove container #%s: %w", id, err)
	}
	return true, nil
}

func (this *DockerRepository) findContainerById(ctx context.Context, apiClient client.APIClient, id string) (*types.Container, int, error) {
	return this.findContainerBy(ctx, apiClient, filters.NewArgs(
		filters.Arg("id", id),
	))
}

func (this *DockerRepository) findContainerByName(ctx context.Context, apiClient client.APIClient, name string) (*types.Container, int, error) {
	return this.findContainerBy(ctx, apiClient, filters.NewArgs(
		filters.Arg("name", name),
	))
}

func (this *DockerRepository) findContainerBy(ctx context.Context, apiClient client.APIClient, filters filters.Args) (*types.Container, int, error) {
	list, err := apiClient.ContainerList(ctx, container.ListOptions{
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

func (this *DockerRepository) Close() error {
	return nil
}

func (this *DockerRepository) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("authorizer")
}
