package environment

import (
	"context"
	"fmt"
	"io"
	"syscall"

	"github.com/docker/docker/api/types"
	"github.com/google/uuid"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
)

var (
	errDockerEnvironmentDuplicate = errors.System.Newf("duplicated docker environment")
)

type docker struct {
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

func (this *DockerRepository) new(ctx context.Context, container *types.Container) (*docker, error) {
	fail := func(err error) (*docker, error) {
		return nil, errors.System.Newf("cannot create environment from container %s of flow %v: %w", container.ID, this.flow, err)
	}
	failf := func(msg string, args ...any) (*docker, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	result := docker{
		repository: this,
	}
	if err := result.parseContainer(container); err != nil {
		return fail(err)
	}
	s, err := this.imp.GetReconnectSignal(ctx)
	if err != nil {
		return fail(err)
	}
	if err := this.apiClient.ContainerKill(ctx, result.containerId, s); err != nil {
		return failf("cannot interrupt container %v: %w", result.containerId, err)
	}
	if err := result.attach(ctx); err != nil {
		return fail(err)
	}

	return &result, nil
}

func (this *docker) Dispose(ctx context.Context) (bool, error) {
	fail := func(err error) (bool, error) {
		return false, errors.Newf(errors.System, "cannot dispose environment: %w", err)
	}

	ok, err := this.repository.removeContainer(ctx, this.containerId)
	if err != nil {
		return fail(err)
	}

	return ok, nil
}

func (this *docker) Release() error {
	return nil // TODO! Should in the future release this from the stack
}

func (this *docker) isRelevantError(err error) bool {
	return err != nil && !errors.Is(err, syscall.EIO) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF)
}
