package environment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/docker/docker/api/types"
	log "github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
)

type docker struct {
	repository *DockerRepository

	containerId string
	sessionId   session.Id

	remoteUser string
	remoteHost net.Host

	shellCommand []string
	execCommand  []string
	sftpCommand  []string
	user         string
	directory    string

	portForwardingAllowed bool

	impBinding net.HostPort
	impSession imp.Session

	owners atomic.Int32
}

func (this *docker) SessionId() session.Id {
	return this.sessionId
}

func (this *docker) PublicKey() crypto.PublicKey {
	return nil
}

func (this *docker) EndpointAddr() net.HostPort {
	return this.impBinding
}

func (this *DockerRepository) new(ctx context.Context, container *types.Container, logger log.Logger) (*docker, error) {
	fail := func(err error) (*docker, error) {
		return nil, errors.System.Newf("cannot create environment from container %s of flow %v: %w", container.ID, this.flow, err)
	}

	result := &docker{
		repository: this,
	}
	if err := result.parseContainer(container); err != nil {
		return fail(err)
	}
	var err error
	if result.impSession, err = this.imp.Open(ctx, result); err != nil {
		return fail(err)
	}

	connId, err := connection.NewId()
	if err != nil {
		return fail(err)
	}

	for try := 1; try <= 200; try++ {
		if err := result.impSession.Ping(ctx, connId); err == nil {
			break
		} else if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// try waiting...
		} else {
			return fail(err)
		}
		l := logger.With("try", try)
		if try <= 2 {
			l.Debug("waiting for container's imp getting ready...")
		} else {
			l.Info("still waiting for container's imp getting ready...")
		}
		time.Sleep(500 * time.Millisecond)
	}

	result.owners.Add(1)

	return result, nil
}

func (this *docker) Dispose(ctx context.Context) (_ bool, rErr error) {
	fail := func(err error) (bool, error) {
		return false, errors.Newf(errors.System, "cannot dispose environment: %w", err)
	}

	defer this.repository.sessionIdMutex.Lock(this.sessionId)()
	defer common.KeepError(&rErr, this.closeGuarded)

	ok, err := this.repository.removeContainer(ctx, this.containerId)
	if err != nil {
		return fail(err)
	}

	return ok, nil
}

func (this *docker) Close() (rErr error) {
	defer this.repository.sessionIdMutex.Lock(this.sessionId)()

	return this.closeGuarded()
}

func (this *docker) closeGuarded() error {
	if this.owners.Add(-1) > 0 {
		return nil
	}
	this.repository.activeInstances.Delete(this.sessionId)
	return nil
}

func (this *docker) isRelevantError(err error) bool {
	return err != nil && !errors.Is(err, syscall.EIO) && !sys.IsClosedError(err)
}

var (
	containerContainsProblemsErr = errors.System.Newf("container contains problems")
)

func (this *docker) parseContainer(container *types.Container) (err error) {
	fail := func(err error) error {
		return fmt.Errorf("%w: %v", containerContainsProblemsErr, err)
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.System.Newf(msg, args...))
	}
	decodeStrings := func(in string) (result []string, err error) {
		err = json.Unmarshal([]byte(in), &result)
		return result, err
	}

	this.containerId = container.ID

	labels := container.Labels
	if v := labels[DockerLabelFlow]; v == "" {
		return failf("missing label %s", DockerLabelFlow)
	} else if v != this.repository.flow.String() {
		return failf("expected flow: %v; bot container had: %v", this.repository.flow, v)
	}
	if v := labels[DockerLabelSessionId]; v == "" {
		return failf("missing label %s", DockerLabelSessionId)
	} else if err = this.sessionId.UnmarshalText([]byte(v)); err != nil {
		return failf("cannot decode label %s: %w", DockerLabelSessionId, err)
	}

	this.remoteUser = labels[DockerLabelCreatedRemoteUser]
	if v := labels[DockerLabelCreatedRemoteHost]; v == "" {
		return failf("missing label %s", DockerLabelCreatedRemoteHost)
	} else if err = this.remoteHost.Set(v); err != nil {
		return failf("cannot decode label %s: %w", DockerLabelCreatedRemoteHost, err)
	}

	if v := labels[DockerLabelShellCommand]; v == "" {
		return failf("missing label %s", DockerLabelShellCommand)
	} else if this.shellCommand, err = decodeStrings(v); err != nil {
		return failf("cannot decode label %s: %w", DockerLabelShellCommand, err)
	}
	if v := labels[DockerLabelExecCommand]; v == "" {
		return failf("missing label %s", DockerLabelExecCommand)
	} else if this.execCommand, err = decodeStrings(v); err != nil {
		return failf("cannot decode label %s: %w", DockerLabelExecCommand, err)
	}
	if v := labels[DockerLabelSftpCommand]; v == "" {
		this.sftpCommand = nil
	} else if this.sftpCommand, err = decodeStrings(v); err != nil {
		return failf("cannot decode label %s: %w", DockerLabelSftpCommand, err)
	}

	this.user = labels[DockerLabelUser]
	this.directory = labels[DockerLabelDirectory]
	this.portForwardingAllowed = labels[DockerLabelPortForwardingAllowed] == "true"

	if this.impBinding, err = this.resolveImpBinding(container); err != nil {
		return fail(err)
	}

	return nil
}

func (this *docker) resolveImpBinding(container *types.Container) (net.HostPort, error) {
	fail := func(err error) (net.HostPort, error) {
		return net.HostPort{}, err
	}
	failf := func(msg string, args ...any) (net.HostPort, error) {
		return fail(errors.System.Newf(msg, args...))
	}

	iph := this.repository.conf.ImpPublishHost
	if iph.IsZero() {
		ns := container.NetworkSettings
		if ns == nil {
			return failf("missing network settings of container %v", container.ID)
		}
		result := net.HostPort{Port: imp.ServicePort}
		for n, candidate := range ns.Networks {
			if ip := candidate.IPAddress; ip != "" {
				if err := result.Host.Set(ip); err != nil {
					return failf("cannot parse ip address of network %s to: %w", n, err)
				}
				return result, nil
			}
		}
		return failf("network configuration of container does not any valid network configuration")
	}

	for _, candidate := range container.Ports {
		if candidate.PrivatePort != imp.ServicePort {
			continue
		}
		if candidate.Type != "tcp" {
			continue
		}
		result := net.HostPort{Port: candidate.PublicPort}
		if err := result.Host.Set(candidate.IP); err != nil {
			return failf("cannot parse ip address where the host is bound to: %w", err)
		}
		if result.Host.IsZero() {
			result.Host = iph.Clone()
		}
		return result, nil
	}

	return failf("container does not have any valid exposed port")
}
