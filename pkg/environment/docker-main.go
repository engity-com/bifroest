package environment

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/docker/docker/api/types"

	"github.com/engity-com/bifroest/pkg/errors"
)

func (this *docker) attach(_ context.Context) error {
	fail := func(err error) error {
		return errors.System.Newf("cannot attach to container %v of flow %v: %w", this.containerId, this.repository.flow, err)
	}
	failf := func(msg string, args ...any) error {
		return fail(fmt.Errorf(msg, args...))
	}

	if !this.repository.instances.CompareAndSwap(this.sessionId, nil, this) {
		return failf("cannot attach, because there is already an active attachment: %w", errDockerEnvironmentDuplicate)
	}
	go this.observe()

	return nil
}

func (this *docker) observe() {
	defer this.repository.instances.CompareAndSwap(this.sessionId, this, nil)

	// TODO! Do the observe
}

func (this *docker) parseContainer(container *types.Container) (err error) {
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

	annotations := container.HostConfig.Annotations
	if v := annotations[DockerAnnotationShellCommand]; v == "" {
		return failf("missing annotation %s", DockerAnnotationShellCommand)
	} else if this.shellCommand, err = decodeStrings(v); err != nil {
		return failf("cannot decode annotation %s: %w", DockerAnnotationShellCommand, err)
	}
	if v := annotations[DockerAnnotationExecCommand]; v == "" {
		return failf("missing annotation %s", DockerAnnotationExecCommand)
	} else if this.execCommand, err = decodeStrings(v); err != nil {
		return failf("cannot decode annotation %s: %w", DockerAnnotationExecCommand, err)
	}
	if v := annotations[DockerAnnotationSftpCommand]; v == "" {
		this.sftpCommand = nil
	} else if this.sftpCommand, err = decodeStrings(v); err != nil {
		return failf("cannot decode annotation %s: %w", DockerAnnotationSftpCommand, err)
	}

	this.user = annotations[DockerAnnotationUser]
	this.directory = annotations[DockerAnnotationDirectory]
	this.portForwardingAllowed = annotations[DockerAnnotationPortForwardingAllowed] == "true"

	if v := annotations[DockerAnnotationAccessToken]; v == "" {
		return failf("missing annotation %s", DockerAnnotationAccessToken)
	} else if this.accessToken, err = hex.DecodeString(v); err != nil {
		return failf("cannot decode annotation %s: %w", DockerAnnotationAccessToken, err)
	}

	return nil
}
