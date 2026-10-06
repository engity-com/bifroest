package environment

import (
	"context"
	"fmt"
	"io"

	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/alternatives"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
)

var _ = RegisterRepository(NewManagementRepository)

// ManagementCommandRunner binds the management environment to the already
// running service instead of opening its exclusively locked repositories again.
type ManagementCommandRunner interface {
	RunManagementCommand(Task, bool) (int, error)
}

func NewManagementRepository(ctx context.Context, flow configuration.FlowName, conf *configuration.EnvironmentManagement, _ alternatives.Provider, _ imp.Imp) (*ManagementRepository, error) {
	if conf == nil {
		return nil, fmt.Errorf("nil management environment configuration")
	}
	runner := repositoryDependenciesFrom(ctx).management
	if runner == nil {
		return nil, fmt.Errorf("management environment requires a service command runner")
	}
	return &ManagementRepository{flow: flow, includingCredentials: conf.IncludingCredentials, runner: runner}, nil
}

type ManagementRepository struct {
	flow                 configuration.FlowName
	includingCredentials bool
	runner               ManagementCommandRunner
}

func (this *ManagementRepository) WillBeAccepted(Context) (bool, error) { return true, nil }

func (this *ManagementRepository) DoesSupportPty(Context, essh.Pty) (bool, error) { return false, nil }

func (this *ManagementRepository) Ensure(req Request) (Environment, error) {
	if req.Authorization().FindSession() == nil {
		return nil, ErrNotAcceptable
	}
	return &managementEnvironment{repository: this}, nil
}

func (this *ManagementRepository) FindBySession(_ context.Context, sess session.Session, _ *FindOpts) (Environment, error) {
	if sess == nil || sess.Flow() != this.flow {
		return nil, ErrNoSuchEnvironment
	}
	return &managementEnvironment{repository: this}, nil
}

func (this *ManagementRepository) Cleanup(context.Context, *CleanupOpts) error { return nil }

func (this *ManagementRepository) Close() error { return nil }

type managementEnvironment struct{ repository *ManagementRepository }

func (this *managementEnvironment) Banner(Request) (io.ReadCloser, error) { return nil, nil }

func (this *managementEnvironment) Run(task Task) (int, error) {
	if task.TaskType() != TaskTypeShell || task.SshSession().Subsystem() != "" || task.SshSession().RawCommand() == "" {
		return -1, fmt.Errorf("management environment requires an SSH exec command")
	}
	return this.repository.runner.RunManagementCommand(task, this.repository.includingCredentials)
}

func (this *managementEnvironment) RunSubsystem(Task, func(bool) error) (int, error) {
	return -1, ErrSubsystemNotAllowed
}

func (this *managementEnvironment) IsPortForwardingAllowed(net.HostPort) (bool, error) {
	return false, nil
}

func (this *managementEnvironment) IsReversePortForwardingAllowed(net.HostPort) (bool, error) {
	return false, nil
}

func (this *managementEnvironment) NewDestinationConnection(context.Context, net.HostPort) (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("management environment does not support port forwarding")
}

func (this *managementEnvironment) Dispose(context.Context) (bool, error) { return false, nil }

func (this *managementEnvironment) Close() error { return nil }
