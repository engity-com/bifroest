package service

import (
	"fmt"
	"io"
	"sync/atomic"
	"testing"

	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestBrowserManagementActionsUiConfirmationDisconnectDisposeAndLostReply(t *testing.T) {
	testBrowserLoginUi(t, true, "management-actions")
}

type actionUITargetRepository struct {
	environment.CloseableRepository
	runs atomic.Int32
}

func (this *actionUITargetRepository) ResolveSessionTarget(ctx environment.Context) (session.Target, error) {
	resolver, ok := environment.SessionTargetResolverFor(this.CloseableRepository, ctx.Authorization().Flow())
	if !ok {
		return "", fmt.Errorf("missing target resolver")
	}
	return resolver.ResolveSessionTarget(ctx)
}
func (this *actionUITargetRepository) Ensure(request environment.Request) (environment.Environment, error) {
	env, err := this.CloseableRepository.Ensure(request)
	if err != nil {
		return nil, err
	}
	if request.Authorization().Flow() != "worker" {
		return env, nil
	}
	return &actionUITargetEnvironment{Environment: env, runs: &this.runs}, nil
}

type actionUITargetEnvironment struct {
	environment.Environment
	runs *atomic.Int32
}

func (this *actionUITargetEnvironment) RunTerminal(task environment.TerminalTask) (int, error) {
	this.runs.Add(1)
	if _, err := io.WriteString(task.Terminal(), "management-target-live\n"); err != nil {
		return -1, err
	}
	<-task.Context().Done()
	return -1, task.Context().Err()
}
