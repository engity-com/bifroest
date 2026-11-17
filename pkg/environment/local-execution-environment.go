package environment

import (
	"fmt"
	"os/exec"

	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/execution"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
)

// Finish every local process environment after all client/key/authorization and
// operator layers. Observability IDs are authoritative execution metadata, not
// an imported environment value or an authorization/reattachment capability.
func (this *local) createCmdAndEnv(task TaskContext) (*exec.Cmd, *sys.EnvVars, func(), error) {
	auth, conn := task.Authorization(), task.Connection()
	if nilTaskDependency(auth) || auth.FindSession() == nil || nilTaskDependency(conn) || conn.Id().IsZero() {
		return nil, nil, nil, fmt.Errorf("local execution requires a stored session and requesting connection")
	}
	cmd, environment, release, err := this.createPlatformCmdAndEnv(task)
	if err != nil {
		return nil, nil, nil, err
	}
	id, err := execution.NewId()
	if err != nil {
		release()
		return nil, nil, nil, fmt.Errorf("cannot create local execution ID: %w", err)
	}
	setReservedEnvironment(environment, localTargetOs,
		session.EnvName, auth.FindSession().Id().String(),
		connection.EnvName, conn.Id().String(),
		execution.EnvName, id.String(),
	)
	return cmd, environment, release, nil
}
