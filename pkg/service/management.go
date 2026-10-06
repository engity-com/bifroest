package service

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/environment"
)

func (this *service) RunManagementCommand(task environment.Task, includingCredentials bool) (int, error) {
	return -1, fmt.Errorf("management command %q is not available yet", task.SshSession().RawCommand())
}
