package environment

import (
	"fmt"

	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/sys"
)

type TaskType uint8

const executionLifecycleCapability = "execution-id-v1"

const (
	TaskTypeShell TaskType = iota
	TaskTypeSftp
)

func (this TaskType) String() string {
	switch this {
	case TaskTypeShell:
		return "shell"
	case TaskTypeSftp:
		return "sftp"
	default:
		return fmt.Sprintf("illegal-task-type-%d", this)
	}
}

type Task interface {
	Context
	SshSession() essh.Session
	TaskType() TaskType
}

func signalFromSsh(value essh.Signal) (sys.Signal, error) {
	var result sys.Signal
	if err := result.Set(string(value)); err != nil {
		return 0, err
	}
	return result, nil
}

func signalProcessFromSsh(value essh.Signal, send func(sys.Signal) error) error {
	signal, err := signalFromSsh(value)
	if err != nil {
		return err
	}
	return send(signal)
}
