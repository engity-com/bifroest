package environment

import (
	"fmt"
	"sort"
	"strings"

	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/configuration"
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

type environmentVariablesProvider interface {
	EnvironmentVariables() configuration.EnvironmentVariables
}

type layeredSshEnvironmentProvider interface {
	ClientEnvironment() []string
	AuthorizedKeyEnvironment() sys.EnvVars
}

type originalCommandProvider interface {
	OriginalCommand() (string, bool)
}

func applyTaskEnvironment(environment *sys.EnvVars, targetOs sys.Os, task Task) error {
	if provider, ok := task.SshSession().(layeredSshEnvironmentProvider); ok {
		addEnvironmentEntries(environment, targetOs, provider.ClientEnvironment())
		if err := addEnvironmentLayer(environment, targetOs, provider.AuthorizedKeyEnvironment()); err != nil {
			return fmt.Errorf("cannot apply authorized-key environment variables: %w", err)
		}
	} else {
		addEnvironmentEntries(environment, targetOs, task.SshSession().Environ())
	}
	if err := addEnvironmentLayer(environment, targetOs, task.Authorization().EnvVars()); err != nil {
		return fmt.Errorf("cannot apply authorization environment variables: %w", err)
	}
	if provider, ok := task.(environmentVariablesProvider); ok {
		values, err := provider.EnvironmentVariables().Render(task)
		if err != nil {
			return fmt.Errorf("cannot render environment variables: %w", err)
		}
		if err := addEnvironmentLayer(environment, targetOs, values); err != nil {
			return fmt.Errorf("cannot apply environment variables: %w", err)
		}
	}
	if provider, ok := task.SshSession().(originalCommandProvider); ok {
		if value, present := provider.OriginalCommand(); present {
			setReservedEnvironment(environment, targetOs, "SSH_ORIGINAL_COMMAND", value)
		}
	}
	return nil
}

func addEnvironmentEntries(environment *sys.EnvVars, targetOs sys.Os, values []string) {
	for _, value := range values {
		key, value, _ := strings.Cut(value, "=")
		if targetOs == sys.OsWindows {
			environment.SetCanonical(key, value)
		} else {
			environment.Set(key, value)
		}
	}
}

func addEnvironmentLayer(environment *sys.EnvVars, targetOs sys.Os, values sys.EnvVars) error {
	keys := make([]string, 0, len(values))
	seen := make([]string, 0, len(values))
	for key := range values {
		if targetOs == sys.OsWindows {
			for _, existing := range seen {
				if strings.EqualFold(existing, key) {
					return fmt.Errorf("ambiguous case-insensitive environment variables %q and %q", existing, key)
				}
			}
			seen = append(seen, key)
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := values[key]
		if targetOs == sys.OsWindows {
			environment.SetCanonical(key, value)
		} else {
			environment.Set(key, value)
		}
	}
	return nil
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

func setReservedEnvironment(environment *sys.EnvVars, targetOs sys.Os, values ...string) {
	if targetOs == sys.OsWindows {
		environment.SetCanonical(values...)
		return
	}
	environment.Set(values...)
}
