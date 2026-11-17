package environment

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/configuration"
	bssh "github.com/engity-com/bifroest/pkg/ssh"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/terminal"
)

type TaskType uint8

const executionLifecycleCapability = "execution-id-v1"

var ErrSubsystemNotAllowed = errors.New("SSH subsystem is not allowed by the environment")

const (
	TaskTypeShell TaskType = iota
	TaskTypeSftp
	TaskTypeSubsystem
)

func (this TaskType) String() string {
	switch this {
	case TaskTypeShell:
		return "shell"
	case TaskTypeSftp:
		return "sftp"
	case TaskTypeSubsystem:
		return "subsystem"
	default:
		return fmt.Sprintf("illegal-task-type-%d", this)
	}
}

type TaskContext interface {
	Context
	TaskType() TaskType
}

// Task remains the legacy SSH entry point for existing environments/adapters.
// New transports use TerminalTask and TerminalRunner without a fake SSH session.
type Task interface {
	TaskContext
	SshSession() essh.Session
}
type TerminalTask interface {
	TaskContext
	Terminal() terminal.Stream
}

// TerminalRunner is a trusted post-authorization execution capability. It does
// not authenticate a caller, register a connection or replace session limits.
// Task.Context and Terminal.Context must describe the same execution lifetime.
type TerminalRunner interface {
	RunTerminal(TerminalTask) (int, error)
}

func taskSshSession(task TaskContext) essh.Session {
	if provider, ok := task.(Task); ok {
		return provider.SshSession()
	}
	return nil
}

func taskTerminal(task TaskContext) (terminal.Stream, func(), error) {
	if provider, ok := task.(TerminalTask); ok {
		stream := provider.Terminal()
		if nilTaskDependency(stream) {
			return nil, nil, fmt.Errorf("missing execution terminal")
		}
		return stream, func() {}, nil
	}
	if legacy := taskSshSession(task); !nilTaskDependency(legacy) {
		stream := bssh.NewTerminal(task.Context(), legacy)
		return stream, stream.Stop, nil
	}
	return nil, nil, fmt.Errorf("task has no execution terminal")
}

func nilTaskDependency(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
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

func applyTaskEnvironment(environment *sys.EnvVars, targetOs sys.Os, task TaskContext) error {
	stream, release, err := taskTerminal(task)
	if err != nil {
		return err
	}
	defer release()
	if provider, ok := stream.(layeredSshEnvironmentProvider); ok {
		addEnvironmentEntries(environment, targetOs, provider.ClientEnvironment())
		if err := addEnvironmentLayer(environment, targetOs, provider.AuthorizedKeyEnvironment()); err != nil {
			return fmt.Errorf("cannot apply authorized-key environment variables: %w", err)
		}
	} else {
		addEnvironmentEntries(environment, targetOs, stream.Environ())
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
	if provider, ok := stream.(originalCommandProvider); ok {
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
	return signalFromTerminal(terminal.Signal(value))
}
func signalFromTerminal(value terminal.Signal) (sys.Signal, error) {
	var result sys.Signal
	if err := result.Set(string(value)); err != nil {
		return 0, err
	}
	return result, nil
}

func signalProcessFromSsh(value essh.Signal, send func(sys.Signal) error) error {
	return signalProcessFromTerminal(terminal.Signal(value), send)
}
func signalProcessFromTerminal(value terminal.Signal, send func(sys.Signal) error) error {
	signal, err := signalFromTerminal(value)
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
