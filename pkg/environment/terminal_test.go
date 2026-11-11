package environment

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"

	log "github.com/echocat/slf4g"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	bnet "github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
	"github.com/engity-com/bifroest/pkg/terminal"
)

// This task/stream deliberately implement no SSH interface or SSH context.
type neutralTerminalTask struct {
	stream *neutralTerminalStream
	auth   authorization.Authorization
	conn   *neutralTerminalConnection
}

func (this *neutralTerminalTask) Context() context.Context                   { return this.stream.Context() }
func (this *neutralTerminalTask) Connection() connection.Connection          { return this.conn }
func (this *neutralTerminalTask) Authorization() authorization.Authorization { return this.auth }
func (*neutralTerminalTask) TaskType() TaskType                              { return TaskTypeShell }
func (this *neutralTerminalTask) Terminal() terminal.Stream                  { return this.stream }
func (*neutralTerminalTask) StartPreparation(string, string, PreparationProgressAttributes) (PreparationProgress, error) {
	return nil, nil
}

type neutralTerminalConnection struct {
	id  connection.Id
	ctx context.Context
}

func (this *neutralTerminalConnection) Id() connection.Id         { return this.id }
func (*neutralTerminalConnection) Remote() bnet.Remote            { return sshTestRemote{} }
func (*neutralTerminalConnection) Logger() log.Logger             { return log.GetLogger("neutral-terminal-test") }
func (this *neutralTerminalConnection) Lifetime() context.Context { return this.ctx }

type neutralTerminalStream struct {
	ctx            context.Context
	cancel         context.CancelFunc
	command        string
	input          io.Reader
	output, stderr neutralTerminalBuffer
	pty            terminal.Pty
	hasPty         bool
	windows        chan terminal.Window
	mutex          sync.Mutex
	signals        chan<- terminal.Signal
}
type neutralTerminalBuffer struct {
	sync.Mutex
	buffer bytes.Buffer
}

func (this *neutralTerminalBuffer) Write(data []byte) (int, error) {
	this.Lock()
	defer this.Unlock()
	return this.buffer.Write(data)
}
func (this *neutralTerminalBuffer) Read(data []byte) (int, error) {
	this.Lock()
	defer this.Unlock()
	return this.buffer.Read(data)
}
func (this *neutralTerminalBuffer) String() string {
	this.Lock()
	defer this.Unlock()
	return this.buffer.String()
}
func newNeutralTerminalTask(t *testing.T, command string, stored session.Session) *neutralTerminalTask {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	stream := &neutralTerminalStream{ctx: ctx, cancel: cancel, command: command, input: bytes.NewReader(nil), windows: make(chan terminal.Window, 1)}
	return &neutralTerminalTask{stream: stream, auth: &sshTestAuthorization{session: stored, environment: sys.EnvVars{"LAYER": "authorization"}}, conn: &neutralTerminalConnection{id: connection.MustNewId(), ctx: ctx}}
}
func (this *neutralTerminalStream) Context() context.Context       { return this.ctx }
func (this *neutralTerminalStream) RawCommand() string             { return this.command }
func (*neutralTerminalStream) Environ() []string                   { return []string{"LAYER=client"} }
func (this *neutralTerminalStream) Read(data []byte) (int, error)  { return this.input.Read(data) }
func (this *neutralTerminalStream) Write(data []byte) (int, error) { return this.output.Write(data) }
func (this *neutralTerminalStream) Stderr() io.ReadWriter          { return &this.stderr }
func (this *neutralTerminalStream) Close() error                   { this.cancel(); return nil }
func (*neutralTerminalStream) CloseWrite() error                   { return nil }
func (this *neutralTerminalStream) Pty() (terminal.Pty, <-chan terminal.Window, bool) {
	return terminal.ClonePty(this.pty), this.windows, this.hasPty
}
func (this *neutralTerminalStream) Signals(receiver chan<- terminal.Signal) {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	this.signals = receiver
}

func TestNeutralTerminalExecutesAgainstSshTargetWithoutSourceSshSession(t *testing.T) {
	target := newSshTarget(t)
	defer target.Close()
	conf := &configuration.EnvironmentSsh{}
	require.NoError(t, conf.SetDefaults())
	conf.Address = template.MustNewString(target.Address())
	conf.User = template.MustNewString("target-user")
	conf.AcceptAllHostKeys = true
	repository, err := NewSshRepositoryWithHostKeys(t.Context(), "test", conf, []crypto.PrivateKey{newSshTestPrivateKey(t)})
	require.NoError(t, err)
	defer repository.Close()
	stored := &sshTestStoredSession{id: session.MustNewId()}
	for range 2 {
		task := newNeutralTerminalTask(t, "show-environment", stored)
		_, legacy := any(task).(Task)
		require.False(t, legacy, "neutral execution must not satisfy the legacy SSH task")
		env, err := repository.Ensure(task)
		require.NoError(t, err)
		runner, ok := env.(TerminalRunner)
		require.True(t, ok)
		code, err := runner.RunTerminal(task)
		require.NoError(t, err)
		require.Equal(t, 7, code)
		require.Contains(t, task.stream.output.String(), "command=show-environment")
		require.Contains(t, task.stream.output.String(), "LAYER=authorization")
		require.Contains(t, task.stream.output.String(), session.EnvName+"="+stored.id.String())
		require.Equal(t, "target stderr", task.stream.stderr.String())
		require.NoError(t, env.Close())
	}
	// Separate requesting connections still execute independently, not reattach.
	require.EqualValues(t, 2, target.connections.Load())
}

func TestTaskTerminalRequiresExplicitCapability(t *testing.T) {
	var missing TaskContext = &struct{ TaskContext }{}
	_, _, err := taskTerminal(missing)
	require.ErrorContains(t, err, "no execution terminal")
	task := newNeutralTerminalTask(t, "", nil)
	task.stream = nil
	_, _, err = taskTerminal(task)
	require.ErrorContains(t, err, "missing execution terminal")
	_, _, err = taskTerminal(&sshTestTask{session: (*sshTestSession)(nil)})
	require.ErrorContains(t, err, "no execution terminal")
}

var _ TerminalTask = (*neutralTerminalTask)(nil)
var _ terminal.Stream = (*neutralTerminalStream)(nil)
var _ TerminalRunner = (*local)(nil)
var _ TerminalRunner = (*docker)(nil)
var _ TerminalRunner = (*kubernetes)(nil)
var _ TerminalRunner = (*sshEnvironment)(nil)
