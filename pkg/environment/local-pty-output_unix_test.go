//go:build unix

package environment

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	essh "github.com/engity-com/ssh-server-go"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/user"
)

func TestLocalPtyOutputDrainWithActualCurrentUserProcess(t *testing.T) {
	for range 20 {
		master, slave, err := pty.Open()
		require.NoError(t, err)
		func() {
			defer master.Close()
			defer slave.Close()
			cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", "printf stdout; printf stderr >&2")
			cmd.SysProcAttr = &syscall.SysProcAttr{}
			cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
			require.NoError(t, (&local{}).configureCmdForPty(cmd, master, slave))
			require.NoError(t, cmd.Start())
			defer func() { _ = cmd.Process.Kill() }()
			require.NoError(t, slave.Close())
			var output bytes.Buffer
			done := make(chan error, 1)
			go func() { _, err := io.Copy(&output, master); done <- err }()
			require.NoError(t, cmd.Wait())
			err = waitLocalPtyOutput(t.Context(), done, 2*time.Second, func() { _ = master.Close() })
			if (&local{}).isRelevantError(err) {
				t.Fatal(err)
			}
			require.Equal(t, "stdoutstderr", output.String())
		}()
	}
}

type localPtyOutputSession struct{ *sshTestSession }

func (*localPtyOutputSession) Pty() (essh.Pty, <-chan essh.Window, bool) {
	return essh.Pty{Term: "xterm", Window: essh.Window{Width: 80, Height: 24}}, nil, true
}

func TestLocalUnixPtyForwardsOutputOfEveryFastExit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("starting a process with Unix credentials requires root")
	}
	for range 20 {
		ctx, cancel := newSshTestContext()
		stored := &sshTestStoredSession{id: session.MustNewId()}
		stream := &localPtyOutputSession{newSshTestSession(ctx, "printf stdout; printf stderr >&2", nil)}
		task := &sshTestTask{context: ctx, connection: &sshTestConnection{id: connection.MustNewId(), context: ctx}, authorization: &sshTestAuthorization{session: stored}, session: stream, taskType: TaskTypeShell}
		env := &local{repository: &LocalRepository{conf: &configuration.EnvironmentLocal{}}, user: &user.User{Name: "test", Uid: user.Id(os.Getuid()), Group: user.Group{Gid: user.GroupId(os.Getgid())}, HomeDir: t.TempDir(), Shell: "/bin/sh"}}
		code, err := env.Run(task)
		cancel()
		require.NoError(t, err)
		require.Zero(t, code)
		require.Equal(t, "stdoutstderr", stream.stdout.String())
	}
}
