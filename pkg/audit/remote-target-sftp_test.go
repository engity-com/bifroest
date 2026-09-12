package audit

import (
	"context"
	goerrors "errors"
	"io"
	"net"
	"testing"
	"time"

	gosftp "github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	bferrors "github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestSftpRemoteTargetClassifiesFailuresWithoutRetry(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		errorType bferrors.Type
	}{
		{"permission", gosftp.ErrSSHFxPermissionDenied, bferrors.Permission},
		{"permission-status", &gosftp.StatusError{Code: uint32(gosftp.ErrSSHFxPermissionDenied)}, bferrors.Permission},
		{"authentication", goerrors.New("ssh: unable to authenticate"), bferrors.Permission},
		{"unsupported-operation", gosftp.ErrSSHFxOpUnsupported, bferrors.Config},
		{"unsupported-status", &gosftp.StatusError{Code: uint32(gosftp.ErrSSHFxOpUnsupported)}, bferrors.Config},
		{"host-key", sftpHostKeyError{error: goerrors.New("host key mismatch")}, bferrors.Config},
		{"no-connection", gosftp.ErrSSHFxNoConnection, bferrors.Network},
		{"connection-lost", gosftp.ErrSSHFxConnectionLost, bferrors.Network},
		{"eof", io.EOF, bferrors.Network},
		{"local", goerrors.New("failure"), bferrors.System},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := classifySftpRemoteError(context.Background(), "test operation", test.err)
			require.True(t, test.errorType.IsErr(err), err)
		})
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, classifySftpRemoteError(canceled, "test operation", io.EOF), context.Canceled)
}

func TestSftpRemoteTargetContextAndClose(t *testing.T) {
	target := &sftpRemoteTarget{}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, target.Publish(canceled, validRemoteTargetTestSegment()), context.Canceled)
	require.NoError(t, target.Close())
	require.NoError(t, target.Close())
	err := target.Publish(context.Background(), validRemoteTargetTestSegment())
	require.ErrorContains(t, err, "closed")
	require.True(t, bferrors.System.IsErr(err), err)
}

func TestNewSftpRemoteTargetRejectsInvalidTrustWithoutConnecting(t *testing.T) {
	tests := []struct {
		name       string
		knownHosts crypto.KnownHosts
		file       crypto.KnownHostsFile
	}{
		{"inline", "invalid", ""},
		{"file", "", crypto.KnownHostsFile(t.TempDir() + "/missing-known-hosts")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conf := &configuration.AuditlogTargetSftp{
				Address:        "sftp.example.invalid:22",
				User:           template.MustNewString("archive"),
				Directory:      "/archive",
				KnownHosts:     test.knownHosts,
				KnownHostsFile: test.file,
				Password:       template.MustNewString("secret"),
				ConnectTimeout: template.DurationOf(time.Second),
			}
			_, err := newSftpRemoteTarget(context.Background(), RemoteTargetScope{}, conf)
			require.True(t, bferrors.Config.IsErr(err), err)
		})
	}
}

func TestSftpRemoteTargetCancelsStalledHandshake(t *testing.T) {
	listener, accepted := newStalledSshListener(t)
	target := newStalledSftpRemoteTarget(listener, 0)
	ctx, cancel := context.WithCancel(context.Background())
	published := make(chan error, 1)
	go func() { published <- target.Publish(ctx, validRemoteTargetTestSegment()) }()
	<-accepted
	cancel()
	select {
	case err := <-published:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("Publish did not stop after context cancellation")
	}
}

func TestSftpRemoteTargetAppliesConnectTimeoutToStalledHandshake(t *testing.T) {
	listener, _ := newStalledSshListener(t)
	target := newStalledSftpRemoteTarget(listener, 20*time.Millisecond)

	started := time.Now()
	err := target.Publish(context.Background(), validRemoteTargetTestSegment())
	require.True(t, bferrors.Network.IsErr(err), err)
	require.Less(t, time.Since(started), time.Second)
}

func newStalledSshListener(t *testing.T) (net.Listener, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	release := make(chan struct{})
	done := make(chan struct{})
	accepted := make(chan struct{})
	go func() {
		defer close(done)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		close(accepted)
		<-release
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		close(release)
		<-done
	})
	return listener, accepted
}

func newStalledSftpRemoteTarget(listener net.Listener, timeout time.Duration) *sftpRemoteTarget {
	target := &sftpRemoteTarget{
		address: listener.Addr().String(),
		sshConfig: &gossh.ClientConfig{
			User:            "archive",
			HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		},
	}
	target.dial = func(ctx context.Context) (*sftpRemoteConnection, error) {
		return dialSftpRemoteConnection(ctx, target.address, timeout, target.sshConfig)
	}
	return target
}
