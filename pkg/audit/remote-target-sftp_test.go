package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	goerrors "errors"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	gosftp "github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

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

func TestSftpTemporaryPathIsDeterministicAndShorterThanFinalName(t *testing.T) {
	segment := validRemoteTargetTestSegment()
	directory := path.Join("/archive", segment.ProducerId().String())
	finalPath := path.Join(directory, segment.FileName())
	temporaryPath := sftpTemporaryPath(directory, finalPath, nil)

	require.Equal(t, temporaryPath, sftpTemporaryPath(directory, finalPath, nil))
	require.NotEqual(t, temporaryPath, sftpTemporaryPath(directory, finalPath+"-other", nil))
	checksum := remoteTestChecksum(t, segment)
	artifactTemporaryPath := sftpTemporaryPath(directory, finalPath, checksum)
	require.NotEqual(t, temporaryPath, artifactTemporaryPath)
	otherChecksum := append([]byte(nil), checksum...)
	otherChecksum[0]++
	require.NotEqual(t, artifactTemporaryPath, sftpTemporaryPath(directory, finalPath, otherChecksum))
	require.Equal(t, directory, path.Dir(temporaryPath))
	require.Len(t, path.Base(temporaryPath), 85)
	require.LessOrEqual(t, len(path.Base(temporaryPath)), len(path.Base(finalPath)))
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

func TestSftpRemoteTrustFingerprintAndCallbackUseSameSnapshot(t *testing.T) {
	firstKey := newSftpRemoteTrustTestKey(t)
	secondKey := newSftpRemoteTrustTestKey(t)
	address := "sftp.example.invalid:22"
	firstLine := knownhosts.Line([]string{knownhosts.Normalize(address)}, firstKey) + "\n"
	secondLine := knownhosts.Line([]string{knownhosts.Normalize(address)}, secondKey) + "\n"
	firstPath := filepath.Join(t.TempDir(), "first")
	secondPath := filepath.Join(t.TempDir(), "second")
	require.NoError(t, os.WriteFile(firstPath, []byte(firstLine), 0o600))
	require.NoError(t, os.WriteFile(secondPath, []byte(firstLine), 0o600))
	conf := &configuration.AuditlogTargetSftp{
		Address: address, User: template.MustNewString("archive"), Directory: "/archive",
		KnownHostsFile: crypto.KnownHostsFile(firstPath), Password: template.MustNewString("secret"),
		ConnectTimeout: configuration.DefaultAuditlogTargetSftpConnectTimeout,
	}
	prepare := func() (*sftpRemoteTarget, remoteDeliveryDestinationFingerprint) {
		t.Helper()
		target, _, fingerprint, err := prepareSftpRemoteTarget(t.Context(), RemoteTargetScope{}, conf)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, target.Close()) })
		return target.(*sftpRemoteTarget), fingerprint
	}
	target, first := prepare()
	conf.KnownHostsFile = crypto.KnownHostsFile(secondPath)
	_, same := prepare()
	require.Equal(t, first, same)
	require.NoError(t, os.WriteFile(firstPath, []byte(secondLine), 0o600))
	require.NoError(t, os.WriteFile(secondPath, []byte(secondLine), 0o600))
	_, changed := prepare()
	require.NotEqual(t, first, changed)
	// A prepared target must continue to verify against the fingerprinted bytes.
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	require.NoError(t, target.sshConfig.HostKeyCallback(address, remote, firstKey))
	require.Error(t, target.sshConfig.HostKeyCallback(address, remote, secondKey))
	conf.KnownHosts = crypto.KnownHosts(firstLine)
	_, withInline := prepare()
	require.NotEqual(t, changed, withInline)
	conf.KnownHosts = ""
	conf.KnownHostsFile = ""
	conf.AcceptAllHostKeys = true
	_, acceptAll := prepare()
	require.NotEqual(t, first, acceptAll)
	require.NotEqual(t, changed, acceptAll)
	conf.AcceptAllHostKeys = false
	conf.KnownHostsFile = crypto.KnownHostsFile(firstPath)
	conf.Password = template.MustNewString("rotated-secret")
	_, rotated := prepare()
	require.Equal(t, changed, rotated)
	conf.KnownHostsFile = crypto.KnownHostsFile(filepath.Join(t.TempDir(), "missing"))
	_, _, _, err := prepareSftpRemoteTarget(t.Context(), RemoteTargetScope{}, conf)
	require.True(t, bferrors.Config.IsErr(err), err)
	conf.KnownHosts = crypto.KnownHosts(firstLine)
	_, _, _, err = prepareSftpRemoteTarget(t.Context(), RemoteTargetScope{}, conf)
	require.True(t, bferrors.Config.IsErr(err), err)
	conf.KnownHosts = ""
	oversized := filepath.Join(t.TempDir(), "oversized")
	file, err := os.Create(oversized)
	require.NoError(t, err)
	require.NoError(t, file.Truncate(maximumSftpKnownHostsFileSize+1))
	require.NoError(t, file.Close())
	conf.KnownHostsFile = crypto.KnownHostsFile(oversized)
	_, _, _, err = prepareSftpRemoteTarget(t.Context(), RemoteTargetScope{}, conf)
	require.ErrorContains(t, err, "exceeds")
	require.True(t, bferrors.Config.IsErr(err), err)
	conf.KnownHostsFile = crypto.KnownHostsFile(t.TempDir())
	_, _, _, err = prepareSftpRemoteTarget(t.Context(), RemoteTargetScope{}, conf)
	require.ErrorContains(t, err, "must be regular")
}

func TestSftpRemoteTrustChangeRejectsCursorAndOutstandingReceipt(t *testing.T) {
	conf, identity, segments := newRemoteDeliveryTestJournal(t, 1)
	line := knownhosts.Line([]string{"sftp.example.invalid"}, newSftpRemoteTrustTestKey(t)) + "\n"
	trustPath := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(trustPath, []byte(line), 0o600))
	sftpConf := &configuration.AuditlogTargetSftp{
		Address: "sftp.example.invalid", User: template.MustNewString("archive"), Directory: "/archive",
		KnownHostsFile: crypto.KnownHostsFile(trustPath), Password: template.MustNewString("secret"),
		ConnectTimeout: configuration.DefaultAuditlogTargetSftpConnectTimeout,
	}
	conf.Targets = configuration.AuditlogTargets{{Name: "archive", V: sftpConf}}
	_, fingerprint, err := remoteDeliveryTargetSettings(sftpConf)
	require.NoError(t, err)
	state, err := prepareRemoteDeliveryState(conf.Directory, identity.ProducerId())
	require.NoError(t, err)
	targetState := filepath.Join(state, remoteDeliveryTargetStateName("archive"))
	require.NoError(t, ensureJournalDirectory(targetState, true))
	_, err = writeRemoteDeliveryCursor(targetState, identity, "archive", fingerprint, segments[0].sequence, SegmentHash(segments[0].hash))
	require.NoError(t, err)

	newTargets := func() *RemoteArtifactTargets {
		t.Helper()
		targets, err := NewRemoteArtifactTargets(t.Context(), conf.Name, conf.Targets)
		require.NoError(t, err)
		return targets
	}
	artifact := newRemoteArtifactReceiptTestArtifact(t, identity.ProducerId(), "recording.bcast", []byte("sealed recording"))
	root := t.TempDir()
	targets := newTargets()
	receipts, err := NewRemoteArtifactReceipts(root, identity, conf.Name, targets, &remoteArtifactReceiptTestQuota{maximum: 1 << 20})
	require.NoError(t, err)
	require.NoError(t, receipts.Prepare(t.Context(), artifact, time.Now().UTC()))
	require.NoError(t, receipts.Close())
	require.NoError(t, targets.Close())

	for _, test := range []struct {
		name   string
		change func()
	}{
		{"changed key", func() {
			require.NoError(t, os.WriteFile(trustPath, []byte(knownhosts.Line([]string{"sftp.example.invalid"}, newSftpRemoteTrustTestKey(t))+"\n"), 0o600))
		}},
		{"accept all", func() { sftpConf.KnownHostsFile = ""; sftpConf.AcceptAllHostKeys = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.change()
			delivery, err := NewRemoteDelivery(t.Context(), &conf, identity)
			require.Nil(t, delivery)
			require.ErrorContains(t, err, "different destination")
			targets := newTargets()
			defer targets.Close()
			receipts, err := NewRemoteArtifactReceipts(root, identity, conf.Name, targets, &remoteArtifactReceiptTestQuota{maximum: 1 << 20})
			require.NoError(t, err)
			defer receipts.Close()
			require.ErrorContains(t, receipts.Acknowledge(t.Context(), artifact, "archive", time.Now().UTC()), "different destination")
		})
	}
}

func newSftpRemoteTrustTestKey(t *testing.T) gossh.PublicKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromKey(privateKey)
	require.NoError(t, err)
	return signer.PublicKey()
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
