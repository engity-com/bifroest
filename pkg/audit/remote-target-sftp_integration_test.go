//go:build unix

package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	goerrors "errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
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

type embeddedSftpServer struct {
	listener           net.Listener
	root               string
	hostSigner         gossh.Signer
	clientSigner       gossh.Signer
	clientIdentityFile string
	password           string
	config             *gossh.ServerConfig
	acceptDone         chan struct{}
	connections        sync.Map
	wait               sync.WaitGroup
	connectionAttempts atomic.Int32
	passwordAttempts   atomic.Int32
	publicKeyAttempts  atomic.Int32
	closeOnce          sync.Once
}

type sftpInterruptedReaderAt struct {
	content []byte
	passes  atomic.Int32
}

type sftpTimedOutUploadReaderAt struct {
	content []byte
	context context.Context
	passes  atomic.Int32
}

func (this *sftpTimedOutUploadReaderAt) ReadAt(target []byte, offset int64) (int, error) {
	pass := this.passes.Load()
	if offset == 0 {
		pass = this.passes.Add(1)
	}
	if pass >= 2 {
		limit := int64(len(this.content) / 2)
		if offset >= limit {
			<-this.context.Done()
			return 0, this.context.Err()
		}
		if offset+int64(len(target)) > limit {
			target = target[:limit-offset]
		}
	}
	read, err := bytes.NewReader(this.content).ReadAt(target, offset)
	if pass >= 2 && offset+int64(read) >= int64(len(this.content)/2) {
		return read, nil
	}
	return read, err
}

func (this *sftpInterruptedReaderAt) ReadAt(target []byte, offset int64) (int, error) {
	pass := this.passes.Load()
	if offset == 0 {
		pass = this.passes.Add(1)
	}
	if pass >= 2 {
		limit := int64(len(this.content) / 2)
		if offset >= limit {
			return 0, goerrors.New("interrupted upload")
		}
		if offset+int64(len(target)) > limit {
			target = target[:limit-offset]
		}
	}
	read, err := bytes.NewReader(this.content).ReadAt(target, offset)
	if pass >= 2 && offset+int64(read) >= int64(len(this.content)/2) {
		return read, goerrors.New("interrupted upload")
	}
	return read, err
}

func TestSftpRemoteTargetPublishesAgainstEmbeddedSftpServer(t *testing.T) {
	for _, auth := range []string{"password", "public-key"} {
		t.Run(auth, func(t *testing.T) {
			server := newEmbeddedSftpServer(t)
			target := newEmbeddedSftpRemoteTarget(t, server, auth)
			segment := validRemoteTargetTestSegment()
			content, err := io.ReadAll(segment.Content())
			require.NoError(t, err)
			producerDirectory := filepath.Join(server.root, "archive", segment.ProducerId().String())
			finalPath := filepath.Join(producerDirectory, segment.FileName())

			require.NoError(t, target.Publish(context.Background(), segment))
			require.NoError(t, os.Chmod(producerDirectory, 0o755))
			require.NoError(t, target.Publish(context.Background(), segment))
			require.Equal(t, content, mustReadFile(t, finalPath))
			require.Equal(t, []string{segment.FileName()}, mustReadDirectoryNames(t, producerDirectory))

			conflicting := bytes.Repeat([]byte{'x'}, len(content))
			if bytes.Equal(conflicting, content) {
				conflicting[0]++
			}
			require.NoError(t, os.WriteFile(finalPath, conflicting, 0o600))
			err = target.Publish(context.Background(), segment)
			require.ErrorContains(t, err, "conflicts with local content")
			require.True(t, bferrors.System.IsErr(err), err)
			require.Equal(t, conflicting, mustReadFile(t, finalPath))
			require.Equal(t, os.FileMode(0o700), mustStatFile(t, producerDirectory).Mode().Perm())
			require.Equal(t, os.FileMode(0o600), mustStatFile(t, finalPath).Mode().Perm())
			require.Equal(t, int32(5), server.connectionAttempts.Load())
			if auth == "password" {
				require.Equal(t, int32(5), server.passwordAttempts.Load())
				require.Zero(t, server.publicKeyAttempts.Load())
			} else {
				require.Equal(t, int32(5), server.publicKeyAttempts.Load())
				require.Zero(t, server.passwordAttempts.Load())
			}
		})
	}
}

func TestSftpRemoteTargetPublishesArtifactAgainstEmbeddedServer(t *testing.T) {
	server := newEmbeddedSftpServer(t)
	target := newEmbeddedSftpRemoteTarget(t, server, "public-key")
	artifact := validRemoteArtifactTest()
	content, err := io.ReadAll(artifact.Content())
	require.NoError(t, err)
	producerDirectory := filepath.Join(server.root, "archive", artifact.ProducerId().String())
	finalPath := filepath.Join(producerDirectory, artifact.FileName())

	require.NoError(t, target.PublishArtifact(context.Background(), artifact))
	require.NoError(t, target.PublishArtifact(context.Background(), artifact))
	require.Equal(t, content, mustReadFile(t, finalPath))
	require.Equal(t, []string{artifact.FileName()}, mustReadDirectoryNames(t, producerDirectory))
	err = target.PublishArtifact(context.Background(), conflictingRemoteArtifactTest(t, artifact))
	require.ErrorContains(t, err, "conflicts with local content")
	require.True(t, bferrors.System.IsErr(err), err)
	require.Equal(t, content, mustReadFile(t, finalPath))
}

func TestSftpRemoteTargetConcurrentPublicationAgainstEmbeddedServer(t *testing.T) {
	server := newEmbeddedSftpServer(t)
	targets := []*sftpRemoteTarget{
		newEmbeddedSftpRemoteTarget(t, server, "public-key"),
		newEmbeddedSftpRemoteTarget(t, server, "public-key"),
	}
	segment := validRemoteTargetTestSegment()
	content, err := io.ReadAll(segment.Content())
	require.NoError(t, err)

	start := make(chan struct{})
	results := make(chan error, 2)
	for _, target := range targets {
		go func() {
			<-start
			results <- target.Publish(context.Background(), segment)
		}()
	}
	close(start)
	for range targets {
		if publishErr := <-results; publishErr != nil {
			require.True(t, bferrors.Network.IsErr(publishErr), publishErr)
		}
	}
	require.NoError(t, targets[0].Publish(context.Background(), segment))

	producerDirectory := filepath.Join(server.root, "archive", segment.ProducerId().String())
	finalPath := filepath.Join(producerDirectory, segment.FileName())
	require.Equal(t, content, mustReadFile(t, finalPath))
	require.Equal(t, []string{segment.FileName()}, mustReadDirectoryNames(t, producerDirectory))
}

func TestSftpRemoteTargetCleansUpInterruptedUploadAgainstEmbeddedServer(t *testing.T) {
	server := newEmbeddedSftpServer(t)
	target := newEmbeddedSftpRemoteTarget(t, server, "password")
	segment := validRemoteTargetTestSegment()
	content, err := io.ReadAll(segment.Content())
	require.NoError(t, err)
	segment.content = &sftpInterruptedReaderAt{content: content}

	err = target.Publish(context.Background(), segment)
	require.ErrorContains(t, err, "interrupted upload")
	producerDirectory := filepath.Join(server.root, "archive", segment.ProducerId().String())
	finalPath := filepath.Join(producerDirectory, segment.FileName())
	_, err = os.Stat(finalPath)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Empty(t, mustReadDirectoryNames(t, producerDirectory))
}

func TestSftpRemoteTargetCleansTimedOutPartialUploadWithFreshConnection(t *testing.T) {
	server := newEmbeddedSftpServer(t)
	target := newEmbeddedSftpRemoteTarget(t, server, "password")
	segment := validRemoteTargetTestSegment()
	content, err := io.ReadAll(segment.Content())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	segment.content = &sftpTimedOutUploadReaderAt{content: content, context: ctx}

	err = target.Publish(ctx, segment)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	producerDirectory := filepath.Join(server.root, "archive", segment.ProducerId().String())
	require.Empty(t, mustReadDirectoryNames(t, producerDirectory))
	require.Equal(t, int32(2), server.connectionAttempts.Load())
}

func TestSftpRemoteTargetCleansDeterministicTemporaryAfterLinkTimeout(t *testing.T) {
	server := newEmbeddedSftpServer(t)
	target := newEmbeddedSftpRemoteTarget(t, server, "password")
	segment := validRemoteTargetTestSegment()
	target.link = func(ctx context.Context, client *gosftp.Client, temporaryPath, finalPath string) error {
		require.NoError(t, client.Link(temporaryPath, finalPath))
		<-ctx.Done()
		return ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := target.Publish(ctx, segment)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	producerDirectory := filepath.Join(server.root, "archive", segment.ProducerId().String())
	finalPath := filepath.Join(producerDirectory, segment.FileName())
	require.Equal(t, mustReadSegmentContent(t, segment), mustReadFile(t, finalPath))
	require.Equal(t, []string{segment.FileName()}, mustReadDirectoryNames(t, producerDirectory))
	require.Equal(t, int32(2), server.connectionAttempts.Load())
}

func TestSftpRemoteTargetRetriesFailedCleanupByDeterministicName(t *testing.T) {
	server := newEmbeddedSftpServer(t)
	target := newEmbeddedSftpRemoteTarget(t, server, "password")
	segment := validRemoteTargetTestSegment()
	producerDirectory := filepath.Join(server.root, "archive", segment.ProducerId().String())
	finalPath := filepath.Join(producerDirectory, segment.FileName())
	temporaryPath := sftpTemporaryPath(producerDirectory, finalPath, nil)
	var cleanupAttempts atomic.Int32
	target.cleanup = func(parent context.Context, actualPath string) error {
		require.Equal(t, temporaryPath, actualPath)
		if cleanupAttempts.Add(1) == 1 {
			return goerrors.New("injected cleanup failure")
		}
		return target.cleanupTemporaryWithFreshConnection(parent, actualPath)
	}

	err := target.Publish(context.Background(), segment)
	require.ErrorContains(t, err, "injected cleanup failure")
	require.ElementsMatch(t, []string{segment.FileName(), filepath.Base(temporaryPath)}, mustReadDirectoryNames(t, producerDirectory))
	require.NoError(t, target.Publish(context.Background(), segment))
	require.Equal(t, []string{segment.FileName()}, mustReadDirectoryNames(t, producerDirectory))
	require.Equal(t, int32(2), cleanupAttempts.Load())
}

func TestSftpRemoteTargetResumesMatchingDeterministicTemporary(t *testing.T) {
	server := newEmbeddedSftpServer(t)
	target := newEmbeddedSftpRemoteTarget(t, server, "password")
	segment := validRemoteTargetTestSegment()
	producerDirectory := filepath.Join(server.root, "archive", segment.ProducerId().String())
	require.NoError(t, os.Mkdir(producerDirectory, 0o700))
	finalPath := filepath.Join(producerDirectory, segment.FileName())
	temporaryPath := sftpTemporaryPath(producerDirectory, finalPath, nil)
	require.NoError(t, os.WriteFile(temporaryPath, mustReadSegmentContent(t, segment), 0o600))

	require.NoError(t, target.Publish(context.Background(), segment))
	require.Equal(t, mustReadSegmentContent(t, segment), mustReadFile(t, finalPath))
	require.Equal(t, []string{segment.FileName()}, mustReadDirectoryNames(t, producerDirectory))
}

func TestSftpRemoteTargetRecoversFromPartialDeterministicTemporary(t *testing.T) {
	server := newEmbeddedSftpServer(t)
	target := newEmbeddedSftpRemoteTarget(t, server, "password")
	segment := validRemoteTargetTestSegment()
	content := mustReadSegmentContent(t, segment)
	producerDirectory := filepath.Join(server.root, "archive", segment.ProducerId().String())
	require.NoError(t, os.Mkdir(producerDirectory, 0o700))
	finalPath := filepath.Join(producerDirectory, segment.FileName())
	temporaryPath := sftpTemporaryPath(producerDirectory, finalPath, nil)
	require.NoError(t, os.WriteFile(temporaryPath, content[:len(content)/2], 0o600))

	err := target.Publish(context.Background(), segment)
	require.ErrorContains(t, err, "invalid temporary SFTP audit segment")
	require.True(t, bferrors.Network.IsErr(err), err)
	_, err = os.Stat(temporaryPath)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(finalPath)
	require.ErrorIs(t, err, os.ErrNotExist)

	require.NoError(t, target.Publish(context.Background(), segment))
	require.Equal(t, content, mustReadFile(t, finalPath))
	require.Equal(t, []string{segment.FileName()}, mustReadDirectoryNames(t, producerDirectory))
}

func TestSftpRemoteTargetIdempotenceAndRejectionWithoutHardlinkExtension(t *testing.T) {
	require.NoError(t, gosftp.SetSFTPExtensions("posix-rename@openssh.com", "statvfs@openssh.com", "hardlink@openssh.com"))
	t.Cleanup(func() {
		require.NoError(t, gosftp.SetSFTPExtensions("posix-rename@openssh.com", "statvfs@openssh.com", "hardlink@openssh.com"))
	})
	server := newEmbeddedSftpServer(t)
	target := newEmbeddedSftpRemoteTarget(t, server, "password")
	segment := validRemoteTargetTestSegment()
	require.NoError(t, target.Publish(context.Background(), segment))
	require.NoError(t, gosftp.SetSFTPExtensions("posix-rename@openssh.com", "statvfs@openssh.com"))
	require.NoError(t, target.Publish(context.Background(), segment))
	finalPath := filepath.Join(server.root, "archive", segment.ProducerId().String(), segment.FileName())
	require.NoError(t, os.Remove(finalPath))

	err := target.Publish(context.Background(), segment)
	require.ErrorContains(t, err, "does not support hardlink@openssh.com version 1")
	require.True(t, bferrors.Config.IsErr(err), err)
}

func TestSftpRemoteTargetRejectsAuthenticationAndHostKeyFailures(t *testing.T) {
	t.Run("password", func(t *testing.T) {
		server := newEmbeddedSftpServer(t)
		conf := embeddedSftpConfiguration(server)
		conf.Password = template.MustNewString("wrong-password")
		target, err := newSftpRemoteTarget(context.Background(), RemoteTargetScope{}, conf)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, target.Close()) })
		err = target.Publish(context.Background(), validRemoteTargetTestSegment())
		require.True(t, bferrors.Permission.IsErr(err), err)
		require.NotContains(t, err.Error(), "wrong-password")
	})

	t.Run("host-key", func(t *testing.T) {
		server := newEmbeddedSftpServer(t)
		wrongSigner := newEmbeddedSftpSigner(t)
		conf := embeddedSftpConfiguration(server)
		conf.KnownHosts = crypto.KnownHosts(knownhosts.Line([]string{knownhosts.Normalize(server.listener.Addr().String())}, wrongSigner.PublicKey()))
		target, err := newSftpRemoteTarget(context.Background(), RemoteTargetScope{}, conf)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, target.Close()) })
		err = target.Publish(context.Background(), validRemoteTargetTestSegment())
		require.True(t, bferrors.Config.IsErr(err), err)
	})
}

func newEmbeddedSftpServer(t *testing.T) *embeddedSftpServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "archive"), 0o700))
	hostSigner := newEmbeddedSftpSigner(t)
	clientSigner, clientPrivate := newEmbeddedSftpSignerWithPrivate(t)
	identityFile := filepath.Join(root, "client-key")
	block, err := gossh.MarshalPrivateKey(clientPrivate, "")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(identityFile, pem.EncodeToMemory(block), 0o600))

	server := &embeddedSftpServer{
		listener:           listener,
		root:               root,
		hostSigner:         hostSigner,
		clientSigner:       clientSigner,
		clientIdentityFile: identityFile,
		password:           "archive-password",
		acceptDone:         make(chan struct{}),
	}
	server.config = &gossh.ServerConfig{
		PasswordCallback: func(metadata gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
			server.passwordAttempts.Add(1)
			if metadata.User() != "archive" || !bytes.Equal(password, []byte(server.password)) {
				return nil, fmt.Errorf("password rejected")
			}
			return nil, nil
		},
		PublicKeyCallback: func(metadata gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			server.publicKeyAttempts.Add(1)
			if metadata.User() != "archive" || !bytes.Equal(key.Marshal(), server.clientSigner.PublicKey().Marshal()) {
				return nil, fmt.Errorf("public key rejected")
			}
			return nil, nil
		},
	}
	server.config.AddHostKey(hostSigner)
	go server.accept()
	t.Cleanup(func() { require.NoError(t, server.Close()) })
	return server
}

func (this *embeddedSftpServer) accept() {
	defer close(this.acceptDone)
	for {
		raw, err := this.listener.Accept()
		if err != nil {
			return
		}
		this.connectionAttempts.Add(1)
		this.connections.Store(raw, struct{}{})
		this.wait.Add(1)
		go func() {
			defer this.wait.Done()
			defer this.connections.Delete(raw)
			defer raw.Close()
			this.serve(raw)
		}()
	}
}

func (this *embeddedSftpServer) serve(raw net.Conn) {
	connection, channels, requests, err := gossh.NewServerConn(raw, this.config)
	if err != nil {
		return
	}
	defer connection.Close()
	go gossh.DiscardRequests(requests)
	for channelRequest := range channels {
		if channelRequest.ChannelType() != "session" {
			_ = channelRequest.Reject(gossh.UnknownChannelType, "only session channels are supported")
			continue
		}
		channel, channelRequests, err := channelRequest.Accept()
		if err != nil {
			return
		}
		func() {
			defer channel.Close()
			for request := range channelRequests {
				var subsystem struct{ Name string }
				if request.Type != "subsystem" || gossh.Unmarshal(request.Payload, &subsystem) != nil || subsystem.Name != "sftp" {
					_ = request.Reply(false, nil)
					continue
				}
				if err := request.Reply(true, nil); err != nil {
					return
				}
				server, err := gosftp.NewServer(channel, gosftp.WithServerWorkingDirectory(this.root))
				if err != nil {
					return
				}
				serveErr := server.Serve()
				_ = server.Close()
				if serveErr != nil && !goerrors.Is(serveErr, io.EOF) && !goerrors.Is(serveErr, io.ErrUnexpectedEOF) {
					return
				}
				return
			}
		}()
	}
}

func (this *embeddedSftpServer) Close() error {
	this.closeOnce.Do(func() {
		_ = this.listener.Close()
		<-this.acceptDone
		this.connections.Range(func(connection, _ any) bool {
			_ = connection.(net.Conn).Close()
			return true
		})
		this.wait.Wait()
	})
	return nil
}

func newEmbeddedSftpRemoteTarget(t *testing.T, server *embeddedSftpServer, auth string) *sftpRemoteTarget {
	t.Helper()
	conf := embeddedSftpConfiguration(server)
	if auth == "public-key" {
		conf.Password = template.String{}
		conf.IdentityFiles = []string{server.clientIdentityFile}
	}
	raw, err := newSftpRemoteTarget(context.Background(), RemoteTargetScope{}, conf)
	require.NoError(t, err)
	target := raw.(*sftpRemoteTarget)
	t.Cleanup(func() { require.NoError(t, target.Close()) })
	return target
}

func embeddedSftpConfiguration(server *embeddedSftpServer) *configuration.AuditlogTargetSftp {
	return &configuration.AuditlogTargetSftp{
		Address:        server.listener.Addr().String(),
		User:           template.MustNewString("archive"),
		Directory:      filepath.Join(server.root, "archive"),
		KnownHosts:     crypto.KnownHosts(knownhosts.Line([]string{knownhosts.Normalize(server.listener.Addr().String())}, server.hostSigner.PublicKey())),
		Password:       template.MustNewString(server.password),
		ConnectTimeout: template.DurationOf(5 * time.Second),
	}
}

func newEmbeddedSftpSigner(t *testing.T) gossh.Signer {
	t.Helper()
	signer, _ := newEmbeddedSftpSignerWithPrivate(t)
	return signer
}

func newEmbeddedSftpSignerWithPrivate(t *testing.T) (gossh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromKey(privateKey)
	require.NoError(t, err)
	return signer, privateKey
}

func mustReadFile(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(name)
	require.NoError(t, err)
	return content
}

func mustReadSegmentContent(t *testing.T, segment SealedSegment) []byte {
	t.Helper()
	content, err := io.ReadAll(segment.Content())
	require.NoError(t, err)
	return content
}

func mustReadDirectoryNames(t *testing.T, name string) []string {
	t.Helper()
	entries, err := os.ReadDir(name)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func mustStatFile(t *testing.T, name string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(name)
	require.NoError(t, err)
	return info
}
