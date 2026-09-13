package audit

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	goerrors "errors"
	"hash"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	gosftp "github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	maximumSftpIdentityFileSize = 1 << 20
	sftpTemporaryNameDomain     = "BIFROEST-AUDIT-SFTP-TEMPORARY/v1\x00"
)

var _ = registerPreparedRemoteTarget(
	func() configuration.AuditlogTargetV { return &configuration.AuditlogTargetSftp{} },
	prepareSftpRemoteTarget,
)

type sftpRemoteTarget struct {
	mutex      sync.RWMutex
	address    string
	directory  string
	sshConfig  *gossh.ClientConfig
	dial       func(context.Context) (*sftpRemoteConnection, error)
	link       func(context.Context, *gosftp.Client, string, string) error
	cleanup    func(context.Context, string) error
	closed     bool
	closeError error
}

type sftpHostKeyError struct {
	error
}

type sftpObjectConflictError struct {
	cause error
}

func (this *sftpObjectConflictError) Error() string { return this.cause.Error() }
func (this *sftpObjectConflictError) Unwrap() error { return this.cause }

func newSftpRemoteTarget(ctx context.Context, _ RemoteTargetScope, conf *configuration.AuditlogTargetSftp) (RemoteTarget, error) {
	target, _, _, err := prepareSftpRemoteTarget(ctx, RemoteTargetScope{}, conf)
	return target, err
}

func prepareSftpRemoteTarget(ctx context.Context, _ RemoteTargetScope, conf *configuration.AuditlogTargetSftp) (RemoteTarget, time.Duration, remoteDeliveryDestinationFingerprint, error) {
	if conf == nil {
		return nil, 0, remoteDeliveryDestinationFingerprint{}, errors.Config.Newf("nil SFTP audit target configuration")
	}
	snapshot := *conf
	snapshot.IdentityFiles = append([]string(nil), conf.IdentityFiles...)
	conf = &snapshot
	if err := conf.Validate(); err != nil {
		return nil, 0, remoteDeliveryDestinationFingerprint{}, errors.Config.Newf("invalid SFTP audit target configuration: %w", err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, remoteDeliveryDestinationFingerprint{}, err
	}
	values, err := conf.Render(nil)
	if err != nil {
		return nil, 0, remoteDeliveryDestinationFingerprint{}, errors.Config.Newf("cannot render SFTP audit target configuration: %w", err)
	}
	address, err := normalizedSftpRemoteAddress(conf.Address)
	if err != nil {
		return nil, 0, remoteDeliveryDestinationFingerprint{}, err
	}
	timeout, fingerprint, err := sftpRemoteDeliveryTargetSettings(conf, values, address)
	if err != nil {
		return nil, 0, remoteDeliveryDestinationFingerprint{}, err
	}
	var hostKeyCallback gossh.HostKeyCallback
	if conf.AcceptAllHostKeys {
		hostKeyCallback = gossh.InsecureIgnoreHostKey()
	} else {
		hostKeyCallback, err = bfcrypto.NewKnownHostsCallback(conf.KnownHosts, conf.KnownHostsFile)
		if err != nil {
			return nil, 0, remoteDeliveryDestinationFingerprint{}, errors.Config.Newf("cannot load SFTP host-key trust: %w", err)
		}
	}
	trustedHostKeyCallback := hostKeyCallback
	hostKeyCallback = func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		if err := trustedHostKeyCallback(hostname, remote, key); err != nil {
			return sftpHostKeyError{err}
		}
		return nil
	}

	var auth []gossh.AuthMethod
	if values.Password != "" {
		auth = []gossh.AuthMethod{gossh.Password(values.Password)}
	} else {
		identityKeys, loadErr := loadSftpIdentityFiles(conf.IdentityFiles)
		if loadErr != nil {
			return nil, 0, remoteDeliveryDestinationFingerprint{}, loadErr
		}
		signers := make([]gossh.Signer, len(identityKeys))
		for index, key := range identityKeys {
			signers[index] = key.ToSsh()
		}
		auth = []gossh.AuthMethod{gossh.PublicKeys(signers...)}
	}
	target := &sftpRemoteTarget{
		address:   address,
		directory: conf.Directory,
		sshConfig: &gossh.ClientConfig{
			User:            values.User,
			Auth:            auth,
			HostKeyCallback: hostKeyCallback,
			ClientVersion:   "SSH-2.0-Bifroest",
		},
	}
	target.dial = func(dialContext context.Context) (*sftpRemoteConnection, error) {
		return dialSftpRemoteConnection(dialContext, target.address, values.ConnectTimeout, target.sshConfig)
	}
	return target, timeout, fingerprint, nil
}

func (this *sftpRemoteTarget) Publish(ctx context.Context, segment SealedSegment) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		return errors.System.Newf("SFTP audit target is closed")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	checksum, err := hashSftpSegment(ctx, segment.Content())
	if err != nil {
		return err
	}
	connection, err := this.dial(ctx)
	if err != nil {
		return classifySftpRemoteError(ctx, "connect to SFTP audit target", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.raw.SetDeadline(deadline); err != nil {
			_ = connection.abort()
			_ = connection.Close()
			return classifySftpRemoteError(ctx, "set SFTP audit target deadline", err)
		}
	}
	stopAbort := context.AfterFunc(ctx, func() { _ = connection.abort() })
	result := this.publishConnected(ctx, connection.client, segment, checksum)
	closeErr := connection.Close()
	stopAbort()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return goerrors.Join(result, classifySftpRemoteError(ctx, "close SFTP audit target connection", closeErr))
}

func (this *sftpRemoteTarget) publishConnected(ctx context.Context, client *gosftp.Client, segment SealedSegment, checksum []byte) error {
	if err := ensureSftpDirectory(ctx, client, this.directory, false); err != nil {
		return err
	}
	producerDirectory := path.Join(this.directory, segment.ProducerId().String())
	finalPath := path.Join(producerDirectory, segment.FileName())
	temporaryPath := sftpTemporaryPath(producerDirectory, finalPath)
	exists, err := verifySftpObject(ctx, client, finalPath, segment.Size(), checksum, "existing audit segment")
	if err != nil {
		return err
	}
	if exists {
		return goerrors.Join(ensureSftpDirectory(ctx, client, producerDirectory, true), this.cleanupTemporaryAfterFailure(ctx, temporaryPath))
	}
	if version, supported := client.HasExtension("hardlink@openssh.com"); !supported || version != "1" {
		return errors.Config.Newf("SFTP server does not support hardlink@openssh.com version 1")
	}
	if err := ensureSftpDirectory(ctx, client, producerDirectory, true); err != nil {
		return err
	}
	temporaryExists, err := this.verifyTemporary(ctx, client, temporaryPath, segment.Size(), checksum)
	if err != nil {
		return err
	}
	if !temporaryExists {
		created, uploadErr := putSftpTemporary(ctx, client, temporaryPath, segment)
		if uploadErr != nil {
			if created {
				return goerrors.Join(uploadErr, this.cleanupTemporaryAfterFailure(ctx, temporaryPath))
			}
			temporaryExists, err = this.verifyTemporary(ctx, client, temporaryPath, segment.Size(), checksum)
			if err != nil {
				return goerrors.Join(uploadErr, err)
			}
			if !temporaryExists {
				return uploadErr
			}
		} else {
			temporaryExists, err = this.verifyTemporary(ctx, client, temporaryPath, segment.Size(), checksum)
			if err != nil {
				return err
			}
			if !temporaryExists {
				return goerrors.Join(errors.Network.Newf("temporary SFTP audit segment disappeared after upload"), this.cleanupTemporaryAfterFailure(ctx, temporaryPath))
			}
		}
	}
	linkErr := this.linkTemporary(ctx, client, temporaryPath, finalPath)
	if linkErr == nil {
		return this.cleanupTemporaryAfterFailure(ctx, temporaryPath)
	}
	exists, verifyErr := verifySftpObject(ctx, client, finalPath, segment.Size(), checksum, "existing audit segment")
	cleanupErr := this.cleanupTemporaryAfterFailure(ctx, temporaryPath)
	if verifyErr != nil {
		return goerrors.Join(verifyErr, cleanupErr)
	}
	if exists {
		return cleanupErr
	}
	return goerrors.Join(classifySftpRemoteError(ctx, "publish audit segment with SFTP hardlink", linkErr), cleanupErr)
}

func (this *sftpRemoteTarget) verifyTemporary(ctx context.Context, client *gosftp.Client, temporaryPath string, size int64, checksum []byte) (bool, error) {
	exists, err := verifySftpObject(ctx, client, temporaryPath, size, checksum, "temporary audit segment")
	var conflict *sftpObjectConflictError
	if err == nil || !goerrors.As(err, &conflict) {
		return exists, err
	}
	retryErr := errors.Network.Newf("invalid temporary SFTP audit segment was removed and must be uploaded again: %v", err)
	return false, goerrors.Join(retryErr, this.cleanupTemporaryAfterFailure(ctx, temporaryPath))
}

func hashSftpSegment(ctx context.Context, content io.Reader) ([]byte, error) {
	if content == nil {
		return nil, errors.System.Newf("nil sealed audit segment content")
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, contextReader{context: ctx, reader: content}); err != nil {
		return nil, errors.System.Newf("cannot hash sealed audit segment for SFTP: %w", err)
	}
	return hasher.Sum(nil), nil
}

func ensureSftpDirectory(ctx context.Context, client *gosftp.Client, directory string, create bool) error {
	info, err := client.Lstat(directory)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.Config.Newf("SFTP path %q is not a real directory", directory)
		}
		if create && info.Mode().Perm()&0o077 != 0 {
			if err := client.Chmod(directory, 0o700); err != nil {
				return classifySftpRemoteError(ctx, "protect SFTP producer directory", err)
			}
			protected, err := client.Lstat(directory)
			if err != nil {
				return classifySftpRemoteError(ctx, "inspect protected SFTP producer directory", err)
			}
			if protected.Mode()&os.ModeSymlink != 0 || !protected.IsDir() || protected.Mode().Perm()&0o077 != 0 {
				return errors.Config.Newf("SFTP producer directory %q remains insecure after setting permissions", directory)
			}
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return classifySftpRemoteError(ctx, "inspect SFTP directory", err)
	}
	if !create {
		return errors.Config.Newf("SFTP base directory %q does not exist", directory)
	}
	if err := client.Mkdir(directory); err != nil {
		if info, inspectErr := client.Lstat(directory); inspectErr == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			return ensureSftpDirectory(ctx, client, directory, true)
		}
		return classifySftpRemoteError(ctx, "create SFTP producer directory", err)
	}
	if err := client.Chmod(directory, 0o700); err != nil {
		return classifySftpRemoteError(ctx, "protect SFTP producer directory", err)
	}
	return ensureSftpDirectory(ctx, client, directory, true)
}

func sftpTemporaryPath(directory, finalPath string) string {
	digest := sha256.Sum256(append([]byte(sftpTemporaryNameDomain), finalPath...))
	return path.Join(directory, ".bifroest-upload-"+hex.EncodeToString(digest[:])+".tmp")
}

func putSftpTemporary(ctx context.Context, client *gosftp.Client, temporaryPath string, segment SealedSegment) (bool, error) {
	file, err := client.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return false, classifySftpRemoteError(ctx, "create temporary SFTP audit segment", err)
	}
	if err := file.Chmod(0o600); err != nil {
		return true, goerrors.Join(
			classifySftpRemoteError(ctx, "protect temporary SFTP audit segment", err),
			classifySftpRemoteError(ctx, "close temporary SFTP audit segment", file.Close()),
		)
	}
	written, writeErr := io.Copy(file, contextReader{context: ctx, reader: segment.Content()})
	closeErr := file.Close()
	if writeErr != nil {
		return true, goerrors.Join(classifySftpRemoteError(ctx, "upload temporary SFTP audit segment", writeErr), classifySftpRemoteError(ctx, "close temporary SFTP audit segment", closeErr))
	}
	if written != segment.Size() {
		return true, goerrors.Join(errors.System.Newf("uploaded SFTP audit segment size is %d instead of %d", written, segment.Size()), classifySftpRemoteError(ctx, "close temporary SFTP audit segment", closeErr))
	}
	return true, classifySftpRemoteError(ctx, "close temporary SFTP audit segment", closeErr)
}

func verifySftpObject(ctx context.Context, client *gosftp.Client, objectPath string, size int64, expectedChecksum []byte, description string) (bool, error) {
	info, err := client.Lstat(objectPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, classifySftpRemoteError(ctx, "inspect "+description, err)
	}
	conflict := func(message string, args ...any) error {
		return &sftpObjectConflictError{cause: errors.System.Newf("SFTP %s %q conflicts with local content: "+message, append([]any{description, objectPath}, args...)...)}
	}
	if info.Mode() == 0 {
		return false, conflict("does not expose file type and permission attributes")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, conflict("is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return false, conflict("has insecure permissions %04o", info.Mode().Perm())
	}
	if info.Size() != size {
		return false, conflict("size is %d instead of %d", info.Size(), size)
	}
	file, err := client.Open(objectPath)
	if err != nil {
		return false, classifySftpRemoteError(ctx, "read "+description, err)
	}
	hasher := sha256.New()
	read, readErr := copySftpObject(ctx, hasher, file, size+1, description)
	closeErr := file.Close()
	if readErr != nil {
		return false, goerrors.Join(readErr, classifySftpRemoteError(ctx, "close "+description, closeErr))
	}
	if read != size {
		return false, goerrors.Join(conflict("size is %d instead of %d", read, size), classifySftpRemoteError(ctx, "close "+description, closeErr))
	}
	if subtle.ConstantTimeCompare(hasher.Sum(nil), expectedChecksum) != 1 {
		return false, goerrors.Join(conflict("SHA-256 checksum differs"), classifySftpRemoteError(ctx, "close "+description, closeErr))
	}
	return true, classifySftpRemoteError(ctx, "close "+description, closeErr)
}

func copySftpObject(ctx context.Context, target hash.Hash, source io.Reader, limit int64, description string) (int64, error) {
	read, err := io.Copy(target, contextReader{context: ctx, reader: io.LimitReader(source, limit)})
	if err != nil {
		return read, classifySftpRemoteError(ctx, "read "+description, err)
	}
	return read, nil
}

func cleanupSftpTemporary(ctx context.Context, client *gosftp.Client, temporaryPath string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	err := client.Remove(temporaryPath)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return classifySftpRemoteError(ctx, "remove temporary SFTP audit segment", err)
}

func (this *sftpRemoteTarget) cleanupTemporaryAfterFailure(parent context.Context, temporaryPath string) error {
	if this.cleanup != nil {
		return this.cleanup(parent, temporaryPath)
	}
	return this.cleanupTemporaryWithFreshConnection(parent, temporaryPath)
}

func (this *sftpRemoteTarget) cleanupTemporaryWithFreshConnection(parent context.Context, temporaryPath string) error {
	ctx, cancel := newRemoteTargetCleanupContext(parent)
	defer cancel()
	connection, err := this.dial(ctx)
	if err != nil {
		return classifySftpRemoteError(ctx, "connect to clean up temporary SFTP audit segment", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.raw.SetDeadline(deadline); err != nil {
			_ = connection.abort()
			return goerrors.Join(
				classifySftpRemoteError(ctx, "set temporary SFTP cleanup deadline", err),
				classifySftpRemoteError(ctx, "close temporary SFTP cleanup connection", connection.Close()),
			)
		}
	}
	stopAbort := context.AfterFunc(ctx, func() { _ = connection.abort() })
	cleanupErr := cleanupSftpTemporary(ctx, connection.client, temporaryPath)
	closeErr := connection.Close()
	stopAbort()
	return goerrors.Join(cleanupErr, classifySftpRemoteError(ctx, "close temporary SFTP cleanup connection", closeErr))
}

func (this *sftpRemoteTarget) linkTemporary(ctx context.Context, client *gosftp.Client, temporaryPath, finalPath string) error {
	if this.link != nil {
		return this.link(ctx, client, temporaryPath, finalPath)
	}
	return client.Link(temporaryPath, finalPath)
}

type sftpRemoteConnection struct {
	raw        net.Conn
	sshClient  *gossh.Client
	client     *gosftp.Client
	abortOnce  sync.Once
	abortError error
	closeOnce  sync.Once
	closeError error
}

func dialSftpRemoteConnection(ctx context.Context, address string, timeout time.Duration, config *gossh.ClientConfig) (*sftpRemoteConnection, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = raw.Close()
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	setupDone := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = raw.Close()
		case <-setupDone:
		}
	}()
	clientConnection, channels, requests, err := gossh.NewClientConn(raw, address, config)
	if err != nil {
		close(setupDone)
		<-watcherDone
		return nil, err
	}
	sshClient := gossh.NewClient(clientConnection, channels, requests)
	sftpClient, err := gosftp.NewClient(sshClient)
	close(setupDone)
	<-watcherDone
	if err != nil {
		_ = sshClient.Close()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		_ = sshClient.Close()
		_ = sftpClient.Close()
		return nil, err
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		_ = sshClient.Close()
		_ = sftpClient.Close()
		return nil, err
	}
	success = true
	return &sftpRemoteConnection{raw: raw, sshClient: sshClient, client: sftpClient}, nil
}

func (this *sftpRemoteConnection) abort() error {
	if this == nil {
		return nil
	}
	this.abortOnce.Do(func() {
		if this.raw != nil {
			this.abortError = this.raw.Close()
			if goerrors.Is(this.abortError, net.ErrClosed) {
				this.abortError = nil
			}
		}
	})
	return this.abortError
}

func (this *sftpRemoteConnection) Close() error {
	if this == nil {
		return nil
	}
	this.closeOnce.Do(func() {
		var sftpErr, sshErr error
		if this.client != nil {
			sftpErr = this.client.Close()
		}
		if this.sshClient != nil {
			sshErr = this.sshClient.Close()
		}
		abortErr := this.abort()
		if goerrors.Is(sftpErr, io.EOF) || goerrors.Is(sftpErr, net.ErrClosed) {
			sftpErr = nil
		}
		if goerrors.Is(sshErr, io.EOF) || goerrors.Is(sshErr, net.ErrClosed) {
			sshErr = nil
		}
		this.closeError = goerrors.Join(abortErr, sftpErr, sshErr)
	})
	return this.closeError
}

func classifySftpRemoteError(ctx context.Context, operation string, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if goerrors.Is(err, context.Canceled) || goerrors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var hostKeyError sftpHostKeyError
	var knownHostError *knownhosts.KeyError
	var revokedError *knownhosts.RevokedError
	if goerrors.As(err, &hostKeyError) || goerrors.As(err, &knownHostError) || goerrors.As(err, &revokedError) {
		return errors.Config.Newf("cannot %s: %w", operation, err)
	}
	if strings.Contains(err.Error(), "unable to authenticate") || goerrors.Is(err, os.ErrPermission) || goerrors.Is(err, gosftp.ErrSSHFxPermissionDenied) {
		return errors.Permission.Newf("cannot %s: %w", operation, err)
	}
	if goerrors.Is(err, gosftp.ErrSSHFxOpUnsupported) {
		return errors.Config.Newf("cannot %s: %w", operation, err)
	}
	if goerrors.Is(err, gosftp.ErrSSHFxNoConnection) || goerrors.Is(err, gosftp.ErrSSHFxConnectionLost) ||
		goerrors.Is(err, io.EOF) || goerrors.Is(err, io.ErrUnexpectedEOF) {
		return errors.Network.Newf("cannot %s: %w", operation, err)
	}
	var networkError net.Error
	if goerrors.As(err, &networkError) {
		return errors.Network.Newf("cannot %s: %w", operation, err)
	}
	var statusError *gosftp.StatusError
	if goerrors.As(err, &statusError) {
		switch statusError.FxCode() {
		case gosftp.ErrSSHFxPermissionDenied:
			return errors.Permission.Newf("cannot %s: %w", operation, err)
		case gosftp.ErrSSHFxOpUnsupported:
			return errors.Config.Newf("cannot %s: %w", operation, err)
		case gosftp.ErrSSHFxNoConnection, gosftp.ErrSSHFxConnectionLost:
			return errors.Network.Newf("cannot %s: %w", operation, err)
		}
		return errors.Network.Newf("cannot %s: %w", operation, err)
	}
	return errors.System.Newf("cannot %s: %w", operation, err)
}

func (this *sftpRemoteTarget) Close() error {
	if this == nil {
		return nil
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		return this.closeError
	}
	this.closed = true
	return this.closeError
}

func loadSftpIdentityFile(identityPath string) (bfcrypto.PrivateKey, error) {
	return bfcrypto.LoadSecurePrivateKeyFile(identityPath, maximumSftpIdentityFileSize)
}

func loadSftpIdentityFiles(identityFiles []string) ([]bfcrypto.PrivateKey, error) {
	result := make([]bfcrypto.PrivateKey, len(identityFiles))
	for index, identityFile := range identityFiles {
		key, err := loadSftpIdentityFile(identityFile)
		if err != nil {
			return nil, errors.Config.Newf("cannot load SFTP identity file [%d] %q: %w", index, identityFile, err)
		}
		result[index] = key
	}
	return result, nil
}

// LoadSftpIdentityPublicKeys securely loads SFTP private identity files and
// returns only the public portions needed for key-dedicatedness validation.
func LoadSftpIdentityPublicKeys(identityFiles []string) ([]bfcrypto.PublicKey, error) {
	privateKeys, err := loadSftpIdentityFiles(identityFiles)
	if err != nil {
		return nil, err
	}
	result := make([]bfcrypto.PublicKey, len(privateKeys))
	for index, privateKey := range privateKeys {
		result[index] = privateKey.PublicKey()
	}
	return result, nil
}
