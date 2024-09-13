package session

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	maxFsRepositoryPublicKeyLineSize = 6 * 1024
)

var (
	_ = RegisterRepository(NewFsRepository)
)

func NewFsRepository(_ context.Context, conf *configuration.SessionFs) (*FsRepository, error) {
	result := FsRepository{
		conf: conf,
	}

	return &result, nil
}

type FsRepository struct {
	Logger log.Logger

	conf *configuration.SessionFs

	connectionInterceptors fsConnectionInterceptors

	mutex sync.RWMutex
}

func (this *FsRepository) dir(flow configuration.FlowName, id uuid.UUID) (string, error) {
	fs, err := flow.MarshalText()
	if err != nil {
		return "", err
	}
	is, err := id.MarshalText()
	if err != nil {
		return "", err
	}
	return filepath.Join(this.conf.Storage, string(fs), string(is)), nil
}

func (this *FsRepository) file(flow configuration.FlowName, id uuid.UUID, kind string) (string, error) {
	dir, err := this.dir(flow, id)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, kind), nil
}

func (this *FsRepository) openRead(flow configuration.FlowName, id uuid.UUID, kind string) (*os.File, string, error) {
	fn, err := this.file(flow, id, kind)
	if err != nil {
		return nil, "", err
	}
	f, err := os.Open(fn)
	if err != nil {
		return nil, fn, fmt.Errorf("cannot open session file (%q) of %v/%v for read: %w", fn, flow, id, err)
	}
	return f, fn, nil
}

func (this *FsRepository) openWrite(flow configuration.FlowName, id uuid.UUID, kind string, rw bool) (*os.File, string, error) {
	fn, err := this.file(flow, id, kind)
	if err != nil {
		return nil, "", err
	}
	_ = os.MkdirAll(filepath.Dir(fn), os.FileMode(this.dirFileMode()))
	flags := os.O_WRONLY | os.O_TRUNC | os.O_CREATE
	if rw {
		flags = os.O_RDWR | os.O_CREATE
	}
	f, err := os.OpenFile(fn, flags, os.FileMode(this.conf.FileMode))
	if err != nil {
		return nil, fn, fmt.Errorf("cannot open session file (%q) of %v/%v for write: %w", fn, flow, id, err)
	}
	return f, fn, nil
}

func (this *FsRepository) stat(flow configuration.FlowName, id uuid.UUID, kind string) (os.FileInfo, error) {
	fn, err := this.file(flow, id, kind)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(fn)
	if err != nil {
		return nil, fmt.Errorf("cannot stat session file (%q) of %v/%v for write: %w", fn, flow, id, err)
	}
	return fi, nil
}

func (this *FsRepository) dirFileMode() sys.FileMode {
	result := this.conf.FileMode
	if result&0400 > 0 {
		result |= 0100
	}
	if result&0040 > 0 {
		result |= 0010
	}
	if result&0004 > 0 {
		result |= 0001
	}
	return result
}

func (this *FsRepository) Create(ctx context.Context, flow configuration.FlowName, remote net.Remote, authToken []byte) (Session, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	fail := func(err error) (Session, error) {
		return nil, fmt.Errorf("cannot create session for user %v at flow %v: %w", remote, flow, err)
	}

	id, err := uuid.NewUUID()
	if err != nil {
		return fail(err)
	}

	var sess fs
	sess.info.VState = StateNew
	sess.info.createdAt = time.Now().Truncate(time.Millisecond)
	sess.info.VRemoteUser = remote.User()
	sess.info.VRemoteHost = remote.Host()
	sess.init(this, flow, id)
	if err := sess.info.save(ctx); err != nil {
		return fail(err)
	}
	if _, err := sess.notifyLastAccess(ctx, remote, StateUnchanged); err != nil {
		return fail(err)
	}
	if len(authToken) > 0 {
		if err := sess.setAuthorizationToken(ctx, authToken); err != nil {
			return fail(err)
		}
	}

	return &sess, nil
}

func (this *FsRepository) FindBy(ctx context.Context, flow configuration.FlowName, id uuid.UUID, opts *FindOpts) (Session, error) {
	this.mutex.RLock()
	defer this.mutex.RUnlock()

	return this.findBy(ctx, flow, id, opts, false)
}

func (this *FsRepository) findBy(ctx context.Context, flow configuration.FlowName, id uuid.UUID, opts *FindOpts, expectedToExist bool) (*fs, error) {
	cleanUpIfAllowedAndFail := func(err error) (*fs, error) {
		this.doFindAutoCleanIfAllowed(ctx, flow, id, opts, "found broken session; it was removed entirely", err)
		return nil, err
	}

	f, _, err := this.openRead(flow, id, FsFileSession)
	if err != nil {
		if sys.IsNotExist(err) {
			if expectedToExist {
				this.doFindAutoCleanIfAllowed(ctx, flow, id, opts, "found broken session directory; it was removed entirely", err)
			}
			return nil, ErrNoSuchSession
		}
		return nil, err
	}
	defer common.IgnoreCloseError(f)

	var buf fs
	if err := json.NewDecoder(f).Decode(&buf.info); err != nil {
		return cleanUpIfAllowedAndFail(errors.Newf(errors.System, "cannot decode session %v/%v: %w", flow, id, err))
	}
	fi, err := f.Stat()
	if err != nil {
		return cleanUpIfAllowedAndFail(errors.Newf(errors.System, "cannot stat session file of %v/%v: %w", flow, id, err))
	}
	buf.info.createdAt = fi.ModTime()
	buf.init(this, flow, id)

	this.doAutoCleanUnexpectedFilesIfAllowed(ctx, &buf, opts)

	if ok, err := opts.GetPredicates().Matches(ctx, &buf); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrNoSuchSession
	}

	return &buf, nil
}

func (this *FsRepository) FindByPublicKey(ctx context.Context, key ssh.PublicKey, opts *FindOpts) (Session, error) {
	fail := func(err error) (Session, error) {
		return nil, fmt.Errorf("cannot find session for public key: %w", err)
	}

	loadCandidate := func(flow configuration.FlowName, id uuid.UUID) (*fs, error) {
		this.mutex.RLock()
		defer this.mutex.RUnlock()

		ok, err := this.hasPublicKey(ctx, flow, id, key)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrNoSuchSession
		}

		return this.findBy(ctx, flow, id, opts, true)
	}

	var result Session
	if err := this.iterateFlows(ctx, func(flow configuration.FlowName, path string) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}

		if err := this.iterateFlowDirs(ctx, flow, func(id uuid.UUID, path string) (bool, error) {
			if err := ctx.Err(); err != nil {
				return false, err
			}

			candidate, err := loadCandidate(flow, id)
			if errors.Is(err, ErrNoSuchSession) {
				return true, nil
			} else if err != nil {
				return false, err
			}

			// We found a matching session, therefore we'll use it and stop here for looking...
			result = candidate
			return false, nil
		}, opts); err != nil {
			return false, err
		}
		return result == nil, nil
	}, opts); err != nil {
		return fail(err)
	}

	if result == nil {
		return nil, ErrNoSuchSession
	}

	return result, nil
}

func (this *FsRepository) FindByAccessToken(ctx context.Context, t []byte, opts *FindOpts) (Session, error) {
	fail := func(err error) (Session, error) {
		return nil, fmt.Errorf("cannot find session for public key: %w", err)
	}

	loadCandidate := func(flow configuration.FlowName, id uuid.UUID) (*fs, error) {
		this.mutex.RLock()
		defer this.mutex.RUnlock()

		ok, err := this.hasAccessToken(ctx, flow, id, t)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrNoSuchSession
		}

		return this.findBy(ctx, flow, id, opts, true)
	}

	var result Session
	if err := this.iterateFlows(ctx, func(flow configuration.FlowName, path string) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}

		if err := this.iterateFlowDirs(ctx, flow, func(id uuid.UUID, path string) (bool, error) {
			if err := ctx.Err(); err != nil {
				return false, err
			}

			candidate, err := loadCandidate(flow, id)
			if errors.Is(err, ErrNoSuchSession) {
				return true, nil
			} else if err != nil {
				return false, err
			}

			// We found a matching session, therefore we'll use it and stop here for looking...
			result = candidate
			return false, nil
		}, opts); err != nil {
			return false, err
		}
		return result == nil, nil
	}, opts); err != nil {
		return fail(err)
	}

	if result == nil {
		return nil, ErrNoSuchSession
	}

	return result, nil
}

func (this *FsRepository) FindAll(ctx context.Context, consumer Consumer, opts *FindOpts) error {
	loadCandidate := func(flow configuration.FlowName, id uuid.UUID) (*fs, error) {
		this.mutex.RLock()
		defer this.mutex.RUnlock()

		return this.findBy(ctx, flow, id, opts, true)
	}

	canContinue := true
	return this.iterateFlows(ctx, func(flow configuration.FlowName, path string) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}

		err := this.iterateFlowDirs(ctx, flow, func(id uuid.UUID, path string) (bool, error) {
			if err := ctx.Err(); err != nil {
				return false, err
			}

			candidate, err := loadCandidate(flow, id)
			if errors.Is(err, ErrNoSuchSession) {
				return true, nil
			} else if err != nil {
				return false, err
			}

			canContinue, err = consumer(ctx, candidate)
			return canContinue && err == nil, err
		}, opts)
		return canContinue && err == nil, err
	}, opts)
}

func (this *FsRepository) DeleteBy(ctx context.Context, flow configuration.FlowName, id uuid.UUID) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	return this.deleteBy(ctx, flow, id)
}

func (this *FsRepository) deleteBy(ctx context.Context, flow configuration.FlowName, id uuid.UUID) error {
	dir, err := this.dir(flow, id)
	if err != nil {
		return err
	}

	// Also tell all active connection that we do no longer like them ;-)
	if _, err := this.disposeBy(ctx, flow, id); err != nil {
		return err
	}

	if err := os.RemoveAll(dir); sys.IsNotExist(err) {
		// Ignore
	} else if err != nil {
		return fmt.Errorf("cannot delete session %v/%v: %w", flow, id, err)
	}
	return nil
}

func (this *FsRepository) disposeBy(ctx context.Context, flow configuration.FlowName, id uuid.UUID) (bool, error) {
	var disposed bool

	if this.connectionInterceptors != nil {
		byFlow, hasByFlow := this.connectionInterceptors[flow]
		if hasByFlow {
			byId, hasById := byFlow[id]
			if hasById {
				// Tell all active interceptors, that nothing is allowed from now on.
				byId.disposed.Store(true)
				disposed = byId.active.Load() > 0
			}
		}
	}

	fail := func(err error) (bool, error) {
		return false, errors.Newf(errors.System, "cannot dispose session %v/%v: %w", flow, id, err)
	}

	sess, err := this.findBy(ctx, flow, id, nil, false)
	if errors.Is(err, ErrNoSuchSession) {
		return disposed, nil
	}
	if err != nil {
		return fail(err)
	}

	if sess.info.VState == StateDisposed {
		disposed = true
	} else {
		sess.info.VState = StateDisposed
		if err := sess.info.save(ctx); err != nil {
			return fail(err)
		}
	}

	return disposed, nil
}

func (this *FsRepository) doFindAutoCleanIfAllowed(ctx context.Context, flow configuration.FlowName, id uuid.UUID, opts *FindOpts, successMessage string, cause error) {
	if opts.IsAutoCleanUpAllowed() {
		logger := opts.GetLogger(this.logger).
			Withf("sesion", "%v/%v", flow, id)
		if err := this.deleteBy(ctx, flow, id); err != nil {
			logger.
				WithError(err).
				Error("cannot clean up session automatically; this is really a problem because it could lead to this error shown up repeatedly and a system which gets stuck")
		} else if cause != nil && !errors.Is(cause, ErrNoSuchSession) {
			logger.
				WithError(cause).
				Warn(successMessage)
		} else {
			logger.
				Warn(successMessage)
		}
	}
}

func (this *FsRepository) doAutoCleanUnexpectedFilesIfAllowed(_ context.Context, sess *fs, opts *FindOpts) {
	if opts.IsAutoCleanUpAllowed() {
		logger := opts.GetLogger(this.logger).
			With("session", sess)
		if err := this.deleteUnexpectedFiles(logger, sess); err != nil {
			logger.
				WithError(err).
				Error("cannot clean up session's directory automatically; this is really a problem because it could lead to this error shown up repeatedly and a system which gets stuck")
		}
	}
}

func (this *FsRepository) deleteUnexpectedFiles(logger log.Logger, sess *fs) error {
	dirName, err := this.dir(sess.flow, sess.id)
	if err != nil {
		return err
	}
	f, err := os.Open(dirName)
	if err != nil {
		return err
	}
	defer common.IgnoreCloseError(f)

	entries, err := f.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		switch name {
		case FsFileSession, FsFileLastAccessed, FsFileAccessToken, FsFileEnvironmentToken:
			// Valid filename
			continue
		}

		if strings.HasPrefix(name, FsFilePublicKeysPrefix) {
			plainHash := name[FsFilePublicKeysPrefixLen:]
			hash, err := base58.Decode(plainHash)
			if err == nil && len(hash) == sha1.Size {
				// Valid filename
				continue
			}
		}

		fn := filepath.Join(dirName, name)
		fi, err := os.Stat(fn)
		if sys.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}

		if err := os.RemoveAll(fn); sys.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}

		if fi.IsDir() {
			logger.With("name", name).Warn("found unexpected directory inside of session's directory; it was deleted entirely")
		} else {
			logger.With("name", name).Warn("found unexpected file inside of session's directory; it was deleted entirely")
		}
	}

	return nil
}

func (this *FsRepository) doFindAutoCleanFlowContentIfAllowed(_ context.Context, flow configuration.FlowName, fn string, opts *FindOpts, successMessage string, cause error) {
	if opts.IsAutoCleanUpAllowed() {
		logger := opts.GetLogger(this.logger).
			With("flow", flow).
			With("path", fn)
		if err := os.RemoveAll(fn); err != nil && !os.IsNotExist(err) {
			logger.
				WithError(err).
				Error("cannot clean up flow path automatically; this is really a problem because it could lead to this error shown up repeatedly and a system which gets stuck")
		} else if cause != nil && !errors.Is(cause, ErrNoSuchSession) {
			logger.
				WithError(cause).
				Warn(successMessage)
		} else {
			logger.
				Warn(successMessage)
		}
	}
}

func (this *FsRepository) doFindAutoCleanRootContentIfAllowed(_ context.Context, fn string, opts *FindOpts, successMessage string, cause error) {
	if opts.IsAutoCleanUpAllowed() {
		logger := opts.GetLogger(this.logger).
			With("path", fn)
		if err := os.RemoveAll(fn); err != nil && !os.IsNotExist(err) {
			logger.
				WithError(err).
				Error("cannot clean up path automatically; this is really a problem because it could lead to this error shown up repeatedly and a system which gets stuck")
		} else if cause != nil && !errors.Is(cause, ErrNoSuchSession) {
			logger.
				WithError(cause).
				Warn(successMessage)
		} else {
			logger.
				Warn(successMessage)
		}
	}
}

func (this *FsRepository) Delete(ctx context.Context, s Session) error {
	if s == nil {
		return nil
	}
	switch v := s.(type) {
	case *fs:
		return this.DeleteBy(ctx, v.flow, v.id)
	default:
		return fmt.Errorf("unknown session type: %T", v)
	}
}

func (this *FsRepository) Close() error {
	return nil
}

func (this *FsRepository) publicKeyKind(pub ssh.PublicKey) string {
	hash := sha1.Sum(pub.Marshal())
	return FsFilePublicKeysPrefix + base58.Encode(hash[:])
}

func (this *FsRepository) iterateFlows(ctx context.Context, consumer func(flow configuration.FlowName, path string) (canContinue bool, err error), opts *FindOpts) (rErr error) {
	dirName := this.conf.Storage
	f, err := os.Open(dirName)
	if sys.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer common.KeepCloseError(&rErr, f)

	entries, err := f.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !entry.IsDir() {
			this.doFindAutoCleanRootContentIfAllowed(ctx, filepath.Join(dirName, entry.Name()), opts, "found file inside root directory which should not be there; it was deleted", nil)
			// We ignore files.
			continue
		}
		var flow configuration.FlowName
		if err := flow.UnmarshalText([]byte(entry.Name())); err != nil {
			this.doFindAutoCleanRootContentIfAllowed(ctx, filepath.Join(dirName, entry.Name()), opts, "found directory inside root directory which does not have a UUID as name; it was deleted", nil)
			// We ignore directories which does not match Flow in their names.
			continue
		}
		canContinue, err := consumer(flow, filepath.Join(dirName, entry.Name()))
		if err != nil {
			return err
		}
		if !canContinue {
			break
		}
	}

	return nil
}

func (this *FsRepository) iterateFlowDirs(ctx context.Context, flow configuration.FlowName, consumer func(id uuid.UUID, path string) (canContinue bool, err error), opts *FindOpts) (rErr error) {
	fs, err := flow.MarshalText()
	if err != nil {
		return err
	}

	dirName := filepath.Join(this.conf.Storage, string(fs))
	var entries []os.DirEntry
	defer func() {
		if rErr == nil && len(entries) == 0 && opts.IsAutoCleanUpAllowed() {
			l := opts.GetLogger(this.logger).
				With("path", dirName).
				With("flow", flow)
			if err := os.Remove(dirName); err != nil && !os.IsNotExist(err) {
				l.WithError(err).Warn("was not able to delete orphan flow directory inside of session storage")
			} else {
				l.Info("deleted orphan flow directory inside session storage")
			}
		}
	}()

	f, err := os.Open(dirName)
	if sys.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer common.KeepCloseError(&rErr, f)

	entries, err = f.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !entry.IsDir() {
			this.doFindAutoCleanFlowContentIfAllowed(ctx, flow, filepath.Join(dirName, entry.Name()), opts, "found file inside flow directory which should not be there; it was deleted", nil)
			continue
		}
		var id uuid.UUID
		if err := id.UnmarshalText([]byte(entry.Name())); err != nil {
			this.doFindAutoCleanFlowContentIfAllowed(ctx, flow, filepath.Join(dirName, entry.Name()), opts, "found directory which isn't a UUID inside flow directory which should not be there; it was deleted entirely", nil)
			// We ignore directories which does not match UUID in their names.
			continue
		}
		canContinue, err := consumer(id, filepath.Join(dirName, entry.Name()))
		if err != nil {
			return err
		}
		if !canContinue {
			break
		}
	}

	return nil
}

func (this *FsRepository) findPublicKeyIn(ctx context.Context, flow configuration.FlowName, id uuid.UUID, f *os.File, consumer func(key ssh.PublicKey, lineN int) (canContinue bool, _ error)) (lineN int, rErr error) {
	failN := func(lineN int, err error) (int, error) {
		return lineN, fmt.Errorf("cannot handle publicKeys file (%q:%d) of session %v/%v: %w", f.Name(), lineN, flow, id, err)
	}

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	scanner.Buffer(make([]byte, maxFsRepositoryPublicKeyLineSize), maxFsRepositoryPublicKeyLineSize)

	lineN = -1
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return lineN, err
		}
		line := scanner.Bytes()
		lineN++
		if len(line) == 0 {
			// Skip empty lines...
			continue
		}
		keyBytes, err := base64.StdEncoding.DecodeString(string(line))
		if err != nil {
			return failN(lineN, err)
		}

		candidate, err := ssh.ParsePublicKey(keyBytes)
		if err != nil {
			return failN(lineN, err)
		}

		canContinue, err := consumer(candidate, lineN)
		if err != nil {
			return failN(lineN, err)
		}
		if !canContinue {
			return lineN, nil
		}
	}

	return lineN, nil
}

func (this *FsRepository) hasPublicKey(ctx context.Context, flow configuration.FlowName, id uuid.UUID, pub ssh.PublicKey) (found bool, rErr error) {
	kind := this.publicKeyKind(pub)
	f, _, err := this.openRead(flow, id, kind)
	if sys.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer common.KeepCloseError(&rErr, f)

	_, err = this.findPublicKeyIn(ctx, flow, id, f, func(candidate ssh.PublicKey, lineN int) (canContinue bool, _ error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if pub.Type() != candidate.Type() {
			return true, nil
		}
		if !bytes.Equal(pub.Marshal(), candidate.Marshal()) {
			return true, nil
		}

		found = true
		return false, nil
	})
	if err != nil {
		return false, err
	}
	return found, nil
}

func (this *FsRepository) addPublicKey(ctx context.Context, flow configuration.FlowName, id uuid.UUID, pub ssh.PublicKey) (rErr error) {
	if _, err := this.stat(flow, id, FsFileSession); err != nil {
		return fmt.Errorf("cannot session's %v/%v last access because cannot stat info: %w", flow, id, err)
	}

	kind := this.publicKeyKind(pub)
	f, fn, err := this.openWrite(flow, id, kind, true)
	if err != nil {
		return err
	}
	defer common.KeepCloseError(&rErr, f)

	failN := func(n int, err error) error {
		return fmt.Errorf("cannot add key to publicKeys file (%q:%d) of session %v/%v: %w", fn, n, flow, id, err)
	}

	alreadyContained := false
	lineN, err := this.findPublicKeyIn(ctx, flow, id, f, func(candidate ssh.PublicKey, lineN int) (canContinue bool, _ error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if pub.Type() != candidate.Type() {
			return true, nil
		}
		if !bytes.Equal(pub.Marshal(), candidate.Marshal()) {
			return true, nil
		}

		alreadyContained = true
		return false, nil
	})
	if err != nil {
		return err
	}

	if alreadyContained {
		// We do not add this more than one time...
		return nil
	}

	lineN++
	buf := base64.StdEncoding.EncodeToString(pub.Marshal())
	if _, err := f.WriteString(buf + "\n"); err != nil {
		return failN(lineN, err)
	}
	return nil
}

func (this *FsRepository) deletePublicKey(ctx context.Context, flow configuration.FlowName, id uuid.UUID, pub ssh.PublicKey) (rErr error) {
	kind := this.publicKeyKind(pub)
	fIn, fn, err := this.openRead(flow, id, kind)
	if sys.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer common.KeepCloseError(&rErr, fIn)

	renamed := false

	fnBuf := fn + "~"
	fBuf, err := os.OpenFile(fnBuf, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, os.FileMode(this.conf.FileMode))
	if err != nil {
		return fmt.Errorf("cannot open session file (%q) of %v/%v for write: %w", fnBuf, flow, id, err)
	}
	defer common.DoOnFailureIgnore(&renamed, func() error { return os.Remove(fnBuf) })
	defer common.KeepCloseError(&rErr, fBuf)

	nAdded := 0
	add := func(key ssh.PublicKey) error {
		buf := base64.StdEncoding.EncodeToString(pub.Marshal())
		if _, err := fBuf.WriteString(buf + "\n"); err != nil {
			return fmt.Errorf("cannot preserve key: %w", err)
		}
		nAdded++
		return nil
	}

	_, err = this.findPublicKeyIn(ctx, flow, id, fIn, func(candidate ssh.PublicKey, lineN int) (canContinue bool, _ error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if pub.Type() != candidate.Type() || !bytes.Equal(pub.Marshal(), candidate.Marshal()) {
			// Only if it DOES NOT match, we write it back to the buffer file...
			if err := add(candidate); err != nil {
				return false, err
			}
		}
		return true, nil
	})
	if err != nil {
		return err
	}

	if nAdded <= 0 {
		if err := os.Remove(fn); err != nil {
			return fmt.Errorf("cannot delete buffer publicKeys file (%q) of session %v/%v after deleted key: %w", fn, flow, id, err)
		}
		return nil
	}

	if err := os.Rename(fnBuf, fn); err != nil {
		return fmt.Errorf("cannot rename buffer publicKeys file (%q) to target one (%q) of session %v/%v after deleted key: %w", fnBuf, fn, flow, id, err)
	}

	renamed = true
	return nil
}

func (this *FsRepository) hasAccessToken(_ context.Context, flow configuration.FlowName, id uuid.UUID, t []byte) (found bool, rErr error) {
	f, _, err := this.openRead(flow, id, FsFileAccessToken)
	if sys.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer common.KeepCloseError(&rErr, f)

	return isReaderEqualToBytes(f, t)
}

func (this *FsRepository) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("sessions")
}
