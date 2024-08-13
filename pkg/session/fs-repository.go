package session

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/google/uuid"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	maxFsRepositoryPublicKeyLineSize = 6 * 1024
)

func NewFsRepository(conf *configuration.SessionFs) (*FsRepository, error) {
	result := FsRepository{
		conf: conf,
	}

	return &result, nil
}

type FsRepository struct {
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

func (this *FsRepository) Create(flow configuration.FlowName, remote common.Remote, authToken []byte) (Session, error) {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	fail := func(err error) (Session, error) {
		return nil, fmt.Errorf("cannot create session for user %v at flow %v: %w", remote, flow, err)
	}

	id, err := uuid.NewUUID()
	if err != nil {
		return fail(err)
	}

	sess := fs{
		repository:  this,
		VFlow:       flow,
		VId:         id,
		VState:      StateNew,
		VCreatedAt:  time.Now().Truncate(time.Millisecond),
		VRemoteUser: remote.User(),
		VRemoteHost: remote.Host(),
	}
	if err := sess.save(); err != nil {
		return fail(err)
	}
	if err := sess.NotifyLastAccess(remote, StateUnchanged); err != nil {
		return fail(err)
	}
	if len(authToken) > 0 {
		if err := sess.SetAuthorizationToken(authToken); err != nil {
			return fail(err)
		}
	}

	return &sess, nil
}

func (this *FsRepository) FindBy(flow configuration.FlowName, id uuid.UUID) (Session, error) {
	this.mutex.RLock()
	defer this.mutex.RUnlock()

	return this.findBy(flow, id)
}

func (this *FsRepository) findBy(flow configuration.FlowName, id uuid.UUID) (Session, error) {
	f, _, err := this.openRead(flow, id, FsFileSession)
	if err != nil {
		if sys.IsNotExist(err) {
			return nil, ErrNoSuchSession
		}
		return nil, err
	}
	defer common.IgnoreCloseError(f)

	buf := fs{
		repository: this,
	}
	if err := json.NewDecoder(f).Decode(&buf); err != nil {
		return nil, fmt.Errorf("cannot decode session %v/%v: %w", flow, id, err)
	}

	return &buf, nil
}

func (this *FsRepository) FindByPublicKey(key ssh.PublicKey, predicate func(Session) (bool, error)) (Session, error) {
	this.mutex.RLock()
	defer this.mutex.RUnlock()

	fail := func(err error) (Session, error) {
		return nil, fmt.Errorf("cannot find session for public key: %w", err)
	}

	var result Session
	if err := this.iterateFlows(func(flow configuration.FlowName, path string) (bool, error) {
		if err := this.iterateFlowDirs(flow, func(id uuid.UUID, path string) (bool, error) {
			ok, err := this.hasPublicKey(flow, id, key)
			if err != nil {
				return false, err
			}
			if !ok {
				// This session does not have this key, therefore continue...
				return true, nil
			}

			candidate, err := this.findBy(flow, id)
			if errors.Is(err, ErrNoSuchSession) {
				// Strange that there is a directory which this key inside, but it is not a session,
				// but we'll ignore it here...
				return true, nil
			}
			if err != nil {
				return false, err
			}

			acceptable := false
			if predicate != nil {
				acceptable, err = predicate(candidate)
				if err != nil {
					return false, err
				}
			}

			if !acceptable {
				return true, nil
			}

			// We found a matching session, therefore we'll use it and stop here for looking...
			result = candidate
			return false, nil
		}); err != nil {
			return false, err
		}
		return result == nil, nil
	}); err != nil {
		return fail(err)
	}

	if result == nil {
		return nil, ErrNoSuchSession
	}

	return result, nil
}

func (this *FsRepository) DeleteBy(flow configuration.FlowName, id uuid.UUID) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	dir, err := this.dir(flow, id)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); sys.IsNotExist(err) {
		// Ignore
	} else if err != nil {
		return fmt.Errorf("cannot delete session %v/%v: %w", flow, id, err)
	}
	return nil
}

func (this *FsRepository) Delete(s Session) error {
	if s == nil {
		return nil
	}
	switch v := s.(type) {
	case *fs:
		return this.DeleteBy(v.VFlow, v.VId)
	default:
		return fmt.Errorf("unknown session type: %T", v)
	}
}

func (this *FsRepository) Close() error {
	return nil
}

func (this *FsRepository) publicKeyKind(pub ssh.PublicKey) string {
	hash := sha1.Sum(pub.Marshal())
	return FsFilePublicKeysPrefix + base58.Encode(hash[:]) + FsFilePublicKeysSuffix
}

func (this *FsRepository) iterateFlows(consumer func(flow configuration.FlowName, path string) (canContinue bool, err error)) (rErr error) {
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
		if !entry.IsDir() {
			// We ignore files.
			continue
		}
		var flow configuration.FlowName
		if err := flow.UnmarshalText([]byte(entry.Name())); err != nil {
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

func (this *FsRepository) iterateFlowDirs(flow configuration.FlowName, consumer func(id uuid.UUID, path string) (canContinue bool, err error)) (rErr error) {
	fs, err := flow.MarshalText()
	if err != nil {
		return err
	}

	dirName := filepath.Join(this.conf.Storage, string(fs))
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
		if !entry.IsDir() {
			// We ignore files.
			continue
		}
		var id uuid.UUID
		if err := id.UnmarshalText([]byte(entry.Name())); err != nil {
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

func (this *FsRepository) findPublicKeyIn(flow configuration.FlowName, id uuid.UUID, f *os.File, consumer func(key ssh.PublicKey, lineN int) (canContinue bool, _ error)) (lineN int, rErr error) {
	failN := func(lineN int, err error) (int, error) {
		return lineN, fmt.Errorf("cannot handle publicKeys file (%q:%d) of session %v/%v: %w", f.Name(), lineN, flow, id, err)
	}

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	scanner.Buffer(make([]byte, maxFsRepositoryPublicKeyLineSize), maxFsRepositoryPublicKeyLineSize)

	lineN = -1
	for scanner.Scan() {
		line := scanner.Bytes()
		lineN++
		if len(line) == 0 {
			//Skip empty lines...
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

func (this *FsRepository) hasPublicKey(flow configuration.FlowName, id uuid.UUID, pub ssh.PublicKey) (found bool, rErr error) {
	kind := this.publicKeyKind(pub)
	f, _, err := this.openRead(flow, id, kind)
	if sys.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer common.KeepCloseError(&rErr, f)

	_, err = this.findPublicKeyIn(flow, id, f, func(candidate ssh.PublicKey, lineN int) (canContinue bool, _ error) {
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

func (this *FsRepository) addPublicKey(flow configuration.FlowName, id uuid.UUID, pub ssh.PublicKey) (rErr error) {
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
	lineN, err := this.findPublicKeyIn(flow, id, f, func(candidate ssh.PublicKey, lineN int) (canContinue bool, _ error) {
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

func (this *FsRepository) deletePublicKey(flow configuration.FlowName, id uuid.UUID, pub ssh.PublicKey) (rErr error) {
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

	_, err = this.findPublicKeyIn(flow, id, fIn, func(candidate ssh.PublicKey, lineN int) (canContinue bool, _ error) {
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
			return fmt.Errorf("cannot delete buffer publicKeys file (%q) of session %v/%v after deleted key: %w", fnBuf, fn, flow, id, err)
		}
		return nil
	}

	if err := os.Rename(fnBuf, fn); err != nil {
		return fmt.Errorf("cannot rename buffer publicKeys file (%q) to target one (%q) of session %v/%v after deleted key: %w", fnBuf, fn, flow, id, err)
	}

	renamed = true
	return nil
}
