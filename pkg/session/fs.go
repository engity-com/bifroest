package session

import (
	"encoding/json"
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	FsFileSession             = "se.json"
	FsFileLastAccessed        = "la.json"
	FsFileAccessToken         = "at"
	FsFilePublicKeysPrefix    = "k-"
	FsFilePublicKeysPrefixLen = len(FsFilePublicKeysPrefix)
	FsFilePublicKeysSuffix    = ".pubs"
	FsFilePublicKeysSuffixLen = len(FsFilePublicKeysSuffix)
)

type fsSession struct {
	repository *FsRepository

	VFlow  configuration.FlowName `json:"flow"`
	VId    uuid.UUID              `json:"id"`
	VState State                  `json:"state"`

	VCreatedAt  time.Time `json:"createdAt"`
	VRemoteUser string    `json:"remoteUser"`
	VRemoteHost net.Host  `json:"remoteHost"`

	VTimeout common.Duration `json:"timeout"`
}

func (this *fsSession) Info() (Info, error) {
	return this, nil
}

func (this *fsSession) AuthorizationToken() (_ []byte, rErr error) {
	f, fn, err := this.repository.openRead(this.VFlow, this.VId, FsFileAccessToken)
	if sys.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer common.KeepCloseError(&rErr, f)

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("cannot read session's token file (%q) of %v/%v: %w", fn, this.VFlow, this.VId, err)
	}
	return data, nil
}

func (this *fsSession) SetAuthorizationToken(data []byte) (rErr error) {
	if len(data) == 0 {
		fn, err := this.repository.file(this.VFlow, this.VId, FsFileAccessToken)
		if err != nil {
			return fmt.Errorf("cannot delete session's token file (%q) of %v/%v: %w", fn, this.VFlow, this.VId, err)
		}
		if err := os.Remove(fn); err != nil && !sys.IsNotExist(err) {
			return fmt.Errorf("cannot delete session's token file (%q) of %v/%v: %w", fn, this.VFlow, this.VId, err)
		}
		return nil
	}

	f, fn, err := this.repository.openWrite(this.VFlow, this.VId, FsFileAccessToken, false)
	if err != nil {
		return err
	}
	defer common.KeepCloseError(&rErr, f)

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("cannot write session's token file (%q) of %v/%v: %w", fn, this.VFlow, this.VId, err)
	}
	return nil
}

func (this *fsSession) HasPublicKey(pub ssh.PublicKey) (bool, error) {
	return this.repository.hasPublicKey(this.VFlow, this.VId, pub)
}

func (this *fsSession) IteratePublicKey(consumer func(ssh.PublicKey) (canContinue bool, err error)) error {
	return this.iterateFlowPublicKeyFiles(func(hash, fn string) (canContinue bool, rErr error) {
		fail := func(err error) (bool, error) {
			return false, fmt.Errorf("public keys file (%q) of session %v: %w", fn, this, err)
		}

		f, err := os.Open(fn)
		if err != nil {
			return fail(err)
		}
		defer common.KeepCloseError(&rErr, f)

		if _, err := this.repository.findPublicKeyIn(this.VFlow, this.VId, f, func(key ssh.PublicKey, _ int) (canContinue bool, _ error) {
			var err error
			canContinue, err = consumer(key)
			return canContinue, err
		}); err != nil {
			return fail(err)
		}

		return canContinue, nil
	})
}

func (this *fsSession) AddPublicKey(pub ssh.PublicKey) error {
	return this.repository.addPublicKey(this.VFlow, this.VId, pub)
}

func (this *fsSession) DeletePublicKey(pub ssh.PublicKey) error {
	return this.repository.deletePublicKey(this.VFlow, this.VId, pub)
}

func (this *fsSession) NotifyLastAccess(remote common.Remote, newState State) error {
	buf := fsLastAccessed{
		session:     this,
		VAt:         time.Now().Truncate(time.Millisecond),
		VRemoteUser: remote.User(),
		VRemoteAddr: remote.Host().Clone(),
	}
	if err := buf.save(); err != nil {
		return err
	}
	if newState != 0 && newState != this.VState {
		this.VState = newState
		if err := buf.save(); err != nil {
			return err
		}
	}
	return nil
}

func (this *fsSession) save() error {
	f, _, err := this.repository.openWrite(this.VFlow, this.VId, FsFileSession, false)
	if err != nil {
		return err
	}
	defer common.IgnoreCloseError(f)

	if err := json.NewEncoder(f).Encode(this); err != nil {
		return fmt.Errorf("cannot encode session %v/%v: %w", this.VFlow, this.VId, err)
	}

	return nil
}

func (this *fsSession) iterateFlowPublicKeyFiles(consumer func(hash, path string) (canContinue bool, err error)) (rErr error) {
	dirPath, err := this.repository.dir(this.VFlow, this.VId)
	if err != nil {
		return err
	}
	fd, err := os.Open(dirPath)
	if sys.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer common.KeepCloseError(&rErr, fd)

	entries, err := fd.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			// We ignore directories.
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, FsFilePublicKeysPrefix) || !strings.HasPrefix(name, FsFilePublicKeysSuffix) {
			// Should be a file of "k-*.pubs"
			continue
		}

		hash := name[FsFilePublicKeysPrefixLen : len(name)-FsFilePublicKeysSuffixLen]
		if len(hash) == 0 {
			// Should be a file of "k-*.pubs" not "k-.pubs" ;-)
			continue
		}

		canContinue, err := consumer(hash, filepath.Join(this.repository.conf.Storage, name))
		if err != nil {
			return err
		}
		if !canContinue {
			break
		}
	}

	return nil
}
