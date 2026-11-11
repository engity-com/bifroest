package session

import (
	"context"
	"encoding/json"
	"fmt"
	iofs "io/fs"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

const FsFileSshRemember = "rk"

var ErrInvalidSSHRememberMe = errors.Config.Newf("invalid SSH RememberMe state")

type SSHRememberedCredential struct {
	Identity   authentication.Identity          `json:"identity"`
	Credential authentication.SessionCredential `json:"credential"`
}

type SSHRememberMeSession interface {
	RememberSSHKey(context.Context, ssh.PublicKey, SSHRememberedCredential) error
	SSHKeyCredential(context.Context, ssh.PublicKey) (SSHRememberedCredential, error)
}

func (s *fs) sshCredentials() (map[string]SSHRememberedCredential, error) {
	path, err := s.repository.file(s.flow, s.id, FsFileSshRemember)
	if err != nil {
		return nil, err
	}
	raw, err := crypto.ReadSecurePrivateFile(path, 256<<10)
	if errors.Is(err, iofs.ErrNotExist) {
		return make(map[string]SSHRememberedCredential), nil
	}
	if err != nil {
		return nil, err
	}
	var entries map[string]SSHRememberedCredential
	if err := json.Unmarshal(raw, &entries); err != nil || entries == nil || len(entries) > 256 {
		return nil, fmt.Errorf("invalid SSH RememberMe credentials")
	}
	return entries, nil
}

func (s *fs) RememberSSHKey(ctx context.Context, key ssh.PublicKey, credential SSHRememberedCredential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if key == nil || credential.Identity.Validate() != nil || credential.Credential.Validate() != nil {
		return fmt.Errorf("invalid SSH RememberMe credential")
	}
	s.repository.mutex.Lock()
	defer s.repository.mutex.Unlock()
	entries, err := s.sshCredentials()
	if err != nil {
		return err
	}
	name := ssh.FingerprintSHA256(key)
	if _, exists := entries[name]; !exists && len(entries) >= 256 {
		return fmt.Errorf("SSH RememberMe credential limit reached")
	}
	entries[name] = credential
	raw, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	if len(raw) > 256<<10 {
		return fmt.Errorf("SSH RememberMe credential size limit reached")
	}
	current, err := s.repository.findBy(ctx, s.flow, s.id, nil, false)
	if err != nil {
		return err
	}
	if current.info.VState == StateDisposed {
		return fmt.Errorf("cannot remember an SSH key for a disposed session")
	}
	path, err := s.repository.file(s.flow, s.id, FsFileSshRemember)
	if err != nil {
		return err
	}
	if err := writeFsPrivateFileAtomically(path, raw, os.FileMode(s.repository.dirFileMode())); err != nil {
		return err
	}
	return s.repository.addPublicKey(ctx, s.flow, s.id, key)
}

func (s *fs) SSHKeyCredential(ctx context.Context, key ssh.PublicKey) (SSHRememberedCredential, error) {
	if key == nil {
		return SSHRememberedCredential{}, ErrNoSuchSession
	}
	if err := ctx.Err(); err != nil {
		return SSHRememberedCredential{}, err
	}
	s.repository.mutex.RLock()
	defer s.repository.mutex.RUnlock()
	var empty SSHRememberedCredential
	present, err := s.repository.hasPublicKey(ctx, s.flow, s.id, key)
	if err != nil {
		return empty, err
	}
	if !present {
		return empty, ErrNoSuchSession
	}
	entries, err := s.sshCredentials()
	if err != nil {
		return empty, err
	}
	credential, exists := entries[ssh.FingerprintSHA256(key)]
	if !exists || credential.Identity.Validate() != nil || credential.Credential.Validate() != nil {
		return empty, ErrNoSuchSession
	}
	return credential, nil
}
