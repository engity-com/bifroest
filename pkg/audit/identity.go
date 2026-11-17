package audit

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

const maxAuditIdentityFileSize = 1 << 20

var auditIdentityKeyRequirement = bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}

type Identity struct {
	privateKey  bfcrypto.PrivateKey
	producerId  ProducerId
	fingerprint string
}

func NewIdentity(privateKey bfcrypto.PrivateKey) (*Identity, error) {
	if privateKey == nil || privateKey.PublicKey() == nil || privateKey.ToSsh() == nil {
		return nil, errors.System.Newf("nil audit identity key")
	}
	publicKey := privateKey.PublicKey()
	if privateKey.Type() != gossh.KeyAlgoED25519 {
		return nil, errors.Config.Newf("audit identity contains a %s key instead of Ed25519", privateKey.Type())
	}
	if !isEd25519PrivateKey(privateKey.ToSdk()) {
		return nil, errors.System.Newf("audit identity does not expose an Ed25519 private key")
	}
	if _, ok := publicKey.ToSdk().(ed25519.PublicKey); !ok {
		return nil, errors.System.Newf("audit identity does not expose an Ed25519 public key")
	}
	sshPublicKey := publicKey.ToSsh()
	if sshPublicKey == nil {
		return nil, errors.System.Newf("nil audit identity public key")
	}
	return &Identity{
		privateKey:  privateKey,
		producerId:  newProducerId(publicKey.Marshal()),
		fingerprint: gossh.FingerprintSHA256(sshPublicKey),
	}, nil
}

func isEd25519PrivateKey(signer crypto.Signer) bool {
	switch key := signer.(type) {
	case ed25519.PrivateKey:
		return len(key) == ed25519.PrivateKeySize
	case *ed25519.PrivateKey:
		return key != nil && len(*key) == ed25519.PrivateKeySize
	default:
		return false
	}
}

func (this *Identity) sign(message []byte) ([]byte, error) {
	if this == nil || this.privateKey == nil || this.privateKey.ToSdk() == nil {
		return nil, errors.System.Newf("nil audit identity signer")
	}
	signature, err := this.privateKey.ToSdk().Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		return nil, errors.System.Newf("cannot sign audit data: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, errors.System.Newf("illegal audit signature length: %d", len(signature))
	}
	return signature, nil
}

func (this *Identity) verify(message, signature []byte) error {
	if this == nil || this.privateKey == nil {
		return errors.System.Newf("nil audit identity verifier")
	}
	publicKey, ok := this.privateKey.PublicKey().ToSdk().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return errors.System.Newf("audit identity does not expose an Ed25519 public key")
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, message, signature) {
		return errors.System.Newf("illegal audit signature")
	}
	return nil
}

// EnsureIdentity loads or creates the configured audit identity. A missing key
// is only generated if neither journal nor Recording state could belong to it.
func EnsureIdentity(conf *configuration.Auditlog) (*Identity, error) {
	return ensureIdentity(conf, nil)
}

// EnsureIdentityWithAuditlogs loads or creates the configured audit identity.
// History in any repository sharing the file blocks a replacement identity.
func EnsureIdentityWithAuditlogs(conf *configuration.Auditlog, auditlogs configuration.Auditlogs) (*Identity, error) {
	return ensureIdentity(conf, auditlogs)
}

func ensureIdentity(conf *configuration.Auditlog, auditlogs configuration.Auditlogs) (*Identity, error) {
	if conf == nil {
		return nil, errors.Config.Newf("nil auditlog configuration")
	}
	identityFile := strings.TrimSpace(conf.IdentityFile)
	if identityFile == "" {
		return nil, errors.Config.Newf("audit identity file is empty")
	}
	journalDirectory := strings.TrimSpace(conf.Directory)
	if journalDirectory == "" {
		return nil, errors.Config.Newf("audit journal directory is empty")
	}

	if _, err := os.Lstat(identityFile); errors.Is(err, fs.ErrNotExist) {
		if err := validateMissingAuditIdentityState(conf, identityFile); err != nil {
			return nil, err
		}
		if len(auditlogs) > 0 {
			path, err := sys.CanonicalPath(identityFile)
			if err != nil {
				return nil, errors.Config.Newf("cannot resolve audit identity file: %w", err)
			}
			for index := range auditlogs {
				other := &auditlogs[index]
				otherPath, err := sys.CanonicalPath(other.IdentityFile)
				if err != nil {
					return nil, errors.Config.Newf("cannot resolve identity file of auditlog %q: %w", other.Name, err)
				}
				relative, err := filepath.Rel(path, otherPath)
				if err == nil && relative == "." {
					if err := validateMissingAuditIdentityState(other, identityFile); err != nil {
						return nil, err
					}
				}
			}
		}
		if _, createErr := auditIdentityKeyRequirement.CreateFile(nil, identityFile); createErr != nil && !errors.Is(createErr, fs.ErrExist) {
			return nil, errors.Config.Newf("cannot create audit identity file %q: %w", identityFile, createErr)
		}
	} else if err != nil {
		return nil, errors.System.Newf("cannot inspect audit identity file %q: %w", identityFile, err)
	}

	privateKey, err := loadAuditIdentityFile(identityFile)
	if err != nil {
		return nil, errors.Config.Newf("cannot load audit identity file %q: %w", identityFile, err)
	}
	if privateKey.Type() != gossh.KeyAlgoED25519 {
		return nil, errors.Config.Newf("audit identity file %q contains a %s key instead of Ed25519", identityFile, privateKey.Type())
	}
	identity, err := NewIdentity(privateKey)
	if err != nil {
		return nil, errors.Config.Newf("cannot use audit identity file %q: %w", identityFile, err)
	}
	return identity, nil
}

func validateMissingAuditIdentityState(conf *configuration.Auditlog, identityFile string) error {
	journalDirectory := strings.TrimSpace(conf.Directory)
	if journalDirectory != "" {
		hasHistory, err := auditJournalHasHistory(journalDirectory)
		if err != nil {
			return err
		}
		if hasHistory {
			return errors.Config.Newf("audit identity file %q is missing while journal %q contains history", identityFile, journalDirectory)
		}
	}
	recordingDirectory := strings.TrimSpace(conf.Recording.Directory)
	if conf.Recording.Enabled && recordingDirectory == "" {
		return errors.Config.Newf("audit Recording directory is empty")
	}
	if recordingDirectory != "" {
		// Disabled Recording repositories may still retain evidence.
		hasState, err := journalDirectoryHasEntry(context.Background(), recordingDirectory, func(os.DirEntry) bool { return true })
		if err != nil && !errors.Is(err, fs.ErrNotExist) && (conf.Recording.Enabled || !errors.Is(err, syscall.ENOTDIR)) {
			return errors.System.Newf("cannot inspect audit Recording directory %q: %w", recordingDirectory, err)
		}
		if hasState {
			return errors.Config.Newf("audit identity file %q is missing while Recording directory %q contains state", identityFile, recordingDirectory)
		}
	}
	return nil
}

func loadAuditIdentityFile(path string) (bfcrypto.PrivateKey, error) {
	return bfcrypto.LoadSecurePrivateKeyFile(path, maxAuditIdentityFileSize)
}

// LoadExistingIdentityPublicKey reads an existing private key without creating
// one. Missing files are allowed; unreadable or invalid files are not.
func LoadExistingIdentityPublicKey(path string) (bfcrypto.PublicKey, error) {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, errors.Config.Newf("cannot inspect audit identity file %q: %w", path, err)
	}
	key, err := loadAuditIdentityFile(path)
	if err != nil {
		return nil, errors.Config.Newf("cannot load audit identity file %q: %w", path, err)
	}
	return key.PublicKey(), nil
}

func auditJournalHasHistory(directory string) (bool, error) {
	hasHistory, err := journalDirectoryHasEntry(context.Background(), directory, func(entry os.DirEntry) bool {
		return entry.Name() != journalLockFileName && entry.Name() != journalWorkDirectoryName
	})
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errors.System.Newf("cannot inspect audit journal %q: %w", directory, err)
	}
	if hasHistory {
		return true, nil
	}
	workDirectory := filepath.Join(directory, journalWorkDirectoryName)
	hasHistory, err = journalDirectoryHasEntry(context.Background(), workDirectory, func(os.DirEntry) bool { return true })
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errors.System.Newf("cannot inspect audit journal workspace %q: %w", workDirectory, err)
	}
	return hasHistory, nil
}

func (this *Identity) ProducerId() ProducerId {
	if this == nil {
		return ProducerId{}
	}
	return this.producerId
}

func (this *Identity) Fingerprint() string {
	if this == nil {
		return ""
	}
	return this.fingerprint
}

func (this *Identity) PublicKey() bfcrypto.PublicKey {
	if this == nil || this.privateKey == nil {
		return nil
	}
	return this.privateKey.PublicKey()
}

func (this *Identity) journalPublicKey() []byte {
	if this == nil || this.PublicKey() == nil {
		return nil
	}
	return this.PublicKey().Marshal()
}

// ValidateDedicatedFrom rejects identities that reuse an SSH private key.
func (this *Identity) ValidateDedicatedFrom(privateKeys []bfcrypto.PrivateKey) error {
	if this == nil {
		return nil
	}
	for _, key := range privateKeys {
		if key == nil || key.PublicKey() == nil {
			continue
		}
		if this.privateKey.PublicKey().IsEqualTo(key.PublicKey()) {
			return errors.Config.Newf("audit identity must not reuse an SSH private key (including server host keys)")
		}
	}
	return nil
}

// ValidateDedicatedFromPublicKeys rejects identities reused by SFTP targets.
func (this *Identity) ValidateDedicatedFromPublicKeys(publicKeys []bfcrypto.PublicKey) error {
	if this == nil {
		return nil
	}
	for _, key := range publicKeys {
		if key != nil && this.PublicKey().IsEqualTo(key) {
			return errors.Config.Newf("audit identity must not reuse an SFTP target identity key")
		}
	}
	return nil
}
