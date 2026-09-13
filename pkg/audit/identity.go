package audit

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"io/fs"
	"os"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
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
// is only generated if no journal history exists that could belong to it.
func EnsureIdentity(conf *configuration.Auditlog) (*Identity, error) {
	if conf == nil {
		return nil, errors.Config.Newf("nil auditlog configuration")
	}
	if !conf.Enabled {
		return nil, nil
	}
	identityFile := strings.TrimSpace(conf.IdentityFile)
	if identityFile == "" {
		return nil, errors.Config.Newf("audit identity file is empty")
	}
	journalDirectory := strings.TrimSpace(conf.Journal.Directory)
	if journalDirectory == "" {
		return nil, errors.Config.Newf("audit journal directory is empty")
	}

	if _, err := os.Lstat(identityFile); errors.Is(err, fs.ErrNotExist) {
		hasHistory, inspectErr := auditJournalHasHistory(journalDirectory)
		if inspectErr != nil {
			return nil, inspectErr
		}
		if hasHistory {
			return nil, errors.Config.Newf("audit identity file %q is missing while journal %q contains history", identityFile, journalDirectory)
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

func loadAuditIdentityFile(path string) (bfcrypto.PrivateKey, error) {
	return bfcrypto.LoadSecurePrivateKeyFile(path, maxAuditIdentityFileSize)
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

// ValidateDedicatedFrom rejects identities that reuse one of the SSH server's
// host keys.
func (this *Identity) ValidateDedicatedFrom(hostKeys []bfcrypto.PrivateKey) error {
	if this == nil {
		return nil
	}
	for _, hostKey := range hostKeys {
		if hostKey == nil || hostKey.PublicKey() == nil {
			continue
		}
		if this.privateKey.PublicKey().IsEqualTo(hostKey.PublicKey()) {
			return errors.Config.Newf("audit identity must not reuse an SSH server host key")
		}
	}
	return nil
}
