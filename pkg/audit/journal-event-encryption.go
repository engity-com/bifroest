package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	journalEventEncryptionScheme   = "age-ssh/v1"
	maxEncryptionPublicKeyFileSize = 4 << 20
)

type journalEncryptedEvent struct {
	Scheme     string `json:"scheme"`
	Recipient  string `json:"recipient"`
	Ciphertext []byte `json:"ciphertext"`
}

type journalEventEncryptor struct {
	recipient            age.Recipient
	recipientFingerprint string
}

type journalEventDecrypter struct {
	identities []age.Identity
}

func ResolveEncryptionPublicKey(publicKey bfcrypto.PublicKeys, publicKeyFile bfcrypto.PublicKeysFile) (bfcrypto.PublicKeys, error) {
	if !publicKey.IsZero() && !publicKeyFile.IsZero() {
		return "", errors.Config.Newf("audit encryption public key and public key file cannot be combined")
	}
	if publicKeyFile.IsZero() {
		return publicKey, nil
	}
	keys, err := readEncryptionPublicKeyFile(string(publicKeyFile))
	if err != nil {
		return "", errors.Config.Newf("cannot load audit encryption public key file %q: %w", publicKeyFile, err)
	}
	if len(keys) != 1 {
		return "", errors.Config.Newf("audit encryption public key file %q must contain exactly one SSH public key", publicKeyFile)
	}
	return bfcrypto.PublicKeys(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(keys[0])))), nil
}

func readEncryptionPublicKeyFile(path string) ([]ssh.PublicKey, error) {
	pathInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.Config.Newf("public key file %q is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	openInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(pathInfo, openInfo) {
		return nil, errors.Config.Newf("public key file %q changed while opening", path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxEncryptionPublicKeyFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxEncryptionPublicKeyFileSize {
		return nil, errors.Config.Newf("public key file %q exceeds %d bytes", path, maxEncryptionPublicKeyFileSize)
	}
	return bfcrypto.PublicKeys(strings.TrimSpace(string(raw))).Get()
}

func EncryptionRecipientFingerprint(publicKeys bfcrypto.PublicKeys) (string, error) {
	if publicKeys.IsZero() {
		return "", nil
	}
	_, fingerprint, err := newJournalEventRecipient(publicKeys)
	return fingerprint, err
}

func ValidateEncryptionRecipientDedicatedFrom(publicKeys bfcrypto.PublicKeys, privateKeys []bfcrypto.PrivateKey) error {
	if publicKeys.IsZero() {
		return nil
	}
	keys, err := publicKeys.Get()
	if err != nil {
		return errors.Config.Newf("cannot parse audit encryption public key: %w", err)
	}
	if len(keys) != 1 {
		return errors.Config.Newf("exactly one audit encryption public key is required")
	}
	for _, privateKey := range privateKeys {
		if privateKey != nil && privateKey.PublicKey() != nil && bytes.Equal(keys[0].Marshal(), privateKey.PublicKey().Marshal()) {
			return errors.Config.Newf("audit encryption recipient reuses a private key available to the Bifröst server")
		}
	}
	return nil
}

func ValidateEncryptionRecipientDedicatedFromAuditIdentities(publicKeys bfcrypto.PublicKeys, identities []*Identity) error {
	fingerprint, err := EncryptionRecipientFingerprint(publicKeys)
	if err != nil || fingerprint == "" {
		return err
	}
	for _, identity := range identities {
		if identity != nil && identity.Fingerprint() == fingerprint {
			return errors.Config.Newf("audit encryption recipient reuses an audit signing identity available to the Bifröst server")
		}
	}
	return nil
}

func newJournalEventEncryptor(publicKeys bfcrypto.PublicKeys) (*journalEventEncryptor, error) {
	if publicKeys.IsZero() {
		return nil, nil
	}
	recipient, fingerprint, err := newJournalEventRecipient(publicKeys)
	if err != nil {
		return nil, err
	}
	return &journalEventEncryptor{recipient: recipient, recipientFingerprint: fingerprint}, nil
}

func newJournalEventRecipient(publicKeys bfcrypto.PublicKeys) (age.Recipient, string, error) {
	keys, err := publicKeys.Get()
	if err != nil {
		return nil, "", errors.Config.Newf("cannot parse audit encryption public key: %w", err)
	}
	if len(keys) != 1 {
		return nil, "", errors.Config.Newf("exactly one audit encryption public key is required")
	}
	key := keys[0]
	var recipient age.Recipient
	switch key.Type() {
	case ssh.KeyAlgoED25519:
		recipient, err = agessh.NewEd25519Recipient(key)
	case ssh.KeyAlgoRSA:
		recipient, err = agessh.NewRSARecipient(key)
	default:
		err = errors.Config.Newf("SSH public key type %q cannot be used for audit encryption", key.Type())
	}
	if err != nil {
		return nil, "", errors.Config.Newf("cannot use audit encryption public key: %w", err)
	}
	return recipient, ssh.FingerprintSHA256(key), nil
}

func newJournalEventDecrypter(privateKeys []bfcrypto.PrivateKey) (*journalEventDecrypter, error) {
	if len(privateKeys) == 0 {
		return nil, nil
	}
	identities := make([]age.Identity, 0, len(privateKeys))
	for _, key := range privateKeys {
		if key == nil {
			return nil, errors.Config.Newf("nil audit decryption identity")
		}
		var identity age.Identity
		var err error
		switch value := key.ToSdk().(type) {
		case ed25519.PrivateKey:
			identity, err = agessh.NewEd25519Identity(value)
		case *ed25519.PrivateKey:
			identity, err = agessh.NewEd25519Identity(*value)
		case *rsa.PrivateKey:
			identity, err = agessh.NewRSAIdentity(value)
		default:
			err = errors.Config.Newf("SSH private key type %q cannot be used for audit decryption", key.Type())
		}
		if err != nil {
			return nil, errors.Config.Newf("cannot use audit decryption identity: %w", err)
		}
		identities = append(identities, identity)
	}
	return &journalEventDecrypter{identities: identities}, nil
}

func (this *journalEventEncryptor) encrypt(event Event) (journalEncryptedEvent, error) {
	plaintext, err := json.Marshal(event)
	if err != nil {
		return journalEncryptedEvent{}, errors.System.Newf("cannot encode audit event for encryption: %w", err)
	}
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, this.recipient)
	if err != nil {
		return journalEncryptedEvent{}, errors.System.Newf("cannot initialize audit event encryption: %w", err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		return journalEncryptedEvent{}, errors.System.Newf("cannot encrypt audit event: %w", err)
	}
	if err := writer.Close(); err != nil {
		return journalEncryptedEvent{}, errors.System.Newf("cannot finish audit event encryption: %w", err)
	}
	return journalEncryptedEvent{
		Scheme:     journalEventEncryptionScheme,
		Recipient:  this.recipientFingerprint,
		Ciphertext: ciphertext.Bytes(),
	}, nil
}

func (this *journalEventDecrypter) decrypt(encrypted journalEncryptedEvent) (Event, error) {
	if this == nil || len(this.identities) == 0 {
		return Event{}, errors.Config.Newf("encrypted audit records require a matching decryption identity")
	}
	reader, err := age.Decrypt(bytes.NewReader(encrypted.Ciphertext), this.identities...)
	if err != nil {
		return Event{}, errors.Config.Newf("cannot decrypt audit event with the supplied identities: %w", err)
	}
	plaintext, err := io.ReadAll(io.LimitReader(reader, maxJournalRecordPayloadSize+1))
	if err != nil {
		return Event{}, errors.System.Newf("cannot authenticate encrypted audit event: %w", err)
	}
	if len(plaintext) > maxJournalRecordPayloadSize {
		return Event{}, errors.System.Newf("decrypted audit event exceeds %d bytes", maxJournalRecordPayloadSize)
	}
	var event Event
	if err := decodeCanonicalJournalPayload(plaintext, &event); err != nil {
		return Event{}, errors.System.Newf("cannot decode decrypted audit event: %w", err)
	}
	if err := validateAuditEvent(event); err != nil {
		return Event{}, err
	}
	return event, nil
}
