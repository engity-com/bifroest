package audit

import "github.com/engity-com/bifroest/pkg/audit/evidence"

type journalIdentity interface {
	ProducerId() ProducerId
	journalPublicKey() []byte
	verify([]byte, []byte) error
}

type journalPublicIdentity struct{ inner *evidence.PublicIdentity }

func newJournalPublicIdentity(id ProducerId, key []byte) (*journalPublicIdentity, error) {
	value, err := evidence.NewPublicIdentity(id, key)
	if err != nil {
		return nil, err
	}
	return &journalPublicIdentity{value}, nil
}
func (this *journalPublicIdentity) ProducerId() ProducerId   { return this.inner.ProducerId() }
func (this *journalPublicIdentity) journalPublicKey() []byte { return this.inner.PublicKeyBytes() }
func (this *journalPublicIdentity) verify(message, signature []byte) error {
	return this.inner.VerifySignature(message, signature)
}

// Only a read-only verification capability crosses into the portable codec.
type portableJournalIdentity struct{ journalIdentity }

func asPortableJournalIdentity(identity journalIdentity) evidence.JournalIdentity {
	if identity == nil {
		return nil
	}
	return portableJournalIdentity{identity}
}

func (this portableJournalIdentity) PublicKeyBytes() []byte { return this.journalPublicKey() }
func (this portableJournalIdentity) VerifySignature(message, signature []byte) error {
	return this.verify(message, signature)
}
