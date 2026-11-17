package audit

import (
	"github.com/engity-com/bifroest/pkg/audit/evidence"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

const SessionRecordingCastSignatureSchema = evidence.SessionRecordingCastSignatureSchema

type SessionRecordingCastSignature = evidence.SessionRecordingCastSignature

// NewSessionRecordingCastSignature retains the restricted native signer; the
// portable package can validate/encode/verify, never access this private identity.
func (this *Identity) NewSessionRecordingCastSignature(recordingId, digest string) (SessionRecordingCastSignature, error) {
	if this == nil || this.PublicKey() == nil {
		return SessionRecordingCastSignature{}, errors.System.Newf("nil audit identity signer")
	}
	value := SessionRecordingCastSignature{Schema: SessionRecordingCastSignatureSchema, RecordingId: recordingId, ProducerId: this.ProducerId(), Digest: digest, PublicKey: this.PublicKey().Marshal()}
	message, err := evidence.SessionRecordingCastSignatureMessage(value)
	if err != nil {
		return SessionRecordingCastSignature{}, err
	}
	value.Signature, err = this.sign(message)
	if err != nil {
		return SessionRecordingCastSignature{}, err
	}
	return value, nil
}

func VerifySessionRecordingCastSignature(value SessionRecordingCastSignature) (bfcrypto.PublicKey, error) {
	return evidence.VerifySessionRecordingCastSignature(value)
}
