package audit

import (
	"bytes"
	"encoding/json"

	"github.com/engity-com/bifroest/pkg/errors"
)

const (
	journalHeadFileName        = "head.json"
	journalHeadTempFileName    = "head.tmp"
	journalHeadSchema          = "bifroest.audit-journal-head/v1"
	journalHeadSignatureDomain = "BIFROEST-AUDIT-JOURNAL-HEAD-SIGNATURE/v1\x00"
)

type journalHeadContent struct {
	Schema         string      `json:"schema"`
	ProducerId     ProducerId  `json:"producerId"`
	LastRecordHash journalHash `json:"lastRecordHash"`
	PublicKey      []byte      `json:"publicKey"`
}

type journalHead struct {
	journalHeadContent
	Signature []byte `json:"signature"`
}

func newJournalHead(identity *Identity, lastRecordHash journalHash) (journalHead, []byte, error) {
	content := journalHeadContent{
		Schema:         journalHeadSchema,
		ProducerId:     identity.ProducerId(),
		LastRecordHash: lastRecordHash,
		PublicKey:      identity.PublicKey().Marshal(),
	}
	unsigned, err := json.Marshal(content)
	if err != nil {
		return journalHead{}, nil, errors.System.Newf("cannot encode audit journal head: %w", err)
	}
	signature, err := identity.sign(append([]byte(journalHeadSignatureDomain), unsigned...))
	if err != nil {
		return journalHead{}, nil, err
	}
	head := journalHead{journalHeadContent: content, Signature: signature}
	payload, err := json.Marshal(head)
	if err != nil {
		return journalHead{}, nil, errors.System.Newf("cannot encode signed audit journal head: %w", err)
	}
	return head, payload, nil
}

func decodeJournalHead(payload []byte, identity journalIdentity) (journalHead, error) {
	var head journalHead
	if err := decodeCanonicalJournalPayload(payload, &head); err != nil {
		return journalHead{}, err
	}
	if head.Schema != journalHeadSchema || head.ProducerId != identity.ProducerId() || !bytes.Equal(head.PublicKey, identity.journalPublicKey()) {
		return journalHead{}, errors.Config.Newf("audit journal head belongs to a different identity")
	}
	unsigned, err := json.Marshal(head.journalHeadContent)
	if err != nil {
		return journalHead{}, errors.System.Newf("cannot re-encode audit journal head: %w", err)
	}
	if err := identity.verify(append([]byte(journalHeadSignatureDomain), unsigned...), head.Signature); err != nil {
		return journalHead{}, err
	}
	return head, nil
}
