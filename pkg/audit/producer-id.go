package audit

import (
	"crypto/sha256"
	"github.com/engity-com/bifroest/pkg/audit/evidence"
)

type ProducerId = evidence.ProducerId

func newProducerId(publicKey []byte) ProducerId { return ProducerId(sha256.Sum256(publicKey)) }
