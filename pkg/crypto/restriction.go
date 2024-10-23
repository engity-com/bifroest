package crypto

import gocrypto "crypto"

type Restriction interface {
	KeyAllowed(gocrypto.Signer) (bool, error)
}
