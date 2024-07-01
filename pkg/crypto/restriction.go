package crypto

import "crypto"

type Restriction interface {
	KeyAllowed(crypto.Signer) (bool, error)
}
