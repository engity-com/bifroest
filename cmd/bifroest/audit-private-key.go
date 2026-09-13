package main

import (
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

const maxAuditPrivateKeySize = 1 << 20

func loadAuditPrivateKey(path string) (bfcrypto.PrivateKey, error) {
	return bfcrypto.LoadSecurePrivateKeyFile(path, maxAuditPrivateKeySize)
}
