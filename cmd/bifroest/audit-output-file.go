package main

import (
	crand "crypto/rand"
	"encoding/hex"
)

func randomAuditOutputTemporaryName() (string, error) {
	var random [16]byte
	if _, err := crand.Read(random[:]); err != nil {
		return "", err
	}
	return ".bifroest-audit-output-" + hex.EncodeToString(random[:]), nil
}
