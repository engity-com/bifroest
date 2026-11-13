package authentication

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// SessionCredential records the server-verified primary method, never a rights
// snapshot or secret. PublicKey is the exact SSH public wire value (certificate
// included), NOT the independent browser-generated RememberMe signing key.
type SessionCredential struct {
	Kind      string `json:"kind"`
	Method    string `json:"method"`
	PublicKey string `json:"publicKey,omitempty"`
}

func (this SessionCredential) IsZero() bool { return this == SessionCredential{} }
func (this SessionCredential) Validate() error {
	if this.Kind == "" || len(this.Kind) > 128 || strings.ContainsFunc(this.Kind, func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' }) {
		return fmt.Errorf("invalid session credential kind")
	}
	switch this.Method {
	case "password", "keyboard-interactive":
		if this.PublicKey != "" {
			return fmt.Errorf("unexpected public key in session credential")
		}
	case "public-key":
		if this.PublicKey == "" || len(this.PublicKey) > 12<<10 {
			return fmt.Errorf("missing or oversized session credential key")
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(this.PublicKey)
		if err != nil || len(raw) > 8<<10 || base64.StdEncoding.EncodeToString(raw) != this.PublicKey {
			return fmt.Errorf("invalid session credential key encoding")
		}
	default:
		return fmt.Errorf("invalid session credential method")
	}
	return nil
}
