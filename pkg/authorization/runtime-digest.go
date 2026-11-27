package authorization

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// RuntimeDigest compares the initialized grant authority without exposing its
// resolved client secret. Configuration text alone cannot detect env/file-backed
// templates or changed discovery endpoints.
func (this *OidcDeviceAuthAuthorizer) RuntimeDigest(key []byte) (string, error) {
	var discovery map[string]json.RawMessage
	if err := this.provider.Claims(&discovery); err != nil {
		return "", fmt.Errorf("cannot compare initialized OIDC discovery")
	}
	raw, err := json.Marshal(struct {
		Issuer    string
		Config    any
		Discovery map[string]json.RawMessage
	}{this.issuer, this.oauth2Config, discovery})
	if err != nil {
		return "", fmt.Errorf("cannot encode initialized OIDC authority")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("bifroest-runtime-oidc-v1\x00"))
	_, _ = mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}
