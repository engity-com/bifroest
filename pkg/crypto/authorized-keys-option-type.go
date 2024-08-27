package crypto

import (
	"errors"
	"fmt"
)

type AuthorizedKeyOptionType uint8

var (
	ErrIllegalAuthorizedKeyOptionType = errors.New("illegal authorized key option type")
)

const (
	AuthorizedKeyOptionEmpty AuthorizedKeyOptionType = iota
	AuthorizedKeyAgentForwarding
	AuthorizedKeyNoAgentForwarding
	AuthorizedKeyCertAuthority
	AuthorizedKeyCommand
	AuthorizedKeyEnvironment
	AuthorizedKeyExpiryTime
	AuthorizedKeyFrom
	AuthorizedKeyPermitListen
	AuthorizedKeyPermitOpen
	AuthorizedKeyPrincipals
	AuthorizedKeyPortForwarding
	AuthorizedKeyNoPortForwarding
	AuthorizedKeyPty
	AuthorizedKeyNoPty
	AuthorizedKeyNoTouchRequired
	AuthorizedKeyVerifyRequired
	AuthorizedKeyRestrict
	AuthorizedKeyTunnel
	AuthorizedKeyUserRc
	AuthorizedKeyNoUserRc
	AuthorizedKeyX11Forwarding
	AuthorizedKeyNoX11Forwarding
)

func (this AuthorizedKeyOptionType) hasValue() bool {
	switch this {
	case AuthorizedKeyCommand,
		AuthorizedKeyEnvironment,
		AuthorizedKeyExpiryTime,
		AuthorizedKeyFrom,
		AuthorizedKeyPermitListen,
		AuthorizedKeyPermitOpen,
		AuthorizedKeyPrincipals,
		AuthorizedKeyTunnel:
		return true
	default:
		return false
	}
}

func (this AuthorizedKeyOptionType) MarshalText() ([]byte, error) {
	v, ok := authorizedKeyOptionTypeToName[this]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrIllegalAuthorizedKeyOptionType, this)
	}
	return []byte(v), nil
}

func (this *AuthorizedKeyOptionType) UnmarshalText(text []byte) error {
	v, ok := nameToAuthorizedKeyOptionType[string(text)]
	if !ok {
		return fmt.Errorf("%w: %q", ErrIllegalAuthorizedKeyOptionType, string(text))
	}
	*this = v
	return nil

}

func (this AuthorizedKeyOptionType) String() string {
	v, ok := authorizedKeyOptionTypeToName[this]
	if !ok {
		return fmt.Sprintf("illegal-athorized-key-option-%d", this)
	}
	return v
}

func (this AuthorizedKeyOptionType) IsZero() bool {
	return this == AuthorizedKeyOptionEmpty
}

func (this *AuthorizedKeyOptionType) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this AuthorizedKeyOptionType) Validate() error {
	_, ok := authorizedKeyOptionTypeToName[this]
	if !ok {
		return fmt.Errorf("%w: %d", ErrIllegalAuthorizedKeyOptionType, this)
	}
	return nil
}

func (this AuthorizedKeyOptionType) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case AuthorizedKeyOptionType:
		return this.isEqualTo(&v)
	case *AuthorizedKeyOptionType:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this AuthorizedKeyOptionType) isEqualTo(other *AuthorizedKeyOptionType) bool {
	return this == *other
}

var (
	authorizedKeyOptionTypeToName = map[AuthorizedKeyOptionType]string{
		AuthorizedKeyOptionEmpty:       "",
		AuthorizedKeyAgentForwarding:   "agent-forwarding",
		AuthorizedKeyNoAgentForwarding: "no-agent-forwarding",
		AuthorizedKeyCertAuthority:     "cert-authority",
		AuthorizedKeyCommand:           "command",
		AuthorizedKeyEnvironment:       "environment",
		AuthorizedKeyExpiryTime:        "expiry-time",
		AuthorizedKeyFrom:              "from",
		AuthorizedKeyPermitListen:      "permitlisten",
		AuthorizedKeyPermitOpen:        "permitopen",
		AuthorizedKeyPortForwarding:    "port-forwarding",
		AuthorizedKeyPrincipals:        "principals",
		AuthorizedKeyNoPortForwarding:  "no-port-forwarding",
		AuthorizedKeyPty:               "pty",
		AuthorizedKeyNoPty:             "no-pty",
		AuthorizedKeyNoTouchRequired:   "no-touch-required",
		AuthorizedKeyVerifyRequired:    "verify-required",
		AuthorizedKeyRestrict:          "restrict",
		AuthorizedKeyTunnel:            "tunnel",
		AuthorizedKeyUserRc:            "user-rc",
		AuthorizedKeyNoUserRc:          "no-user-rc",
		AuthorizedKeyX11Forwarding:     "x11-forwarding",
		AuthorizedKeyNoX11Forwarding:   "no-x11-forwarding",
	}

	nameToAuthorizedKeyOptionType = func(in map[AuthorizedKeyOptionType]string) map[string]AuthorizedKeyOptionType {
		result := make(map[string]AuthorizedKeyOptionType, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(authorizedKeyOptionTypeToName)
)
