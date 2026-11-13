// Package authentication contains the transport-independent identity exposed by
// authentication results. It does not depend on SSH, HTTP or operating-system
// account repositories and can also be used by browser clients.
package authentication

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const AnonymousPrincipal = "anonymous"

// Identity separates a configurable principal from the authority-scoped subject
// that identifies an authenticated actor. Session matching must additionally
// check the flow and effective target; a principal alone is not an identity key.
type Identity struct {
	Principal string `json:"principal" yaml:"principal"`
	Issuer    string `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	Subject   string `json:"subject,omitempty" yaml:"subject,omitempty"`
}

type Provider interface {
	Authentication() (Identity, error)
}

func Anonymous() Identity { return Identity{Principal: AnonymousPrincipal} }

func (this Identity) IsAuthenticated() bool {
	return this.Issuer != "" && this.Subject != ""
}

// SameSubject never equates anonymous actors, including two identical anonymous
// display labels. Reusing their sessions requires an independent possession proof.
func (this Identity) SameSubject(other Identity) bool {
	return this.Validate() == nil && other.Validate() == nil &&
		this.IsAuthenticated() && other.IsAuthenticated() &&
		this.Issuer == other.Issuer && this.Subject == other.Subject
}

func (this Identity) Validate() error {
	for _, field := range []struct{ name, value string }{
		{"principal", this.Principal}, {"issuer", this.Issuer}, {"subject", this.Subject},
	} {
		if len(field.value) > 1024 || !utf8.ValidString(field.value) || strings.ContainsFunc(field.value, unicode.IsControl) {
			return fmt.Errorf("authentication %s is invalid", field.name)
		}
	}
	if strings.TrimSpace(this.Principal) == "" {
		return fmt.Errorf("authentication principal is empty")
	}
	if this.Issuer == "" && this.Subject == "" {
		if this.Principal != AnonymousPrincipal {
			return fmt.Errorf("an anonymous authentication cannot claim a different principal")
		}
		return nil
	}
	if strings.TrimSpace(this.Issuer) == "" || strings.TrimSpace(this.Subject) == "" {
		return fmt.Errorf("authentication issuer and subject are required together")
	}
	return nil
}

func (this Identity) GetField(name string) (any, bool, error) {
	switch name {
	case "principal":
		return this.Principal, true, nil
	case "issuer":
		return this.Issuer, true, nil
	case "subject":
		return this.Subject, true, nil
	case "isAuthenticated":
		return this.IsAuthenticated(), true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}
