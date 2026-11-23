//go:build unix || windows

package authorization

import (
	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
)

var (
	ErrInvalidLocalAuthenticationAssumption = errors.Config.Newf("invalid local authentication assumption")
	ErrAssumedLocalFieldUnavailable         = errors.Config.Newf("local authentication field was not modeled")
)

// LocalAccountView exposes metadata, not credentials, native account getters or
// provisioning capabilities. Values retain the production field types.
type LocalAccountView interface {
	GetField(string) (any, bool, error)
}

// AssumedLocalAuthentication binds an explicitly assumed successful local
// authentication to a configured local flow and one owned account snapshot.
// Principal/issuer/subject are derived from that account using the production
// identity mapping; they cannot be supplied independently of the account facts.
// It does not select a flow or apply its principal mapping.
//
// This is data for controlled policy evaluation, NOT a production Authorization,
// authorizer, native password-policy proof, credential, token or session. No
// registered factory, request flag or production login path constructs it.
// A future runner must explicitly adapt it at its assumed-result boundary and
// retain the fact that authentication was assumed, not performed.
type AssumedLocalAuthentication struct {
	flow      configuration.FlowName
	reference string
	identity  authentication.Identity
	account   assumedLocalAccountView
}

func (this *AssumedLocalAuthentication) Flow() configuration.FlowName {
	if this == nil {
		return ""
	}
	return this.flow
}

func (this *AssumedLocalAuthentication) AuthorizationReference() string {
	if this == nil {
		return ""
	}
	return this.reference
}

func (this *AssumedLocalAuthentication) Authentication() (authentication.Identity, error) {
	if this == nil || this.account.source == nil {
		return authentication.Identity{}, ErrInvalidLocalAuthenticationAssumption
	}
	return this.identity, nil
}

func (this *AssumedLocalAuthentication) Account() (LocalAccountView, error) {
	if this == nil || this.account.source == nil {
		return nil, ErrInvalidLocalAuthenticationAssumption
	}
	return this.account, nil
}

type assumedLocalAccountView struct{ source LocalAccountView }

func (this assumedLocalAccountView) GetField(name string) (any, bool, error) {
	if this.source == nil {
		return nil, false, ErrInvalidLocalAuthenticationAssumption
	}
	if name == "managed" {
		// Management is an environment/flow-dependent observation, not an
		// authentication result. Never turn an unmodeled resolver into false
		// or invoke a native resolver through an arbitrary caller context.
		return nil, false, errors.Config.Newf("%w: managed", ErrAssumedLocalFieldUnavailable)
	}
	return this.source.GetField(name)
}

func validateAssumedLocalFlow(flow *configuration.Flow) error {
	if flow == nil || flow.Name.Validate() != nil {
		return ErrInvalidLocalAuthenticationAssumption
	}
	conf, ok := flow.Authorization.V.(*configuration.AuthorizationLocal)
	if !ok || conf == nil {
		return ErrInvalidLocalAuthenticationAssumption
	}
	return nil
}

func (this *AssumedLocalAuthentication) validateManagementFlow(flow *configuration.Flow) error {
	if this == nil || this.account.source == nil {
		return ErrInvalidLocalAuthenticationAssumption
	}
	if err := validateAssumedLocalFlow(flow); err != nil {
		return err
	}
	if flow.Name != this.flow || flow.Authorization.Reference != this.reference {
		return errors.Config.Newf("%w: management flow mismatch", ErrInvalidLocalAuthenticationAssumption)
	}
	return nil
}

func bindAssumedLocalAuthentication(flow *configuration.Flow, account LocalAccountView, name, subject string) (*AssumedLocalAuthentication, error) {
	identity := localAuthenticationIdentity(name, subject)
	if identity.Validate() != nil || !identity.IsAuthenticated() {
		return nil, ErrInvalidLocalAuthenticationAssumption
	}
	return &AssumedLocalAuthentication{
		flow: flow.Name, reference: flow.Authorization.Reference, identity: identity,
		account: assumedLocalAccountView{source: account},
	}, nil
}
