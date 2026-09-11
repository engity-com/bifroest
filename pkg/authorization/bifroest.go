package authorization

import (
	"context"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
)

const bifroestAuthorizationTokenSchema = "bifroest.authorization/v1"

type BifroestAuthorization struct {
	remote   net.Remote
	flow     configuration.FlowName
	session  session.Session
	evidence *AuthorizationEvidence
	policy   *AuthorizedKeyPolicy
}

func (*BifroestAuthorization) AuthorizationKind() string { return "bifroest" }

func (this *BifroestAuthorization) Remote() net.Remote { return this.remote }

func (*BifroestAuthorization) IsAuthorized() bool { return true }

func (*BifroestAuthorization) EnvVars() sys.EnvVars { return nil }

func (this *BifroestAuthorization) Flow() configuration.FlowName { return this.flow }

func (this *BifroestAuthorization) FindSession() session.Session { return this.session }

func (*BifroestAuthorization) FindSessionsPublicKey() ssh.PublicKey { return nil }

func (this *BifroestAuthorization) AuthorizedKeyPolicy() *AuthorizedKeyPolicy {
	return cloneAuthorizedKeyPolicy(this.policy)
}

func (this *BifroestAuthorization) AuthorizationEvidence() *AuthorizationEvidence {
	return this.evidence.Clone()
}

func (this *BifroestAuthorization) GetField(name string, ce ContextEnabled) (any, bool, error) {
	return getField(name, ce, this, func() (any, bool, error) {
		switch name {
		case "origin":
			return this.evidence.Origin, true, nil
		case "peer":
			return this.evidence.LastHop(), true, nil
		case "hops":
			return append([]AuthorizationEvidenceHop(nil), this.evidence.Hops...), true, nil
		case "policy":
			return this.evidence.Policy(), true, nil
		default:
			return nil, false, fmt.Errorf("unknown field %q", name)
		}
	})
}

func (this *BifroestAuthorization) Dispose(ctx context.Context) (bool, error) {
	if this.session == nil {
		return false, nil
	}
	if err := this.session.SetAuthorizationToken(ctx, nil); err != nil {
		return false, err
	}
	return true, nil
}

type bifroestAuthorizationToken struct {
	Schema   string                      `json:"schema"`
	Evidence AuthorizationEvidence       `json:"evidence"`
	Policy   AuthorizationEvidencePolicy `json:"policy"`
}

func cloneAuthorizedKeyPolicy(value *AuthorizedKeyPolicy) *AuthorizedKeyPolicy {
	if value == nil {
		return nil
	}
	result := *value
	result.Environment = value.Environment.Clone()
	result.permitOpen = append([]authorizedKeyHostPortPattern(nil), value.permitOpen...)
	result.permitListen = append([]authorizedKeyHostPortPattern(nil), value.permitListen...)
	return &result
}
