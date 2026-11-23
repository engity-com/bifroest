//go:build unix

package authorization

import (
	"context"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/user"
)

// BindAssumedLocalUnixAuthentication binds an assumed post-authentication account
// name to supplied existing Unix facts. The name is not the requesting name,
// mapped principal or environment target selector. This function performs no
// PAM/password/key validation, native lookup, remoteName rendering or I/O.
// Known absence is an inconsistent success assumption; unmodeled observations
// remain errors. The MemoryLookup returns an owned, metadata-only snapshot.
func BindAssumedLocalUnixAuthentication(ctx context.Context, flow *configuration.Flow, accountName string, accounts *user.MemoryLookup) (*AssumedLocalAuthentication, error) {
	if err := validateAssumedLocalFlow(flow); err != nil {
		return nil, err
	}
	if accountName == "" {
		return nil, ErrInvalidLocalAuthenticationAssumption
	}
	account, err := accounts.LookupByName(ctx, accountName)
	if err != nil {
		return nil, err
	}
	name, uid := account.Identity()
	return bindAssumedLocalAuthentication(flow, account, name, uid.String())
}
