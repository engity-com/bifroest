//go:build windows

package test

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/windowslocal"
	"golang.org/x/sys/windows"
	"gopkg.in/yaml.v3"
)

func newAccountInventory(world facts) (accountInventory, error) {
	if len(world.AbsentUIDs) > 0 {
		return accountInventory{}, invalid("numeric absent UIDs are not Windows facts")
	}
	observations := windowslocal.AccountLookupFacts{AbsentNames: world.AbsentNames, AbsentSIDs: world.AbsentSIDs}
	for _, sid := range world.AbsentSIDs {
		if !canonicalSID(sid) {
			return accountInventory{}, invalid("Windows absent SID must be canonical")
		}
	}
	for _, fact := range world.Accounts {
		if fact.UID != nil || fact.Group != nil || !windowslocal.ValidSAMName(fact.Name) {
			return accountInventory{}, invalid("Windows account facts require local name and sid, not uid or primary group")
		}
		sid, err := windows.StringToSid(fact.SID)
		if err != nil || sid == nil || !sid.IsValid() || sid.String() != fact.SID {
			return accountInventory{}, invalid("Windows fixture SID must be canonical")
		}
		metadata := windowslocal.AccountFacts{Identity: windowslocal.Account{Name: fact.Name, SID: fact.SID}, DisplayName: fact.DisplayName, HomeDir: fact.HomeDir, Shell: fact.Shell}
		if fact.Groups != nil {
			groups := make([]windowslocal.AccountGroupFacts, 0, len(*fact.Groups))
			for _, group := range *fact.Groups {
				if group.GID != nil || !canonicalSID(group.SID) || !windowslocal.ValidSAMName(group.Name) {
					return accountInventory{}, invalid("Windows account groups require canonical name and sid")
				}
				groups = append(groups, windowslocal.AccountGroupFacts{Name: group.Name, SID: group.SID})
			}
			metadata.Groups = &groups
		}
		snapshot, err := windowslocal.NewAccountSnapshot(metadata)
		if err != nil {
			return accountInventory{}, err
		}
		observations.Accounts = append(observations.Accounts, snapshot)
	}
	lookup, err := windowslocal.NewMemoryLookup(observations)
	if err != nil {
		return accountInventory{}, err
	}
	groupFacts := windowslocal.GroupLookupFacts{AbsentNames: world.AbsentGroupNames}
	accountSIDs := map[string]bool{}
	for _, account := range world.Accounts {
		accountSIDs[account.SID] = true
	}
	for _, group := range world.LocalGroups {
		if !canonicalSID(group.SID) || accountSIDs[group.SID] {
			return accountInventory{}, invalid("Windows local group SID must be canonical")
		}
		if group.Members != nil {
			for _, member := range *group.Members {
				if !canonicalSID(member) {
					return accountInventory{}, invalid("Windows member SID must be canonical")
				}
			}
		}
		groupFacts.Groups = append(groupFacts.Groups, windowslocal.LocalGroupFacts{Name: group.Name, SID: group.SID, Members: group.Members})
	}
	groups, err := windowslocal.NewMemoryGroupLookup(groupFacts)
	if err != nil {
		return accountInventory{}, err
	}
	return accountInventory{bind: func(ctx context.Context, flow *configuration.Flow, name string) (*authorization.AssumedLocalAuthentication, error) {
		return authorization.BindAssumedLocalWindowsAuthentication(ctx, flow, name, lookup)
	}, management: func(ctx context.Context, flow *configuration.Flow, bound *authorization.AssumedLocalAuthentication) (authorization.LocalAccountView, error) {
		return bound.WindowsAccountWithManagement(ctx, flow, groups)
	}, project: func(ctx *policyContext, conf *configuration.EnvironmentLocal) (environment.TargetProjection, error) {
		return environment.ProjectLocalWindowsTarget(ctx, conf, lookup)
	}}, nil
}

func canonicalSID(value string) bool {
	sid, err := windows.StringToSid(value)
	return err == nil && sid != nil && sid.IsValid() && sid.String() == value
}

func mappedAccountMatches(expected, actual string) bool { return strings.EqualFold(expected, actual) }

// Prevent the product's import-time COMSPEC default from becoming a controlled
// runtime selector. Explicit empty lists are valid; host defaults are not.
func admitLocalConfiguration(node *yaml.Node) error {
	for _, name := range []string{"shellCommand", "execCommandPrefix"} {
		found := false
		for i := 0; i < len(node.Content); i += 2 {
			if node.Content[i].Value == name && node.Content[i+1].Tag != "!!null" {
				found = true
			}
		}
		if !found {
			return invalid("offline Windows local environments require explicit shellCommand and execCommandPrefix")
		}
	}
	return nil
}

func admitLocalTargetTemplates(conf *configuration.EnvironmentLocal) error {
	sources := []string{conf.Name.String(), conf.Uid.String(), conf.DisplayName.String(), conf.Skel.String()}
	for _, group := range conf.Groups {
		sources = append(sources, group.Name.String(), group.Gid.String())
	}
	return admitLocalCommonTemplates(conf, sources)
}

func localSelectorValue(field string, value any) (any, error) {
	if field != "groups" {
		return value, nil
	}
	plain, ok := value.(string)
	if !ok {
		return nil, invalid("invalid local group selector")
	}
	var requested []configuration.WindowsUserGroupRequirement
	if len(plain) > maxSource || json.Unmarshal([]byte(plain), &requested) != nil {
		return nil, invalid("invalid local group selector")
	}
	groups := make([]any, 0, len(requested))
	for _, group := range requested {
		groups = append(groups, map[string]any{"name": group.Name, "gid": group.Gid})
	}
	return groups, nil
}
