//go:build unix

package test

import (
	"context"
	"encoding/json"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/user"
	"gopkg.in/yaml.v3"
)

func newAccountInventory(world facts) (accountInventory, error) {
	if len(world.AbsentSIDs) > 0 || len(world.LocalGroups) > 0 || len(world.AbsentGroupNames) > 0 {
		return accountInventory{}, invalid("Windows SID/group observations are not Unix facts")
	}
	observations := user.AccountLookupFacts{AbsentNames: world.AbsentNames}
	for _, id := range world.AbsentUIDs {
		observations.AbsentIds = append(observations.AbsentIds, user.Id(id))
	}
	for _, fact := range world.Accounts {
		if fact.SID != "" || fact.UID == nil {
			return accountInventory{}, invalid("Unix account facts require uid, not sid")
		}
		uid := user.Id(*fact.UID)
		metadata := user.AccountFacts{Name: fact.Name, Uid: &uid, DisplayName: fact.DisplayName, HomeDir: fact.HomeDir, Shell: fact.Shell}
		if fact.Group != nil {
			group, err := unixGroup(*fact.Group)
			if err != nil {
				return accountInventory{}, err
			}
			metadata.Group = &group
		}
		if fact.Groups != nil {
			groups := make(user.Groups, 0, len(*fact.Groups))
			for _, value := range *fact.Groups {
				group, err := unixGroup(value)
				if err != nil {
					return accountInventory{}, err
				}
				groups = append(groups, group)
			}
			metadata.Groups = &groups
		}
		snapshot, err := user.NewSnapshot(metadata)
		if err != nil {
			return accountInventory{}, err
		}
		observations.Accounts = append(observations.Accounts, snapshot)
	}
	lookup, err := user.NewMemoryLookup(observations)
	if err != nil {
		return accountInventory{}, err
	}
	return accountInventory{bind: func(ctx context.Context, flow *configuration.Flow, name string) (*authorization.AssumedLocalAuthentication, error) {
		return authorization.BindAssumedLocalUnixAuthentication(ctx, flow, name, lookup)
	}, management: func(ctx context.Context, flow *configuration.Flow, bound *authorization.AssumedLocalAuthentication) (authorization.LocalAccountView, error) {
		return bound.UnixAccountWithManagement(ctx, flow)
	}, project: func(ctx *policyContext, conf *configuration.EnvironmentLocal) (environment.TargetProjection, error) {
		return environment.ProjectLocalUnixTarget(ctx, conf, lookup)
	}}, nil
}

func unixGroup(fact accountGroup) (user.Group, error) {
	if fact.GID == nil || fact.SID != "" {
		return user.Group{}, invalid("Unix groups require an explicit gid, not sid")
	}
	return user.Group{Name: fact.Name, Gid: user.GroupId(*fact.GID)}, nil
}

func mappedAccountMatches(expected, actual string) bool { return expected == actual }

func admitLocalConfiguration(*yaml.Node) error { return nil }

func admitLocalTargetTemplates(conf *configuration.EnvironmentLocal) error {
	sources := []string{conf.User.Name.String(), conf.User.DisplayName.String(), conf.User.Shell.String(), conf.User.HomeDir.String(), conf.User.Skel.String(), conf.User.Group.Name.String()}
	if conf.User.Uid != nil {
		sources = append(sources, conf.User.Uid.String())
	}
	if conf.User.Group.Gid != nil {
		sources = append(sources, conf.User.Group.Gid.String())
	}
	for _, group := range conf.User.Groups {
		sources = append(sources, group.Name.String())
		if group.Gid != nil {
			sources = append(sources, group.Gid.String())
		}
	}
	return admitLocalCommonTemplates(conf, sources)
}

func localSelectorValue(field string, value any) (any, error) {
	if field != "account" {
		return value, nil
	}
	plain, ok := value.(string)
	if !ok {
		return nil, invalid("invalid local account selector")
	}
	var requested user.Requirement
	if len(plain) > maxSource || json.Unmarshal([]byte(plain), &requested) != nil {
		return nil, invalid("invalid local account selector")
	}
	var uid any
	if requested.Uid != nil {
		uid = int64(*requested.Uid)
	}
	groupView := func(group user.GroupRequirement) any {
		var gid any
		if group.Gid != nil {
			gid = int64(*group.Gid)
		}
		return map[string]any{"name": group.Name, "gid": gid}
	}
	groups := make([]any, 0, len(requested.Groups))
	for _, group := range requested.Groups {
		groups = append(groups, groupView(group))
	}
	return map[string]any{"name": requested.Name, "uid": uid, "displayName": requested.DisplayName, "group": groupView(requested.Group), "groups": groups, "shell": requested.Shell, "homeDir": requested.HomeDir, "skel": requested.Skel}, nil
}
