//go:build windows

package environment

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/engity-com/bifroest/pkg/session"
)

func (this *LocalRepository) ResolveSessionTarget(ctx Context) (session.Target, error) {
	account, name, uid, err := this.lookupConfiguredAccount(ctx)
	if err != nil && !errors.Is(err, errLocalWindowsAccountNotFound) {
		return "", fmt.Errorf("cannot inspect local Windows session target account")
	}
	if err == nil {
		name = account.Name
	}
	fields := localSessionTargetFields(ctx, &this.conf.EnvironmentLocalCommon)
	fields.values["name"] = strings.ToLower(name)
	fields.values["requestedSID"] = uid
	fields.string("displayName", &this.conf.DisplayName)
	fields.string("skel", &this.conf.Skel)
	groups, err := this.conf.Groups.Render(ctx)
	if err != nil {
		return "", fmt.Errorf("cannot resolve local Windows session target groups")
	}
	raw, err := json.Marshal(groups)
	if err != nil {
		return "", fmt.Errorf("cannot encode local Windows session target groups")
	}
	fields.values["groups"] = string(raw)
	return fields.target("local-windows")
}
