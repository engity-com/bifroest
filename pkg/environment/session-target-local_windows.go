//go:build windows

package environment

import "github.com/engity-com/bifroest/pkg/session"

func (this *LocalRepository) ResolveSessionTarget(ctx Context) (session.Target, error) {
	projection, err := ProjectLocalWindowsTarget(ctx, this.conf, localWindowsAccountLookup{})
	if err != nil {
		return "", err
	}
	return projection.SessionTarget()
}
