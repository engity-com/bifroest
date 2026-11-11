package service

import (
	"context"

	"github.com/engity-com/bifroest/pkg/authorization"
)

// Side-band progress is deliberately count-only and provisional. It does not
// release structured results or acknowledge capture/seal/final-audit completion.
type managementReadProgress struct {
	Phase     string `json:"phase"`
	Completed int64  `json:"completed"`
	Total     int64  `json:"total"`
}
type managementProgressContextKey struct{}
type managementProgressWriter interface {
	ManagementProgress(managementReadProgress) error
}

func bindManagementProgress(conn *terminalConnection, output any) {
	if writer, ok := output.(managementProgressWriter); ok {
		conn.ctx = context.WithValue(conn.ctx, managementProgressContextKey{}, func(progress managementReadProgress) error {
			if conn.IsClosed() || conn.check(false) != nil {
				return errWebAccessDenied
			}
			return writer.ManagementProgress(managementProgressFor(conn.authorization, progress))
		})
	}
}

func managementProgressFor(auth authorization.Authorization, progress managementReadProgress) managementReadProgress {
	// Forced read ceilings must not learn whole-archive counts outside
	// their permitted flow/user projection through a side channel.
	if key := authorization.AuthorizedKeyPolicyOf(auth); key != nil && key.ForcedCommand != nil {
		progress.Completed, progress.Total = 0, -1
	}
	return progress
}

func reportManagementProgress(ctx context.Context, phase string, completed, total int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if report, ok := ctx.Value(managementProgressContextKey{}).(func(managementReadProgress) error); ok {
		return report(managementReadProgress{phase, completed, total})
	}
	return nil
}
