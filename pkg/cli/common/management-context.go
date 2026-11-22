package common

import (
	"context"
	"io"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/configuration"
	managementaccess "github.com/engity-com/bifroest/pkg/management/access"
	bfRecording "github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
)

// ManagementAccess is bound to one authorized SSH invocation, never to the
// shared, compiled command schema.
type ManagementAccess struct {
	Configuration  *configuration.Configuration
	Sessions       session.Repository
	SessionControl ManagementSessionControl
	Check          func(context.Context, managementaccess.Permission) error
	WireFormat     bool
	WireStream     bool
	ProducerID     func(configuration.AuditlogName) (audit.ProducerId, error)
	Recordings     ManagementRecordingBrowser
	Audit          ManagementAuditOperations
	Recording      ManagementRecordingOperations
	Keys           ManagementKeyOperations
	Metrics        ManagementMetrics
}

func (a ManagementAccess) Require(ctx context.Context, permission managementaccess.Permission) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !permission.Valid() {
		return managementaccess.Denied(permission)
	}
	if a.Check != nil {
		return a.Check(ctx, permission)
	}
	allowed, err := (managementaccess.Policy{}).Allows(permission, nil)
	if err != nil || !allowed {
		return managementaccess.Denied(permission)
	}
	return nil
}

func RequireManagementPermission(ctx context.Context, permission managementaccess.Permission) error {
	access, ok := ManagementAccessFromContext(ctx)
	if !ok {
		return managementaccess.Denied(permission)
	}
	return access.Require(ctx, permission)
}

type ManagementMetrics interface {
	Snapshot(context.Context, []string) (model.MetricsSnapshot, error)
}

type ManagementSessionControl interface {
	Disconnect(context.Context, session.Id) (model.SessionActionResult, error)
	Dispose(context.Context, session.Id) (model.SessionActionResult, error)
}

type ManagementKeyOperations interface {
	Export(context.Context, model.KeyExportRequest) ([]byte, error)
}

type ManagementAuditOperations interface {
	Verify(context.Context, configuration.AuditlogName, bool) (string, error)
	Export(context.Context, []configuration.AuditlogName, bool, audit.RecordOrder, io.Writer) error
}

type ManagementRecordingOperations interface {
	Verify(context.Context, configuration.AuditlogName, bfRecording.Id, bool) (string, error)
	Export(context.Context, configuration.AuditlogName, bfRecording.Id, io.Writer) error
	Play(context.Context, configuration.AuditlogName, bfRecording.Id, float64, io.Writer) error
}

type ManagementRecordingBrowser interface {
	Visit(context.Context, configuration.AuditlogName, bfRecording.SealedPageOptions, func(model.RecordingView) error) error
	Detail(context.Context, configuration.AuditlogName, bfRecording.Id) (model.RecordingView, error)
}

// FormatForInvocation selects CBOR for the versioned SSH command; users may
// also request CBOR explicitly with --format=cbor.
func FormatForInvocation(ctx context.Context, selected format.Format) format.Format {
	if access, ok := ManagementAccessFromContext(ctx); ok && access.WireFormat {
		return format.WireCbor
	}
	return selected
}

// MetricsFormatForInvocation selects the internal SSH envelope without making
// CBOR a public metrics output format.
func MetricsFormatForInvocation(ctx context.Context, selected format.MetricsFormat) format.MetricsFormat {
	if access, ok := ManagementAccessFromContext(ctx); ok && access.WireFormat {
		return format.MetricsWireCbor
	}
	return selected
}

type managementAccessKey struct{}

func ContextWithManagementAccess(ctx context.Context, access ManagementAccess) context.Context {
	return context.WithValue(ctx, managementAccessKey{}, access)
}

func ManagementAccessFromContext(ctx context.Context) (ManagementAccess, bool) {
	access, ok := ctx.Value(managementAccessKey{}).(ManagementAccess)
	return access, ok
}
