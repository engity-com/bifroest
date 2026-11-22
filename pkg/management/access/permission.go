// Package access defines the shared management permission catalog and policy.
package access

import (
	"errors"
	"fmt"
	"slices"
)

var ErrDenied = errors.New("management access denied")

func Denied(p Permission) error { return fmt.Errorf("%w: %s", ErrDenied, p) }

type Permission string

const (
	VersionRead        Permission = "version.read"
	MetricsRead        Permission = "metrics.read"
	FlowsRead          Permission = "flows.read"
	FlowsCredentials   Permission = "flows.credentials"
	SessionsRead       Permission = "sessions.read"
	SessionsDisconnect Permission = "sessions.disconnect"
	SessionsDispose    Permission = "sessions.dispose"
	AuditlogsRead      Permission = "auditlogs.read"
	AuditlogsEvents    Permission = "auditlogs.events"
	AuditlogsVerify    Permission = "auditlogs.verify"
	AuditlogsDownload  Permission = "auditlogs.download"
	RecordingsRead     Permission = "recordings.read"
	RecordingsVerify   Permission = "recordings.verify"
	RecordingsDownload Permission = "recordings.download"
	KeysRead           Permission = "keys.read"
)

var permissions = []Permission{
	VersionRead, MetricsRead, FlowsRead, FlowsCredentials,
	SessionsRead, SessionsDisconnect, SessionsDispose,
	AuditlogsRead, AuditlogsEvents, AuditlogsVerify, AuditlogsDownload,
	RecordingsRead, RecordingsVerify, RecordingsDownload, KeysRead,
}

func Permissions() []Permission { return slices.Clone(permissions) }

func (p Permission) Valid() bool { return slices.Contains(permissions, p) }

func defaultAllowed(p Permission) bool {
	return p.Valid() && p != FlowsCredentials && p != AuditlogsDownload && p != RecordingsDownload
}
