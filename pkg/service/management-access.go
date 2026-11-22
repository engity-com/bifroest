package service

import (
	"context"
	"errors"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/management/access"
	managementpolicy "github.com/engity-com/bifroest/pkg/management/policy"
	"github.com/engity-com/bifroest/pkg/management/protocol"
)

func managementAccessDenied(err error) bool {
	return errors.Is(err, access.ErrDenied) || errors.Is(err, errManagementPolicy)
}

// Capabilities are UI hints, never a grant. Operations still check their live
// policy independently, including target-specific forced-command ceilings.
func (s *service) managementCapabilities(ctx context.Context, actor environment.Context) []access.Permission {
	result := make([]access.Permission, 0)
	for _, permission := range access.Permissions() {
		if s.requireManagement(ctx, actor, permission) != nil {
			continue
		}
		if key := authorization.AuthorizedKeyPolicyOf(actor.Authorization()); key != nil && key.ForcedCommand != nil {
			read, readErr := managementpolicy.ForcedRead(*key.ForcedCommand)
			action, actionErr := managementpolicy.ForcedAction(*key.ForcedCommand)
			if (readErr != nil || managementReadPermission(protocol.ReadRequest{Operation: read.Operation}) != permission) && (actionErr != nil || managementActionPermission(action.Action) != permission) {
				continue
			}
		}
		result = append(result, permission)
	}
	return result
}

// Every transport supplies a verified actor context, never a client-provided
// permission map. Evaluate only the requested path, immediately before use.
func (s *service) requireManagement(ctx context.Context, actor environment.Context, permission access.Permission) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if actor == nil || actor.Authorization() == nil || !actor.Authorization().IsAuthorized() || actor.Authorization().FindSession() == nil || actor.Authorization().FindSession().Flow() != actor.Authorization().Flow() {
		return access.Denied(permission)
	}
	for _, flow := range s.Configuration.Flows {
		if flow.Name != actor.Authorization().Flow() {
			continue
		}
		conf, ok := flow.Environment.V.(*configuration.EnvironmentManagement)
		if !ok || conf == nil {
			break
		}
		allowed, err := conf.Access.Allows(permission, actor)
		if err == nil && allowed {
			return ctx.Err()
		}
		break
	}
	return access.Denied(permission)
}

func (s *service) requireManagementConnection(ctx context.Context, conn *terminalConnection, permission access.Permission) error {
	if conn == nil {
		return access.Denied(permission)
	}
	actor := &environmentContext{service: s, connection: conn, authorization: conn.authorization, executionContext: ctx}
	return s.requireManagement(ctx, actor, permission)
}

func managementReadPermission(request protocol.ReadRequest) access.Permission {
	switch request.Operation {
	case protocol.ShowVersion:
		return access.VersionRead
	case protocol.ListFlows:
		return access.FlowsRead
	case protocol.ListSessions, protocol.ShowSession:
		return access.SessionsRead
	case protocol.ListAuditlogs:
		return access.AuditlogsRead
	case protocol.ListAuditEvents:
		return access.AuditlogsEvents
	case protocol.ListRecordings:
		return access.RecordingsRead
	case protocol.VerifyRecordings:
		return access.RecordingsVerify
	default:
		return ""
	}
}

func managementActionPermission(action string) access.Permission {
	switch action {
	case "disconnect":
		return access.SessionsDisconnect
	case "dispose":
		return access.SessionsDispose
	default:
		return ""
	}
}

func managementArtifactPermission(operation protocol.ArtifactOperation) access.Permission {
	switch operation {
	case protocol.DownloadAudit:
		return access.AuditlogsDownload
	case protocol.DownloadRecording:
		return access.RecordingsDownload
	default:
		return ""
	}
}
