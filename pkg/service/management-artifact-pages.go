package service

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	managementview "github.com/engity-com/bifroest/pkg/management/view"
	"github.com/engity-com/bifroest/pkg/recording"
)

func (this *service) managementAuditlogPage(ctx context.Context, request protocol.ReadRequest) (protocol.Page[protocol.AuditlogSummary], error) {
	filter := managementGridPredicate(request.GridFilter, request.Operation)
	page := protocol.Page[protocol.AuditlogSummary]{Items: make([]protocol.AuditlogSummary, 0)}
	after, _, err := request.Cursor()
	if err != nil {
		return page, err
	}
	var items []readSlot[protocol.AuditlogSummary]
	var total int64
	descending := request.Sort == "name-desc"
	position := ""
	if after != "" {
		position = managementGridKey(after, descending)
	}
	for index, conf := range this.Configuration.Auditlogs {
		if err := reportManagementProgress(ctx, "inventory", int64(index), int64(len(this.Configuration.Auditlogs))); err != nil {
			return page, err
		}
		if err := ctx.Err(); err != nil {
			return page, err
		}
		name := conf.Name.String()
		if !managementSearch(request.Query, name) {
			continue
		}
		item := managementview.Auditlog(conf)
		if filter(map[string]protocol.GridValue{"name": protocol.GridText(item.Name), "enabled": protocol.GridBoolean(item.Enabled), "recordingEnabled": protocol.GridBoolean(item.RecordingEnabled), "encrypted": protocol.GridBoolean(item.Encrypted)}) {
			total++
			if managementGridKey(name, descending) > position {
				items = insertRead(items, managementGridKey(name, descending), item, request.Limit+1)
			}
		}
	}
	if err := reportManagementProgress(ctx, "finalizing", total, total); err != nil {
		return page, err
	}
	for i, item := range items {
		if i == request.Limit {
			page.Next = request.Next(items[i-1].value.Name, "")
			break
		}
		page.Items = append(page.Items, item.value)
	}
	return page, nil
}

func (this *service) managementRecordingPage(ctx context.Context, request protocol.ReadRequest, actor authorization.Authorization) (protocol.Page[protocol.RecordingSummary], error) {
	page := protocol.Page[protocol.RecordingSummary]{Items: make([]protocol.RecordingSummary, 0)}
	if actor == nil || !actor.IsAuthorized() || actor.FindSession() == nil || actor.FindSession().Flow() != actor.Flow() || !this.isManagementFlow(actor.Flow()) {
		return page, errManagementPolicy
	}
	if _, err := managementReadCeiling(actor, request); err != nil {
		return page, err
	}
	name := configuration.AuditlogName(request.Auditlog)
	repository := this.recordingRepositories[name]
	if repository == nil || repository.native == nil {
		return page, fmt.Errorf("no active recording repository")
	}
	var after protocol.RecordingPageCursor
	if request.After != "" {
		var err error
		after, err = request.RecordingCursor()
		if err != nil {
			return page, err
		}
		mac, err := repository.native.CatalogCursorMAC(after.Payload())
		provided, decodeErr := base64.RawURLEncoding.Strict().DecodeString(after.MAC)
		if err != nil || decodeErr != nil || !hmac.Equal(mac, provided) || after.ActorFlow != actor.Flow().String() || after.ActorSession != actor.FindSession().Id().String() || after.Expires <= time.Now().Unix() {
			return page, protocol.ErrRequest
		}
	}
	from, until, position := time.Time{}, time.Time{}, time.Time{}
	if request.StartedFrom != "" {
		from, _ = protocol.RecordingTime(request.StartedFrom)
	}
	if request.StartedUntil != "" {
		until, _ = protocol.RecordingTime(request.StartedUntil)
	}
	if after.ID != "" {
		position, _ = protocol.RecordingTime(after.StartedAt)
	}
	var selected []readSlot[recording.NativeRecordingSummary]
	var total int64
	filter := managementGridPredicate(request.GridFilter, request.Operation)
	ascending := request.Sort == "started-asc"
	err := repository.native.WalkMetadata(ctx, func(row recording.NativeRecordingSummary) error {
		// Older recordings lack the requesting user; target accounts remain
		// unknown. Encrypted private context never enters this index. Unknown
		// values cannot match concrete filters; never enrich from live sessions
		// or historical journals.
		if request.User != "" && request.User != row.User || request.Target != "" || request.Flow != "" && request.Flow != row.Flow || request.SessionID != "" && request.SessionID != row.SessionID ||
			request.Status != "all" && request.Status != string(row.Status) ||
			!from.IsZero() && row.StartedAt.Before(from) || !until.IsZero() && row.StartedAt.After(until) ||
			!managementSearch(request.Query, row.RecordingId.String(), row.User, row.Flow, string(row.Status)) {
			return nil
		}
		public := managementRecordingSummary(request.Auditlog, row)
		fields := map[string]protocol.GridValue{"id": protocol.GridText(row.RecordingId.String()), "status": protocol.GridText(string(row.Status)), "format": protocol.GridText(public.Format), "startedAt": protocol.GridTime(row.StartedAt), "endedAt": protocol.GridTime(row.EndedAt), "containerBytes": protocol.GridNumber(float64(row.Bytes)), "duration": protocol.GridNumber(max(0, row.EndedAt.Sub(row.StartedAt).Seconds())), "encrypted": protocol.GridBoolean(public.Encrypted)}
		if !public.MetadataUnavailable {
			if public.User != "" {
				fields["user"] = protocol.GridText(public.User)
			}
			fields["flow"] = protocol.GridText(public.Flow)
			fields["sessionId"] = protocol.GridText(public.SessionID)
		}
		if filter(fields) {
			total++
			if !position.IsZero() && ((!ascending && row.StartedAt.After(position)) || (ascending && row.StartedAt.Before(position)) || row.StartedAt.Equal(position) && row.RecordingId.String() <= after.ID) {
				return nil
			}
			key := managementGridKey(row.StartedAt.UTC().Format("2006-01-02T15:04:05.000000000Z"), !ascending) + row.RecordingId.String()
			selected = insertRead(selected, key, row, request.Limit+1)
		}
		return nil
	}, func(progress recording.NativeCatalogProgress) error {
		phase := progress.Phase
		if phase == "metadata" && (request.Query != "" || request.Flow != "" || request.SessionID != "" || request.User != "" || request.StartedFrom != "" || request.StartedUntil != "" || request.Status != "all" || request.GridFilter != nil) {
			phase = "searching"
		}
		return reportManagementProgress(ctx, phase, progress.Completed, progress.Total)
	})
	if err != nil {
		return page, fmt.Errorf("recording catalog metadata read failed: %w", err)
	}
	for index, slot := range selected {
		row := slot.value
		if err := reportManagementProgress(ctx, "reverifying", int64(index), int64(min(len(selected), request.Limit))); err != nil {
			return page, err
		}
		if err := ctx.Err(); err != nil {
			return page, fmt.Errorf("recording page reverification interrupted: %w", err)
		}
		if index == request.Limit {
			last := page.Items[len(page.Items)-1]
			cursor := protocol.RecordingPageCursor{Auditlog: request.Auditlog, Filter: request.RecordingFilter(),
				ActorFlow: actor.Flow().String(), ActorSession: actor.FindSession().Id().String(),
				StartedAt: last.StartedAt.Format(time.RFC3339Nano), ID: last.ID, Expires: time.Now().Add(5 * time.Minute).Unix()}
			mac, err := repository.native.CatalogCursorMAC(cursor.Payload())
			if err != nil {
				return page, err
			}
			cursor.MAC = base64.RawURLEncoding.EncodeToString(mac)
			page.Next = cursor.Token()
			break
		}
		// A cache entry is selection metadata, never authority to publish a row.
		remainingContainer, remainingCast := uint64(recording.MaximumNativeCatalogBytes), uint64(recording.MaximumNativeCatalogBytes)
		if row.Bytes > remainingContainer || row.CastBytes > remainingCast {
			return page, fmt.Errorf("recording page exceeds bounded reverification budget")
		}
		current, err := reverifyManagementRecording(ctx, repository.native, row, &remainingContainer, &remainingCast)
		if err != nil {
			return page, fmt.Errorf("recording page reverification failed for %s: %w", row.RecordingId.String(), err)
		}
		page.Items = append(page.Items, managementRecordingSummary(request.Auditlog, current))
	}
	if err := reportManagementProgress(ctx, "finalizing", total, total); err != nil {
		return page, err
	}
	return page, nil
}

// Called only inside the authenticated/policy-checked catalog path. Keeping the
// selected snapshot separate from actual open-file costs makes replacements and
// per-recording budget exhaustion fail before publication, never after extra decode.
func reverifyManagementRecording(ctx context.Context, repository *recording.LocalNativeRecordingRepository, selected recording.NativeRecordingSummary, remainingContainer, remainingCast *uint64) (recording.NativeRecordingSummary, error) {
	artifact, err := repository.OpenCatalogSealed(ctx, selected.RecordingId, recording.CatalogVerifyLimits{
		MaximumContainerBytes: *remainingContainer, MaximumCastBytes: *remainingCast,
	})
	if err != nil {
		return recording.NativeRecordingSummary{}, err
	}
	current := artifact.Summary()
	containerBytes, castVerificationBytes := uint64(artifact.Size()), artifact.VerificationCastBytes()
	if err := artifact.Close(); err != nil {
		return recording.NativeRecordingSummary{}, err
	}
	if current != selected {
		return recording.NativeRecordingSummary{}, fmt.Errorf("recording changed after catalog selection")
	}
	if containerBytes > *remainingContainer || castVerificationBytes > *remainingCast {
		return recording.NativeRecordingSummary{}, fmt.Errorf("recording page exceeds actual reverification budget")
	}
	*remainingContainer -= containerBytes
	*remainingCast -= castVerificationBytes
	return current, nil
}

func managementRecordingSummary(auditlog string, row recording.NativeRecordingSummary) protocol.RecordingSummary {
	encrypted := row.RecipientFingerprint != ""
	result := protocol.RecordingSummary{RecordingView: protocol.RecordingView{
		Auditlog: auditlog, ID: row.RecordingId.String(), ProducerID: row.ProducerId.String(),
		Format: "bcast/v1", Status: string(row.Status), StartedAt: row.StartedAt, EndedAt: row.EndedAt,
		ContainerBytes: int64(row.Bytes), ChunkCount: row.ChunkCount, Encrypted: encrypted,
		RecipientFingerprint: row.RecipientFingerprint, VerificationScope: "full",
	}}
	if encrypted {
		result.Format, result.VerificationScope, result.MetadataUnavailable = "becast-cbor/v1", "outer", true
	} else {
		result.Flow, result.SessionID, result.User = row.Flow, row.SessionID, row.User
		result.MetadataUnavailable = row.Flow == "" || row.SessionID == ""
	}
	return result
}
