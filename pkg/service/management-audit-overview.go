package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/recording"
)

func managementLongRead(path string) bool {
	switch path {
	case webAPI + "management/auditlogs/list", webAPI + "management/recordings/list", webAPI + "management/audit-events/list", webAPI + "management/recordings/verify", webAPI + "management/artifacts/recording", webAPI + "management/artifacts/audit":
		return true
	}
	return false
}

func (this *service) managementAuditCursorMAC(data []byte) ([]byte, error) {
	this.managementCursorOnce.Do(func() { _, this.managementCursorErr = rand.Read(this.managementCursorKey[:]) })
	if this.managementCursorErr != nil {
		return nil, this.managementCursorErr
	}
	mac := hmac.New(sha256.New, this.managementCursorKey[:])
	_, _ = mac.Write([]byte("bifroest.management.audit-events/v1\x00"))
	_, _ = mac.Write(data)
	return mac.Sum(nil), nil
}
func overviewKey(at time.Time, sequence, index uint64, descending bool) string {
	return managementGridKey(at.UTC().Format("2006-01-02T15:04:05.000000000Z"), descending) + fmt.Sprintf("%020d/%020d", sequence, index)
}

func (this *service) managementAuditEventPage(ctx context.Context, request protocol.ReadRequest, actor authorization.Authorization) (page protocol.Page[protocol.AuditEventSummary], source protocol.AuditEventSource, resultErr error) {
	page.Items = make([]protocol.AuditEventSummary, 0)
	if actor == nil || !actor.IsAuthorized() || actor.FindSession() == nil || !this.managementArtifactAllowed(actor) {
		return page, source, errManagementPolicy
	}
	name := configuration.AuditlogName(request.Auditlog)
	identity := this.auditIdentities[name]
	if identity == nil {
		return page, source, fmt.Errorf("audit overview source has no active identity")
	}
	var journal audit.JournalSource
	for _, conf := range this.Configuration.Auditlogs {
		if conf.Name == name {
			key, err := audit.ResolveEncryptionPublicKey(conf.EncryptionPublicKey, conf.EncryptionPublicKeyFile)
			if err != nil {
				return page, source, err
			}
			recipient, err := audit.EncryptionRecipientFingerprint(key)
			if err != nil {
				return page, source, err
			}
			journal = audit.JournalSource{Name: request.Auditlog, Directory: conf.Directory, ExpectedProducerId: identity.ProducerId(), ExpectedEncryptionRecipient: recipient}
			break
		}
	}
	if journal.Directory == "" {
		return page, source, protocol.ErrRequest
	}
	if journal.ExpectedEncryptionRecipient != "" && request.Sensitive {
		return page, source, fmt.Errorf("encrypted private audit fields require local decryption")
	}
	source = protocol.AuditEventSource{Auditlog: request.Auditlog, Encrypted: journal.ExpectedEncryptionRecipient != "", Sensitive: request.Sensitive, Verification: "server-overview"}
	var cursor protocol.AuditEventPageCursor
	position := ""
	if request.After != "" {
		var err error
		cursor, err = request.AuditEventCursor()
		if err != nil {
			return page, source, err
		}
		mac, err := this.managementAuditCursorMAC(cursor.Payload())
		provided, decodeErr := base64.RawURLEncoding.Strict().DecodeString(cursor.MAC)
		if err != nil || decodeErr != nil || !hmac.Equal(mac, provided) || cursor.ActorFlow != actor.Flow().String() || cursor.ActorSession != actor.FindSession().Id().String() || cursor.Expires <= time.Now().Unix() {
			return page, source, protocol.ErrRequest
		}
		at, _ := protocol.RecordingTime(cursor.RecordedAt)
		position = overviewKey(at, cursor.Sequence, cursor.Index, request.Sort != "recorded-asc")
	}
	this.auditOverviewOnce.Do(func() {
		roots := make([]string, 0, len(this.Configuration.Auditlogs))
		for _, conf := range this.Configuration.Auditlogs {
			roots = append(roots, conf.Directory)
		}
		this.auditOverview = audit.NewOverviewReader(roots...)
	})
	var selected []readSlot[audit.OverviewRecord]
	defer func() {
		for _, slot := range selected {
			resultErr = errors.Join(resultErr, slot.value.Release())
		}
	}()
	filter := managementGridPredicate(request.GridFilter, request.Operation)
	var total int64
	err := this.auditOverview.Walk(ctx, journal, func(row audit.OverviewRecord) error {
		if request.ID != "" && row.ID != request.ID {
			return nil
		}
		fields := map[string]protocol.GridValue{"id": protocol.GridText(row.ID), "name": protocol.GridText(row.Name), "domain": protocol.GridText(row.Domain), "outcome": protocol.GridText(row.Outcome), "recordedAt": protocol.GridTime(row.RecordedAt)}
		contextEvent := audit.Event{}
		if request.Flow != "" || request.Sensitive {
			if source.Encrypted {
				return nil
			}
			var err error
			contextEvent, err = row.MetadataContext(ctx)
			if err != nil {
				return err
			}
			if request.Flow != "" && (request.Flow == "-" && contextEvent.Flow != "" || request.Flow != "-" && request.Flow != contextEvent.Flow) {
				return nil
			}
		}
		if request.Sensitive {
			fields["flow"], fields["reason"], fields["sessionId"] = protocol.GridText(contextEvent.Flow), protocol.GridText(contextEvent.Reason), protocol.GridText(contextEvent.SessionId)
		}
		// Exact URI scope is explicit selection intent, not an implicit private
		// export. Other predicates cannot treat redacted/unknown fields as empty.
		if request.Flow != "" && request.GridFilter != nil && request.GridFilter.Field == "flow" && (request.GridFilter.Operator == "equals" && request.GridFilter.Value == request.Flow || request.Flow == "-" && request.GridFilter.Operator == "isEmpty") {
			fields["flow"] = protocol.GridText(contextEvent.Flow)
		}
		search := []string{row.ID, row.Name, row.Domain, row.Outcome}
		if request.Sensitive {
			search = append(search, contextEvent.Flow, contextEvent.Reason, contextEvent.SessionId)
		}
		if !filter(fields) || !managementSearch(request.Query, search...) {
			return nil
		}
		total++
		key := overviewKey(row.RecordedAt, row.Sequence, row.Index, request.Sort != "recorded-asc")
		if key <= position {
			return nil
		}
		index := sort.Search(len(selected), func(index int) bool { return selected[index].key >= key })
		maximum := request.Limit + 1
		if index >= maximum {
			return nil
		}
		if err := row.Retain(); err != nil {
			return err
		}
		var dropped *audit.OverviewRecord
		if len(selected) == maximum {
			copy := selected[maximum-1].value
			dropped = &copy
		}
		selected = insertRead(selected, key, row, maximum)
		if dropped != nil {
			return dropped.Release()
		}
		return nil
	}, func(count int64) error {
		phase := "metadata"
		if request.Query != "" || request.GridFilter != nil || request.Flow != "" || request.Sensitive {
			phase = "searching"
		}
		return reportManagementProgress(ctx, phase, count, -1)
	})
	if err != nil {
		return page, source, err
	}
	if request.ID != "" && total > 1 {
		return page, source, fmt.Errorf("audit event ID is ambiguous in the requested scope")
	}
	for index, slot := range selected {
		row := slot.value
		if index == request.Limit {
			last := selected[index-1].value
			c := protocol.AuditEventPageCursor{Auditlog: request.Auditlog, Filter: request.AuditEventFilter(), ActorFlow: actor.Flow().String(), ActorSession: actor.FindSession().Id().String(), RecordedAt: last.RecordedAt.Format(time.RFC3339Nano), Sequence: last.Sequence, Index: last.Index, ID: last.ID, Expires: time.Now().Add(5 * time.Minute).Unix()}
			mac, err := this.managementAuditCursorMAC(c.Payload())
			if err != nil {
				return page, source, err
			}
			c.MAC = base64.RawURLEncoding.EncodeToString(mac)
			page.Next = c.Token()
			break
		}
		if err := ctx.Err(); err != nil {
			return page, source, err
		}
		event, err := row.ReadRecord(ctx, request.Sensitive)
		if err != nil {
			return page, source, err
		}
		if request.ID == "" {
			event = audit.Event{Name: event.Name, Domain: event.Domain, Outcome: event.Outcome, Flow: event.Flow, SessionId: event.SessionId, Reason: event.Reason}
		}
		raw, err := json.Marshal(event)
		if err != nil {
			return page, source, err
		}
		var body map[string]any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&body); err != nil {
			return page, source, err
		}
		for field, value := range body {
			if number, ok := value.(json.Number); ok {
				integer, err := number.Int64()
				if err != nil || integer > 1<<53-1 || integer < -(1<<53-1) {
					body[field] = number.String()
				}
			}
		}
		page.Items = append(page.Items, protocol.AuditEventSummary{Key: fmt.Sprintf("%d:%d:%s", row.Sequence, row.Index, row.ID), ID: row.ID, RecordedAt: row.RecordedAt, Event: body})
	}
	if err := reportManagementProgress(ctx, "finalizing", total, total); err != nil {
		return page, source, err
	}
	return page, source, nil
}

func (this *service) managementVerifyRecordings(ctx context.Context, request protocol.ReadRequest) (protocol.CatalogVerification, error) {
	result := protocol.CatalogVerification{Auditlog: request.Auditlog}
	repository := this.recordingRepositories[configuration.AuditlogName(request.Auditlog)]
	if repository == nil || repository.native == nil {
		return result, fmt.Errorf("no active recording source")
	}
	err := repository.native.VerifyCatalog(ctx, func(row recording.NativeRecordingSummary) error {
		result.Checked++
		if row.RecipientFingerprint == "" {
			result.Full++
		} else {
			result.Outer++
		}
		return nil
	}, func(progress recording.NativeCatalogProgress) error {
		return reportManagementProgress(ctx, progress.Phase, progress.Completed, progress.Total)
	})
	if err != nil {
		return protocol.CatalogVerification{}, err
	}
	return result, nil
}
