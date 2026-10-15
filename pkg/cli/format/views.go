package format

import (
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/cli/model"
)

func WriteFlowList(output io.Writer, selected Format, entries []model.FlowSummary) error {
	rows := make([][]string, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, []string{entry.Name.String(), entry.Auditlog.String(), entry.Authorization, entry.Environment})
	}
	return WriteList(output, selected, []string{"NAME", "AUDITLOG", "AUTHORIZATION", "ENVIRONMENT"}, rows, entries)
}

func WriteSessionList(output io.Writer, selected Format, entries []model.SessionView) error {
	rows := make([][]string, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, []string{entry.ID, entry.Flow, entry.State, entry.User, entry.CreatedAt.Format(time.RFC3339)})
	}
	return WriteList(output, selected, []string{"ID", "FLOW", "STATE", "USER", "CREATED"}, rows, entries)
}

func WriteSessionDetail(output io.Writer, selected Format, entry model.SessionView) error {
	fields := []Field{{"ID", entry.ID}, {"Flow", entry.Flow}, {"State", entry.State}, {"User", entry.User}, {"Remote", entry.Remote}, {"Created", entry.CreatedAt.Format(time.RFC3339)}}
	if entry.LastAccessed != nil {
		fields = append(fields, Field{"Last accessed", entry.LastAccessed.Format(time.RFC3339)})
	}
	if entry.ValidUntil != nil {
		fields = append(fields, Field{"Valid until", entry.ValidUntil.Format(time.RFC3339)})
	}
	return WriteDetail(output, selected, fields, entry)
}

func WriteAuditlogList(output io.Writer, selected Format, entries []model.AuditlogSummary) error {
	rows := make([][]string, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, []string{entry.Name.String(), fmt.Sprint(entry.Enabled), fmt.Sprint(entry.RecordingEnabled), fmt.Sprint(entry.Encrypted)})
	}
	return WriteList(output, selected, []string{"NAME", "AUDIT", "RECORDING", "ENCRYPTED"}, rows, entries)
}

func WriteRecordingList(output io.Writer, selected Format, entries []model.RecordingView) error {
	sort.Slice(entries, func(i, j int) bool { return entries[i].StartedAt.Before(entries[j].StartedAt) })
	rows := make([][]string, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, []string{entry.ID, entry.Auditlog, entry.Status, entry.StartedAt.Format(time.RFC3339), entry.VerificationScope})
	}
	return WriteList(output, selected, []string{"ID", "AUDITLOG", "STATUS", "STARTED", "VERIFIED"}, rows, entries)
}

func WriteRecordingDetail(output io.Writer, selected Format, entry model.RecordingView) error {
	fields := []Field{
		{"ID", entry.ID}, {"Auditlog", entry.Auditlog}, {"Producer ID", entry.ProducerID},
		{"Format", entry.Format}, {"Status", entry.Status}, {"Started", entry.StartedAt.Format(time.RFC3339)},
		{"Ended", entry.EndedAt.Format(time.RFC3339)}, {"Encrypted", fmt.Sprint(entry.Encrypted)},
		{"Verification scope", entry.VerificationScope}, {"Container bytes", fmt.Sprint(entry.ContainerBytes)},
		{"Chunks", fmt.Sprint(entry.ChunkCount)},
	}
	if entry.RecipientFingerprint != "" {
		fields = append(fields, Field{"Recipient", entry.RecipientFingerprint})
	}
	return WriteDetail(output, selected, fields, entry)
}

type AuditEventFilter struct {
	Name  string
	Flow  string
	Since time.Time
	Until time.Time
	Limit int
}

func WriteAuditEvents(output io.Writer, selected Format, records []audit.VerifiedRecord, filter AuditEventFilter, sensitive bool) error {
	if filter.Flow != "" && !sensitive {
		return fmt.Errorf("filtering audit events by flow requires --with-sensitive")
	}
	if filter.Limit < 0 {
		return fmt.Errorf("audit event limit cannot be negative")
	}
	matching := make([]audit.VerifiedRecord, 0)
	for _, record := range records {
		if filter.Name != "" && record.Event.Name != filter.Name ||
			filter.Flow != "" && record.Event.Flow != filter.Flow ||
			!filter.Since.IsZero() && record.RecordedAt.Before(filter.Since) ||
			!filter.Until.IsZero() && record.RecordedAt.After(filter.Until) {
			continue
		}
		matching = append(matching, record)
	}
	if filter.Limit > 0 && len(matching) > filter.Limit {
		matching = matching[len(matching)-filter.Limit:]
	}
	rows := make([][]string, 0, len(matching))
	for _, record := range matching {
		rows = append(rows, []string{record.RecordedAt.Format(time.RFC3339), record.Event.Name, string(record.Event.Domain), string(record.Event.Outcome), record.Id.String()})
	}
	if selected == Text && sensitive {
		for index := range rows {
			rows[index] = append(rows[index], matching[index].Event.Flow)
		}
		return WriteList(output, selected, []string{"RECORDED", "NAME", "DOMAIN", "OUTCOME", "ID", "FLOW"}, rows, matching)
	}
	return WriteList(output, selected, []string{"RECORDED", "NAME", "DOMAIN", "OUTCOME", "ID"}, rows, matching)
}
