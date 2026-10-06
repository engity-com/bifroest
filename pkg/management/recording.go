package management

import (
	"context"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/recording"
)

type RecordingView struct {
	Auditlog             string    `json:"auditlog" yaml:"auditlog"`
	ID                   string    `json:"id" yaml:"id"`
	ProducerID           string    `json:"producerId" yaml:"producerId"`
	Format               string    `json:"format" yaml:"format"`
	Status               string    `json:"status" yaml:"status"`
	StartedAt            time.Time `json:"startedAt" yaml:"startedAt"`
	EndedAt              time.Time `json:"endedAt" yaml:"endedAt"`
	ContainerBytes       int64     `json:"containerBytes" yaml:"containerBytes"`
	ChunkCount           uint64    `json:"chunkCount" yaml:"chunkCount"`
	Encrypted            bool      `json:"encrypted" yaml:"encrypted"`
	RecipientFingerprint string    `json:"recipientFingerprint,omitempty" yaml:"recipientFingerprint,omitempty"`
	VerificationScope    string    `json:"verificationScope" yaml:"verificationScope"`
}

type RecordingSource func(context.Context, string, configuration.AuditlogName) ([]RecordingView, error)

func RegisterRecordingCommands(parent *kingpin.CmdClause, source RecordingSource, ctx context.Context, output io.Writer, local bool) {
	register := func(command *kingpin.CmdClause, action func(string, Format) error) {
		var path, format string
		formats := []string{"table", "json", "yaml"}
		if !local {
			formats = append(formats, "cbor")
		}
		command.Flag("format", "Display as a table/list, JSON, or YAML.").Default("table").EnumVar(&format, formats...)
		if local {
			command.Flag("configuration", "Bifröst configuration file.").Short('c').StringVar(&path)
		}
		command.Action(func(*kingpin.ParseContext) error { return action(path, Format(format)) })
	}
	var listAuditlog configuration.AuditlogName
	list := parent.Command("ls", "List sealed Recordings in one auditlog.")
	list.Arg("auditlog", "Configured auditlog name.").Required().SetValue(&listAuditlog)
	register(list, func(path string, format Format) error {
		entries, err := source(ctx, path, listAuditlog)
		if err != nil {
			return err
		}
		return WriteRecordingList(output, format, entries)
	})
	var showAuditlog configuration.AuditlogName
	var rawID string
	show := parent.Command("show", "Show verified metadata of one sealed Recording.")
	show.Arg("auditlog", "Configured auditlog name.").Required().SetValue(&showAuditlog)
	show.Arg("id", "Recording UUID.").Required().StringVar(&rawID)
	register(show, func(path string, format Format) error {
		var id recording.Id
		if err := id.UnmarshalText([]byte(rawID)); err != nil {
			return err
		}
		entries, err := source(ctx, path, showAuditlog)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.ID == id.String() {
				return WriteRecordingDetail(output, format, entry)
			}
		}
		return fmt.Errorf("recording %s does not exist in auditlog %q", id, showAuditlog)
	})
}

func InspectRecording(ctx context.Context, auditlog configuration.AuditlogName, source io.ReaderAt, size int64, expected audit.ProducerId) (RecordingView, error) {
	inspection, err := recording.Inspect(source, size, recording.InspectOptions{Context: ctx, ExpectedProducerId: expected})
	if err != nil {
		return RecordingView{}, err
	}
	if inspection.Native == nil {
		return RecordingView{}, fmt.Errorf("managed recording is not a signed native artifact")
	}
	start, err := inspection.Native.Header.StartedAt.Time()
	if err != nil {
		return RecordingView{}, err
	}
	end, err := inspection.Native.Seal.EndedAt.Time()
	if err != nil {
		return RecordingView{}, err
	}
	status := ""
	switch inspection.Native.Seal.Status {
	case 1:
		status = "completed"
	case 2:
		status = "failed"
	case 3:
		status = "incomplete"
	}
	view := RecordingView{
		Auditlog: auditlog.String(), ID: recording.Id(inspection.Native.Header.RecordingId).String(),
		ProducerID: audit.ProducerId(inspection.Native.Header.ProducerId).String(),
		Format:     string(inspection.Format), Status: status,
		StartedAt: start, EndedAt: end, ContainerBytes: size,
		ChunkCount:           inspection.Native.Seal.ChunkCount,
		Encrypted:            inspection.Native.Header.Encryption != 0,
		RecipientFingerprint: inspection.Native.Header.Recipient,
		VerificationScope:    "full",
	}
	if view.Encrypted {
		view.VerificationScope = "outer"
	}
	return view, nil
}

func WriteRecordingList(output io.Writer, format Format, entries []RecordingView) error {
	sort.Slice(entries, func(i, j int) bool { return entries[i].StartedAt.Before(entries[j].StartedAt) })
	rows := make([][]string, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, []string{entry.ID, entry.Auditlog, entry.Status, entry.StartedAt.Format(time.RFC3339), entry.VerificationScope})
	}
	return WriteList(output, format, []string{"ID", "AUDITLOG", "STATUS", "STARTED", "VERIFIED"}, rows, entries)
}

func WriteRecordingDetail(output io.Writer, format Format, entry RecordingView) error {
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
	return WriteDetail(output, format, fields, entry)
}
