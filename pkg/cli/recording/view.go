package recording

import (
	"context"
	"fmt"
	"io"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/cli/model"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/recording"
)

type RecordingView = model.RecordingView

type RecordingSource func(context.Context, string, configuration.AuditlogName) ([]RecordingView, error)
type RecordingDetailSource func(context.Context, string, configuration.AuditlogName, recording.Id) (RecordingView, error)

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
