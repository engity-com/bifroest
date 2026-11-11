package service

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/management/wire"
	"github.com/engity-com/bifroest/pkg/recording"
)

const webRecordingSourceMediaType = "application/vnd.bifroest.recording-source.v1"
const webRecordingSourceFileBytes int64 = 64 << 20
const webRecordingSourceImageBytes int64 = 72 << 20

type managementArtifactLimitKey struct{}

type webRecordingSourceGate struct {
	mutex    sync.Mutex
	ctx      context.Context
	next     chan struct{}
	expected uint64
	waiting  bool
}

func (g *webRecordingSourceGate) ready(index uint64) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.expected, g.waiting = index, true
}
func (g *webRecordingSourceGate) advance(index uint64) bool {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if !g.waiting || g.expected != index {
		return false
	}
	select {
	case g.next <- struct{}{}:
		g.waiting = false
		return true
	default:
		return false
	}
}
func (g *webRecordingSourceGate) wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-g.next:
		return ctx.Err()
	}
}

// One explicit source request borrows its already admitted actor. Individual
// files still use the ordinary authorization/task/audit/transfer driver, including
// post-driver completion. A one-file credit window bounds memory and work.
func (s *webService) handleManagementRecordingSource(w http.ResponseWriter, r *http.Request, scope webScope, values map[string]string) {
	output, ok := w.(*webManagementResponse)
	channel, bound := r.Context().Value(webManagementContextKey{}).(*webManagementChannel)
	if !ok || !bound || output.channel != channel || len(values) != 2 || !protocol.ValidAuditlogName(values["auditlog"]) {
		webError(w, http.StatusBadRequest, "source transfer requires an admitted management channel")
		return
	}
	access, err := s.managementAccess(r, scope)
	if err != nil {
		webError(w, http.StatusUnauthorized, "web access denied")
		return
	}
	if !s.service.isManagementFlow(access.auth.Flow()) || !s.service.managementArtifactAllowed(access.auth) {
		webError(w, http.StatusForbidden, "artifact transfer denied")
		return
	}
	repository := s.service.recordingRepositories[configuration.AuditlogName(values["auditlog"])]
	if repository == nil || repository.native == nil {
		webError(w, http.StatusServiceUnavailable, "recording source unavailable")
		return
	}
	gate := &webRecordingSourceGate{next: make(chan struct{}, 1), ctx: r.Context()}
	channel.mutex.Lock()
	if channel.sources == nil {
		channel.sources = make(map[string]*webRecordingSourceGate)
	}
	channel.sources[output.id] = gate
	channel.mutex.Unlock()
	var started bool
	var count, total int64
	err = repository.native.WalkMetadata(r.Context(), func(row recording.NativeRecordingSummary) error {
		id := row.RecordingId
		if !started || count >= total || channel.conn.check(false) != nil {
			return errWebAccessDenied
		}
		if err := gate.wait(r.Context()); err != nil {
			return err
		}
		if channel.conn.check(false) != nil {
			return errWebAccessDenied
		}
		ctx := context.WithValue(r.Context(), managementArtifactLimitKey{}, webRecordingSourceFileBytes)
		request := r.Clone(ctx)
		request.URL.Path = webAPI + "management/artifacts/recording"
		request.URL.RawPath = ""
		entry := &webRecordingSourceEntry{parent: output, header: make(http.Header), recordingID: id.String(), index: count + 1, recipient: row.RecipientFingerprint}
		if !s.serveManagementArtifact(entry, request, scope, map[string]string{"slug": scope.Slug, "auditlog": values["auditlog"], "id": id.String()}) || entry.status != 200 || entry.failed || r.Context().Err() != nil {
			if r.Context().Err() == nil {
				status := entry.status
				if status < 400 {
					status = http.StatusServiceUnavailable
				}
				_ = channel.stream.status(struct {
					Type      string `json:"type"`
					RequestID string `json:"requestId"`
					Status    int    `json:"status"`
				}{"source-failed", output.id, status})
			}
			return fmt.Errorf("recording source entry did not complete")
		}
		count++
		if count < total {
			gate.ready(uint64(count + 1))
		}
		return channel.stream.status(struct {
			Type      string `json:"type"`
			RequestID string `json:"requestId"`
			Index     int64  `json:"index"`
		}{"source-entry-complete", output.id, count})
	}, func(value recording.NativeCatalogProgress) error {
		if r.Context().Err() != nil || channel.conn.check(false) != nil {
			return errWebAccessDenied
		}
		if !started && value.Total >= 0 {
			total, started = value.Total, true
			if total > 0 {
				gate.ready(1)
			}
			w.Header().Set("Content-Type", webRecordingSourceMediaType)
			w.WriteHeader(200)
			return channel.stream.status(struct {
				Type      string `json:"type"`
				RequestID string `json:"requestId"`
				Source    string `json:"source"`
				Total     int64  `json:"total"`
			}{"source-start", output.id, values["auditlog"], total})
		}
		if !started {
			return output.ManagementProgress(managementReadProgress{Phase: value.Phase, Completed: value.Completed, Total: value.Total})
		}
		return nil
	})
	if err != nil || !started || count != total {
		output.cancel()
	}
}

type webRecordingSourceEntry struct {
	parent      *webManagementResponse
	header      http.Header
	recordingID string
	recipient   string
	index       int64
	status      int
	failed      bool
	written     int64
}

func (w *webRecordingSourceEntry) Header() http.Header { return w.header }
func (w *webRecordingSourceEntry) WriteHeader(code int) {
	if w.status != 0 {
		return
	}
	w.status = code
	if code != 200 || w.header.Get("Content-Type") != wire.TransferMediaType {
		w.failed = true
		return
	}
	if err := w.parent.channel.stream.status(struct {
		Type        string `json:"type"`
		RequestID   string `json:"requestId"`
		Index       int64  `json:"index"`
		RecordingID string `json:"recordingId"`
		Status      int    `json:"status"`
		ContentType string `json:"contentType"`
		Encrypted   bool   `json:"encrypted"`
		Recipient   string `json:"recipient"`
	}{"source-entry", w.parent.id, w.index, w.recordingID, code, wire.TransferMediaType, w.recipient != "", w.recipient}); err != nil {
		w.failed = true
		w.parent.cancel()
	}
}
func (w *webRecordingSourceEntry) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	if w.failed || int64(len(data)) > webRecordingSourceImageBytes-w.written {
		w.failed = true
		return 0, wire.ErrArtifactLimit
	}
	n, err := w.parent.Write(data)
	w.written += int64(n)
	if err != nil {
		w.failed = true
	}
	return n, err
}
func (w *webRecordingSourceEntry) FlushError() error {
	if w.failed {
		return fmt.Errorf("source entry failed")
	}
	return w.parent.FlushError()
}
func (w *webRecordingSourceEntry) SetReadDeadline(time.Time) error { return nil }
func (w *webRecordingSourceEntry) SetWriteDeadline(t time.Time) error {
	return w.parent.SetWriteDeadline(t)
}
