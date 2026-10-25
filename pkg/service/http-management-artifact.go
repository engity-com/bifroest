package service

import (
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/management/wire"
)

func managementArtifactRequest(path string, values map[string]string) (protocol.ArtifactRequest, error) {
	request := protocol.ArtifactRequest{Auditlog: values["auditlog"], ID: values["id"]}
	switch path {
	case webAPI + "management/artifacts/recording":
		request.Operation = protocol.DownloadRecording
		if len(values) != 3 {
			return request, protocol.ErrRequest
		}
	case webAPI + "management/artifacts/audit":
		request.Operation = protocol.DownloadAudit
		if len(values) != 2 {
			return request, protocol.ErrRequest
		}
	default:
		return request, protocol.ErrRequest
	}
	return request, request.Validate()
}

func (this *webService) handleManagementArtifact(w http.ResponseWriter, r *http.Request, scope webScope, values map[string]string) {
	request, err := managementArtifactRequest(r.URL.Path, values)
	if err != nil {
		webError(w, 400, "invalid artifact request")
		return
	}
	access, err := this.lookup(scope, webBearer(r), false)
	if err != nil {
		webError(w, 401, "web access denied")
		return
	}
	if !this.service.managementArtifactAllowed(access.auth) {
		webError(w, 403, "artifact transfer denied")
		return
	}
	conn, transport, err := this.managementConnection(w, r, scope, access)
	if err != nil {
		webError(w, 403, "management connection denied")
		return
	}
	defer func() { transport.writing.Store(false); _ = conn.Close(); <-conn.done }()
	output := &managementArtifactHTTPWriter{writer: w, conn: conn, transport: transport}
	framed, err := wire.NewTransferWriter(output, request)
	if err != nil {
		webError(w, 400, "invalid artifact request")
		return
	}
	status, err := this.service.executeManagementArtifact(conn, request, framed, func() error {
		if err := framed.EndData(); err != nil {
			return err
		}
		return transport.controller.Flush()
	})
	if err == nil && status == 0 && conn.check(false) == nil && !conn.IsClosed() && conn.Lifetime().Err() == nil {
		err = framed.Complete()
		if err == nil {
			_ = transport.controller.Flush()
		}
		return
	}
	// An already-started binary response fails by missing its final completion,
	// never by an appended private error, optimistic success or automatic retry.
	if !output.started.Load() {
		webError(w, 503, "artifact operation could not be confirmed")
	}
}

type managementArtifactHTTPWriter struct {
	writer    http.ResponseWriter
	conn      *terminalConnection
	transport *managementHTTPConnection
	started   atomic.Bool
}

func (this *managementArtifactHTTPWriter) Write(data []byte) (int, error) {
	if this.conn.IsClosed() || this.conn.Lifetime().Err() != nil {
		return 0, fmt.Errorf("artifact access ended")
	}
	if !this.started.Load() {
		this.transport.writing.Store(true)
		if this.conn.IsClosed() || this.conn.Lifetime().Err() != nil {
			return 0, fmt.Errorf("artifact access ended")
		}
		this.started.Store(true)
		this.writer.Header().Set("Content-Type", wire.TransferMediaType)
		this.writer.Header().Set("X-Bifroest-Connection-Id", this.conn.Id().String())
		this.writer.WriteHeader(200)
	}
	return this.writer.Write(data)
}
