package service

import (
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management/protocol"
)

func managementReadRequest(path string, values map[string]string) (protocol.ReadRequest, error) {
	request := protocol.ReadRequest{After: values["after"], Flow: values["flow"], User: values["user"], State: values["state"], ID: values["id"], Auditlog: values["auditlog"]}
	switch path {
	case webAPI + "management/version/show":
		request.Operation = protocol.ShowVersion
		request.VersionDetail = "long"
		if value, present := values["long"]; present {
			switch value {
			case "true":
			case "false":
				request.VersionDetail = "short"
			default:
				return request, protocol.ErrRequest
			}
		}
	case webAPI + "management/flows/list":
		request.Operation = protocol.ListFlows
	case webAPI + "management/sessions/list":
		request.Operation = protocol.ListSessions
	case webAPI + "management/sessions/show":
		request.Operation = protocol.ShowSession
	case webAPI + "management/auditlogs/list":
		request.Operation = protocol.ListAuditlogs
	case webAPI + "management/recordings/list":
		request.Operation = protocol.ListRecordings
	default:
		return request, protocol.ErrRequest
	}
	if value, present := values["limit"]; present {
		number, err := strconv.Atoi(value)
		if err != nil || number < 1 || strconv.Itoa(number) != value {
			return request, protocol.ErrRequest
		}
		request.Limit = number
	}
	request, err := request.Normalize()
	if err != nil {
		return request, err
	}
	if request.Flow != "" {
		if err := configuration.FlowName(request.Flow).Validate(); err != nil {
			return request, protocol.ErrRequest
		}
	}
	return request, nil
}

func (this *webService) handleManagement(w http.ResponseWriter, r *http.Request, scope webScope, values map[string]string) {
	if r.URL.Path == webAPI+"management/artifacts/recording" || r.URL.Path == webAPI+"management/artifacts/audit" {
		this.handleManagementArtifact(w, r, scope, values)
		return
	}
	if r.URL.Path == webAPI+"management/sessions/prepare" || r.URL.Path == webAPI+"management/sessions/confirm" || r.URL.Path == webAPI+"management/sessions/cancel" {
		this.handleManagementAction(w, r, scope, values)
		return
	}
	request, err := managementReadRequest(r.URL.Path, values)
	if err != nil {
		webError(w, http.StatusBadRequest, "invalid structured management request")
		return
	}
	access, err := this.lookup(scope, webBearer(r), false)
	if err != nil {
		webError(w, http.StatusUnauthorized, "web access denied")
		return
	}
	_, policyErr := managementReadCeiling(access.auth, request)
	if !this.service.isManagementFlow(access.auth.Flow()) || policyErr != nil {
		webError(w, http.StatusForbidden, "structured management is not available for this authorization")
		return
	}
	conn, transport, err := this.managementConnection(w, r, scope, access)
	if err != nil {
		webError(w, http.StatusForbidden, "management connection denied")
		return
	}
	defer func() { _ = conn.Close(); <-conn.done }()
	data, err := this.service.executeManagementRead(conn, request)
	if err != nil {
		webError(w, http.StatusServiceUnavailable, "management operation could not be confirmed")
		return
	}
	this.deliverManagement(w, conn, transport, data, 200)
}

func (this *webService) deliverManagement(w http.ResponseWriter, conn *terminalConnection, transport *managementHTTPConnection, data []byte, status int) {
	if conn.IsClosed() || conn.Lifetime().Err() != nil || conn.check(false) != nil {
		webError(w, http.StatusForbidden, "management access ended")
		return
	}
	transport.writing.Store(true)
	if conn.IsClosed() || conn.Lifetime().Err() != nil {
		transport.writing.Store(false)
		webError(w, http.StatusForbidden, "management access ended")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("X-Bifroest-Connection-Id", conn.Id().String())
	w.WriteHeader(status)
	if _, err := w.Write(data); err == nil {
		_ = transport.controller.Flush()
	}
	// Go may still finish its HTTP framing after handler return. A normal lease
	// close must not expire that write deadline; only concurrent revocation while
	// actively writing/flush-blocked interrupts the response.
	transport.writing.Store(false)
}

type managementHTTPConnection struct {
	*webLoginConnection
	controller *http.ResponseController
	writing    atomic.Bool
}

func (this *managementHTTPConnection) Close() error {
	// Normal operation ends only after response delivery. Revocation/cancel must
	// also unblock a slow HTTP/1 or HTTP/2 response, not just cancel Go work.
	if this.webLoginConnection.IsClosed() {
		return this.webLoginConnection.Close()
	}
	if this.writing.Load() {
		_ = this.controller.SetWriteDeadline(time.Now())
	}
	return this.webLoginConnection.Close()
}
