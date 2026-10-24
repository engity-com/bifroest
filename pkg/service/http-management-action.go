package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/netip"
	"time"

	bconn "github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/management/protocol"
)

const webManagementConfirmationLifetime = time.Minute
const webManagementMaximumConfirmations = 64
const webManagementMaximumConfirmationsPerPeer = 4

type webManagementConfirmation struct {
	access     *webAccess
	peer       netip.Addr
	request    protocol.SessionAction
	pin        [32]byte
	expires    time.Time
	claiming   bool
	connection bconn.Id
}

func managementConfirmationKey(value string) ([32]byte, bool) {
	if len(value) != 48 || value[:5] != "bmc1." {
		return [32]byte{}, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value[5:])
	if err != nil || len(raw) != 32 {
		return [32]byte{}, false
	}
	return sha256.Sum256([]byte(value)), true
}

func (this *webService) handleManagementAction(w http.ResponseWriter, r *http.Request, scope webScope, values map[string]string) {
	access, err := this.lookup(scope, webBearer(r), false)
	if err != nil {
		webError(w, 401, "web access denied")
		return
	}
	if !this.service.isManagementFlow(access.auth.Flow()) || managementActionPolicy(access.auth) != nil {
		webError(w, 403, "management action denied")
		return
	}
	peer, err := webPeer(r)
	if err != nil {
		webError(w, 400, "invalid direct peer")
		return
	}
	if r.URL.Path == webAPI+"management/sessions/prepare" {
		request := protocol.SessionAction{Action: values["action"], Flow: values["flow"], ID: values["id"]}
		if len(values) != 4 || request.Validate() != nil {
			webError(w, 400, "invalid session action request")
			return
		}
		conn, transport, err := this.managementConnection(w, r, scope, access)
		if err != nil {
			webError(w, 403, "management connection denied")
			return
		}
		defer func() { _ = conn.Close(); <-conn.done }()
		_, target, pin, err := this.service.managementActionTarget(conn.Lifetime(), access.auth.FindSession(), request)
		if err != nil {
			webError(w, 403, "management target is unavailable or self-protected")
			return
		}
		// Preparation is a real, audited/recorded read, not a side-effect commit.
		data, err := this.service.executeManagementRead(conn, protocol.ReadRequest{Operation: protocol.ShowSession, Flow: request.Flow, ID: request.ID})
		if err != nil {
			webError(w, 503, "management preparation could not be confirmed")
			return
		}
		var read protocol.ReadResult
		if json.Unmarshal(data, &read) != nil || read.Session == nil || !read.Session.CreatedAt.Equal(target.CreatedAt) {
			webError(w, 503, "management target changed during preparation")
			return
		}
		_, target, after, err := this.service.managementActionTarget(conn.Lifetime(), access.auth.FindSession(), request)
		if err != nil || after != pin {
			webError(w, 403, "management target changed during preparation")
			return
		}
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			webError(w, 503, "management confirmation unavailable")
			return
		}
		token := "bmc1." + base64.RawURLEncoding.EncodeToString(nonce[:])
		index, _ := managementConfirmationKey(token)
		expires := minDeadline(time.Now().Add(webManagementConfirmationLifetime), access.expires)
		encoded, err := json.Marshal(protocol.ActionPreparation{Version: 1, Status: "confirmation-required", ConfirmationToken: token, ExpiresAt: expires, Action: request.Action, Target: target})
		if err != nil {
			webError(w, 503, "management confirmation could not be encoded")
			return
		}
		permission := &webManagementConfirmation{access: access, peer: peer, request: request, pin: pin, expires: expires}
		this.mutex.Lock()
		this.pruneLocked(time.Now())
		count := 0
		for _, entry := range this.confirmations {
			if entry.peer == peer {
				count++
			}
		}
		access.mutex.Lock()
		closed := access.closed
		access.mutex.Unlock()
		_, collision := this.confirmations[index]
		if this.ctx.Err() != nil || conn.IsClosed() || closed || !time.Now().Before(expires) || len(this.confirmations) >= webManagementMaximumConfirmations || count >= webManagementMaximumConfirmationsPerPeer || collision {
			this.mutex.Unlock()
			webError(w, 429, "management confirmation limit reached")
			return
		}
		this.confirmations[index] = permission
		this.mutex.Unlock()
		this.deliverManagement(w, conn, transport, encoded, 202)
		return
	}
	if len(values) != 2 {
		webError(w, 400, "only slug and confirmationToken are accepted")
		return
	}
	index, ok := managementConfirmationKey(values["confirmationToken"])
	if !ok {
		webError(w, 403, "management confirmation denied")
		return
	}
	this.mutex.Lock()
	permission := this.confirmations[index]
	if permission == nil || permission.access != access || permission.peer != peer || permission.claiming || !time.Now().Before(permission.expires) {
		this.mutex.Unlock()
		webError(w, 403, "management confirmation denied")
		return
	}
	if r.URL.Path == webAPI+"management/sessions/cancel" {
		delete(this.confirmations, index)
		this.mutex.Unlock()
		w.WriteHeader(204)
		return
	}
	permission.claiming = true // Consume before registration/IO/any possible effect.
	this.mutex.Unlock()
	defer func() { this.mutex.Lock(); delete(this.confirmations, index); this.mutex.Unlock() }()
	conn, transport, err := this.managementConnection(w, r, scope, access)
	if err != nil {
		webError(w, 403, "management connection denied")
		return
	}
	defer func() { _ = conn.Close(); <-conn.done }()
	permission.connection = conn.Id()
	data, err := this.service.executeManagementAction(conn, permission)
	if err != nil {
		webError(w, 503, "management action result could not be confirmed")
		return
	}
	this.deliverManagement(w, conn, transport, data, 200)
}

func minDeadline(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (this *webService) managementConnection(w http.ResponseWriter, r *http.Request, scope webScope, access *webAccess) (*terminalConnection, *managementHTTPConnection, error) {
	base, err := newWebLoginConnection(r.Context(), r, scope, access.user)
	if err != nil {
		return nil, nil, err
	}
	transport := &managementHTTPConnection{webLoginConnection: base, controller: http.NewResponseController(w)}
	conn, err := this.connect(scope, webBearer(r), transport)
	if err != nil {
		_ = transport.Close()
		return nil, nil, err
	}
	return conn, transport, nil
}
