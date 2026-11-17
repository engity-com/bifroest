package service

import (
	"errors"
	"io/fs"
	"net/http"
	"strconv"
	"time"

	"github.com/engity-com/bifroest/pkg/https"
	"github.com/engity-com/bifroest/pkg/webui"
)

func (this *webService) admitAsset(w http.ResponseWriter, r *http.Request) (func(), bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		webError(w, 405, "GET or HEAD required")
		return nil, false
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		webError(w, 400, "asset request body forbidden")
		return nil, false
	}
	peer, err := webPeer(r)
	if err != nil {
		webError(w, 400, "invalid direct peer")
		return nil, false
	}
	release, ok := this.admit(peer, false)
	if !ok {
		w.Header().Set("Retry-After", "60")
		webError(w, 429, "web request limit reached")
		return nil, false
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(20 * time.Second))
	return release, true
}

func (this *webService) serveAsset(w http.ResponseWriter, r *http.Request) {
	if this.assets == nil {
		http.NotFound(w, r)
		return
	}
	release, ok := this.admitAsset(w, r)
	if !ok {
		return
	}
	defer release()
	data, contentType, err := this.assets.Resource(r.URL.Path)
	if errors.Is(err, fs.ErrNotExist) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		webError(w, 503, "public asset unavailable")
		return
	}
	w.Header().Set("Content-Type", contentType)
	if r.URL.Path == webui.KeyWorkerPath || r.URL.Path == webui.TransferWorkerPath || r.URL.Path == webui.EvidenceWorkerPath {
		w.Header().Set("Content-Security-Policy", https.BrowserWasmWorkerPolicy)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

func (this *webService) serveDocument(w http.ResponseWriter, r *http.Request) bool {
	if this.assets == nil {
		return false
	}
	data, nonce, err := this.assets.Document()
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		webError(w, 503, "browser document unavailable")
		return true
	}
	policy, err := https.DocumentPolicy(nonce)
	if err != nil {
		webError(w, 503, "browser document unavailable")
		return true
	}
	w.Header().Set("Content-Security-Policy", policy)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
	return true
}
