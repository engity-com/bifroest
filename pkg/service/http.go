package service

import (
	stdcrypto "crypto"
	"fmt"
	"net/http"

	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/https"
	"github.com/engity-com/bifroest/pkg/webui"
)

func (this *service) prepareHTTPS() error {
	if !this.Configuration.Http.IsEnabled() {
		return nil
	}
	// Audit best-effort policy must not waive transport key safety.
	for _, auditlog := range this.Configuration.Auditlogs {
		recipients, err := audit.ResolveEncryptionPublicKey(auditlog.EncryptionPublicKey, auditlog.EncryptionPublicKeyFile)
		if err != nil {
			return fmt.Errorf("cannot verify configured audit recipient separation for HTTPS")
		}
		if err := recipients.ForEach(func(_ int, key gossh.PublicKey, _ string) (bool, error) {
			public, err := crypto.PublicKeyFromSsh(key)
			if err != nil {
				return false, err
			}
			this.httpsForbiddenKeys = append(this.httpsForbiddenKeys, public)
			return true, nil
		}); err != nil {
			return fmt.Errorf("cannot inspect audit recipient identities for HTTPS")
		}
	}
	conf := this.Configuration.Http
	if conf.WebUi.IsEnabled() || conf.LoginFlow.IsEnabled() {
		this.web = newWebService(this)
		assets, err := webui.New(conf)
		if err != nil {
			return fmt.Errorf("cannot prepare public browser assets: %w", err)
		}
		this.web.assets = assets
	}
	if conf.SshTunnel.IsEnabled() {
		this.sshTunnel = newSshTunnel()
		this.sshTunnel.logger = this.logger()
	}
	endpoint, err := https.NewEndpoint(conf, https.EndpointOptions{ValidateKey: this.validateHTTPSKey, Handler: http.HandlerFunc(this.serveHTTPS)})
	if err != nil {
		return fmt.Errorf("cannot prepare HTTPS endpoint: %w", err)
	}
	this.https = endpoint
	if this.Configuration.Http.Tls.Dummy {
		this.logger().With("domains", this.Configuration.Http.Domains).
			Warn("http.tls.dummy=true: created an ephemeral self-signed HTTPS dummy certificate for testing only; browsers do not trust it, certificate expires in 24 hours")
	}
	return nil
}

func (this *service) serveHTTPS(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == https.SshTunnelPath {
		if this.sshTunnel != nil {
			this.sshTunnel.ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
		return
	}
	if this.web != nil {
		this.web.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

func (this *service) validateHTTPSKey(key stdcrypto.PublicKey) error {
	public, err := crypto.PublicKeyFromSdk(key)
	if err != nil {
		return fmt.Errorf("cannot inspect HTTPS key identity")
	}
	for _, other := range this.httpsForbiddenKeys {
		if public.IsEqualTo(other) {
			return fmt.Errorf("HTTPS/ACME key must be distinct from SSH, audit signing, SFTP and audit encryption keys")
		}
	}
	return nil
}
