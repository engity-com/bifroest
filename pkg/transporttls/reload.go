package transporttls

import (
	"context"
	"fmt"
	"time"
)

func (this *TLS) HasFileCertificates() bool { return len(this.files) != 0 }

// RunFileReload watches only explicit files. ACME maintenance is caller-driven
// through RenewDue and is never triggered by this loop.
func (this *TLS) RunFileReload(ctx context.Context, onFailure func(error)) error {
	this.mutex.RLock()
	closed, prepared := this.closed, this.ready
	this.mutex.RUnlock()
	if closed {
		return ErrClosed
	}
	if !prepared {
		return ErrNotReady
	}
	select {
	case this.reloading <- struct{}{}:
		defer func() { <-this.reloading }()
	default:
		return fmt.Errorf("TLS file reload loop is already running")
	}
	var timer *time.Timer
	var wake <-chan time.Time
	if this.HasFileCertificates() {
		timer = time.NewTimer(this.reloadInterval)
		defer timer.Stop()
		wake = timer.C
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-this.lifetime.Done():
			return ErrClosed
		case <-wake:
		}
		if err := this.ReloadFiles(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if this.lifetime.Err() != nil {
				return ErrClosed
			}
			if onFailure != nil {
				onFailure(err)
			}
		}
		timer.Reset(this.reloadInterval)
	}
}

// ReloadFiles publishes a complete validated snapshot. No file I/O is performed
// by handshakes, and a bad rotation never replaces still-valid live material.
func (this *TLS) ReloadFiles(ctx context.Context) error {
	if len(this.files) == 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-this.lifetime.Done():
		return ErrClosed
	case this.preparing <- struct{}{}:
		defer func() { <-this.preparing }()
	}
	if this.validateFiles != nil {
		if err := this.validateFiles(); err != nil {
			return fmt.Errorf("TLS certificate path safety check failed (details redacted)")
		}
	}
	next := make(map[string]*preparedCertificate)
	for index, configured := range this.files {
		if err := ctx.Err(); err != nil {
			return err
		}
		certificate, err := loadCertificate(configured, this.now())
		if err != nil {
			return fmt.Errorf("cannot reload TLS certificate [%d]: %w", index, err)
		}
		if this.validateKey != nil {
			if err := this.validateKey(certificate.value.Leaf.PublicKey); err != nil {
				return err
			}
		}
		matched := false
		for _, domain := range this.domains {
			if certificateMatches(certificate.value, domain) {
				matched = true
				if next[domain] == nil {
					next[domain] = certificate
				}
			}
		}
		if !matched {
			return fmt.Errorf("reloaded TLS certificate [%d] covers no configured domain", index)
		}
	}
	if this.validateFiles != nil {
		if err := this.validateFiles(); err != nil {
			return fmt.Errorf("TLS certificate path safety check failed (details redacted)")
		}
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	if this.closed {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for domain := range this.explicit {
		if next[domain] == nil {
			return fmt.Errorf("reloaded TLS certificates no longer cover a configured file-backed domain")
		}
	}
	for _, certificate := range next {
		if !certificate.validAt(this.now()) {
			return fmt.Errorf("reloaded TLS certificate expired before publication")
		}
	}
	live := make(map[string]*preparedCertificate, len(this.certificates))
	for domain, certificate := range this.certificates {
		live[domain] = certificate
	}
	for domain, certificate := range next {
		live[domain] = certificate
	}
	this.explicit, this.certificates = next, live
	return nil
}
