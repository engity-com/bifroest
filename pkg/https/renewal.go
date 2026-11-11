package https

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/acme"
)

type RenewableCertificateSource interface {
	CertificateSource
	Renew(context.Context, string, Challenge) (*tls.Certificate, error)
}

func certificateRenewalAt(certificate *preparedCertificate) time.Time {
	before := min(certificate.notAfter.Sub(certificate.notBefore)/3, 30*24*time.Hour)
	return certificate.notAfter.Add(-before)
}

// RenewDue refreshes only ACME-managed domains whose renewal date has arrived.
// Updates are persisted by the source before replacing the live snapshot. A
// failed renewal keeps the old certificate until its normal validity expires.
func (this *TLS) RenewDue(ctx context.Context) error {
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, this.startupTimeout)
	stopClose := context.AfterFunc(this.lifetime, cancel)
	defer stopClose()
	defer cancel()
	select {
	case <-this.lifetime.Done():
		return ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	case this.preparing <- struct{}{}:
		defer func() { <-this.preparing }()
	}
	this.mutex.RLock()
	closed, ready := this.closed, this.ready
	this.mutex.RUnlock()
	if closed {
		return ErrClosed
	}
	if !ready {
		return ErrNotReady
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var failures []error
	for _, domain := range this.domains {
		if this.explicit[domain] != nil {
			continue
		}
		this.mutex.RLock()
		if this.closed {
			this.mutex.RUnlock()
			return ErrClosed
		}
		previous, retry := this.certificates[domain], this.renewRetry[domain]
		this.mutex.RUnlock()
		if certificateRenewalAt(previous).After(this.now()) || retry.After(this.now()) {
			continue
		}
		source, ok := this.source.(RenewableCertificateSource)
		if !ok {
			return fmt.Errorf("TLS certificate source does not support renewal")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		this.mutex.Lock()
		if this.closed {
			this.mutex.Unlock()
			return ErrClosed
		}
		this.activeDomain = domain
		this.mutex.Unlock()
		candidate, err := source.Renew(ctx, domain, func(proof *tls.Certificate) (func(), error) { return this.installChallenge(ctx, domain, proof) })
		this.mutex.Lock()
		this.activeDomain = ""
		delete(this.challenges, domain)
		this.mutex.Unlock()
		if ctx.Err() != nil {
			if parent.Err() != nil {
				return parent.Err()
			}
			if this.lifetime.Err() != nil {
				return ErrClosed
			}
			err = ctx.Err()
		}
		var checked *preparedCertificate
		if err == nil {
			checked, err = validateCertificate(candidate, this.now())
		}
		if err == nil && !certificateMatches(checked.value, domain) {
			err = fmt.Errorf("renewed TLS certificate does not cover its configured domain")
		}
		if err == nil && this.validateKey != nil {
			err = this.validateKey(checked.value.Leaf.PublicKey)
		}
		if err == nil && !certificateRenewalAt(checked).After(this.now()) {
			err = fmt.Errorf("renewed TLS certificate already requires renewal")
		}
		this.mutex.Lock()
		if this.closed {
			this.mutex.Unlock()
			return ErrClosed
		}
		if parent.Err() != nil {
			this.mutex.Unlock()
			return parent.Err()
		}
		if this.lifetime.Err() != nil {
			this.mutex.Unlock()
			return ErrClosed
		}
		if err == nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err == nil {
			this.certificates[domain] = checked
			delete(this.renewRetry, domain)
		} else {
			delay := 30 * time.Minute
			var problem *acme.Error
			if errors.As(err, &problem) {
				if retry, limited := acme.RateLimit(problem); limited && retry > delay {
					delay = retry
				}
			}
			this.renewRetry[domain] = this.now().Add(delay)
			failures = append(failures, fmt.Errorf("cannot renew TLS certificate for %q: %w", domain, err))
		}
		this.mutex.Unlock()
		if ctx.Err() != nil {
			return errors.Join(failures...)
		}
	}
	return errors.Join(append(failures, ctx.Err())...)
}

// RunRenewal is a blocking, caller-owned renewal loop. It starts no detached
// work, honors shutdown, and applies per-domain backoff (including Retry-After).
// onFailure receives log-safe errors; it must return promptly.
func (this *TLS) RunRenewal(ctx context.Context, onFailure func(error)) error {
	if _, renewable := this.source.(RenewableCertificateSource); !renewable {
		for _, domain := range this.domains {
			if this.explicit[domain] == nil {
				return fmt.Errorf("TLS certificate source does not support renewal")
			}
		}
	}
	select {
	case this.renewing <- struct{}{}:
		defer func() { <-this.renewing }()
	default:
		return fmt.Errorf("TLS renewal loop is already running")
	}
	for {
		this.mutex.RLock()
		if this.closed {
			this.mutex.RUnlock()
			return ErrClosed
		}
		if !this.ready {
			this.mutex.RUnlock()
			return ErrNotReady
		}
		var next time.Time
		for domain, certificate := range this.certificates {
			if this.explicit[domain] != nil {
				continue
			}
			candidate := certificateRenewalAt(certificate)
			if retry := this.renewRetry[domain]; retry.After(candidate) {
				candidate = retry
			}
			if next.IsZero() || candidate.Before(next) {
				next = candidate
			}
		}
		this.mutex.RUnlock()
		var wake <-chan time.Time
		var timer *time.Timer
		if !next.IsZero() {
			timer = time.NewTimer(max(0, next.Sub(this.now())))
			wake = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return ctx.Err()
		case <-this.lifetime.Done():
			if timer != nil {
				timer.Stop()
			}
			return ErrClosed
		case <-wake:
		}
		if err := this.RenewDue(ctx); err != nil {
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
	}
}
