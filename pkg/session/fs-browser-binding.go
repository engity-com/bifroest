package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"os"
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
)

const browserBindingsSchema = "bifroest-browser-bindings-v1"
const maximumBrowserBindingsBytes = 128 << 10

// Presence alone protects damaged state from automatic destructive repair. An
// unreadable or malformed file is evidence to inspect, not permission to erase.
func (this *FsRepository) persistentSessionProtection(flow configuration.FlowName, id Id) error {
	for _, marker := range []struct {
		name    string
		problem error
	}{{FsFileAssociation, ErrInvalidAssociation}, {FsFileBrowserBindings, ErrInvalidBrowserBinding}} {
		path, err := this.file(flow, id, marker.name)
		if err != nil {
			return err
		}
		if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
			return marker.problem
		}
	}
	return nil
}

type browserBindingsFile struct {
	Schema    string           `json:"schema"`
	Flow      string           `json:"flow"`
	SessionID string           `json:"sessionId"`
	Bindings  []BrowserBinding `json:"bindings"`
}

func (this *fs) BrowserBindings(ctx context.Context) ([]BrowserBinding, error) {
	this.repository.mutex.RLock()
	defer this.repository.mutex.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := this.repository.findBy(ctx, this.flow, this.id, nil, false); err != nil {
		return nil, err
	}
	bindings, err := this.readBrowserBindings()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return bindings, err
}

func (this *fs) CreateBrowserBinding(ctx context.Context, spec BrowserBindingSpec, idle time.Duration) (BrowserBinding, error) {
	return this.createBrowserBinding(ctx, spec, idle, time.Time{})
}

func (this *fs) createBrowserBinding(ctx context.Context, spec BrowserBindingSpec, idle time.Duration, now time.Time) (BrowserBinding, error) {
	if err := spec.Validate(); err != nil {
		return BrowserBinding{}, err
	}
	if err := validateBrowserIdle(idle); err != nil {
		return BrowserBinding{}, err
	}
	this.repository.mutex.Lock()
	defer this.repository.mutex.Unlock()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := this.checkBrowserBindingSession(ctx, now, true); err != nil {
		return BrowserBinding{}, err
	}
	if err := this.checkBrowserBindingOwner(spec); err != nil {
		return BrowserBinding{}, err
	}
	bindings, err := this.readBrowserBindings()
	if err != nil {
		return BrowserBinding{}, err
	}
	retained := make([]BrowserBinding, 0, len(bindings)+1)
	for _, binding := range bindings {
		if now.Before(binding.EffectiveExpiry(idle)) {
			retained = append(retained, binding)
		}
	}
	if len(retained) >= MaximumBrowserBindings {
		return BrowserBinding{}, ErrBrowserBindingLimit
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return BrowserBinding{}, err
	}
	binding := BrowserBinding{BrowserBindingSpec: spec, ID: "bbr1." + base64.RawURLEncoding.EncodeToString(nonce[:]), Revision: 1, CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(idle)}
	for _, previous := range bindings {
		if previous.ID == binding.ID {
			return BrowserBinding{}, ErrBrowserBindingDenied
		}
	}
	retained = append(retained, binding)
	if err := this.writeBrowserBindings(ctx, retained); err != nil {
		return BrowserBinding{}, err
	}
	return binding, nil
}

func (this *fs) UseBrowserBinding(ctx context.Context, id string, revision uint64, idle time.Duration) (BrowserBinding, error) {
	return this.useBrowserBinding(ctx, id, revision, idle, time.Time{})
}

func (this *fs) CheckBrowserBinding(ctx context.Context, id string, revision uint64, idle time.Duration) (BrowserBinding, error) {
	return this.checkOrUseBrowserBinding(ctx, id, revision, idle, time.Time{}, false)
}

func (this *fs) useBrowserBinding(ctx context.Context, id string, revision uint64, idle time.Duration, now time.Time) (BrowserBinding, error) {
	return this.checkOrUseBrowserBinding(ctx, id, revision, idle, now, true)
}

func (this *fs) checkOrUseBrowserBinding(ctx context.Context, id string, revision uint64, idle time.Duration, now time.Time, use bool) (BrowserBinding, error) {
	if !validBrowserBindingID(id) || revision == 0 {
		return BrowserBinding{}, ErrBrowserBindingDenied
	}
	if err := validateBrowserIdle(idle); err != nil {
		return BrowserBinding{}, err
	}
	this.repository.mutex.Lock()
	defer this.repository.mutex.Unlock()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := this.checkBrowserBindingSession(ctx, now, true); err != nil {
		return BrowserBinding{}, err
	}
	bindings, err := this.readBrowserBindings()
	if err != nil {
		return BrowserBinding{}, err
	}
	for index, binding := range bindings {
		if binding.ID != id {
			continue
		}
		if binding.Revision != revision || revision == math.MaxUint64 || now.Before(binding.LastUsedAt) {
			return BrowserBinding{}, ErrBrowserBindingDenied
		}
		if err := this.checkBrowserBindingOwner(binding.BrowserBindingSpec); err != nil {
			return BrowserBinding{}, err
		}
		expiry := binding.EffectiveExpiry(idle)
		if !now.Before(expiry) {
			// Remember an observed shorter-policy expiry. A later configuration
			// increase must not revive this already rejected permission.
			if expiry.Before(binding.ExpiresAt) {
				binding.ExpiresAt = expiry
				bindings[index] = binding
				if err := this.writeBrowserBindings(ctx, bindings); err != nil {
					return BrowserBinding{}, err
				}
			}
			return BrowserBinding{}, ErrBrowserBindingDenied
		}
		if !use {
			return binding, nil
		}
		binding.LastUsedAt = now
		binding.ExpiresAt = now.Add(idle)
		binding.Revision++
		bindings[index] = binding
		if err := this.writeBrowserBindings(ctx, bindings); err != nil {
			return BrowserBinding{}, err
		}
		return binding, nil
	}
	return BrowserBinding{}, ErrBrowserBindingDenied
}

func (this *fs) RevokeBrowserBinding(ctx context.Context, id string) error {
	if !validBrowserBindingID(id) {
		return ErrBrowserBindingDenied
	}
	this.repository.mutex.Lock()
	defer this.repository.mutex.Unlock()
	// Logout may remove an expired binding, even after session expiry/disposal.
	// It never changes session state or stops other connections/bindings itself.
	if err := this.checkBrowserBindingSession(ctx, time.Now(), false); err != nil {
		return err
	}
	bindings, err := this.readBrowserBindings()
	if err != nil {
		return err
	}
	for index, binding := range bindings {
		if binding.ID == id {
			return this.writeBrowserBindings(ctx, append(bindings[:index], bindings[index+1:]...))
		}
	}
	return nil // Idempotent revocation cannot create or revive a binding.
}

// All helpers below require the repository lock. No authorizer or callback runs
// under it, and no user-provided data can escape the containing flow/session path.
func (this *fs) checkBrowserBindingSession(ctx context.Context, now time.Time, requireValid bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateFsRepositoryProcessLock(this.repository.processLock, this.repository.processLockPath()); err != nil {
		return err
	}
	current, err := this.repository.findBy(ctx, this.flow, this.id, nil, false)
	if err != nil {
		return err
	}
	if !requireValid {
		return nil
	}
	if current.info.VState == StateDisposed {
		return ErrBrowserBindingDenied
	}
	until, err := current.info.validUntilLocked()
	if err != nil {
		return err
	}
	if !until.IsZero() && !now.Before(until) {
		return ErrBrowserBindingDenied
	}
	return nil
}

func (this *fs) checkBrowserBindingOwner(spec BrowserBindingSpec) error {
	association, err := this.repository.readAssociation(this.flow, this.id)
	if err != nil {
		return err
	}
	if association != nil && (!association.SameSubject(spec.Identity) || association.Target != spec.Target) {
		return ErrBrowserBindingDenied
	}
	return nil
}

func (this *fs) readBrowserBindings() ([]BrowserBinding, error) {
	path, err := this.repository.file(this.flow, this.id, FsFileBrowserBindings)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, ErrInvalidBrowserBinding
	}
	raw, err := crypto.ReadSecurePrivateFile(path, maximumBrowserBindingsBytes)
	if err != nil {
		return nil, ErrInvalidBrowserBinding
	}
	return decodeBrowserBindings(raw, this.flow.String(), this.id.String())
}

func (this *fs) writeBrowserBindings(ctx context.Context, bindings []BrowserBinding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(bindings) > MaximumBrowserBindings {
		return ErrBrowserBindingLimit
	}
	if bindings == nil {
		bindings = []BrowserBinding{}
	}
	for _, binding := range bindings {
		if err := binding.Validate(); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(browserBindingsFile{browserBindingsSchema, this.flow.String(), this.id.String(), bindings})
	if err != nil || len(raw) > maximumBrowserBindingsBytes {
		return ErrInvalidBrowserBinding
	}
	path, err := this.repository.file(this.flow, this.id, FsFileBrowserBindings)
	if err != nil {
		return err
	}
	return writeFsPrivateFileAtomically(path, raw, os.FileMode(this.repository.dirFileMode()))
}
