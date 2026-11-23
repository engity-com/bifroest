//go:build unix

package user

import (
	"context"

	"github.com/engity-com/bifroest/pkg/errors"
)

var (
	ErrAccountNotModeled        = errors.Config.Newf("account lookup was not modeled")
	ErrAccountLookupUnavailable = errors.System.Newf("account lookup is unavailable")
)

// IdentityLookup is a read-only boundary for target selection. A known absent
// account returns ErrNoSuchUser. Missing facts are an error, not absence. Names
// and numeric IDs come from the lookup result, never from inferred defaults.
type IdentityLookup interface {
	LookupIdentityByName(context.Context, string) (string, Id, error)
	LookupIdentityById(context.Context, Id) (string, Id, error)
}

// AccountLookupFacts declares only modeled observations. Existing snapshots
// bind both selectors; absence is selector-specific and implies nothing about
// another unmodeled name or ID. Contradictory/duplicate selectors are rejected.
type AccountLookupFacts struct {
	Accounts    []*Snapshot
	AbsentNames []string
	AbsentIds   []Id
}

// MemoryLookup owns immutable observations. It has no repository, native
// lookup, authentication, ensure, delete or process-management capability.
// There is no fallback for unknown keys, including in an empty inventory.
type MemoryLookup struct {
	byName map[string]*Snapshot
	byId   map[Id]*Snapshot
}

func NewMemoryLookup(facts AccountLookupFacts) (*MemoryLookup, error) {
	result := &MemoryLookup{byName: make(map[string]*Snapshot), byId: make(map[Id]*Snapshot)}
	for _, account := range facts.Accounts {
		if account == nil || account.known == nil {
			return nil, ErrInvalidAccountFacts
		}
		name, id := account.Identity()
		if _, present := result.byName[name]; present {
			return nil, ErrInvalidAccountFacts
		}
		if _, present := result.byId[id]; present {
			return nil, ErrInvalidAccountFacts
		}
		// Copy the outer value too: the caller can overwrite an exported
		// snapshot through its pointer, even though all its fields are private.
		copyOfAccount := *account
		result.byName[name], result.byId[id] = &copyOfAccount, &copyOfAccount
	}
	for _, name := range facts.AbsentNames {
		if !validSnapshotIdentity(name) {
			return nil, ErrInvalidAccountFacts
		}
		if _, present := result.byName[name]; present {
			return nil, ErrInvalidAccountFacts
		}
		result.byName[name] = nil
	}
	for _, id := range facts.AbsentIds {
		if _, present := result.byId[id]; present {
			return nil, ErrInvalidAccountFacts
		}
		result.byId[id] = nil
	}
	return result, nil
}

func (this *MemoryLookup) LookupByName(ctx context.Context, name string) (*Snapshot, error) {
	if err := this.check(ctx); err != nil {
		return nil, err
	}
	account, modeled := this.byName[name]
	return memoryLookupResult(ctx, account, modeled)
}

func (this *MemoryLookup) LookupById(ctx context.Context, id Id) (*Snapshot, error) {
	if err := this.check(ctx); err != nil {
		return nil, err
	}
	account, modeled := this.byId[id]
	return memoryLookupResult(ctx, account, modeled)
}

func (this *MemoryLookup) LookupIdentityByName(ctx context.Context, name string) (string, Id, error) {
	account, err := this.LookupByName(ctx, name)
	if err != nil {
		return "", 0, err
	}
	name, id := account.Identity()
	return name, id, nil
}

func (this *MemoryLookup) LookupIdentityById(ctx context.Context, id Id) (string, Id, error) {
	account, err := this.LookupById(ctx, id)
	if err != nil {
		return "", 0, err
	}
	name, id := account.Identity()
	return name, id, nil
}

func (this *MemoryLookup) check(ctx context.Context) error {
	if ctx == nil || this == nil || this.byName == nil || this.byId == nil {
		return ErrAccountLookupUnavailable
	}
	if err := ctx.Err(); err != nil {
		return errors.System.Newf("%w", err)
	}
	return nil
}

func memoryLookupResult(ctx context.Context, account *Snapshot, modeled bool) (*Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.System.Newf("%w", err)
	}
	if !modeled {
		return nil, ErrAccountNotModeled
	}
	if account == nil {
		return nil, ErrNoSuchUser
	}
	copyOfAccount := *account
	return &copyOfAccount, nil
}
