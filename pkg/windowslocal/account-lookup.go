package windowslocal

import (
	"context"
	"strings"

	"github.com/engity-com/bifroest/pkg/errors"
)

var (
	ErrAccountNotModeled        = errors.Config.Newf("account lookup was not modeled")
	ErrAccountLookupUnavailable = errors.System.Newf("account lookup is unavailable")
)

// IdentityLookup is a read-only identity boundary. A known absent account
// returns ErrNotFound, never nil success. Missing observations are a separate
// error. It does not expose a native Account object or password-policy evidence.
type IdentityLookup interface {
	LookupIdentityByName(context.Context, string) (string, string, error)
	LookupIdentityBySID(context.Context, string) (string, string, error)
}

// AccountLookupFacts declares supplied existing accounts and selector-specific
// absences. Names are case-insensitive; SID selectors must already use their
// fixture-validated canonical spelling. No native SID/hostname query is made.
type AccountLookupFacts struct {
	Accounts    []*AccountSnapshot
	AbsentNames []string
	AbsentSIDs  []string
}

// MemoryLookup owns immutable observations without native account, token,
// profile, process or authentication capabilities. Empty inventories mean
// nothing is modeled, not that every account is absent.
type MemoryLookup struct {
	byName map[string]*AccountSnapshot
	bySID  map[string]*AccountSnapshot
}

func NewMemoryLookup(facts AccountLookupFacts) (*MemoryLookup, error) {
	result := &MemoryLookup{byName: make(map[string]*AccountSnapshot), bySID: make(map[string]*AccountSnapshot)}
	for _, account := range facts.Accounts {
		if account == nil || account.identity.Name == "" || account.identity.SID == "" {
			return nil, ErrInvalidAccountFacts
		}
		name, sid := account.Identity()
		name = strings.ToLower(name)
		if _, present := result.byName[name]; present {
			return nil, ErrInvalidAccountFacts
		}
		if _, present := result.bySID[sid]; present {
			return nil, ErrInvalidAccountFacts
		}
		copyOfAccount := *account
		result.byName[name], result.bySID[sid] = &copyOfAccount, &copyOfAccount
	}
	for _, name := range facts.AbsentNames {
		if !validAccountFactIdentity(name) {
			return nil, ErrInvalidAccountFacts
		}
		name = strings.ToLower(name)
		if _, present := result.byName[name]; present {
			return nil, ErrInvalidAccountFacts
		}
		result.byName[name] = nil
	}
	for _, sid := range facts.AbsentSIDs {
		if !validAccountFactIdentity(sid) {
			return nil, ErrInvalidAccountFacts
		}
		if _, present := result.bySID[sid]; present {
			return nil, ErrInvalidAccountFacts
		}
		result.bySID[sid] = nil
	}
	return result, nil
}

func (this *MemoryLookup) LookupByName(ctx context.Context, name string) (*AccountSnapshot, error) {
	if err := this.check(ctx); err != nil {
		return nil, err
	}
	account, modeled := this.byName[strings.ToLower(name)]
	return memoryLookupResult(ctx, account, modeled)
}

func (this *MemoryLookup) LookupBySID(ctx context.Context, sid string) (*AccountSnapshot, error) {
	if err := this.check(ctx); err != nil {
		return nil, err
	}
	account, modeled := this.bySID[sid]
	return memoryLookupResult(ctx, account, modeled)
}

func (this *MemoryLookup) LookupIdentityByName(ctx context.Context, name string) (string, string, error) {
	account, err := this.LookupByName(ctx, name)
	if err != nil {
		return "", "", err
	}
	name, sid := account.Identity()
	return name, sid, nil
}

func (this *MemoryLookup) LookupIdentityBySID(ctx context.Context, sid string) (string, string, error) {
	account, err := this.LookupBySID(ctx, sid)
	if err != nil {
		return "", "", err
	}
	name, sid := account.Identity()
	return name, sid, nil
}

func (this *MemoryLookup) check(ctx context.Context) error {
	if ctx == nil || this == nil || this.byName == nil || this.bySID == nil {
		return ErrAccountLookupUnavailable
	}
	if err := ctx.Err(); err != nil {
		return errors.System.Newf("%w", err)
	}
	return nil
}

func memoryLookupResult(ctx context.Context, account *AccountSnapshot, modeled bool) (*AccountSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.System.Newf("%w", err)
	}
	if !modeled {
		return nil, ErrAccountNotModeled
	}
	if account == nil {
		return nil, ErrNotFound
	}
	copyOfAccount := *account
	return &copyOfAccount, nil
}
