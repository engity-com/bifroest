package session

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/browserauth"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

const MaximumBrowserBindings = 16

var (
	ErrInvalidBrowserBinding = errors.New("invalid persisted browser binding")
	ErrBrowserBindingDenied  = errors.New("browser binding unavailable, expired or changed")
	ErrBrowserBindingLimit   = errors.New("browser binding limit reached")
)

// BrowserBindingSpec is immutable. These are verified server-side selectors,
// not authorization from a client. Flow/session are the containing session.
type BrowserBindingSpec struct {
	Origin     string                           `json:"origin"`
	Slug       string                           `json:"slug"`
	Identity   authentication.Identity          `json:"identity"`
	Target     Target                           `json:"target"`
	User       string                           `json:"user"`
	PublicKey  browserauth.PublicKey            `json:"publicKey"`
	Credential authentication.SessionCredential `json:"credential,omitzero"`
}

type BrowserBinding struct {
	BrowserBindingSpec
	ID         string    `json:"id"`
	Revision   uint64    `json:"revision"`
	CreatedAt  time.Time `json:"createdAt"`
	LastUsedAt time.Time `json:"lastUsedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// BrowserBindingSession is optional. Implementations do not add SSH remembered
// keys, allocate leases, renew session access, or dispose/close anything. A
// trusted caller must verify fresh possession AND current authorization/target
// before creating/using a binding. This storage API is not authentication.
type BrowserBindingSession interface {
	BrowserBindings(context.Context) ([]BrowserBinding, error)
	CreateBrowserBinding(context.Context, BrowserBindingSpec, time.Duration) (BrowserBinding, error)
	// Check validates eligibility without renewing it or advancing the revision.
	// An observed shorter-policy expiry is persisted, preventing later revival.
	CheckBrowserBinding(context.Context, string, uint64, time.Duration) (BrowserBinding, error)
	UseBrowserBinding(context.Context, string, uint64, time.Duration) (BrowserBinding, error)
	RevokeBrowserBinding(context.Context, string) error
}

func (this BrowserBindingSpec) Validate() error {
	parsed, err := url.Parse(this.Origin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" {
		return ErrInvalidBrowserBinding
	}
	host, err := bnet.CanonicalHttpHost(parsed.Host)
	if err != nil {
		return ErrInvalidBrowserBinding
	}
	authority := host
	if port := parsed.Port(); port != "" {
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 || number == 443 {
			return ErrInvalidBrowserBinding
		}
		authority += ":" + strconv.FormatUint(number, 10)
	}
	if this.Origin != "https://"+authority || len(this.Origin) > 320 || bnet.ValidateHttpSlug(this.Slug) != nil {
		return ErrInvalidBrowserBinding
	}
	if this.Identity.Validate() != nil || this.Target.Validate() != nil || len(this.User) > 256 || !utf8.ValidString(this.User) || strings.ContainsFunc(this.User, unicode.IsControl) {
		return ErrInvalidBrowserBinding
	}
	if _, err := this.PublicKey.Parse(); err != nil {
		return ErrInvalidBrowserBinding
	}
	// Foundation-era records without primary provenance remain inspectable and
	// revocable, but cannot authorize browser resumption or invent a method.
	if !this.Credential.IsZero() && this.Credential.Validate() != nil {
		return ErrInvalidBrowserBinding
	}
	return nil
}

func validBrowserBindingID(id string) bool {
	if len(id) != len("bbr1.")+43 || !strings.HasPrefix(id, "bbr1.") {
		return false
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(id[5:])
	return err == nil && len(value) == 32 && base64.RawURLEncoding.EncodeToString(value) == id[5:]
}

func (this BrowserBinding) Validate() error {
	if this.BrowserBindingSpec.Validate() != nil || !validBrowserBindingID(this.ID) || this.Revision == 0 {
		return ErrInvalidBrowserBinding
	}
	if this.CreatedAt.IsZero() || this.CreatedAt.After(this.LastUsedAt) || !this.ExpiresAt.After(this.LastUsedAt) || this.ExpiresAt.Year() > 9999 {
		return ErrInvalidBrowserBinding
	}
	return nil
}

func (this BrowserBinding) EffectiveExpiry(idle time.Duration) time.Time {
	result := this.LastUsedAt.Add(idle)
	if this.ExpiresAt.Before(result) {
		result = this.ExpiresAt
	}
	return result
}

func validateBrowserIdle(idle time.Duration) error {
	if idle <= 0 {
		return fmt.Errorf("browser binding idle timeout must be positive")
	}
	return nil
}
