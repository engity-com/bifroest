package authorization

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	coidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
)

var (
	ErrInvalidOidcAuthenticationAssumption = errors.Config.Newf("invalid OIDC authentication assumption")
	ErrAssumedOidcFieldUnavailable         = errors.Config.Newf("OIDC authentication field was not modeled")
)

// AssumedOidcFacts describes an explicitly assumed, already verified result.
// Artifact records are complete JSON snapshots of canonical metadata and raw
// claims/extra objects. An omitted record is unknown; JSON null is known absent.
// These are NOT credentials, signed tokens or evidence of any verification.
type AssumedOidcFacts struct {
	Issuer   string          `json:"issuer"`
	Subject  string          `json:"subject"`
	Token    json.RawMessage `json:"token,omitempty"`
	IDToken  json.RawMessage `json:"idToken,omitempty"`
	UserInfo json.RawMessage `json:"userInfo,omitempty"`
}

// AssumedOidcAuthentication is data for controlled policy evaluation, NOT a
// production Authorization/authorizer, credential, session or browser capability.
// No registered factory or normal SSH/HTTP request constructs it. The offline
// runner must explicitly adapt it and retain that authentication was assumed.
// GetField returns production OIDC wrappers, never generic replacement maps.
type AssumedOidcAuthentication struct {
	auth       *oidc
	tokenKnown bool
}

func (this *AssumedOidcAuthentication) Flow() configuration.FlowName {
	if this == nil || this.auth == nil {
		return ""
	}
	return this.auth.flow
}
func (this *AssumedOidcAuthentication) Authentication() (authentication.Identity, error) {
	if this == nil || this.auth == nil {
		return authentication.Identity{}, ErrInvalidOidcAuthenticationAssumption
	}
	return this.auth.identity, nil
}
func (this *AssumedOidcAuthentication) GetField(name string) (any, bool, error) {
	if this == nil || this.auth == nil {
		return nil, false, ErrInvalidOidcAuthenticationAssumption
	}
	switch name {
	case "token":
		if !this.tokenKnown {
			return nil, false, ErrAssumedOidcFieldUnavailable
		}
		return &this.auth.token, true, nil
	case "idToken":
		return &this.auth.idToken, true, nil
	case "userInfo":
		return &this.auth.userInfo, true, nil
	default:
		return nil, false, errors.Config.Newf("%w: unknown field", ErrAssumedOidcFieldUnavailable)
	}
}

// BindAssumedOidcAuthentication binds assumed identity/artifact facts to the
// actual configured flow and its rendered HTTPS issuer. It performs no discovery,
// signature/expiry verification, token exchange, account lookup or session I/O.
// The caller must admit templates and supply a controlled rendering context;
// arbitrary production template contexts are not inherently hermetic.
func BindAssumedOidcAuthentication(flow *configuration.Flow, facts AssumedOidcFacts, renderContext any) (*AssumedOidcAuthentication, error) {
	fail := func() (*AssumedOidcAuthentication, error) { return nil, ErrInvalidOidcAuthenticationAssumption }
	if flow == nil || flow.Name.Validate() != nil {
		return fail()
	}
	if code, ok := flow.Authorization.V.(*configuration.AuthorizationOidcAuthorizationCode); ok && code == nil {
		return fail()
	}
	conf := configuration.OidcSettings(flow.Authorization.V)
	if conf == nil {
		return fail()
	}
	issuer, err := conf.Issuer.Render(renderContext)
	if err != nil {
		return nil, errors.Config.Newf("cannot resolve assumed OIDC issuer: %w", err)
	}
	if issuer == nil || issuer.String() != facts.Issuer {
		return fail()
	}
	if err := requireOidcHttpsEndpoint("issuer", issuer.String()); err != nil {
		return nil, err
	}
	identity := oidcIdentity(facts.Issuer, facts.Subject)
	if !identity.IsAuthenticated() || identity.Validate() != nil {
		return fail()
	}

	var token assumedOidcToken
	tokenPresent, err := decodeAssumedOidcRecord(facts.Token, &token, "accessToken", "tokenType", "refreshToken", "expiry", "extra")
	if err != nil {
		return nil, err
	}
	var id assumedOidcIDToken
	idPresent, err := decodeAssumedOidcRecord(facts.IDToken, &id, "issuer", "subject", "audience", "expiry", "issuedAt", "nonce", "accessTokenHash", "claims")
	if err != nil {
		return nil, err
	}
	var info assumedOidcUserInfo
	infoPresent, err := decodeAssumedOidcRecord(facts.UserInfo, &info, "subject", "profile", "email", "emailVerified", "claims")
	if err != nil {
		return nil, err
	}
	if (idPresent && (id.Issuer != identity.Issuer || id.Subject != identity.Subject)) || (infoPresent && info.Subject != identity.Subject) {
		return fail()
	}
	// A hidden artifact may remain unknown, but enabled retrieval is an evaluated
	// dependency. Never turn a missing observation into a successful nil result.
	if (conf.RetrieveIdToken && len(facts.IDToken) == 0) || (conf.RetrieveUserInfo && !infoPresent) {
		return nil, ErrAssumedOidcFieldUnavailable
	}

	auth := &oidc{flow: flow.Name, kind: "oidc-device-auth", identity: identity}
	if _, code := flow.Authorization.V.(*configuration.AuthorizationOidcAuthorizationCode); code {
		auth.kind = "oidc-authorization-code"
	}
	if tokenPresent {
		expiry, err := assumedOidcTime(token.Expiry)
		if err != nil {
			return nil, err
		}
		extra, err := assumedOidcClaims(token.Extra)
		if err != nil {
			return nil, err
		}
		auth.token.Token = (&oauth2.Token{AccessToken: token.AccessToken, TokenType: token.TokenType, RefreshToken: token.RefreshToken, Expiry: expiry}).WithExtra(extra)
	}
	var idToken *coidc.IDToken
	var idClaims map[string]any
	if idPresent {
		expiry, err := assumedOidcTime(id.Expiry)
		if err != nil {
			return nil, err
		}
		issuedAt, err := assumedOidcTime(id.IssuedAt)
		if err != nil {
			return nil, err
		}
		idClaims, err = assumedOidcClaims(id.Claims)
		if err != nil {
			return nil, err
		}
		idToken = &coidc.IDToken{Issuer: id.Issuer, Subject: id.Subject, Audience: id.Audience, Expiry: expiry, IssuedAt: issuedAt, Nonce: id.Nonce, AccessTokenHash: id.AccessTokenHash}
		if err := validateAssumedOidcIDClaims(idToken, idClaims); err != nil {
			return nil, err
		}
	}
	var userInfo *coidc.UserInfo
	var infoClaims map[string]any
	if infoPresent {
		infoClaims, err = assumedOidcClaims(info.Claims)
		if err != nil {
			return nil, err
		}
		userInfo = &coidc.UserInfo{Subject: info.Subject, Profile: info.Profile, Email: info.Email, EmailVerified: info.EmailVerified}
		if err := validateAssumedOidcUserClaims(userInfo, infoClaims); err != nil {
			return nil, err
		}
	}
	if err := auth.publishArtifacts(conf, true, oidcArtifactSource{
		hasIDToken: idPresent, expectedIssuer: identity.Issuer, expectedSubject: identity.Subject, providerIssuer: identity.Issuer,
		idToken:  func() (*coidc.IDToken, error) { return idToken, nil },
		userInfo: func() (*coidc.UserInfo, error) { return userInfo, nil },
	}); err != nil {
		return nil, errors.Config.Newf("cannot bind assumed OIDC artifacts: %w", err)
	}
	// coidc keeps raw claims private. Seed the SAME production wrapper cache with
	// independently decoded JSON data, retaining float64 numbers and []any arrays.
	// Hidden wrappers remain empty and cannot reveal the supplied claims.
	if auth.idToken.IDToken != nil {
		auth.idToken.init.Do(func() { auth.idToken.claims = idClaims })
	}
	if auth.userInfo.UserInfo != nil {
		auth.userInfo.init.Do(func() { auth.userInfo.claims = infoClaims })
	}
	return &AssumedOidcAuthentication{auth: auth, tokenKnown: len(facts.Token) != 0}, nil
}

type assumedOidcToken struct {
	AccessToken  string          `json:"accessToken"`
	TokenType    string          `json:"tokenType"`
	RefreshToken string          `json:"refreshToken"`
	Expiry       string          `json:"expiry"`
	Extra        json.RawMessage `json:"extra"`
}
type assumedOidcIDToken struct {
	Issuer          string          `json:"issuer"`
	Subject         string          `json:"subject"`
	Audience        []string        `json:"audience"`
	Expiry          string          `json:"expiry"`
	IssuedAt        string          `json:"issuedAt"`
	Nonce           string          `json:"nonce"`
	AccessTokenHash string          `json:"accessTokenHash"`
	Claims          json.RawMessage `json:"claims"`
}
type assumedOidcUserInfo struct {
	Subject       string          `json:"subject"`
	Profile       string          `json:"profile"`
	Email         string          `json:"email"`
	EmailVerified bool            `json:"emailVerified"`
	Claims        json.RawMessage `json:"claims"`
}

func decodeAssumedOidcRecord(raw json.RawMessage, target any, fields ...string) (bool, error) {
	if len(raw) > 64<<10 {
		return false, ErrInvalidOidcAuthenticationAssumption
	}
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false, nil
	}
	var record map[string]json.RawMessage
	if json.Unmarshal(raw, &record) != nil || len(record) != len(fields) {
		return false, ErrInvalidOidcAuthenticationAssumption
	}
	for _, field := range fields {
		value := bytes.TrimSpace(record[field])
		if len(value) == 0 || bytes.Equal(value, []byte("null")) {
			return false, ErrInvalidOidcAuthenticationAssumption
		}
	}
	if audience, present := record["audience"]; present {
		var values []any
		if json.Unmarshal(audience, &values) != nil {
			return false, ErrInvalidOidcAuthenticationAssumption
		}
		for _, value := range values {
			if _, ok := value.(string); !ok {
				return false, ErrInvalidOidcAuthenticationAssumption
			}
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return false, ErrInvalidOidcAuthenticationAssumption
	}
	return true, nil
}

func assumedOidcClaims(raw json.RawMessage) (map[string]any, error) {
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil || claims == nil {
		return nil, ErrInvalidOidcAuthenticationAssumption
	}
	return claims, nil
}
func assumedOidcTime(raw string) (time.Time, error) {
	value, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || !strings.HasSuffix(raw, "Z") {
		return time.Time{}, ErrInvalidOidcAuthenticationAssumption
	}
	return value, nil
}

func validateAssumedOidcIDClaims(token *coidc.IDToken, claims map[string]any) error {
	for key, expected := range map[string]string{"iss": token.Issuer, "sub": token.Subject, "nonce": token.Nonce, "at_hash": token.AccessTokenHash} {
		if value, present := claims[key]; present && value != expected {
			return ErrInvalidOidcAuthenticationAssumption
		}
	}
	for key, expected := range map[string]time.Time{"exp": token.Expiry, "iat": token.IssuedAt} {
		if value, present := claims[key]; present {
			number, ok := value.(float64)
			if !ok || !expected.Equal(time.Unix(int64(number), 0)) {
				return ErrInvalidOidcAuthenticationAssumption
			}
		}
	}
	if value, present := claims["aud"]; present {
		var audience []string
		switch v := value.(type) {
		case string:
			audience = []string{v}
		case []any:
			audience = make([]string, len(v))
			for i, item := range v {
				var ok bool
				audience[i], ok = item.(string)
				if !ok {
					return ErrInvalidOidcAuthenticationAssumption
				}
			}
		default:
			return ErrInvalidOidcAuthenticationAssumption
		}
		if !reflect.DeepEqual(audience, token.Audience) {
			return ErrInvalidOidcAuthenticationAssumption
		}
	}
	return nil
}
func validateAssumedOidcUserClaims(info *coidc.UserInfo, claims map[string]any) error {
	for key, expected := range map[string]string{"sub": info.Subject, "profile": info.Profile, "email": info.Email} {
		if value, present := claims[key]; present && value != expected {
			return ErrInvalidOidcAuthenticationAssumption
		}
	}
	if value, present := claims["email_verified"]; present && value != info.EmailVerified && value != map[bool]string{true: "true", false: "false"}[info.EmailVerified] {
		return ErrInvalidOidcAuthenticationAssumption
	}
	return nil
}
