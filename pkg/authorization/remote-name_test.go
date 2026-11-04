package authorization

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/template"
)

const stripRemoteSuffix = `{{ regexReplaceAll "@[^@]+$" .remote.user "" }}`

type mappingTestRequest struct {
	*facadeSelectionRequest
	selection                connection.Selection
	markerReads, validations int
}

func (r *mappingTestRequest) Selection() connection.Selection      { return r.selection }
func (*mappingTestRequest) PublicKeyVerified() bool                { return true } // Trusted test adapter, not client input.
func (r *mappingTestRequest) Validate(Authorization) (bool, error) { r.validations++; return true, nil }
func (r *mappingTestRequest) GetField(name string) (any, bool, error) {
	switch name {
	case "password":
		return r.password, true, nil
	case "marker":
		r.markerReads++
		return "", true, nil
	default:
		return nil, false, fmt.Errorf("unknown fixture field %q", name)
	}
}

func mappingHtpasswd(t *testing.T) crypto.Htpasswd {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("correct"), bcrypt.MinCost)
	require.NoError(t, err)
	var entries crypto.Htpasswd
	require.NoError(t, entries.Set("alice:"+string(hash)+"\nbob:"+string(hash)))
	return entries
}

func sessionCount(t *testing.T, repository session.Repository) int {
	t.Helper()
	count := 0
	require.NoError(t, repository.FindAll(t.Context(), func(context.Context, session.Session) (bool, error) { count++; return true, nil }, nil))
	return count
}

func TestRemoteNameSharedCredentialsKeepOriginalFlowAndSessionSelectors(t *testing.T) {
	for _, kind := range []string{"simple", "htpasswd"} {
		methods := []string{"password", "keyboard-interactive", "public-key"}
		if kind == "simple" {
			methods = append(methods, "certificate")
		}
		for _, transport := range []connection.Transport{connection.TransportSsh, connection.TransportHttp} {
			for _, method := range methods {
				t.Run(fmt.Sprintf("%s/%s/%s", kind, transport, method), func(t *testing.T) {
					key := newEvidenceTestSigner(t).PublicKey()
					var authority ssh.Signer
					if method == "certificate" {
						authority = newEvidenceTestSigner(t)
						key = newUserCertificateTestCertificate(t, authority, key, time.Now())
					}
					var definition configuration.AuthorizationV
					if kind == "simple" {
						definition = &configuration.AuthorizationSimple{RemoteName: template.MustNewString(stripRemoteSuffix + `{{.marker}}`), Entries: configuration.AuthorizationSimpleEntries{{Name: "alice", Password: crypto.Password("plain:correct"), AuthorizedKeys: crypto.AuthorizedKeys(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))}}}
						if authority != nil {
							conf := definition.(*configuration.AuthorizationSimple)
							conf.Entries[0].AuthorizedKeys = ""
							conf.TrustedUserCAs = crypto.PublicKeys(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(authority.PublicKey()))))
						}
					} else {
						definition = &configuration.AuthorizationHtpasswd{RemoteName: template.MustNewString(stripRemoteSuffix + `{{.marker}}`), Entries: mappingHtpasswd(t)}
					}
					var flows configuration.Flows
					for _, suffix := range []string{"node-a", "node-b"} {
						flows = append(flows, configuration.Flow{Name: configuration.FlowName(suffix), Authorization: configuration.Authorization{V: definition}, Requirement: configuration.Requirement{IncludedRequestingName: common.MustNewRegexp("@" + suffix + "$"), Http: configuration.RequirementHttp{IncludedSlug: common.MustNewRegexp("^Work$")}}})
					}
					facade, _ := newSelectionTestFacade(t, flows)
					base := newFacadeSelectionRequest(t, "alice@node-a")
					base.password = "correct"
					base.key = key
					r := &mappingTestRequest{facadeSelectionRequest: base, selection: connection.Selection{Transport: transport, Host: "app.example.org", Slug: "Work"}}
					if transport == connection.TransportSsh {
						r.selection = connection.Selection{Transport: transport}
					}
					ids := map[session.Id]bool{}
					for _, suffix := range []string{"node-a", "node-b"} {
						base.name = "alice@" + suffix
						if kind == "htpasswd" && method == "public-key" {
							initial, err := facade.AuthorizePassword(r)
							require.NoError(t, err)
							require.True(t, initial.IsAuthorized())
							info, err := initial.FindSession().Info(t.Context())
							require.NoError(t, err)
							last, err := info.LastAccessed(t.Context())
							require.NoError(t, err)
							require.Equal(t, base.name, last.Remote().User())
							require.NoError(t, initial.FindSession().AddPublicKey(t.Context(), key))
						}
						r.markerReads = 0
						r.validations = 0
						var auth Authorization
						var err error
						switch method {
						case "password":
							auth, err = facade.AuthorizePassword(r)
						case "keyboard-interactive":
							auth, err = facade.AuthorizeInteractive(r)
						case "public-key", "certificate":
							auth, err = facade.AuthorizePublicKey(r)
						}
						require.NoError(t, err)
						require.True(t, auth.IsAuthorized())
						require.Equal(t, suffix, auth.Flow().String())
						require.Equal(t, base.name, auth.Remote().User())
						identity, err := AuthenticationOf(auth)
						require.NoError(t, err)
						require.Equal(t, "alice", identity.Subject)
						if method == "certificate" {
							require.False(t, AuthorizedKeyPolicyOf(auth).PortForwardingAllowed)
						}
						require.Equal(t, 1, r.markerReads, "the request template is evaluated exactly once per attempt")
						require.Equal(t, 1, r.validations, "one authorization validation per selected flow")
						require.NotNil(t, auth.FindSession())
						require.False(t, ids[auth.FindSession().Id()])
						ids[auth.FindSession().Id()] = true
					}
					require.Equal(t, 2, sessionCount(t, base.repository))
					base.name = "alice@node-c"
					r.markerReads = 0
					var denied Authorization
					var err error
					if method == "certificate" {
						denied, err = facade.AuthorizePublicKey(r)
					} else {
						denied, err = facade.AuthorizePassword(r)
					}
					require.NoError(t, err)
					require.False(t, denied.IsAuthorized())
					require.Zero(t, r.markerReads, "filters inspect the original name before mapping")
					require.Equal(t, 2, sessionCount(t, base.repository))
				})
			}
		}
	}
}

func TestRemoteNameCertificateUsesMappedPrincipalWithoutRelaxingCertificatePolicy(t *testing.T) {
	for _, mode := range []string{"valid", "original principal", "other principal", "expired", "other CA", "critical option", "unsigned probe"} {
		t.Run(mode, func(t *testing.T) {
			authority := newEvidenceTestSigner(t)
			subject := newEvidenceTestSigner(t)
			cert := newUserCertificateTestCertificate(t, authority, subject.PublicKey(), time.Now())
			switch mode {
			case "original principal":
				cert.ValidPrincipals = []string{"alice@node-a"}
			case "other principal":
				cert.ValidPrincipals = []string{"bob"}
			case "expired":
				cert.ValidBefore = uint64(time.Now().Add(-time.Hour).Unix())
			case "critical option":
				cert.CriticalOptions = map[string]string{"unknown": "value"}
			}
			require.NoError(t, cert.SignCert(rand.Reader, authority))
			conf := &configuration.AuthorizationSimple{RemoteName: template.MustNewString(stripRemoteSuffix), Entries: configuration.AuthorizationSimpleEntries{{Name: "alice"}}}
			auth := &SimpleAuthorizer{flow: "node-a", conf: conf, trustedUserCAs: []ssh.PublicKey{authority.PublicKey()}}
			if mode == "other CA" {
				auth.trustedUserCAs = []ssh.PublicKey{newEvidenceTestSigner(t).PublicKey()}
			}
			base := newFacadeSelectionRequest(t, "alice@node-a")
			base.key = cert
			var req PublicKeyRequest = &mappingTestRequest{facadeSelectionRequest: base}
			if mode == "unsigned probe" {
				req = base
			}
			result, err := auth.AuthorizePublicKey(req)
			require.NoError(t, err)
			if mode == "valid" || mode == "unsigned probe" {
				require.True(t, result.IsAuthorized())
				require.Equal(t, "alice@node-a", result.Remote().User())
				require.True(t, AuthorizedKeyPolicyOf(result).PtyAllowed)
				require.False(t, AuthorizedKeyPolicyOf(result).PortForwardingAllowed)
				if mode == "unsigned probe" {
					require.Nil(t, result.FindSession())
					require.Zero(t, sessionCount(t, base.repository))
				} else {
					require.Equal(t, 1, sessionCount(t, base.repository))
				}
			} else {
				require.False(t, result.IsAuthorized())
				require.Zero(t, sessionCount(t, base.repository))
			}
		})
	}
}

func TestRemoteNameRejectsInvalidResultsAndSanitizesRequestTemplateFailures(t *testing.T) {
	for _, source := range []string{`{{""}}`, `{{"\n"}}`, `{{repeat 1025 "a"}}`, `{{.missing}}`, `{{mustRegexReplaceAll "[" .password ""}}`} {
		t.Run(source, func(t *testing.T) {
			base := newFacadeSelectionRequest(t, "alice")
			base.password = "PRIVATE-REMOTE-NAME-PASSWORD"
			req := &mappingTestRequest{facadeSelectionRequest: base}
			auth := &SimpleAuthorizer{flow: "selected", conf: &configuration.AuthorizationSimple{RemoteName: template.MustNewString(source), Entries: configuration.AuthorizationSimpleEntries{{Name: "alice", Password: crypto.Password("plain:" + base.password)}}}}
			result, err := auth.AuthorizePassword(req)
			require.Error(t, err)
			require.Nil(t, result)
			require.Zero(t, req.validations)
			require.Zero(t, sessionCount(t, base.repository))
			require.NotContains(t, fmt.Sprintf("%+v", err), base.password)
		})
	}
}

func TestRemoteNameMappingChangesCannotResumeAnotherSubjectOrReuseRememberedSessionKeys(t *testing.T) {
	for _, kind := range []string{"simple", "htpasswd"} {
		t.Run(kind, func(t *testing.T) {
			base := newFacadeSelectionRequest(t, "alice@node-a")
			base.password = "correct"
			req := &mappingTestRequest{facadeSelectionRequest: base, selection: connection.Selection{Transport: connection.TransportHttp, Host: "app.example.org", Slug: "Work"}}
			var authorizer Authorizer
			var setMapping func(string)
			if kind == "simple" {
				conf := &configuration.AuthorizationSimple{RemoteName: template.MustNewString(stripRemoteSuffix), Entries: configuration.AuthorizationSimpleEntries{{Name: "alice", Password: crypto.Password("plain:correct")}, {Name: "bob", Password: crypto.Password("plain:correct")}}}
				authorizer = &SimpleAuthorizer{flow: "selected", conf: conf}
				setMapping = func(value string) { conf.RemoteName = template.MustNewString(value) }
			} else {
				conf := &configuration.AuthorizationHtpasswd{RemoteName: template.MustNewString(stripRemoteSuffix), Entries: mappingHtpasswd(t)}
				authorizer = &HtpasswdAuthorizer{flow: "selected", conf: conf}
				setMapping = func(value string) { conf.RemoteName = template.MustNewString(value) }
			}
			initial, err := authorizer.AuthorizePassword(req)
			require.NoError(t, err)
			require.True(t, initial.IsAuthorized())
			identity, err := AuthenticationOf(initial)
			require.NoError(t, err)
			remembered := newEvidenceTestSigner(t).PublicKey()
			require.NoError(t, initial.FindSession().AddPublicKey(t.Context(), remembered))
			base.key = remembered
			resume := &resumeTestRequest{Request: req, sess: initial.FindSession(), identity: identity, credential: authentication.SessionCredential{Kind: kind, Method: "public-key", PublicKey: base64.StdEncoding.EncodeToString(remembered.Marshal())}, verified: true, selection: req.selection}
			resumed, err := authorizer.(SessionResumer).ResumeSession(resume)
			require.NoError(t, err)
			require.Equal(t, initial.FindSession().Id(), resumed.FindSession().Id())
			before, err := initial.FindSession().AuthorizationToken(t.Context())
			require.NoError(t, err)
			base.name = "alice@node-b"
			_, err = authorizer.(SessionResumer).ResumeSession(resume)
			require.ErrorIs(t, err, ErrSessionResumeDenied, "the original target suffix is still a session boundary")
			base.name = "alice@node-a"
			setMapping("bob")
			_, err = authorizer.(SessionResumer).ResumeSession(resume)
			require.ErrorIs(t, err, ErrSessionResumeDenied)
			denied, err := authorizer.AuthorizePublicKey(req)
			require.NoError(t, err)
			require.False(t, denied.IsAuthorized(), "an old session key cannot authenticate the newly mapped subject")
			require.Equal(t, 1, sessionCount(t, base.repository))
			after, err := initial.FindSession().AuthorizationToken(t.Context())
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

func TestRememberedSimpleKeyRequiresCanonicalStoredSubject(t *testing.T) {
	for _, tc := range []struct {
		name    string
		token   []byte
		allowed bool
	}{
		{"empty", nil, false}, {"malformed", []byte(`not-json`), false},
		{"missing subject", []byte(`{}`), false}, {"other subject", []byte(`{"user":{"name":"bob"}}`), false},
		{"matching subject", []byte(`{"user":{"name":"alice"}}`), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := newFacadeSelectionRequest(t, "alice")
			sess, err := base.repository.Create(t.Context(), "selected", base.Connection().Remote(), tc.token)
			require.NoError(t, err)
			require.NoError(t, sess.AddPublicKey(t.Context(), base.key))
			auth := &SimpleAuthorizer{flow: "selected", conf: &configuration.AuthorizationSimple{Entries: configuration.AuthorizationSimpleEntries{{Name: "alice"}}}}
			result, err := auth.AuthorizePublicKey(&mappingTestRequest{facadeSelectionRequest: base})
			require.NoError(t, err)
			require.Equal(t, tc.allowed, result.IsAuthorized())
			if tc.allowed {
				require.Equal(t, sess.Id(), result.FindSession().Id())
			}
			require.Equal(t, 1, sessionCount(t, base.repository), "invalid remembered state must never allocate a replacement session")
		})
	}
}
