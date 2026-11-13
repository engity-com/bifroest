//go:build linux

package service

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/GehirnInc/crypt"
	"github.com/GehirnInc/crypt/apr1_crypt"
	"github.com/GehirnInc/crypt/md5_crypt"
	"github.com/GehirnInc/crypt/sha256_crypt"
	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
	buser "github.com/engity-com/bifroest/pkg/user"
)

func TestLocalCryptPasswordAndInteractiveHttpsRejectVerifierDerivedCredentials(t *testing.T) {
	for _, algorithm := range []struct {
		name string
		new  func() crypt.Crypter
		salt string
	}{
		{"md5", md5_crypt.New, "$1$fixture$"},
		{"apr1", apr1_crypt.New, "$apr1$fixture$"},
		{"sha256", sha256_crypt.New, "$5$fixture$"},
		{"sha512", sha512_crypt.New, "$6$fixture$"},
	} {
		t.Run(algorithm.name, func(t *testing.T) {
			// The existing fixture owns its passwd/group/shadow files; this does
			// not create or alter an account in the host operating system.
			username := prepareLocalUserCertificateTest(t)
			repository := buser.DefaultRepositoryProvider.(*buser.SharedRepositoryProvider[*buser.EtcColonRepository]).V
			verifier, err := algorithm.new().Generate([]byte("correct"), []byte(algorithm.salt))
			require.NoError(t, err)
			forged, err := algorithm.new().Generate([]byte(verifier), []byte(algorithm.salt))
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(repository.ShadowFilename, []byte(fmt.Sprintf("%s:%s:19722:0:99999:7:::\n", username, verifier)), 0600))
			fixture := newWebSocketFixture(t, nil, func(conf *configuration.Configuration) {
				local := &configuration.AuthorizationLocal{}
				require.NoError(t, local.SetDefaults())
				local.PamService = ""
				local.Password.Allowed = template.BoolOf(true)
				local.Password.InteractiveAllowed = template.BoolOf(true)
				conf.Flows[0].Authorization.V = local
				conf.Flows[0].DiscoverAsSlug = "Work"
			})
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				request, err := http.NewRequestWithContext(r.Context(), r.Method, "https://app.example.org"+r.URL.Path, r.Body)
				require.NoError(t, err)
				request.Header = r.Header.Clone()
				response, err := fixture.client.Do(request)
				require.NoError(t, err)
				defer response.Body.Close()
				require.Equal(t, 2, response.ProtoMajor, "the real TLS/HTTP2 boundary must be used")
				for name, values := range response.Header {
					w.Header()[name] = values
				}
				w.WriteHeader(response.StatusCode)
				_, err = io.Copy(w, response.Body)
				require.NoError(t, err)
			})
			for _, input := range []struct {
				name, password string
				status         int
			}{
				{"wrong", "wrong", http.StatusUnauthorized},
				{"verifier replay", verifier, http.StatusUnauthorized},
				{"hash of verifier", forged, http.StatusUnauthorized},
				{"correct", "correct", http.StatusOK},
			} {
				t.Run(input.name, func(t *testing.T) {
					password := webTestPassword(handler, username, input.password, "Work")
					require.Equal(t, input.status, password.Code, password.Body.String())
					attempt := startWebAttempt(t, handler, "interactive", username, "Work", nil)
					step := waitWebLoginStep(t, handler, attempt, "Work")
					require.Equal(t, http.StatusAccepted, answerWebStep(handler, attempt, "Work", step, input.password).Code)
					interactive := finishWebAttempt(t, handler, attempt, "Work")
					require.Equal(t, input.status, interactive.Code, interactive.Body.String())
					if input.status != http.StatusOK {
						require.Zero(t, webSessionCount(t, fixture.svc), "rejected credentials must not allocate a session")
						return
					}
					one := webTestAccess(t, fixture.svc, webTestToken(t, password), "Work")
					two := webTestAccess(t, fixture.svc, webTestToken(t, interactive), "Work")
					require.Equal(t, one.auth.FindSession().Id(), two.auth.FindSession().Id())
					require.Equal(t, 1, webSessionCount(t, fixture.svc))
				})
			}
		})
	}
}
