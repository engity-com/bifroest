package authorization

import (
	"errors"
	"fmt"
	"testing"

	coidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestOidcSharedArtifactPublicationMatrix(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		for _, id := range []bool{false, true} {
			for _, info := range []bool{false, true} {
				t.Run(fmt.Sprintf("allowed=%t/id=%t/info=%t", allowed, id, info), func(t *testing.T) {
					auth := &oidc{identity: oidcIdentity("https://issuer.example", "subject")}
					conf := &configuration.AuthorizationOidcDeviceAuth{RetrieveIdToken: id, RetrieveUserInfo: info}
					var idCalls, infoCalls int
					var messages []string
					err := auth.publishArtifacts(conf, allowed, oidcArtifactSource{
						hasIDToken: true, expectedIssuer: "https://issuer.example", expectedSubject: "subject", providerIssuer: "https://issuer.example",
						idToken: func() (*coidc.IDToken, error) {
							idCalls++
							return &coidc.IDToken{Issuer: "https://issuer.example", Subject: "subject"}, nil
						},
						userInfo:   func() (*coidc.UserInfo, error) { infoCalls++; return &coidc.UserInfo{Subject: "subject"}, nil },
						onVerified: func(message string) { messages = append(messages, message) },
					})
					require.NoError(t, err)
					require.Equal(t, allowed && id, idCalls == 1)
					require.Equal(t, allowed && info, infoCalls == 1)
					require.Equal(t, allowed && id, auth.idToken.IDToken != nil)
					require.Equal(t, allowed && info, auth.userInfo.UserInfo != nil)
					require.Equal(t, oidcIdentity("https://issuer.example", "subject"), auth.identity)
					require.Len(t, messages, idCalls+infoCalls)
				})
			}
		}
	}
}

func TestOidcSharedPublicationRejectsConflictsAndPreservesRetrievalErrors(t *testing.T) {
	for _, conflict := range []string{"id-subject", "id-issuer", "userinfo", "id-error", "userinfo-error"} {
		t.Run(conflict, func(t *testing.T) {
			auth := &oidc{identity: oidcIdentity("https://issuer.example", "subject")}
			conf := &configuration.AuthorizationOidcDeviceAuth{RetrieveIdToken: true, RetrieveUserInfo: true}
			sentinel := errors.New("retrieval failed")
			var infoCalls int
			err := auth.publishArtifacts(conf, true, oidcArtifactSource{
				hasIDToken: true, expectedIssuer: "https://issuer.example", expectedSubject: "subject",
				idToken: func() (*coidc.IDToken, error) {
					id := &coidc.IDToken{Issuer: "https://issuer.example", Subject: "subject"}
					switch conflict {
					case "id-subject":
						id.Subject = "other"
					case "id-issuer":
						id.Issuer = "https://other.example"
					case "id-error":
						return nil, sentinel
					}
					return id, nil
				},
				userInfo: func() (*coidc.UserInfo, error) {
					infoCalls++
					if conflict == "userinfo-error" {
						return nil, sentinel
					}
					return &coidc.UserInfo{Subject: "other"}, nil
				},
			})
			require.Error(t, err)
			if conflict == "id-error" || conflict == "userinfo-error" {
				require.ErrorIs(t, err, sentinel)
			}
			if conflict != "userinfo" && conflict != "userinfo-error" {
				require.Zero(t, infoCalls, "an ID token failure must stop before UserInfo")
			}
		})
	}
	conf := &configuration.AuthorizationOidcDeviceAuth{RetrieveIdToken: true, RetrieveUserInfo: true, ForceDisposeSessionOn: "never", RefreshToken: configuration.AuthorizationOidcRefreshToken{Mode: "never"}}
	err := new(oidc).publishArtifacts(conf, true, oidcArtifactSource{})
	require.EqualError(t, err, "token does not contain id_token")
	conf.RetrieveIdToken = false
	auth := new(oidc)
	require.NoError(t, auth.publishArtifacts(conf, true, oidcArtifactSource{providerIssuer: "https://issuer.example", userInfo: func() (*coidc.UserInfo, error) { return &coidc.UserInfo{Subject: "subject"}, nil }}))
	require.Equal(t, oidcIdentity("https://issuer.example", "subject"), auth.identity, "legacy UserInfo identity fallback must be preserved")
}
