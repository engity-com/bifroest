package service

import (
	"testing"

	"github.com/echocat/slf4g/level"
	logrecording "github.com/echocat/slf4g/testing/recording"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
)

func TestNoMatchingFlowIsLoggedForEachAuthenticationMethod(t *testing.T) {
	for _, test := range []struct {
		name      string
		user      string
		configure func(*configuration.Configuration)
	}{
		{name: "not included", user: "unknown-user"},
		{
			name: "excluded",
			user: "blocked-user",
			configure: func(conf *configuration.Configuration) {
				conf.Flows[0].Requirement.IncludedRequestingName = common.MustNewRegexp("")
				conf.Flows[0].Requirement.ExcludedRequestingName = common.MustNewRegexp("^blocked-user$")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := logrecording.NewProvider()
			provider.SetLevel(level.Debug)
			defer provider.HookGlobally()()

			server := newAuthorizedKeysTestServerWithConfiguration(t, "", &authorizedKeysTestEnvironment{}, test.configure)
			client, err := gossh.Dial("tcp", server.address, &gossh.ClientConfig{
				User: test.user,
				Auth: []gossh.AuthMethod{
					gossh.PublicKeys(server.signer),
					gossh.Password("wrong-password"),
					gossh.KeyboardInteractive(func(_, _ string, _ []string, _ []bool) ([]string, error) {
						t.Fatal("unmatched flow must not prompt the client")
						return nil, nil
					}),
				},
				HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // The server and key are test-local.
			})
			if client != nil {
				_ = client.Close()
			}
			require.Error(t, err)

			var messages int
			messageKey := provider.GetFieldKeysSpec().GetMessage()
			for _, event := range provider.GetAll() {
				if message, ok := event.Get(messageKey); ok && message == "no flow matches requested user" {
					require.Equal(t, level.Debug, event.GetLevel())
					messages++
				}
			}
			require.Equal(t, 3, messages)
		})
	}
}

func TestMatchingFlowDoesNotLogNoMatchWhenCredentialsAreRejected(t *testing.T) {
	provider := logrecording.NewProvider()
	provider.SetLevel(level.Debug)
	defer provider.HookGlobally()()

	server := newAuthorizedKeysTestServer(t, "", &authorizedKeysTestEnvironment{})
	client, err := gossh.Dial("tcp", server.address, &gossh.ClientConfig{
		User:            server.username,
		Auth:            []gossh.AuthMethod{gossh.Password("wrong-password")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // The server and key are test-local.
	})
	if client != nil {
		_ = client.Close()
	}
	require.Error(t, err)

	messageKey := provider.GetFieldKeysSpec().GetMessage()
	for _, event := range provider.GetAll() {
		message, ok := event.Get(messageKey)
		require.False(t, ok && message == "no flow matches requested user")
	}
}
