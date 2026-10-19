package service

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clibase "github.com/echocat/cli4g"
	"github.com/kevinburke/ssh_config"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"gopkg.in/yaml.v3"

	appcli "github.com/engity-com/bifroest/pkg/cli"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/transport"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/management"
)

func TestManagementKeyExportsOverIntegratedAndDirectSSH(t *testing.T) {
	directory := t.TempDir()
	newKey := func(name string) bfcrypto.PrivateKey {
		key, err := bfcrypto.EnsureKeyFile(filepath.Join(directory, name), &bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}, nil)
		require.NoError(t, err)
		return key
	}
	login, authority, subject := newKey("login"), newKey("authority"), newKey("subject")
	staticIdentity, initialTrust := newKey("static"), newKey("initial-trust")
	caFile, hostFile := filepath.Join(directory, "trusted-cas"), filepath.Join(directory, "target-hosts")
	require.NoError(t, os.WriteFile(caFile, bfcrypto.MarshalPublicKey(initialTrust.PublicKey()), 0600))
	initialHosts := knownhosts.Line([]string{"target.example.org"}, initialTrust.PublicKey().ToSsh()) + "\n"
	require.NoError(t, os.WriteFile(hostFile, []byte(initialHosts), 0600))
	server := newAuthorizedKeysTestServerWithConfiguration(t, "", nil, func(conf *configuration.Configuration) {
		conf.Flows[0].Environment.V = &configuration.EnvironmentManagement{}
		auth := conf.Flows[0].Authorization.V.(*configuration.AuthorizationSimple)
		auth.Entries[0].AuthorizedKeys = bfcrypto.AuthorizedKeys(bfcrypto.MarshalPublicKey(login.PublicKey()))
		auth.TrustedUserCAsFile = bfcrypto.PublicKeysFile(caFile)
		var gateway configuration.Flow
		require.NoError(t, yaml.Unmarshal([]byte(fmt.Sprintf(`
name: gateway
requirement:
  includedRequestingName: ^unused$
authorization:
  type: none
environment:
  type: ssh
  address: target.example.org
  user: alice
  knownHostsFile: %q
  certificate:
    identityFile: %q
    authorityIdentityFile: %q
`, filepath.ToSlash(hostFile), filepath.ToSlash(filepath.Join(directory, "subject")), filepath.ToSlash(filepath.Join(directory, "authority")))), &gateway))
		var ordinary configuration.Flow
		require.NoError(t, yaml.Unmarshal([]byte(fmt.Sprintf(`
name: static
requirement:
  includedRequestingName: ^unused$
authorization:
  type: none
environment:
  type: ssh
  address: target.example.org
  user: alice
  knownHostsFile: %q
  identityFiles:
    - %q
    - %q
    - '{{.session.id}}'
`, filepath.ToSlash(hostFile), filepath.ToSlash(filepath.Join(directory, "static")), filepath.ToSlash(filepath.Join(directory, "missing")))), &ordinary))
		conf.Flows = append(conf.Flows, gateway, ordinary)
	})
	identityPath, hostsPath := configureManagementKeyClient(t, server, directory)
	app := appcli.NewApplication[clibase.NoOptions](nil, "", nil).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	run := func(input []byte, output *bytes.Buffer, args ...string) (string, error) {
		t.Helper()
		var stderr bytes.Buffer
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		ctx = common.ContextWithRemoteTarget(ctx, management.Target{Host: "management-keys"})
		ctx = clibase.ContextWithStdio(ctx, bytes.NewReader(input), output, &stderr)
		err := app.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileRemote}}, args...)
		return stderr.String(), err
	}
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"key", "export", "ca", "gateway"}, string(bfcrypto.MarshalPublicKey(authority.PublicKey()))},
		{[]string{"key", "export", "public", "gateway", "--comment=server subject"}, strings.TrimSpace(string(bfcrypto.MarshalPublicKey(subject.PublicKey()))) + " server subject\n"},
		{[]string{"key", "export", "public", "static"}, string(bfcrypto.MarshalPublicKey(staticIdentity.PublicKey()))},
		{[]string{"key", "export", "host", "--address=[::1]:2222"}, knownhosts.Line([]string{"[::1]:2222"}, server.service.server.HostSigners[0].PublicKey()) + "\n"},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			var output bytes.Buffer
			stderr, err := run(nil, &output, test.args...)
			require.NoError(t, err, stderr)
			require.Empty(t, stderr)
			require.Equal(t, test.want, output.String())
		})
	}
	t.Run("exports use active keys without creating missing files", func(t *testing.T) {
		for _, name := range []string{"authority", "subject"} {
			path := filepath.Join(directory, name)
			original, err := os.ReadFile(path)
			require.NoError(t, err)
			require.NoError(t, os.Remove(path))
			var output bytes.Buffer
			kind := "ca"
			if name == "subject" {
				kind = "public"
			}
			_, err = run(nil, &output, "key", "export", kind, "gateway")
			require.NoError(t, err)
			require.NotEmpty(t, output.Bytes())
			_, err = os.Stat(path)
			require.ErrorIs(t, err, os.ErrNotExist)
			require.NoError(t, os.WriteFile(path, original, 0600))
		}
		var output bytes.Buffer
		_, err := run(nil, &output, "key", "export", "public", "static", "--identityIndex=1")
		require.ErrorContains(t, err, "does not exist")
		require.Empty(t, output.Bytes())
		_, err = os.Stat(filepath.Join(directory, "missing"))
		require.ErrorIs(t, err, os.ErrNotExist)
	})
	for _, args := range [][]string{
		{"key", "generate"},
		{"key", "export", "ca", "static"},
		{"key", "export", "public", "static", "--identityIndex=2"},
		{"key", "export", "public", "static", "--identityIndex=3"},
		{"key", "export", "public", "gateway", "--identityFile=" + identityPath},
		{"key", "export", "host", "--address=host", "--configuration=server.yaml"},
		{"key", "import", "ca", "gateway", "--trustedCAsFile=" + caFile},
		{"key", "import", "host", "gateway", "--knownHostsFile=" + hostFile},
	} {
		var output bytes.Buffer
		_, err := run(nil, &output, args...)
		require.Error(t, err, args)
		require.Empty(t, output.Bytes(), args)
	}
	t.Run("client output destinations", func(t *testing.T) {
		path := filepath.Join(directory, "exported-ca")
		var output bytes.Buffer
		args := []string{"key", "export", "ca", "gateway", "--output=" + path}
		_, err := run(nil, &output, args...)
		require.NoError(t, err)
		require.Empty(t, output.Bytes())
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, bfcrypto.MarshalPublicKey(authority.PublicKey()), content)
		_, err = run(nil, &output, args...)
		require.Error(t, err)
		_, err = run(nil, &output, append(args, "--force")...)
		require.NoError(t, err)
		_, err = run(nil, &output, "key", "export", "public", "static", "--identityIndex=1", "--output="+path, "--force")
		require.ErrorContains(t, err, "does not exist")
		unchanged, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, content, unchanged, "failed export must preserve an existing output even with force")
		for _, protected := range []string{identityPath, hostsPath} {
			original, err := os.ReadFile(protected)
			require.NoError(t, err)
			// Private-key provisioning makes the login identity read-only. Make
			// this fixture writable so the stdout guard, not the OS, rejects it.
			require.NoError(t, os.Chmod(protected, 0600))
			alias := protected + "-alias"
			require.NoError(t, os.Link(protected, alias))
			for _, destination := range []string{protected, alias} {
				_, err = run(nil, &output, "key", "export", "ca", "gateway", "--output="+destination, "--force")
				require.ErrorContains(t, err, "must not replace")
				file, err := os.OpenFile(destination, os.O_WRONLY|os.O_APPEND, 0)
				require.NoError(t, err)
				ctx := common.ContextWithRemoteTarget(t.Context(), management.Target{Host: "management-keys"})
				ctx = clibase.ContextWithStdio(ctx, nil, file, nil)
				err = app.ParseAndExecute(ctx, &clibase.ParseOpts{Profiles: []string{common.ProfileRemote}}, "key", "export", "ca", "gateway")
				require.ErrorContains(t, err, "must not replace")
				require.NoError(t, file.Close())
			}
			current, err := os.ReadFile(protected)
			require.NoError(t, err)
			require.Equal(t, original, current)
		}
	})
	client, err := gossh.Dial("tcp", server.address, &gossh.ClientConfig{
		User: server.username, Auth: []gossh.AuthMethod{gossh.PublicKeys(login.ToSsh())},
		HostKeyCallback: gossh.FixedHostKey(server.service.server.HostSigners[0].PublicKey()),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	human := func(command string, input []byte) ([]byte, string, error) {
		t.Helper()
		sess, err := client.NewSession()
		require.NoError(t, err)
		defer sess.Close()
		var stderr bytes.Buffer
		sess.Stdin, sess.Stderr = bytes.NewReader(input), &stderr
		output, err := sess.Output(command)
		return output, stderr.String(), err
	}
	content, _, err := human("key export ca gateway", nil)
	require.NoError(t, err)
	require.Equal(t, bfcrypto.MarshalPublicKey(authority.PublicKey()), content)
	content, _, err = human("key export public gateway", nil)
	require.NoError(t, err)
	require.Equal(t, bfcrypto.MarshalPublicKey(subject.PublicKey()), content)
	content, _, err = human("key export host --address=server.example.org", nil)
	require.NoError(t, err)
	require.Equal(t, knownhosts.Line([]string{"server.example.org"}, server.service.server.HostSigners[0].PublicKey())+"\n", string(content))
	for _, command := range []string{
		"key export ca gateway --output=server-file",
		"key export public gateway --identityFile=server-file",
		"key import ca restricted-key --input=server-file",
		"key import host gateway --address=untrusted.example.org",
		"key generate",
	} {
		content, _, err := human(command, nil)
		require.Error(t, err, command)
		require.Empty(t, content, command)
	}
	for _, test := range []struct{ kind, flow, file, destinationFlag string }{
		{"ca", "restricted-key", caFile, "trustedCAsFile"}, {"host", "gateway", hostFile, "knownHostsFile"},
	} {
		input := bfcrypto.MarshalPublicKey(login.PublicKey())
		if test.kind == "host" {
			input = []byte(knownhosts.Line([]string{"target.example.org"}, login.PublicKey().ToSsh()) + "\n")
		}
		original, err := os.ReadFile(test.file)
		require.NoError(t, err)
		inputFile := filepath.Join(directory, "incoming-"+test.kind)
		require.NoError(t, os.WriteFile(inputFile, input, 0600))
		var output bytes.Buffer
		_, err = run(input, &output, "key", "import", test.kind, test.flow)
		require.Error(t, err, "remote imports must not be registered")
		require.Empty(t, output.Bytes())
		args := []string{"key", "import", test.kind, "--" + test.destinationFlag + "=" + test.file, "--input=" + inputFile}
		_, err = run(nil, &output, args...)
		require.Error(t, err, "remote invocation must not fall back to a local import")
		require.Empty(t, output.Bytes())
		command := fmt.Sprintf("key import %s --%s=%q --input=%q", test.kind, test.destinationFlag, filepath.ToSlash(test.file), filepath.ToSlash(inputFile))
		content, _, err := human(command, input)
		require.Error(t, err, "direct SSH must not expose local import handlers")
		require.Empty(t, content)
		request, err := transport.EncodeWireRequest(args)
		require.NoError(t, err)
		sess, err := client.NewSession()
		require.NoError(t, err)
		sess.Stdin = bytes.NewReader(request)
		content, err = sess.Output(transport.WireCommand)
		_ = sess.Close()
		require.Error(t, err, "wire requests must not expose local import handlers")
		require.Empty(t, content)
		_, err = (management.Target{Host: "management-keys"}).ExportKey(t.Context(), args...)
		require.ErrorContains(t, err, "only public key exports")
		current, err := os.ReadFile(test.file)
		require.NoError(t, err)
		require.Equal(t, original, current, "rejected imports must leave trust files unchanged")
	}
}

func configureManagementKeyClient(t *testing.T, server *authorizedKeysTestServer, directory string) (string, string) {
	t.Helper()
	identity := filepath.Join(directory, "login")
	hosts := filepath.Join(directory, "client-known-hosts")
	require.NoError(t, os.WriteFile(hosts, []byte(knownhosts.Line([]string{knownhosts.Normalize(server.address)}, server.service.server.HostSigners[0].PublicKey())+"\n"), 0600))
	host, port, err := net.SplitHostPort(server.address)
	require.NoError(t, err)
	path := filepath.Join(directory, "ssh_config")
	require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf(
		"Host management-keys\n HostName %s\n Port %s\n User %s\n IdentityAgent none\n IdentityFile %q\n UserKnownHostsFile %q\n",
		host, port, server.username, filepath.ToSlash(identity), filepath.ToSlash(hosts))), 0600))
	previous := ssh_config.DefaultUserSettings
	settings := &ssh_config.UserSettings{}
	settings.ConfigFinder(func() string { return path })
	ssh_config.DefaultUserSettings = settings
	t.Cleanup(func() { ssh_config.DefaultUserSettings = previous })
	return identity, hosts
}
