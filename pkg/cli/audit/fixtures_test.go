package audit

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	cli "github.com/echocat/cli4g"
	"github.com/echocat/cli4g/codec"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	bfAudit "github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

func newAuditCliTestApplication(t *testing.T) *cli.Application[cli.NoOptions] {
	t.Helper()
	app := cli.NewSimpleApplication("bifroest").
		WithFallbackToStdio(false).
		WithErrorHandlerEnabled(false).
		WithCodec(configuration.NewCliCodec(common.ProfileExecutable)).
		WithCodec(codec.NewDateTime().WithFormats(time.RFC3339), "rfc3339").
		WithCommand(CreateCommands()...).MustCreate()
	t.Cleanup(func() { require.NoError(t, app.Close()) })
	return app
}

func runAuditCliTestCommand(t *testing.T, app *cli.Application[cli.NoOptions], stdout io.Writer, args ...string) error {
	t.Helper()
	ctx := cli.ContextWithStdio(t.Context(), nil, stdout, nil)
	return app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}, args...)
}

func createAuditCliTestKeyPair(t *testing.T, parent, name string) (string, string) {
	t.Helper()
	path := filepath.Join(parent, name)
	private, err := (bfcrypto.KeyRequirement{Type: bfcrypto.KeyTypeEd25519}).CreateFile(nil, path)
	require.NoError(t, err)
	public := path + ".pub"
	require.NoError(t, os.WriteFile(public, bfcrypto.MarshalPublicKey(private.PublicKey()), 0600))
	return path, public
}

func createAuditCliTestJournal(t *testing.T, parent, name, eventName string) configuration.Auditlog {
	return createAuditCliTestJournalWithEncryption(t, parent, name, eventName, "")
}

func createAuditCliTestJournalWithEncryption(t *testing.T, parent, name, eventName string, encryptionPublicKey bfcrypto.PublicKeys) configuration.Auditlog {
	t.Helper()
	configured := configuration.Auditlog{
		Name:                configuration.AuditlogName(name),
		Enabled:             true,
		IdentityFile:        filepath.Join(parent, name+"-key"),
		EncryptionPublicKey: encryptionPublicKey,
		Directory:           filepath.Join(parent, name+"-journal"),
	}
	identity, err := bfAudit.EnsureIdentity(&configured)
	require.NoError(t, err)
	recorder, err := bfAudit.NewRecorder(&configured, identity)
	require.NoError(t, err)
	require.NoError(t, recorder.Record(t.Context(), bfAudit.Event{
		Name: eventName, Domain: bfAudit.EventDomainSession, Outcome: bfAudit.EventOutcomeSuccess,
		Flow: "confidential-flow-" + name, Reason: "internal-detail",
	}))
	require.NoError(t, recorder.Close())
	return configured
}

func auditCliTestProducerId(t *testing.T, identityFile string) bfAudit.ProducerId {
	t.Helper()
	privateKey, err := LoadAuditPrivateKey(identityFile)
	require.NoError(t, err)
	identity, err := bfAudit.NewIdentity(privateKey)
	require.NoError(t, err)
	return identity.ProducerId()
}

func writeAuditCliTestConfiguration(t *testing.T, directory string, auditlogs ...configuration.Auditlog) string {
	t.Helper()
	raw, err := yaml.Marshal(map[string]any{
		"auditlog": auditlogs,
		"session":  map[string]string{"type": "fs", "storage": filepath.ToSlash(filepath.Join(directory, "sessions"))},
		"flows": []map[string]any{{
			"name": "flow", "auditlog": auditlogs[0].Name,
			"authorization": map[string]string{"type": "simple"},
			"environment":   map[string]string{"type": "dummy"},
		}},
	})
	require.NoError(t, err)
	path := filepath.Join(directory, "configuration.yaml")
	require.NoError(t, os.WriteFile(path, raw, 0600))
	return path
}
