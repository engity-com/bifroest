package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	bfAudit "github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
)

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

func writeAuditCliTestConfiguration(t *testing.T, directory string, auditlogs ...configuration.Auditlog) configuration.Ref {
	t.Helper()
	var raw strings.Builder
	raw.WriteString("auditlog:\n")
	for _, configured := range auditlogs {
		_, _ = fmt.Fprintf(&raw, "  - name: %s\n    enabled: true\n    identityFile: %s\n    directory: %s\n",
			configured.Name, filepath.ToSlash(configured.IdentityFile), filepath.ToSlash(configured.Directory))
		if !configured.EncryptionPublicKey.IsZero() {
			_, _ = fmt.Fprintf(&raw, "    encryptionPublicKey: %q\n", string(configured.EncryptionPublicKey))
		}
	}
	_, _ = fmt.Fprintf(&raw, "flows:\n  - name: flow\n    auditlog: %s\n    authorization:\n      type: simple\n    environment:\n      type: dummy\n", auditlogs[0].Name)
	path := filepath.Join(directory, "configuration.yaml")
	require.NoError(t, os.WriteFile(path, []byte(raw.String()), 0600))
	var ref configuration.Ref
	require.NoError(t, ref.Set(path))
	return ref
}
