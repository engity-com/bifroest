package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	gos "os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBrowserLicenseModulesUseResolvedVersionsWithoutAnAllowlist(t *testing.T) {
	for _, version := range []string{"v1.2.3", "v1.3.0"} {
		t.Run(version, func(t *testing.T) {
			dependency := fmt.Sprintf(`{"Module":{"Path":"example.org/new-module","Version":%q}}`, version)
			graph := `{"Standard":true}` + `{"Module":{"Path":"` + projectModule + `","Main":true}}` + dependency + dependency
			modules, err := browserLicenseModules(strings.NewReader(graph))
			require.NoError(t, err)
			require.Len(t, modules, 1, "multiple packages from one module are deduplicated")
			require.Equal(t, "example.org/new-module", modules[0].component)
			require.Equal(t, version, modules[0].version)
		})
	}
}

func TestBrowserLicenseModulesRejectAmbiguousSourceVersions(t *testing.T) {
	for name, graph := range map[string]string{
		"empty":       `{"Standard":true}`,
		"malformed":   `{`,
		"unversioned": `{"Module":{"Path":"example.org/module"}}`,
		"replaced":    `{"Module":{"Path":"example.org/module","Version":"v1.2.3","Replace":{"Dir":"local"}}}`,
		"conflicting": `{"Module":{"Path":"example.org/module","Version":"v1.2.3"}}{"Module":{"Path":"example.org/module","Version":"v1.3.0"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := browserLicenseModules(strings.NewReader(graph))
			require.Error(t, err)
		})
	}
}

func TestBrowserLicenseInventoryCollectsCurrentLicenseAndNoticeTexts(t *testing.T) {
	policy, err := readThirdPartyLicensePolicy(thirdPartyLicensePolicyRaw)
	require.NoError(t, err)
	for _, text := range []string{"MIT license text, copyright first author\n", "MIT license text, copyright updated author\n"} {
		modules, err := browserLicenseModules(strings.NewReader(`{"Module":{"Path":"example.org/module","Version":"v1.2.3"}}`))
		require.NoError(t, err)
		saved := t.TempDir()
		directory := filepath.Join(saved, "example.org", "module")
		require.NoError(t, gos.MkdirAll(directory, 0755))
		notice := "Required attribution notice\n"
		require.NoError(t, gos.WriteFile(filepath.Join(directory, "NOTICE"), []byte(notice), 0644))
		records := []thirdPartyLicenseRecord{{Library: "example.org/module", Version: "v1.2.3", License: "MIT", Text: text}}
		components, err := reconcileThirdPartyComponents(modules, records, saved, policy)
		require.NoError(t, err)
		inventory, err := browserLicenseInventory(components)
		require.NoError(t, err)
		require.Len(t, inventory, 1)
		require.Equal(t, "example.org/module@v1.2.3", inventory[0].Module)
		require.Equal(t, "MIT", inventory[0].License)
		require.Len(t, inventory[0].Files, 2)
		var texts []string
		for _, file := range inventory[0].Files {
			hash := sha256.Sum256([]byte(file.Text))
			require.Equal(t, hex.EncodeToString(hash[:]), file.SHA256)
			texts = append(texts, file.Text)
		}
		require.ElementsMatch(t, []string{text, notice}, texts, "text changes must not require a new checked-in checksum")
		records[0].License = "Unknown"
		_, err = reconcileThirdPartyComponents(modules, records, saved, policy)
		require.Error(t, err, "unclassified licenses still require review")
	}
}
