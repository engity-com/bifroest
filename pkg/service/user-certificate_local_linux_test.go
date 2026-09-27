//go:build linux

package service

import (
	"os"
	osuser "os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	buser "github.com/engity-com/bifroest/pkg/user"
)

func prepareLocalUserCertificateTest(t *testing.T) string {
	t.Helper()
	const username = "certificate-local-user"
	current, err := osuser.Current()
	require.NoError(t, err)
	userDirectory := t.TempDir()
	passwdFile := filepath.Join(userDirectory, "passwd")
	groupFile := filepath.Join(userDirectory, "group")
	shadowFile := filepath.Join(userDirectory, "shadow")
	require.NoError(t, os.WriteFile(passwdFile, []byte(username+":x:"+current.Uid+":"+current.Gid+"::"+current.HomeDir+":/bin/sh\n"), 0600))
	require.NoError(t, os.WriteFile(groupFile, []byte(username+":x:"+current.Gid+":"+username+"\n"), 0600))
	require.NoError(t, os.WriteFile(shadowFile, []byte(username+":!:19722:0:99999:7:::\n"), 0600))
	previousRepositoryProvider := buser.DefaultRepositoryProvider
	buser.DefaultRepositoryProvider = &buser.SharedRepositoryProvider[*buser.EtcColonRepository]{V: &buser.EtcColonRepository{
		PasswdFilename: passwdFile,
		GroupFilename:  groupFile,
		ShadowFilename: shadowFile,
	}}
	t.Cleanup(func() { buser.DefaultRepositoryProvider = previousRepositoryProvider })
	return username
}

func configureLocalUserCertificateAuthorization(local *configuration.AuthorizationLocal) {
	local.PamService = ""
}
