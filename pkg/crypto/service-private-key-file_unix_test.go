//go:build unix

package crypto

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type serviceKeyFileInfo struct {
	mode os.FileMode
	stat syscall.Stat_t
}

func (this serviceKeyFileInfo) Name() string       { return "key" }
func (this serviceKeyFileInfo) Size() int64        { return 100 }
func (this serviceKeyFileInfo) Mode() os.FileMode  { return this.mode }
func (this serviceKeyFileInfo) ModTime() time.Time { return time.Time{} }
func (this serviceKeyFileInfo) IsDir() bool        { return false }
func (this serviceKeyFileInfo) Sys() any           { return &this.stat }

func TestServicePrivateKeysOnlyAllowReadOnlyRootManagedPrimaryGroup(t *testing.T) {
	file := serviceKeyFileInfo{mode: 0440, stat: syscall.Stat_t{Uid: 0, Gid: uint32(os.Getegid()), Nlink: 1}}
	require.NoError(t, validateServicePrivateKeyFile("redacted", nil, file))
	require.Error(t, validateSecurePrivateKeyFile("redacted", nil, file), "strict state/SSH policy is unchanged")
	for _, mutate := range []func(*serviceKeyFileInfo){
		func(v *serviceKeyFileInfo) { v.mode = 0640 },
		func(v *serviceKeyFileInfo) { v.mode = 0460 },
		func(v *serviceKeyFileInfo) { v.mode = 0444 },
		func(v *serviceKeyFileInfo) { v.stat.Uid = uint32(os.Geteuid() + 1) },
		func(v *serviceKeyFileInfo) { v.stat.Gid++ },
		func(v *serviceKeyFileInfo) { v.stat.Nlink = 2 },
	} {
		candidate := file
		mutate(&candidate)
		require.Error(t, validateServicePrivateKeyFile("redacted", nil, candidate))
	}
}
