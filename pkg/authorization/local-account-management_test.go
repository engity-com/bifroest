//go:build unix || windows

package authorization

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/errors"
)

type localManagedFieldTestView struct {
	get func(string) (any, bool, error)
}

func (this localManagedFieldTestView) GetField(name string) (any, bool, error) { return this.get(name) }

func TestLocalManagementFieldOverlayPreservesKnownNilAndBooleanValues(t *testing.T) {
	no, yes := false, true
	for _, managed := range []*bool{nil, &no, &yes} {
		view := localAccountWithManagement{account: localManagedFieldTestView{get: func(string) (any, bool, error) {
			panic("a resolved management observation must not query the underlying account")
		}}, managed: managed}
		value, present, err := view.GetField("managed")
		require.NoError(t, err)
		require.True(t, present)
		if managed == nil {
			require.Nil(t, value)
		} else {
			require.Equal(t, *managed, value)
		}
	}
}

func TestLocalManagementFieldOverlayRetainsMetadataAndErrorTypes(t *testing.T) {
	upstream := errors.Network.Newf("metadata unavailable")
	view := localAccountWithManagement{account: localManagedFieldTestView{get: func(name string) (any, bool, error) {
		require.Equal(t, "homeDir", name)
		return nil, false, upstream
	}}}
	value, present, err := view.GetField("homeDir")
	require.ErrorIs(t, err, upstream)
	require.True(t, errors.Network.IsErr(err))
	require.Nil(t, value)
	require.False(t, present)
	_, _, err = (localAccountWithManagement{}).GetField("homeDir")
	require.ErrorIs(t, err, ErrLocalAccountViewUnavailable)
	require.True(t, errors.System.IsErr(err))
}
