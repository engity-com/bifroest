package managementclient

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPageantRequestChecksBoundsBeforeContact(t *testing.T) {
	_, err := pageantQuery(nil)
	require.ErrorContains(t, err, "invalid")
	_, err = pageantQuery([]byte{0, 0, 0, 8, 1})
	require.ErrorContains(t, err, "invalid")
	oversized := make([]byte, pageantMaxMessage+1)
	binary.BigEndian.PutUint32(oversized[:4], uint32(len(oversized)-4))
	_, err = pageantQuery(oversized)
	require.ErrorContains(t, err, "oversized")
}
