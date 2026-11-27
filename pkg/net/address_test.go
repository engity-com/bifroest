package net

import (
	gonet "net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddressListenFailureReturnsNilInterface(t *testing.T) {
	occupied, err := gonet.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, occupied.Close()) })

	listener, err := MustNewAddress(occupied.Addr().String()).Listen()
	require.Error(t, err)
	require.True(t, listener == nil, "a failed bind must not return a typed nil listener")
}
