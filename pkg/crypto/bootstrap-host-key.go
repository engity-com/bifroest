package crypto

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	bfssh "github.com/engity-com/bifroest/pkg/ssh"
)

var errHostKeyCaptured = errors.New("SSH host key captured")

var hostKeyScanAlgorithms = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512,
	ssh.KeyAlgoRSASHA256,
}

func FetchKnownHostKey(ctx context.Context, address string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	resolvedAddress, err := bfssh.ParseAddress(address)
	if err != nil {
		return nil, err
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", resolvedAddress.String())
	if err != nil {
		return nil, fmt.Errorf("cannot connect to SSH server %q: %w", resolvedAddress, err)
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("cannot set SSH handshake deadline: %w", err)
		}
	}
	stopClose := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopClose()

	var captured ssh.PublicKey
	config := &ssh.ClientConfig{
		User:              "bifroest-host-key-scan",
		HostKeyAlgorithms: hostKeyScanAlgorithms,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			captured = key
			return errHostKeyCaptured
		},
	}
	_, _, _, handshakeErr := ssh.NewClientConn(connection, resolvedAddress.String(), config)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var networkErr net.Error
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline && !time.Now().Before(deadline) && errors.As(handshakeErr, &networkErr) && networkErr.Timeout() {
		return nil, context.DeadlineExceeded
	}
	if !errors.Is(handshakeErr, errHostKeyCaptured) || captured == nil {
		return nil, fmt.Errorf("cannot retrieve SSH host key from %q: %w", resolvedAddress, handshakeErr)
	}
	host := knownhosts.Normalize(resolvedAddress.String())
	return []byte(knownhosts.Line([]string{host}, captured) + "\n"), nil
}
