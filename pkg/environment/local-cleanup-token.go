package environment

import (
	"bytes"
	"context"
	"fmt"

	"github.com/engity-com/bifroest/pkg/session"
)

func updateLocalCleanupToken(ctx context.Context, sess session.Session, previous, updated []byte) error {
	if writer, ok := sess.(session.EnvironmentCleanupTokenUpdater); ok {
		return writer.UpdateEnvironmentTokenForCleanup(ctx, previous, updated)
	}
	current, err := sess.EnvironmentToken(ctx)
	if err != nil {
		return err
	}
	if len(current) == 0 || !bytes.Equal(current, previous) {
		return fmt.Errorf("environment token changed during account cleanup")
	}
	return sess.SetEnvironmentToken(ctx, updated)
}
