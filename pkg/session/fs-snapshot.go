package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/configuration"
)

// InspectFsSessions reads session metadata without acquiring the writer's
// exclusive process lock. It only exposes Info, so the caller cannot mutate
// sessions through the returned values. Automatic cleanup is always disabled.
func InspectFsSessions(ctx context.Context, conf *configuration.SessionFs, consumer func(context.Context, Info) (bool, error), diagnostics FindDiagnosticConsumer) error {
	if consumer == nil {
		return fmt.Errorf("session inspection requires a consumer")
	}
	if conf == nil {
		return fmt.Errorf("session inspection requires an FS configuration")
	}
	storage := conf.Storage
	path, err := filepath.EvalSymlinks(storage)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot inspect session storage %q: %w", storage, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("session storage %q is not a directory", storage)
	}
	noCleanup := false
	repository := &FsRepository{storage: path, conf: conf}
	return repository.FindAll(ctx, func(ctx context.Context, found Session) (bool, error) {
		result, err := found.Info(ctx)
		if err != nil {
			return false, err
		}
		return consumer(ctx, result)
	}, &FindOpts{AutoCleanUpAllowed: &noCleanup, DiagnosticConsumer: diagnostics})
}
