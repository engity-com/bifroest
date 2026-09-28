package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/engity-com/bifroest/pkg/common"
)

func (this *base) writeBuildEpoch(ctx context.Context) (rErr error) {
	epoch, err := this.execute(ctx, "git", "show", "-s", "--format=%ct", "HEAD").doAndGet()
	if err != nil {
		return fmt.Errorf("cannot determine source date epoch: %w", err)
	}
	if _, err := strconv.ParseUint(epoch, 10, 64); err != nil {
		return fmt.Errorf("invalid commit time %q: %w", epoch, err)
	}
	filename := os.Getenv("GITHUB_ENV")
	if filename == "" {
		return fmt.Errorf("GITHUB_ENV is required to write the build epoch")
	}
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer common.KeepCloseError(&rErr, f)
	_, err = fmt.Fprintf(f, "SOURCE_DATE_EPOCH=%s\n", epoch)
	return err
}
