package sys

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/engity-com/bifroest/pkg/errors"
)

type FullDuplexCopyOpts struct {
	OnStart       func()
	OnEnd         func(l2r, r2l int64, duration time.Duration, err error, wasInL2r *bool)
	OnStreamStart func(isL2r bool)
	OnStreamEnd   func(isL2r bool, err error)
}

func FullDuplexCopy(ctx context.Context, left io.ReadWriter, right io.ReadWriter, opts *FullDuplexCopyOpts) (rErr error) {
	type done struct {
		wasL2r bool
		error  error
	}
	dones := make(chan done, 2)
	var wg sync.WaitGroup
	var errWasInL2r *bool
	var l2r, r2l atomic.Int64
	started := time.Now()
	go func() {
		wg.Wait()
		close(dones)

		if opts != nil {
			if f := opts.OnEnd; f != nil {
				f(l2r.Load(), r2l.Load(), time.Since(started), rErr, errWasInL2r)
			}
		}
	}()

	copyFull := func(from io.Reader, to io.Writer, isL2r bool) {
		defer wg.Done()
		if opts != nil {
			if f := opts.OnStreamStart; f != nil {
				f(isL2r)
			}
		}

		n, err := io.Copy(to, from)
		if isRelevantError(err) {
			dones <- done{isL2r, err}
		} else {
			dones <- done{isL2r, nil}
		}
		if isL2r {
			l2r.Store(n)
		} else {
			r2l.Store(n)
		}
		if opts != nil {
			if f := opts.OnStreamEnd; f != nil {
				f(isL2r, err)
			}
		}
	}
	wg.Add(2)
	go copyFull(right, left, false)
	go copyFull(left, right, true)

	if opts != nil {
		if f := opts.OnStart; f != nil {
			f()
		}
	}

	for {
		select {
		case <-ctx.Done():
			if err := ctx.Err(); !isSilentError(err) {
				errWasInL2r = nil
				return err
			}
			return nil
		case v := <-dones:
			if isRelevantError(v.error) {
				errWasInL2r = &v.wasL2r
				return v.error
			}
			return nil
		}
	}
}

func isSilentError(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

func isRelevantError(err error) bool {
	return err != nil && !errors.Is(err, syscall.EIO) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF)
}
