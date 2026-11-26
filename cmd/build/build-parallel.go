package main

import (
	"context"
	"sync"

	"github.com/engity-com/bifroest/pkg/common"
)

// Limit CPU/memory-heavy packaging work without adding runners or changing the
// order of artifacts. Always join workers before returning or closing outputs.
func createBuildArtifactsInParallel(ctx context.Context, sources buildArtifacts, create func(context.Context, *buildArtifact) (buildArtifacts, error)) (buildArtifacts, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make([]buildArtifacts, len(sources))
	slots := make(chan struct{}, 2)
	var workers sync.WaitGroup
	var failed sync.Once
	var firstError error
	for i, source := range sources {
		workers.Go(func() {
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				return
			}
			if ctx.Err() != nil {
				return
			}
			artifacts, err := create(ctx, source)
			results[i] = artifacts
			if err != nil {
				failed.Do(func() {
					firstError = err
					cancel()
				})
			}
		})
	}
	workers.Wait()
	var result buildArtifacts
	for _, artifacts := range results {
		result = append(result, artifacts...)
	}
	if firstError == nil {
		firstError = ctx.Err()
	}
	if firstError != nil {
		common.IgnoreCloseError(result)
		return nil, firstError
	}
	return result, nil
}
