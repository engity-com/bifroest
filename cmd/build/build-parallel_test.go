package main

import (
	"context"
	"errors"
	"fmt"
	gos "os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/sys"
)

func TestParallelPackagingLimitsWorkAndPreservesSourceOrder(t *testing.T) {
	var sources, expected buildArtifacts
	for i := range 8 {
		source := &buildArtifact{filepath: fmt.Sprint(i)}
		sources = append(sources, source)
		expected = append(expected, source, source)
	}
	type outcome struct {
		artifacts buildArtifacts
		err       error
	}
	done := make(chan outcome, 1)
	started := make(chan struct{}, len(sources))
	release := make(chan struct{})
	var active, peak atomic.Int32
	go func() {
		artifacts, err := createBuildArtifactsInParallel(t.Context(), sources, func(ctx context.Context, source *buildArtifact) (buildArtifacts, error) {
			current := active.Add(1)
			defer active.Add(-1)
			for previous := peak.Load(); current > previous; previous = peak.Load() {
				if peak.CompareAndSwap(previous, current) {
					break
				}
			}
			started <- struct{}{}
			select {
			case <-release:
				return buildArtifacts{source, source}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
		done <- outcome{artifacts, err}
	}()
	for range 2 {
		select {
		case <-started:
		case <-time.After(10 * time.Second):
			close(release)
			t.Fatal("packaging did not start two independent tasks")
		}
	}
	require.Equal(t, int32(2), active.Load())
	close(release)
	result := <-done
	require.NoError(t, result.err)
	require.Equal(t, expected, result.artifacts)
	require.Equal(t, int32(2), peak.Load())
	require.Zero(t, active.Load(), "all work must finish before returning")
}

func TestParallelPackagingCancelsJoinsAndClosesPartialResultsOnFailure(t *testing.T) {
	injected := errors.New("packaging failed")
	first, second := &buildArtifact{}, &buildArtifact{}
	started := make(chan struct{})
	var closed, active atomic.Int32
	for _, artifact := range []*buildArtifact{first, second} {
		artifact.addCloser(func() error {
			closed.Add(1)
			return nil
		})
	}
	artifacts, err := createBuildArtifactsInParallel(t.Context(), buildArtifacts{first, second}, func(ctx context.Context, source *buildArtifact) (buildArtifacts, error) {
		active.Add(1)
		defer active.Add(-1)
		if source == first {
			<-started
			return buildArtifacts{source}, injected
		}
		close(started)
		<-ctx.Done()
		return buildArtifacts{source}, ctx.Err()
	})
	require.ErrorIs(t, err, injected, "keep the root failure, not a secondary cancellation")
	require.Nil(t, artifacts, "never publish partial results")
	require.Equal(t, int32(2), closed.Load())
	require.Zero(t, active.Load())
}

func TestParallelPackagingHonorsCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	called := false
	artifacts, err := createBuildArtifactsInParallel(ctx, buildArtifacts{{}}, func(context.Context, *buildArtifact) (buildArtifacts, error) {
		called = true
		return nil, nil
	})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, artifacts)
	require.False(t, called)
}

func TestParallelArchivesMatchSerialBytesForEveryPlatform(t *testing.T) {
	b, bc := testReleaseManifestBuild(t)
	b.buildContextP.Store(bc)
	b.archive.includedResources = nil
	b.binaryMode = binaryUseExisting
	b.rawStages = buildStages{buildStageBinary, buildStageArchive}
	var binaries buildArtifacts
	for p := range b.distributablePlatforms(false) {
		prefix := p.FilenamePrefix(b.prefix)
		binary := testReleaseManifestFile(t, bc, p, buildArtifactTypeBinary, p.Os.AppendExtToFilename(prefix), "binary:"+p.String(), nil)
		notice := testReleaseManifestFile(t, bc, p, buildArtifactTypeNotice, prefix+".third-party-notices.txt", "notices:"+p.String(), nil)
		binary.thirdPartyNoticesFilepath, binary.thirdPartyLicenseInventory = notice.filepath, testThirdPartyLicenseInventory()
		testBrowserManifest(t, binary)
		require.NoError(t, b.binary.save(binary, notice))
		binaries = append(binaries, binary)
	}
	require.Len(t, binaries, 14)
	t.Chdir(filepath.Join("..", ".."))
	serial := map[string][]byte{}
	for _, binary := range binaries {
		archive, err := b.archive.create(t.Context(), binary)
		require.NoError(t, err)
		raw, err := gos.ReadFile(archive.filepath)
		require.NoError(t, err)
		serial[archive.name()] = raw
		require.NoError(t, archive.Close())
		require.NoError(t, gos.Remove(archive.filepath))
	}
	artifacts, err := b.buildAll(t.Context(), false)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, artifacts.Close()) })
	var names []string
	for archive := range artifacts.onlyOfType(buildArtifactTypeArchive) {
		raw, err := gos.ReadFile(archive.filepath)
		require.NoError(t, err)
		require.Equal(t, serial[archive.name()], raw, archive.name())
		names = append(names, archive.name())
	}
	require.Len(t, names, 14)
	slices.Sort(names)
	require.Equal(t, "bifroest-darwin-amd64-generic.tgz", names[0])
}

func TestParallelArchiveFailurePreventsPreparedPackagePlan(t *testing.T) {
	b, bc := testReleaseManifestBuild(t)
	b.buildContextP.Store(bc)
	b.binaryMode, b.preparePackages = binaryUseExisting, true
	b.rawStages = buildStages{buildStageBinary, buildStageArchive}
	b.oses, b.archs, b.editions = sys.Oses{sys.OsLinux}, sys.Archs{sys.ArchAmd64}, sys.Editions{sys.EditionGeneric}
	b.archive.includedResources = nil
	p := &bib.Platform{Os: sys.OsLinux, Arch: sys.ArchAmd64, Edition: sys.EditionGeneric}
	prefix := p.FilenamePrefix(b.prefix)
	binary := testReleaseManifestFile(t, bc, p, buildArtifactTypeBinary, prefix, "binary", nil)
	notice := testReleaseManifestFile(t, bc, p, buildArtifactTypeNotice, prefix+".third-party-notices.txt", "notices", nil)
	binary.thirdPartyNoticesFilepath, binary.thirdPartyLicenseInventory = notice.filepath, testThirdPartyLicenseInventory()
	testBrowserManifest(t, binary)
	require.NoError(t, b.binary.save(binary, notice))
	t.Chdir(t.TempDir()) // Required release licenses are absent.
	artifacts, err := b.buildAll(t.Context(), false)
	require.Error(t, err)
	require.Nil(t, artifacts)
	_, err = gos.Stat(filepath.Join(b.dest, preparedPackagesFilename))
	require.ErrorIs(t, err, gos.ErrNotExist)
}

func TestParallelSbomFailureDoesNotReturnIncompleteInventory(t *testing.T) {
	b, _ := testReleaseManifestBuild(t)
	// No license inventory: fail before looking up Syft, regardless of platform.
	source := &buildArtifact{Platform: &testSbomPlatform, t: buildArtifactTypeArchive}
	artifacts, err := b.sbom.create(t.Context(), buildArtifacts{source})
	require.ErrorContains(t, err, "has no third-party license inventory")
	require.Nil(t, artifacts)
}
