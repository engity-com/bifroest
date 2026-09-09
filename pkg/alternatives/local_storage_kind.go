//go:build local_build && local_kind

package alternatives

import (
	"context"
	"io"
	goos "os"
	"os/exec"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"sigs.k8s.io/kind/pkg/cluster"
	"sigs.k8s.io/kind/pkg/cluster/nodes"
	"sigs.k8s.io/kind/pkg/cluster/nodeutils"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
)

func writeToLocalStorage(ctx context.Context, tag name.Tag, img v1.Image) error {
	if err := writeToLocalDockerDaemon(ctx, tag, img); err != nil {
		return err
	}

	return ensureInLocalStorage(ctx, tag, img)
}

func ensureInLocalStorage(ctx context.Context, tag name.Tag, img v1.Image) error {
	fail := func(err error) error {
		return errors.System.Newf("cannot write oci image %v to local kind cluster: %w", tag, err)
	}
	failf := func(message string, args ...any) error {
		return fail(errors.System.Newf(message, args...))
	}

	if err := ctx.Err(); err != nil {
		return fail(err)
	}

	provider, err := newLocalKindProvider()
	if err != nil {
		return fail(err)
	}
	clusters, err := provider.List()
	if err != nil {
		return failf("cannot list clusters: %w", err)
	}
	clusterName, err := selectLocalKindCluster(clusters, goos.Getenv("BIFROEST_LOCAL_KIND_CLUSTER"))
	if err != nil {
		return fail(err)
	}

	allNodes, err := provider.ListInternalNodes(clusterName)
	if err != nil {
		return failf("cannot list nodes of cluster %q: %w", clusterName, err)
	}
	if len(allNodes) == 0 {
		return failf("cluster %q does not have any internal nodes", clusterName)
	}

	imageId, err := img.ConfigName()
	if err != nil {
		return failf("cannot resolve image ID: %w", err)
	}

	var targetNodes []nodes.Node
	for _, node := range allNodes {
		actualImageId, err := nodeutils.ImageID(node, tag.String())
		if err == nil && actualImageId == imageId.String() {
			continue
		}
		targetNodes = append(targetNodes, node)
	}
	if len(targetNodes) == 0 {
		return nil
	}

	archive, err := goos.CreateTemp("", "bifroest-kind-image-*.tar")
	if err != nil {
		return failf("cannot create temporary image archive: %w", err)
	}
	archiveName := archive.Name()
	defer common.IgnoreError(func() error { return goos.Remove(archiveName) })

	if err := tarball.Write(tag, img, archive); err != nil {
		common.IgnoreCloseError(archive)
		return failf("cannot write temporary image archive: %w", err)
	}
	if err := archive.Close(); err != nil {
		return failf("cannot close temporary image archive: %w", err)
	}

	for _, node := range targetNodes {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}

		archive, err := goos.Open(archiveName)
		if err != nil {
			return failf("cannot open temporary image archive for node %q: %w", node.String(), err)
		}
		loadErr := nodeutils.LoadImageArchive(node, archive)
		closeErr := archive.Close()
		if loadErr != nil {
			return failf("cannot load image into node %q of cluster %q: %w", node.String(), clusterName, loadErr)
		}
		if closeErr != nil {
			return failf("cannot close temporary image archive for node %q: %w", node.String(), closeErr)
		}
	}

	return nil
}

func selectLocalKindCluster(clusters []string, requested string) (string, error) {
	if requested != "" {
		for _, candidate := range clusters {
			if candidate == requested {
				return requested, nil
			}
		}
		return "", errors.System.Newf("requested cluster %q not found in %v", requested, clusters)
	}
	if len(clusters) != 1 {
		return "", errors.System.Newf("expected exactly one cluster, got %d: %v", len(clusters), clusters)
	}
	return clusters[0], nil
}

func newLocalKindProvider() (*cluster.Provider, error) {
	provider, err := resolveLocalKindProvider(goos.Getenv("KIND_EXPERIMENTAL_PROVIDER"), localKindProviderAvailable)
	if err != nil {
		return nil, err
	}
	var option cluster.ProviderOption
	switch provider {
	case "docker":
		option = cluster.ProviderWithDocker()
	case "podman":
		option = cluster.ProviderWithPodman()
	}

	return cluster.NewProvider(option), nil
}

func resolveLocalKindProvider(provider string, available func(string) bool) (string, error) {
	if provider == "" {
		for _, candidate := range []string{"docker", "podman"} {
			if available(candidate) {
				return candidate, nil
			}
		}
		return "", errors.Config.Newf("cannot detect an available Docker or Podman provider for local kind image storage")
	}
	if provider != "docker" && provider != "podman" {
		return "", errors.Config.Newf("unsupported KIND_EXPERIMENTAL_PROVIDER value %q; local kind image storage requires a Docker-compatible Docker or Podman API", provider)
	}
	return provider, nil
}

func localKindProviderAvailable(provider string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, provider, "info")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}
