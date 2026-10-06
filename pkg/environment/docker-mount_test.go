package environment

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/moby/moby/api/types/mount"
	"github.com/stretchr/testify/require"
)

func TestParseDockerMount(t *testing.T) {
	for _, test := range []struct {
		name, input string
		want        mount.Mount
	}{
		{
			name:  "bind with relative source and aliases",
			input: "dst=/workspace,src=./data,type=bind,ro,bind-propagation=rprivate,bind-recursive=readonly,bind-create-src=false",
			want: mount.Mount{
				Type: mount.TypeBind, Source: filepath.Join(mustGetwd(t), "data"), Target: "/workspace", ReadOnly: true,
				BindOptions: &mount.BindOptions{Propagation: mount.PropagationRPrivate, ReadOnlyForceRecursive: true},
			},
		},
		{
			name:  "default volume and quoted comma",
			input: `source=cache,target=/data,volume-driver=local,"volume-opt=device=/path,with,commas",volume-label=team=infra,volume-nocopy`,
			want: mount.Mount{
				Type: mount.TypeVolume, Source: "cache", Target: "/data",
				VolumeOptions: &mount.VolumeOptions{
					NoCopy: true, Labels: map[string]string{"team": "infra"},
					DriverConfig: &mount.Driver{Name: "local", Options: map[string]string{"device": "/path,with,commas"}},
				},
			},
		},
		{
			name:  "tmpfs",
			input: "type=tmpfs,target=/tmp,tmpfs-size=2m,tmpfs-mode=1770",
			want:  mount.Mount{Type: mount.TypeTmpfs, Target: "/tmp", TmpfsOptions: &mount.TmpfsOptions{SizeBytes: 2 * 1024 * 1024, Mode: os.FileMode(01770)}},
		},
		{
			name:  "image",
			input: "type=image,src=example:latest,target=/base,image-subpath=tools,readonly=false",
			want:  mount.Mount{Type: mount.TypeImage, Source: "example:latest", Target: "/base", ImageOptions: &mount.ImageOptions{Subpath: "tools"}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseDockerMount(test.input)
			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}

func TestParseDockerMountRejectsInvalidOptions(t *testing.T) {
	for _, input := range []string{
		"", "type=bind,src=/tmp,target=/data,unknown=true", "type=bind,,target=/data",
		"type=tmpfs,target=/tmp,volume-nocopy", "type=volume,target=/data,bind-propagation=rprivate",
		"type=bind,target=/data,bind-recursive=readonly,readonly", "type=bind,target=/data,bind-recursive=writable",
		"type=bind,target=/data,bind-nonrecursive", "type=bind,target=/data,ro=maybe",
		"type=tmpfs,target=/tmp,tmpfs-size=invalid", "type=tmpfs,target=/tmp,tmpfs-mode=invalid",
		"type=bind,target= /data", "type=bind,target=/data\ntype=volume,target=/other",
	} {
		t.Run(input, func(t *testing.T) {
			_, err := parseDockerMount(input)
			require.Error(t, err)
		})
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	return wd
}
