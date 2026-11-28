package environment

import (
	"context"
	"errors"
	"testing"

	"github.com/moby/moby/client"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
)

type dockerPreparationTestClient struct {
	client.APIClient
	version   client.ServerVersionResult
	probeErr  error
	closeErr  error
	closes    int
	onVersion func()
}

func (this *dockerPreparationTestClient) ServerVersion(context.Context, client.ServerVersionOptions) (client.ServerVersionResult, error) {
	if this.onVersion != nil {
		this.onVersion()
	}
	return this.version, this.probeErr
}

func (this *dockerPreparationTestClient) Close() error {
	this.closes++
	return this.closeErr
}

func TestDockerPreparationReleasesClientOnEveryFailureAndTransfersItOnSuccess(t *testing.T) {
	for _, mode := range []string{"probe", "os", "arch", "canceled", "success"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			api := &dockerPreparationTestClient{}
			api.version.Os, api.version.Arch = "linux", "amd64"
			closeErr := errors.New("injected client close failure")
			if mode != "success" {
				api.closeErr = closeErr
			}
			switch mode {
			case "probe":
				api.probeErr = errors.New("injected version probe failure")
			case "os":
				api.version.Os = "invalid"
			case "arch":
				api.version.Arch = "invalid"
			case "canceled":
				api.onVersion = cancel
			}
			conf := &configuration.EnvironmentDocker{}
			repository, err := newDockerRepositoryUsing(ctx, "work", conf, nil, nil, func(*configuration.EnvironmentDocker) (client.APIClient, error) {
				return api, nil
			})
			if mode == "success" {
				require.NoError(t, err)
				require.Zero(t, api.closes)
				require.NoError(t, repository.Close())
				require.NoError(t, repository.Close())
			} else {
				require.Nil(t, repository)
				require.ErrorIs(t, err, closeErr)
				switch mode {
				case "probe":
					require.ErrorIs(t, err, api.probeErr)
				case "canceled":
					require.ErrorIs(t, err, context.Canceled)
				}
			}
			require.Equal(t, 1, api.closes)
		})
	}
}
