package common

import (
	"context"
	"fmt"
	os2 "os"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/configuration"
)

type ConfigurationOptions interface {
	GetConfiguration() *configuration.Configuration
}

// ResolveConfiguration selects the invocation's server configuration or its
// already decoded executable option. Remote invocations return the explicit
// option (normally nil), never loading the local default file.
func ResolveConfiguration[O ConfigurationOptions](ctx context.Context, options O) (*configuration.Configuration, error) {
	if access, ok := ManagementAccessFromContext(ctx); ok {
		if access.Configuration == nil {
			return nil, fmt.Errorf("management configuration is unavailable")
		}
		return access.Configuration, nil
	}
	if cli.ContextContainsProfile(ctx, ProfileRemote) {
		return options.GetConfiguration(), nil
	}
	if conf := options.GetConfiguration(); conf != nil {
		return conf, nil
	}
	if !cli.ContextContainsProfile(ctx, ProfileExecutable) {
		return nil, fmt.Errorf("local configuration requires the executable profile")
	}
	var result configuration.Configuration
	if err := result.LoadFromFile(configuration.DefaultFilename); err != nil {
		return nil, err
	}
	return &result, nil
}

func WorkingDirectory() string {
	v, err := os2.Getwd()
	if err == nil {
		return v
	}
	return "/"
}
