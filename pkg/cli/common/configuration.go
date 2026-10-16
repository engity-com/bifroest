package common

import (
	"context"
	"fmt"
	os2 "os"

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
	if configuration.RemoteConfigurationForbidden(ctx) {
		return options.GetConfiguration(), nil
	}
	if conf := options.GetConfiguration(); conf != nil {
		return conf, nil
	}
	var ref configuration.Ref
	if err := ref.Set(configuration.DefaultRef); err != nil {
		return nil, err
	}
	return ref.Get(), nil
}

func WorkingDirectory() string {
	v, err := os2.Getwd()
	if err == nil {
		return v
	}
	return "/"
}
