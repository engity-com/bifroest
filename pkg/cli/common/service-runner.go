package common

import (
	"context"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/sys"
)

// ServiceRunner starts the executable's SSH service. It is supplied when the
// executable CLI is built; management invocations cannot activate serve.
type ServiceRunner func(context.Context, configuration.Configuration, sys.Version) error
