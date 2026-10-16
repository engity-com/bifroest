package configuration

import (
	"context"
	"reflect"

	cli "github.com/echocat/cli4g"
	"github.com/echocat/cli4g/codec"
)

// NewCliCodec loads a *Configuration from a non-empty file path.
// Whether a flag is required, optional or has a default belongs to its schema;
// an absent optional flag leaves its *Configuration nil without loading a file.
// Resolving requires the executable profile exclusively. The caller supplies
// its name so configuration does not depend on CLI command packages.
func NewCliCodec(executableProfile string) codec.Codec[*Configuration, string] {
	return cliCodec{executableProfile: executableProfile}
}

type cliCodec struct{ executableProfile string }

func (c cliCodec) CanHandleType(ctx context.Context, typ reflect.Type) (bool, error) {
	return typ == reflect.TypeFor[*Configuration](), ctx.Err()
}

func (c cliCodec) ExpectMinMax(context.Context, codec.Usage) (int, int) {
	return 1, 1
}

func (c cliCodec) ParseRequirement(ctx context.Context, usage codec.Usage, args ...string) (string, error) {
	if err := codec.EnsureArgumentsMatching(ctx, usage, c, args...); err != nil {
		return "", err
	}
	if args[0] == "" {
		return "", codec.NewValidationError("configuration path must not be empty")
	}
	return args[0], ctx.Err()
}

func (c cliCodec) FormatRequirement(ctx context.Context, path string) ([]string, error) {
	return []string{path}, ctx.Err()
}

func (c cliCodec) DisplayRequirement(ctx context.Context, path string) ([]string, error) {
	return c.FormatRequirement(ctx, path)
}

func (c cliCodec) Resolve(ctx context.Context, _ codec.Scope, path string) (*Configuration, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	profiles, _ := cli.ProfilesFromContext(ctx)
	allowed := false
	for selected := range profiles {
		if selected != c.executableProfile {
			allowed = false
			break
		}
		allowed = true
	}
	if !allowed {
		return nil, codec.NewValidationError("configuration files require the executable profile exclusively")
	}
	var result Configuration
	if err := result.LoadFromFile(path); err != nil {
		return nil, codec.NewValidationError("cannot load configuration", err)
	}
	return &result, ctx.Err()
}

func (c cliCodec) ToRaw(ctx context.Context) codec.Codec[any, any] {
	return codec.Raw(ctx, c)
}
