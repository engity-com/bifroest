package configuration

import (
	"context"
	"os"
	"path/filepath"
	"reflect"

	"github.com/echocat/cli4g/codec"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

func NewCliCodec(mustBeNotZero, mustExist bool) codec.Codec[Configuration, string] {
	return cliCodec{mustBeNotZero, mustExist}
}

// NewOptionalCliCodec decodes an explicitly supplied configuration file. A
// missing flag leaves the pointer nil so the caller can choose its own source.
func NewOptionalCliCodec() codec.Codec[*Configuration, string] {
	return optionalCliCodec{cliCodec{mustBeNotZero: true, mustExist: true}}
}

type optionalCliCodec struct{ cliCodec }

func (c optionalCliCodec) CanHandleType(ctx context.Context, typ reflect.Type) (bool, error) {
	return typ == reflect.TypeFor[*Configuration](), ctx.Err()
}

func (c optionalCliCodec) Resolve(ctx context.Context, scope codec.Scope, path string) (*Configuration, error) {
	if RemoteConfigurationForbidden(ctx) {
		return nil, codec.NewValidationErrorf("--configuration cannot be combined with a remote target")
	}
	resolved, err := c.cliCodec.Resolve(ctx, scope, path)
	if err != nil {
		return nil, err
	}
	return &resolved, nil
}

func (c optionalCliCodec) ToRaw(ctx context.Context) codec.Codec[any, any] {
	return codec.Raw(ctx, c)
}

type cliCodec struct {
	mustBeNotZero bool
	mustExist     bool
}

func (c cliCodec) CanHandleType(ctx context.Context, typ reflect.Type) (bool, error) {
	return typ == reflect.TypeFor[Configuration](), ctx.Err()
}

func (c cliCodec) ExpectMinMax(context.Context, codec.Usage) (int, int) {
	return 1, 1
}

func (c cliCodec) ParseRequirement(ctx context.Context, usage codec.Usage, args ...string) (string, error) {
	if err := codec.EnsureArgumentsMatching(ctx, usage, c, args...); err != nil {
		return "", err
	}
	path := args[0]
	if path == "" && c.mustBeNotZero {
		return "", codec.NewValidationErrorf("configuration path must be not empty")
	}
	return args[0], nil
}

func (c cliCodec) FormatRequirement(_ context.Context, path string) ([]string, error) {
	return []string{path}, nil
}

func (c cliCodec) DisplayRequirement(ctx context.Context, path string) ([]string, error) {
	return c.FormatRequirement(ctx, path)
}

func (c cliCodec) Resolve(ctx context.Context, _ codec.Scope, fn string) (Configuration, error) {
	if err := ctx.Err(); err != nil {
		return Configuration{}, err
	}
	if fn == "" && !c.mustBeNotZero {
		return Configuration{}, nil
	}
	f, err := os.Open(fn)
	if sys.IsNotExist(err) {
		if c.mustExist {
			return Configuration{}, codec.NewValidationErrorf("configuration file %q does not exist", fn)
		}
		return Configuration{}, nil
	}
	if err != nil {
		return Configuration{}, codec.NewValidationErrorf("cannot open configuration file %q: %w", fn, err)
	}
	defer common.IgnoreCloseError(f)
	var result Configuration

	if err := result.LoadFromYaml(f, fn); err != nil {
		return Configuration{}, codec.NewValidationError("cannot load configuration", err)
	}

	return result, nil
}

func (c cliCodec) ToRaw(ctx context.Context) codec.Codec[any, any] {
	return codec.Raw(ctx, c)
}

type Ref struct {
	v  Configuration
	fn string
}

func (this Ref) IsZero() bool {
	return len(this.fn) == 0
}

func (this Ref) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this Ref) String() string {
	return this.fn
}

func (this *Ref) UnmarshalText(text []byte) error {
	buf := Ref{
		fn: string(text),
	}

	if len(buf.fn) > 0 {
		if err := buf.v.LoadFromFile(buf.fn); err != nil {
			return err
		}
	}

	*this = buf
	return nil
}

func (this *Ref) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this *Ref) Get() *Configuration {
	return &this.v
}

func (this *Ref) GetFilename() string {
	return this.fn
}

func (this *Ref) MakeAbsolute() error {
	abs, err := filepath.Abs(this.fn)
	if err != nil {
		return errors.Config.Newf("canont make this configuration file reference absolute: %w", err)
	}
	return this.Set(abs)
}

func (this Ref) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Ref:
		return this.isEqualTo(&v)
	case *Ref:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Ref) isEqualTo(other *Ref) bool {
	return this.fn == other.fn
}
