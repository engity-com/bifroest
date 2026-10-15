package format

import (
	"strings"

	"github.com/engity-com/bifroest/pkg/errors"
)

var ErrIllegal = errors.User.Newf("illegal format")

type Format string

const (
	Text Format = "table"
	Json Format = "json"
	Yaml Format = "yaml"
	Cbor Format = "cbor"
	// WireCbor is an internal transport envelope, not a user-visible enum value.
	WireCbor Format = "internal-cbor"
)

func (this Format) MarshalText() ([]byte, error) {
	switch this {
	case Text, Json, Yaml, Cbor:
		return []byte(this), nil
	default:
		return nil, errors.User.Newf("%w: %s", ErrIllegal, this)
	}
}

func (this *Format) UnmarshalText(b []byte) error {
	switch strings.ToLower(string(b)) {
	case "text", "table":
		*this = Text
	case "json":
		*this = Json
	case "yaml":
		*this = Yaml
	case "cbor":
		*this = Cbor
	default:
		return errors.User.Newf("%w: %s", ErrIllegal, b)
	}
	return nil
}

type Opts struct {
	Format Format `flag:"format" enum:"table|json|yaml|cbor" default:"table" description:"Display result as table, JSON, YAML or CBOR."`
}
