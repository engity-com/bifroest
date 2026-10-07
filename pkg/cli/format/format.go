package format

import (
	"strings"

	"github.com/engity-com/bifroest/pkg/errors"
)

var (
	ErrIllegal = errors.User.Newf("illegal format")
)

type Format uint8

const (
	Text Format = iota
	Json
	Yaml
)

func (this Format) MarshalText() ([]byte, error) {
	switch this {
	case Text:
		return []byte("text"), nil
	case Json:
		return []byte("json"), nil
	case Yaml:
		return []byte("yaml"), nil
	default:
		return nil, errors.User.Newf("%w: %d", ErrIllegal, this)
	}
}

func (this *Format) UnmarshalText(b []byte) error {
	switch strings.ToLower(string(b)) {
	case "text", "table":
		*this = Text
		return nil
	case "json":
		*this = Json
		return nil
	case "yaml":
		*this = Yaml
		return nil
	default:
		return errors.User.Newf("%w: %s", ErrIllegal, string(b))
	}
}

type Opts struct {
	Format Format `flag:"format" default:"text" description:"Display result as: text, JSON or YAML."`
}
