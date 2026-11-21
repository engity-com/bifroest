package format

import (
	"strings"

	"github.com/engity-com/bifroest/pkg/errors"
)

type MetricsFormat string

const (
	MetricsText        MetricsFormat = "table"
	MetricsJson        MetricsFormat = "json"
	MetricsOpenMetrics MetricsFormat = "openmetrics"
	// MetricsWireCbor is an internal transport envelope, not a user-visible enum value.
	MetricsWireCbor MetricsFormat = "internal-cbor"
)

func (this MetricsFormat) MarshalText() ([]byte, error) {
	switch this {
	case MetricsText, MetricsJson, MetricsOpenMetrics:
		return []byte(this), nil
	default:
		return nil, errors.User.Newf("%w: %s", ErrIllegal, this)
	}
}

func (this *MetricsFormat) UnmarshalText(b []byte) error {
	switch strings.ToLower(string(b)) {
	case "text", "table":
		*this = MetricsText
	case "json":
		*this = MetricsJson
	case "openmetrics":
		*this = MetricsOpenMetrics
	default:
		return errors.User.Newf("%w: %s", ErrIllegal, b)
	}
	return nil
}

type MetricsOpts struct {
	Format MetricsFormat `flag:"format" enum:"table|json|openmetrics" default:"table" description:"Display metrics as table, JSON or OpenMetrics."`
}
