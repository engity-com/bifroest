package configuration

import (
	"github.com/engity-com/bifroest/pkg/common"
	"gopkg.in/yaml.v3"
	"time"
)

var (
	DefaultHouseKeepingEvery        = common.DurationOf(time.Minute * 10)
	DefaultHouseKeepingInitialDelay = common.DurationOf(0)
	DefaultHouseKeepingAutoRepair   = true

	// DefaultHouseKeepingKeepExpiredFor is the default setting for HouseKeeping.KeepExpiredFor.
	DefaultHouseKeepingKeepExpiredFor = common.DurationOf(14 * 24 * time.Hour)
)

type HouseKeeping struct {
	Every        common.Duration `yaml:"every"`
	InitialDelay common.Duration `yaml:"initialDelay"`

	// AutoRepair tells the housekeeping service to repair/cleanup broken or
	// unwanted stuff automatically, if possible. Defaults to DefaultHouseKeepingAutoRepair.
	AutoRepair bool `yaml:"autoRepair"`

	// KeepExpiredFor defines for how long a session should be kept before it will finally delete, although it
	// is already expired. In case of 0 it will be deleted immediately.
	// Defaults to DefaultHouseKeepingKeepExpiredFor
	KeepExpiredFor common.Duration `yaml:"keepExpiredFor"`
}

func (this *HouseKeeping) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("every", func(v *HouseKeeping) *common.Duration { return &v.Every }, DefaultHouseKeepingEvery),
		fixedDefault("initialDelay", func(v *HouseKeeping) *common.Duration { return &v.InitialDelay }, DefaultHouseKeepingInitialDelay),
		fixedDefault("autoRepair", func(v *HouseKeeping) *bool { return &v.AutoRepair }, DefaultHouseKeepingAutoRepair),
		fixedDefault("keepExpiredFor", func(v *HouseKeeping) *common.Duration { return &v.KeepExpiredFor }, DefaultHouseKeepingKeepExpiredFor),
	)
}

func (this *HouseKeeping) Trim() error {
	return trim(this,
		noopTrim[HouseKeeping]("every"),
		noopTrim[HouseKeeping]("initialDelay"),
		noopTrim[HouseKeeping]("autoRepair"),
		noopTrim[HouseKeeping]("keepExpiredFor"),
	)
}

func (this *HouseKeeping) Validate() error {
	return validate(this,
		noopValidate[HouseKeeping]("every"),
		noopValidate[HouseKeeping]("initialDelay"),
		noopValidate[HouseKeeping]("autoRepair"),
		noopValidate[HouseKeeping]("keepExpiredFor"),
	)
}

func (this *HouseKeeping) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *HouseKeeping, node *yaml.Node) error {
		type raw HouseKeeping
		return node.Decode((*raw)(target))
	})
}

func (this HouseKeeping) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case HouseKeeping:
		return this.isEqualTo(&v)
	case *HouseKeeping:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this HouseKeeping) isEqualTo(other *HouseKeeping) bool {
	return isEqual(&this.Every, &other.Every) &&
		isEqual(&this.InitialDelay, &other.InitialDelay) &&
		this.AutoRepair == other.AutoRepair &&
		isEqual(&this.KeepExpiredFor, &other.KeepExpiredFor)
}
