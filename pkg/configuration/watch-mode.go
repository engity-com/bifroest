package configuration

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/errors"
)

// WatchMode is a process-start option, not a property of Configuration.
type WatchMode uint8

const (
	WatchModeOff WatchMode = iota
	WatchModePreserve
	WatchModeReconnect
	WatchModeReuse
)

var (
	watchModeToName = map[WatchMode]string{
		WatchModeOff: "off", WatchModePreserve: "preserve",
		WatchModeReconnect: "reconnect", WatchModeReuse: "reuse",
	}
	nameToWatchMode = func(in map[WatchMode]string) map[string]WatchMode {
		result := make(map[string]WatchMode, len(in)+4)
		for value, name := range in {
			result[name] = value
		}
		result["false"], result["no"], result["0"] = WatchModeOff, WatchModeOff, WatchModeOff
		// cli4g's optional-value flag adapter supplies true for a bare --watch.
		result["true"] = WatchModePreserve
		return result
	}(watchModeToName)
)

func (this WatchMode) IsZero() bool     { return this == WatchModeOff }
func (this WatchMode) IsEnabled() bool  { return this != WatchModeOff }
func (this WatchMode) IsBoolFlag() bool { return true }

func (this WatchMode) MarshalText() ([]byte, error) {
	name, ok := watchModeToName[this]
	if !ok {
		return nil, errors.Config.Newf("illegal watch mode: %d", this)
	}
	return []byte(name), nil
}

func (this WatchMode) String() string {
	if name, ok := watchModeToName[this]; ok {
		return name
	}
	return fmt.Sprintf("illegal-watch-mode-%d", this)
}

func (this *WatchMode) UnmarshalText(text []byte) error {
	value, ok := nameToWatchMode[string(text)]
	if !ok {
		return errors.Config.Newf("illegal watch mode: %s", string(text))
	}
	*this = value
	return nil
}

func (this *WatchMode) Set(text string) error { return this.UnmarshalText([]byte(text)) }
func (this WatchMode) Validate() error        { _, err := this.MarshalText(); return err }
func (this WatchMode) Clone() WatchMode       { return this }

func (this WatchMode) IsEqualTo(other any) bool {
	switch value := other.(type) {
	case WatchMode:
		return this == value
	case *WatchMode:
		return value != nil && this == *value
	default:
		return false
	}
}
