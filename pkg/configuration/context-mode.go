package configuration

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/errors"
)

type ContextMode uint8

const (
	ContextModeOnline ContextMode = iota
	ContextModeOffline
	ContextModeDebug
)

var (
	contextModeToName = map[ContextMode]string{
		ContextModeOnline:  "online",
		ContextModeOffline: "offline",
		ContextModeDebug:   "debug",
	}
	nameToContextMode = func(in map[ContextMode]string) map[string]ContextMode {
		result := make(map[string]ContextMode, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(contextModeToName)
)

func (this ContextMode) IsZero() bool {
	return false
}

func (this ContextMode) MarshalText() (text []byte, err error) {
	v, ok := contextModeToName[this]
	if !ok {
		return nil, errors.Config.Newf("illegal context-mode: %d", this)
	}
	return []byte(v), nil
}

func (this ContextMode) String() string {
	v, ok := contextModeToName[this]
	if !ok {
		return fmt.Sprintf("illegal-context-mode-%d", this)
	}
	return v
}

func (this *ContextMode) UnmarshalText(text []byte) error {
	v, ok := nameToContextMode[string(text)]
	if !ok {
		return errors.Config.Newf("illegal context-mode: %s", string(text))
	}
	*this = v
	return nil
}

func (this *ContextMode) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this ContextMode) Validate() error {
	_, err := this.MarshalText()
	return err
}

func (this ContextMode) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case ContextMode:
		return this.isEqualTo(&v)
	case *ContextMode:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this ContextMode) isEqualTo(other *ContextMode) bool {
	return this == *other
}

func (this ContextMode) Clone() ContextMode {
	return this
}
