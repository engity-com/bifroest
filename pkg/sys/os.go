package sys

import "fmt"

type Os uint8

const (
	OsUnknown Os = iota
	OsLinux
	OsWindows
)

func (this Os) String() string {
	v, ok := osToName[this]
	if !ok {
		return fmt.Sprintf("illegal-os-%d", this)
	}
	return v
}

func (this Os) MarshalText() ([]byte, error) {
	v, ok := osToName[this]
	if !ok {
		return nil, fmt.Errorf("illegal-os: %d", this)
	}
	return []byte(v), nil
}

func (this *Os) UnmarshalText(in []byte) error {
	v, ok := stringToOs[string(in)]
	if !ok {
		return fmt.Errorf("illegal-os: %s", string(in))
	}
	*this = v
	return nil
}

func (this *Os) Set(plain string) error {
	return this.UnmarshalText([]byte(plain))
}

func (this *Os) SetOci(plain string) error {
	return this.Set(plain)
}

func (this Os) IsZero() bool {
	return this == 0
}

func (this Os) IsEqualTo(other any) bool {
	switch v := other.(type) {
	case Os:
		return this == v
	case *Os:
		return this == *v
	default:
		return false
	}
}

var (
	osToName = map[Os]string{
		OsLinux:   "linux",
		OsWindows: "windows",
	}
	stringToOs = func(in map[Os]string) map[string]Os {
		result := make(map[string]Os, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(osToName)
)
