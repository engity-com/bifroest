package sys

import (
	"fmt"
	"slices"
	"strings"
)

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

func (this Os) Validate() error {
	_, err := this.MarshalText()
	return err
}

func (this Os) AppendExtToFilename(filename string) string {
	v := osToExt[this]
	return filename + v
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

func (this Os) IsUnix() bool {
	switch this {
	case OsLinux:
		return true
	default:
		return false
	}
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

type Oses []Os

func (this Oses) String() string {
	return strings.Join(this.Strings(), ",")
}

func (this Oses) Strings() []string {
	strs := make([]string, len(this))
	for i, v := range this {
		strs[i] = v.String()
	}
	return strs
}

func (this *Oses) Set(plain string) error {
	parts := strings.Split(plain, ",")
	buf := make(Oses, len(parts))
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if err := buf[i].Set(part); err != nil {
			return err
		}
	}
	*this = buf
	return nil
}

func AllOsVariants() Oses {
	return slices.Clone(allOsVariants)
}

var (
	osToName = map[Os]string{
		OsLinux:   "linux",
		OsWindows: "windows",
	}
	osToExt = map[Os]string{
		OsWindows: ".exe",
	}
	stringToOs = func(in map[Os]string) map[string]Os {
		result := make(map[string]Os, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(osToName)
	allOsVariants = func(in map[Os]string) Oses {
		result := make(Oses, len(in))
		var i int
		for k := range in {
			result[i] = k
			i++
		}
		return result
	}(osToName)
)
