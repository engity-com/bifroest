package sys

import (
	"fmt"
	"slices"
	"strings"
)

type Arch uint8

const (
	ArchUnknown Arch = iota
	Arch386
	ArchAmd64
	ArchArmV6
	ArchArmV7
	ArchArm64
	ArchMips64Le
	ArchRiscV64
)

type archDetails struct {
	name string
	bare string
	oci  string
}

func (this Arch) String() string {
	v, ok := archToDetails[this]
	if !ok {
		return fmt.Sprintf("illegal-arch-%d", this)
	}
	return v.name
}

func (this Arch) Oci() string {
	v, ok := archToDetails[this]
	if !ok {
		return fmt.Sprintf("illegal-arch-%d", this)
	}
	if v.oci != "" {
		return v.oci
	}
	return v.name
}

func (this Arch) Bare() string {
	v, ok := archToDetails[this]
	if !ok {
		return fmt.Sprintf("illegal-arch-%d", this)
	}
	if v.bare != "" {
		return v.bare
	}
	return v.name
}

func (this Arch) MarshalText() ([]byte, error) {
	v, ok := archToDetails[this]
	if !ok {
		return nil, fmt.Errorf("illegal-arch: %d", this)
	}
	return []byte(v.name), nil
}

func (this *Arch) UnmarshalText(in []byte) error {
	v, ok := stringToArch[string(in)]
	if !ok {
		return fmt.Errorf("illegal-arch: %s", string(in))
	}
	*this = v
	return nil
}

func (this *Arch) Set(plain string) error {
	return this.UnmarshalText([]byte(plain))
}

func (this *Arch) SetOci(plain string) error {
	v, ok := ociStringToArch[plain]
	if !ok {
		return fmt.Errorf("illegal-arch: %s", plain)
	}
	*this = v
	return nil
}

func (this Arch) IsZero() bool {
	return this == 0
}

func (this Arch) Validate() error {
	_, err := this.MarshalText()
	return err
}

func (this Arch) IsEqualTo(other any) bool {
	switch v := other.(type) {
	case Arch:
		return this == v
	case *Arch:
		return this == *v
	default:
		return false
	}
}

type Archs []Arch

func (this Archs) String() string {
	return strings.Join(this.Strings(), ",")
}

func (this Archs) Strings() []string {
	strs := make([]string, len(this))
	for i, v := range this {
		strs[i] = v.String()
	}
	return strs
}

func (this *Archs) Set(plain string) error {
	parts := strings.Split(plain, ",")
	buf := make(Archs, len(parts))
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if err := buf[i].Set(part); err != nil {
			return err
		}
	}
	*this = buf
	return nil
}

func AllArchVariants() Archs {
	return slices.Clone(allArchVariants)
}

var (
	// See https://go.dev/doc/install/source for more details
	archToDetails = map[Arch]archDetails{
		Arch386:      {name: "386"},
		ArchAmd64:    {name: "amd64"},
		ArchArmV6:    {name: "armv6", bare: "arm", oci: "arm/v6"},
		ArchArmV7:    {name: "armv7", bare: "arm", oci: "arm/v7"},
		ArchArm64:    {name: "arm64"},
		ArchMips64Le: {name: "mips64le"},
		ArchRiscV64:  {name: "riscv64"},
	}
	stringToArch = func(in map[Arch]archDetails) map[string]Arch {
		result := make(map[string]Arch, len(in))
		for k, v := range in {
			result[v.name] = k
		}
		return result
	}(archToDetails)
	ociStringToArch = func(in map[Arch]archDetails) map[string]Arch {
		result := make(map[string]Arch, len(in))
		for k, v := range in {
			if v.oci != "" {
				result[v.oci] = k
			} else {
				result[v.name] = k
			}
		}
		return result
	}(archToDetails)
	allArchVariants = func(in map[Arch]archDetails) Archs {
		result := make(Archs, len(in))
		var i int
		for k := range in {
			result[i] = k
			i++
		}
		return result
	}(archToDetails)
)
