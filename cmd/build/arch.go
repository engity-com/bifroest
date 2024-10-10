package main

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/engity-com/bifroest/pkg/common"
)

type arch uint8

const (
	archUnknown arch = iota
	arch386
	archAmd64
	archArmV6
	archArmV7
	archArm64
	archMips64Le
	archRiscV64

	fromDefaultLinux         = "scratch"
	fromDefaultLinuxExtended = "ubuntu"
	fromDefaultWindows       = "mcr.microsoft.com/windows/nanoserver:ltsc2022"
)

var goarch = func() arch {
	var buf arch
	common.Must(buf.Set(runtime.GOARCH))
	return buf
}()

func (this arch) String() string {
	v, ok := archToDetails[this]
	if !ok {
		return fmt.Sprintf("illegal-arch-%d", this)
	}
	return v.name
}

func (this arch) ociString() string {
	v, ok := archToDetails[this]
	if !ok {
		return fmt.Sprintf("illegal-arch-%d", this)
	}
	if v.oci != "" {
		return v.oci
	}
	return v.name
}

func (this *arch) Set(plain string) error {
	v, ok := stringToArch[plain]
	if !ok {
		return fmt.Errorf("illegal-arch: %s", plain)
	}
	*this = v
	return nil
}

func (this arch) isOsSupported(o os) bool {
	return this.details().isOsSupported(o)
}

func (this arch) setToEnv(o os, assumedGoos os, assumedGoarch arch, env interface{ setEnv(key, val string) }) {
	this.details().setToEnv(o, this, assumedGoos, assumedGoarch, env)
}

func (this arch) details() archDetails {
	return archToDetails[this]
}

type archs []arch

func (this archs) String() string {
	return strings.Join(this.Strings(), ",")
}

func (this archs) Strings() []string {
	strs := make([]string, len(this))
	for i, v := range this {
		strs[i] = v.String()
	}
	return strs
}

func (this *archs) Set(plain string) error {
	parts := strings.Split(plain, ",")
	buf := make(archs, len(parts))
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if err := buf[i].Set(part); err != nil {
			return err
		}
	}
	*this = buf
	return nil
}

type archDetails struct {
	name string
	bare string
	oci  string

	i386  string
	arm   string
	amd64 string

	os map[os]archOsDetails
}

func (this archDetails) isOsSupported(o os) bool {
	_, ok := this.os[o]
	return ok
}

func (this archDetails) setToEnv(o os, a arch, assumedGoos os, assumedGoarch arch, env interface{ setEnv(key, val string) }) {
	osDetails, ok := this.os[o]
	if !ok {
		return
	}

	o.setToEnv(env)
	if v := this.bare; v != "" {
		env.setEnv("GOARCH", v)
	} else {
		env.setEnv("GOARCH", this.name)
	}
	if v := this.i386; v != "" {
		env.setEnv("GO386", v)
	}
	if v := this.arm; v != "" {
		env.setEnv("GOARM", v)
	}
	if v := this.amd64; v != "" {
		env.setEnv("GOAMD64", v)
	}

	osDetails.setToEnv(o, a, assumedGoos, assumedGoarch, env)
}

type archOsDetails struct {
	fromImage         string
	fromImageExtended string
	build             map[archBuildKey]archBuildDetails
}

func (this archOsDetails) setToEnv(o os, a arch, assumedGoos os, assumedGoarch arch, env interface{ setEnv(key, val string) }) {
	this.build[archBuildKey{assumedGoos, assumedGoarch}].setToEnv(o, a, assumedGoos, assumedGoarch, env)
}

type archBuildKey struct {
	os   os
	arch arch
}

type archBuildDetails struct {
	crossCc string
}

func (this archBuildDetails) setToEnv(o os, a arch, assumedGoos os, assumedGoarch arch, env interface{ setEnv(key, val string) }) {
	if this.crossCc != "" && (assumedGoos != o || assumedGoarch != a) {
		env.setEnv("CC", this.crossCc)
	}
}

var (
	// See https://go.dev/doc/install/source for more details
	archToDetails = map[arch]archDetails{
		arch386: {name: "386", i386: "sse2", os: map[os]archOsDetails{
			osLinux: {fromImage: fromDefaultLinux, build: map[archBuildKey]archBuildDetails{
				{osLinux, archAmd64}:   {"i686-linux-gnu-gcc"},
				{osWindows, archAmd64}: {},
			}},
		}},
		archAmd64: {name: "amd64", amd64: "v1", os: map[os]archOsDetails{
			osLinux: {fromImage: fromDefaultLinux, fromImageExtended: fromDefaultLinuxExtended, build: map[archBuildKey]archBuildDetails{
				{osLinux, archAmd64}:   {"x86-64-linux-gnu-gcc"},
				{osWindows, archAmd64}: {},
			}},
			osWindows: {fromImage: fromDefaultWindows},
		}},
		archArmV6: {name: "armv6", bare: "arm", oci: "arm/v6", arm: "6", os: map[os]archOsDetails{
			osLinux: {fromImage: fromDefaultLinux, build: map[archBuildKey]archBuildDetails{
				{osLinux, archAmd64}:   {"arm-linux-gnueabihf-gcc"},
				{osWindows, archAmd64}: {},
			}},
		}},
		archArmV7: {name: "armv7", bare: "arm", oci: "arm/v7", arm: "7", os: map[os]archOsDetails{
			osLinux: {fromImage: fromDefaultLinux, fromImageExtended: fromDefaultLinuxExtended, build: map[archBuildKey]archBuildDetails{
				{osLinux, archAmd64}:   {"arm-linux-gnueabihf-gcc"},
				{osWindows, archAmd64}: {},
			}},
		}},
		archArm64: {name: "arm64", os: map[os]archOsDetails{
			osLinux: {fromImage: fromDefaultLinux, fromImageExtended: fromDefaultLinuxExtended, build: map[archBuildKey]archBuildDetails{
				{osLinux, archAmd64}:   {"aarch64-linux-gnu-gcc"},
				{osWindows, archAmd64}: {},
			}},
			osWindows: {},
		}},
		archMips64Le: {name: "mips64le", os: map[os]archOsDetails{
			osLinux: {fromImage: fromDefaultLinux, build: map[archBuildKey]archBuildDetails{
				{osLinux, archAmd64}:   {"mips64el-linux-gnuabi64-gcc"},
				{osWindows, archAmd64}: {},
			}},
		}},
		archRiscV64: {name: "riscv64", os: map[os]archOsDetails{
			osLinux: {fromImage: fromDefaultLinux, build: map[archBuildKey]archBuildDetails{
				{osLinux, archAmd64}:   {},
				{osWindows, archAmd64}: {},
			}},
		}},
	}
	stringToArch = func(in map[arch]archDetails) map[string]arch {
		result := make(map[string]arch, len(in))
		for k, v := range in {
			result[v.name] = k
		}
		return result
	}(archToDetails)
	allArchVariants = func(in map[arch]archDetails) archs {
		result := make(archs, len(in))
		var i int
		for k := range in {
			result[i] = k
			i++
		}
		return result
	}(archToDetails)
)
