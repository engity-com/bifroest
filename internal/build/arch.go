package build

import (
	"runtime"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	fromDefaultLinux         = "scratch"
	fromDefaultLinuxExtended = "ubuntu"
	fromDefaultWindows       = "mcr.microsoft.com/windows/nanoserver:ltsc2022"
)

var Goarch = func() sys.Arch {
	var buf sys.Arch
	common.Must(buf.Set(runtime.GOARCH))
	return buf
}()

func ArchToLdFlags(a sys.Arch) string {
	return "-X main.arch=" + a.String()
}

func IsOsAndArchSupported(o sys.Os, a sys.Arch) bool {
	return GetArchDetails(a).IsOsSupported(o)
}

func SetArchToEnv(o sys.Os, a sys.Arch, assumedGoos sys.Os, assumedGoarch sys.Arch, env interface{ SetEnv(key, val string) }) {
	env.SetEnv("GOARCH", a.Bare())
	GetArchDetails(a).setToEnv(o, a, assumedGoos, assumedGoarch, env)
}

func GetArchDetails(a sys.Arch) ArchDetails {
	return archToDetails[a]
}

type ArchDetails struct {
	i386  string
	arm   string
	amd64 string

	os map[sys.Os]archOsDetails
}

func (this ArchDetails) IsOsSupported(o sys.Os) bool {
	_, ok := this.os[o]
	return ok
}

func (this ArchDetails) setToEnv(o sys.Os, a sys.Arch, assumedGoos sys.Os, assumedGoarch sys.Arch, env interface{ SetEnv(key, val string) }) {
	osDetails, ok := this.os[o]
	if !ok {
		return
	}

	if v := this.i386; v != "" {
		env.SetEnv("GO386", v)
	}
	if v := this.arm; v != "" {
		env.SetEnv("GOARM", v)
	}
	if v := this.amd64; v != "" {
		env.SetEnv("GOAMD64", v)
	}

	osDetails.setToEnv(o, a, assumedGoos, assumedGoarch, env)
}

type archOsDetails struct {
	fromImage         string
	fromImageExtended string
	build             map[archBuildKey]archBuildDetails
}

func (this archOsDetails) setToEnv(o sys.Os, a sys.Arch, assumedGoos sys.Os, assumedGoarch sys.Arch, env interface{ SetEnv(key, val string) }) {
	this.build[archBuildKey{assumedGoos, assumedGoarch}].setToEnv(o, a, assumedGoos, assumedGoarch, env)
}

type archBuildKey struct {
	os   sys.Os
	arch sys.Arch
}

type archBuildDetails struct {
	crossCc string
}

func (this archBuildDetails) setToEnv(o sys.Os, a sys.Arch, assumedGoos sys.Os, assumedGoarch sys.Arch, env interface{ SetEnv(key, val string) }) {
	if this.crossCc != "" && (assumedGoos != o || assumedGoarch != a) {
		env.SetEnv("CC", this.crossCc)
	}
}

var (
	// See https://go.dev/doc/install/source for more details
	archToDetails = map[sys.Arch]ArchDetails{
		sys.Arch386: {i386: "sse2", os: map[sys.Os]archOsDetails{
			sys.OsLinux: {fromImage: fromDefaultLinux, build: map[archBuildKey]archBuildDetails{
				{sys.OsLinux, sys.ArchAmd64}:   {"i686-linux-gnu-gcc"},
				{sys.OsWindows, sys.ArchAmd64}: {},
			}},
		}},
		sys.ArchAmd64: {amd64: "v1", os: map[sys.Os]archOsDetails{
			sys.OsLinux: {fromImage: fromDefaultLinux, fromImageExtended: fromDefaultLinuxExtended, build: map[archBuildKey]archBuildDetails{
				{sys.OsLinux, sys.ArchAmd64}:   {"x86-64-linux-gnu-gcc"},
				{sys.OsWindows, sys.ArchAmd64}: {},
			}},
			sys.OsWindows: {fromImage: fromDefaultWindows},
		}},
		sys.ArchArmV6: {arm: "6", os: map[sys.Os]archOsDetails{
			sys.OsLinux: {fromImage: fromDefaultLinux, build: map[archBuildKey]archBuildDetails{
				{sys.OsLinux, sys.ArchAmd64}:   {"arm-linux-gnueabihf-gcc"},
				{sys.OsWindows, sys.ArchAmd64}: {},
			}},
		}},
		sys.ArchArmV7: {arm: "7", os: map[sys.Os]archOsDetails{
			sys.OsLinux: {fromImage: fromDefaultLinux, fromImageExtended: fromDefaultLinuxExtended, build: map[archBuildKey]archBuildDetails{
				{sys.OsLinux, sys.ArchAmd64}:   {"arm-linux-gnueabihf-gcc"},
				{sys.OsWindows, sys.ArchAmd64}: {},
			}},
		}},
		sys.ArchArm64: {os: map[sys.Os]archOsDetails{
			sys.OsLinux: {fromImage: fromDefaultLinux, fromImageExtended: fromDefaultLinuxExtended, build: map[archBuildKey]archBuildDetails{
				{sys.OsLinux, sys.ArchAmd64}:   {"aarch64-linux-gnu-gcc"},
				{sys.OsWindows, sys.ArchAmd64}: {},
			}},
			sys.OsWindows: {},
		}},
		sys.ArchMips64Le: {os: map[sys.Os]archOsDetails{
			sys.OsLinux: {fromImage: fromDefaultLinux, build: map[archBuildKey]archBuildDetails{
				{sys.OsLinux, sys.ArchAmd64}:   {"mips64el-linux-gnuabi64-gcc"},
				{sys.OsWindows, sys.ArchAmd64}: {},
			}},
		}},
		sys.ArchRiscV64: {os: map[sys.Os]archOsDetails{
			sys.OsLinux: {fromImage: fromDefaultLinux, build: map[archBuildKey]archBuildDetails{
				{sys.OsLinux, sys.ArchAmd64}:   {},
				{sys.OsWindows, sys.ArchAmd64}: {},
			}},
		}},
	}
)
