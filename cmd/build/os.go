package main

import (
	"fmt"
	"runtime"
	"slices"
	"strings"

	"github.com/engity-com/bifroest/pkg/common"
)

type os uint8

const (
	osUnknown os = iota
	osLinux   os = iota
	osWindows
)

var goos = func() os {
	var buf os
	common.Must(buf.Set(runtime.GOOS))
	return buf
}()

func (this os) String() string {
	v, ok := osToString[this]
	if !ok {
		return fmt.Sprintf("illegal-os-%d", this)
	}
	return v
}

func (this *os) Set(plain string) error {
	v, ok := stringToOs[plain]
	if !ok {
		return fmt.Errorf("illegal-os: %s", plain)
	}
	*this = v
	return nil
}

func (this os) execExt() string {
	switch this {
	case osWindows:
		return ".exe"
	default:
		return ""
	}
}

func (this os) isUnix() bool {
	switch this {
	case osLinux:
		return true
	default:
		return false
	}
}

func (this os) bifroestBinaryDirPath() string {
	switch this {
	case osWindows:
		return `C:\Program Files\Engity\Bifroest`
	default:
		return `/usr/bin`
	}
}

func (this os) bifroestBinaryFilePath() string {
	switch this {
	case osWindows:
		return this.bifroestBinaryDirPath() + `\bifroest` + this.execExt()
	default:
		return this.bifroestBinaryDirPath() + `/bifroest` + this.execExt()
	}
}

func (this os) bifroestConfigDirPath() string {
	switch this {
	case osWindows:
		return `C:\ProgramData\Engity\Bifroest`
	default:
		return `/etc/engity/bifroest`
	}
}

func (this os) bifroestConfigFilePath() string {
	switch this {
	case osWindows:
		return this.bifroestConfigDirPath() + `\configuration.yaml`
	default:
		return this.bifroestConfigDirPath() + `/configuration.yaml`
	}
}

func (this os) extendPathWith(dir string, sourceEnv []string) []string {
	env := slices.Clone(sourceEnv)
	for i, v := range sourceEnv {
		if strings.HasPrefix(v, "PATH=") {
			switch this {
			case osWindows:
				env[i] = v + ";" + dir
			default:
				env[i] = v + ":" + dir
			}
			return env
		}
	}

	env = append(env, "PATH="+dir)
	return env
}

func (this os) archiveFormat() archiveFormat {
	switch this {
	case osWindows:
		return packFormatZip
	default:
		return packFormatTgz
	}
}

func (this os) setToEnv(env interface{ setEnv(key, val string) }) {
	env.setEnv("GOOS", this.String())
}

type oses []os

func (this oses) String() string {
	return strings.Join(this.Strings(), ",")
}

func (this oses) Strings() []string {
	strs := make([]string, len(this))
	for i, v := range this {
		strs[i] = v.String()
	}
	return strs
}

func (this *oses) Set(plain string) error {
	parts := strings.Split(plain, ",")
	buf := make(oses, len(parts))
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if err := buf[i].Set(part); err != nil {
			return err
		}
	}
	*this = buf
	return nil
}

var (
	osToString = map[os]string{
		osLinux:   "linux",
		osWindows: "windows",
	}
	stringToOs = func(in map[os]string) map[string]os {
		result := make(map[string]os, len(in))
		for k, v := range in {
			result[v] = k
		}
		return result
	}(osToString)
	allOsVariants = func(in map[os]string) oses {
		result := make(oses, len(in))
		var i int
		for k := range in {
			result[i] = k
			i++
		}
		return result
	}(osToString)
)
