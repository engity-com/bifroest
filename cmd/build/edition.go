package main

import (
	"strings"

	"github.com/engity-com/bifroest/pkg/common"
)

type edition common.VersionEdition

func (this edition) String() string {
	return common.VersionEdition(this).String()
}

func (this *edition) Set(plain string) error {
	var buf common.VersionEdition
	if err := buf.Set(plain); err != nil {
		return err
	}
	*this = edition(buf)
	return nil
}

func (this edition) isBinarySupported(o os, a arch, assumedOs os, assumedArch arch) bool {
	if !a.isOsSupported(o) {
		return false
	}

	if this == editionGeneric {
		return true
	}

	if this == editionExtended {
		if assumedOs == 0 {
			assumedOs = goos
		}
		if assumedArch == 0 {
			assumedArch = goarch
		}
		buildDetails := archToDetails[a].os[o].build[archBuildKey{assumedOs, assumedArch}]
		return buildDetails.crossCc != ""
	}

	return false
}

func (this edition) setToEnv(env interface{ setEnv(key, val string) }) {
	switch this {
	case editionExtended:
		env.setEnv("CGO_ENABLED", "1")
	default:
		env.setEnv("CGO_ENABLED", "0")
	}
}

func (this edition) toLdFlags(_ os) string {
	result := "-X main.edition=" + this.String()
	switch this {
	case editionExtended:
		result += " -linkmode external"
	}
	return result
}

type editions []edition

func (this editions) String() string {
	return strings.Join(this.Strings(), ",")
}

func (this editions) Strings() []string {
	strs := make([]string, len(this))
	for i, v := range this {
		strs[i] = v.String()
	}
	return strs
}

func (this *editions) Set(plain string) error {
	parts := strings.Split(plain, ",")
	buf := make(editions, len(parts))
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if err := buf[i].Set(part); err != nil {
			return err
		}
	}
	*this = buf
	return nil
}

const (
	editionUnknown  = edition(common.VersionEditionUnknown)
	editionGeneric  = edition(common.VersionEditionGeneric)
	editionExtended = edition(common.VersionEditionExtended)
)

var (
	allEditionVariants = editions{editionGeneric, editionExtended}
)
