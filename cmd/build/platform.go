package main

import (
	"fmt"
	"iter"
)

type platform struct {
	os      os
	arch    arch
	edition edition
	testing bool
}

func (this platform) String() string {
	var result string
	if v := this.os; v != 0 {
		result = v.String()
	}
	if v := this.arch; v != 0 {
		if result != "" {
			result += "/"
		}
		result += v.String()
	}
	if v := this.edition; v != 0 {
		if result != "" {
			result += "/"
		}
		result += v.String()
	}
	if this.testing {
		result += "(testing)"
	}
	return result
}

func (this platform) ociString() string {
	return this.os.String() + "/" + this.arch.ociString()
}

func (this platform) from() (name string, _ error) {
	b := this.arch.details().os[this.os]

	switch this.edition {
	case editionExtended:
		name = b.fromImageExtended
	default:
		name = b.fromImage
	}

	if name == "" {
		return "", fmt.Errorf("%v is not supported for image creation", this)
	}

	return name, nil
}

func (this platform) setToEnv(assumedGoos os, assumedGoarch arch, env interface{ setEnv(key, val string) }) {
	this.arch.setToEnv(this.os, assumedGoos, assumedGoarch, env)
	this.edition.setToEnv(env)
}

func (this platform) isBinarySupported(assumedOs os, assumedArch arch) bool {
	return this.edition.isBinarySupported(this.os, this.arch, assumedOs, assumedArch)
}

func (this platform) assertBinarySupported(assumedOs os, assumedArch arch) error {
	if this.isBinarySupported(assumedOs, assumedArch) {
		return nil
	}
	return fmt.Errorf("combination %v is not supported for binaries", this)
}

func (this platform) isImageSupported() bool {
	b := this.arch.details().os[this.os]

	switch this.edition {
	case editionExtended:
		return b.fromImageExtended != ""
	default:
		return b.fromImage != ""
	}
}

func (this platform) toLdFlags(o os) string {
	return this.edition.toLdFlags(o)
}

func (this platform) filenamePrefix(mainPrefix string) string {
	result := mainPrefix +
		"-" + this.os.String() +
		"-" + this.arch.String() +
		"-" + this.edition.String()
	if this.testing {
		result += "-testing"
	}
	return result
}

func allBinaryPlatforms(forTesting bool, assumedOs os, assumedArch arch) iter.Seq[*platform] {
	return func(yield func(*platform) bool) {
		for _, o := range allOsVariants {
			for _, a := range allArchVariants {
				if a.isOsSupported(o) {
					for _, e := range allEditionVariants {
						if e.isBinarySupported(o, a, assumedOs, assumedArch) {
							if !yield(&platform{o, a, e, forTesting}) {
								return
							}
						}
					}
				}
			}
		}
	}
}
