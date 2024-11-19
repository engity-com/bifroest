package build

import (
	"fmt"
	"iter"

	"github.com/engity-com/bifroest/pkg/sys"
)

type Platform struct {
	Os      sys.Os
	Arch    sys.Arch
	Edition sys.Edition
	Testing bool
}

func (this Platform) String() string {
	var result string
	if v := this.Os; v != 0 {
		result = v.String()
	}
	if v := this.Arch; v != 0 {
		if result != "" {
			result += "/"
		}
		result += v.String()
	}
	if v := this.Edition; v != 0 {
		if result != "" {
			result += "/"
		}
		result += v.String()
	}
	if this.Testing {
		result += "(testing)"
	}
	return result
}

func (this Platform) Oci() string {
	return this.Os.String() + "/" + this.Arch.Oci()
}

func (this Platform) SourceOciImage() (name string, _ error) {
	b := GetArchDetails(this.Arch).os[this.Os]

	switch this.Edition {
	case sys.EditionExtended:
		name = b.fromImageExtended
	default:
		name = b.fromImage
	}

	if name == "" {
		return "", fmt.Errorf("%v is not supported for image creation", this)
	}

	return name, nil
}

func (this Platform) SetToEnv(assumedGoos sys.Os, assumedGoarch sys.Arch, env interface{ SetEnv(key, val string) }) {
	SetOsToEnv(this.Os, env)
	SetArchToEnv(this.Os, this.Arch, assumedGoos, assumedGoarch, env)
	SetEditionToEnv(this.Edition, env)
}

func (this Platform) IsBinarySupported(assumedOs sys.Os, assumedArch sys.Arch) bool {
	return DoesEditionSupportBinaryFor(this.Edition, this.Os, this.Arch, assumedOs, assumedArch)
}

func (this Platform) AssertBinarySupported(assumedOs sys.Os, assumedArch sys.Arch) error {
	if this.IsBinarySupported(assumedOs, assumedArch) {
		return nil
	}
	return fmt.Errorf("combination %v is not supported for binaries", this)
}

func (this Platform) IsImageSupported() bool {
	b := GetArchDetails(this.Arch).os[this.Os]

	switch this.Edition {
	case sys.EditionExtended:
		return b.fromImageExtended != ""
	default:
		return b.fromImage != ""
	}
}

func (this Platform) ToLdFlags() string {
	return OsToLdFlags(this.Os) +
		" " + ArchToLdFlags(this.Arch) +
		" " + EditionToLdFlags(this.Edition)
}

func (this Platform) FilenamePrefix(mainPrefix string) string {
	result := mainPrefix +
		"-" + this.Os.String() +
		"-" + this.Arch.String() +
		"-" + this.Edition.String()
	if this.Testing {
		result += "-testing"
	}
	return result
}

func AllBinaryPlatforms(forTesting bool, assumedOs sys.Os, assumedArch sys.Arch) iter.Seq[*Platform] {
	return func(yield func(*Platform) bool) {
		for _, o := range sys.AllOsVariants() {
			for _, a := range sys.AllArchVariants() {
				if IsOsAndArchSupported(o, a) {
					for _, e := range sys.AllEditionVariants() {
						if DoesEditionSupportBinaryFor(e, o, a, assumedOs, assumedArch) {
							if !yield(&Platform{o, a, e, forTesting}) {
								return
							}
						}
					}
				}
			}
		}
	}
}
