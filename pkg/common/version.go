package common

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Version interface {
	Title() string
	Version() string
	Revision() string
	Edition() VersionEdition
	BuildAt() time.Time
	Vendor() string
	GoVersion() string
	Platform() string
	Features() VersionFeatures
}

func FormatVersion(v Version, format VersionFormat) string {
	switch format {
	case VersionFormatLong:
		result := v.Title() + `

Version:  ` + v.Version() + `
Revision: ` + v.Revision() + `
Edition:  ` + v.Edition().String() + `
Build:    ` + v.BuildAt().Format(time.RFC3339) + ` by ` + v.Vendor() + `
Go:       ` + v.GoVersion() + `
Platform: ` + v.Platform() + `
Features: `

		csnl := 0
		v.Features().ForEach(func(category VersionFeatureCategory) {
			cnl := len(category.Name()) + 1
			if cnl > csnl {
				csnl = cnl
			}
		})

		v.Features().ForEach(func(category VersionFeatureCategory) {
			var fts []string
			category.ForEach(func(feature VersionFeature) {
				fts = append(fts, feature.Name())
			})
			result += fmt.Sprintf("\n\t%-"+strconv.Itoa(csnl)+"s %s", category.Name()+":", strings.Join(fts, " "))
		})

		return result
	default:
		return v.Title() + ` ` + v.Version() + `-` + v.Revision() + `+` + v.Edition().String() + `@` + v.Platform() + ` ` + v.BuildAt().Format(time.RFC3339)
	}
}

type VersionEdition uint8

const (
	VersionEditionUnknown VersionEdition = iota
	VersionEditionGeneric
	VersionEditionExtended
)

func (this VersionEdition) String() string {
	switch this {
	case VersionEditionUnknown:
		return "unknown"
	case VersionEditionGeneric:
		return "generic"
	case VersionEditionExtended:
		return "extended"
	default:
		return fmt.Sprintf("unknown-%d", this)
	}
}

func (this *VersionEdition) Set(plain string) error {
	switch plain {
	case "", "unknown":
		*this = VersionEditionUnknown
		return nil
	case "generic":
		*this = VersionEditionGeneric
		return nil
	case "extended":
		*this = VersionEditionExtended
		return nil
	default:
		return fmt.Errorf("invalid edition: %q", plain)
	}
}

type VersionFormat uint8

const (
	VersionFormatShort VersionFormat = iota
	VersionFormatLong
)

type VersionFeatures interface {
	ForEach(func(VersionFeatureCategory))
}

type VersionFeatureCategory interface {
	Name() string
	ForEach(func(VersionFeature))
}

type VersionFeature interface {
	Name() string
}
