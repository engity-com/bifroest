package sys

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
	Edition() Edition
	BuildAt() time.Time
	Vendor() string
	GoVersion() string
	Os() Os
	Arch() Arch
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
Platform: ` + v.Os().String() + `/` + v.Arch().String()

		csnl := 0
		hasFeatures := false
		v.Features().ForEach(func(category VersionFeatureCategory) {
			hasFeatures = true
			cnl := len(category.Name()) + 1
			if cnl > csnl {
				csnl = cnl
			}
		})

		if hasFeatures {
			result += "\nFeatures:"
			v.Features().ForEach(func(category VersionFeatureCategory) {
				var fts []string
				category.ForEach(func(feature VersionFeature) {
					fts = append(fts, feature.Name())
				})
				result += fmt.Sprintf("\n\t%-"+strconv.Itoa(csnl)+"s %s", category.Name()+":", strings.Join(fts, " "))
			})
		}

		return result
	default:
		return v.Title() + ` ` + v.Version() + `-` + v.Revision() + `+` + v.Edition().String() + `@` + v.Os().String() + `/` + v.Arch().String() + ` ` + v.BuildAt().Format(time.RFC3339)
	}
}

func VersionToMap(v Version) map[string]any {
	result := map[string]any{
		"version":  v.Version(),
		"revision": v.Revision(),
		"edition":  v.Edition(),
		"buildAt":  v.BuildAt(),
		"vendor":   v.Vendor(),
		"go":       v.GoVersion(),
		"platform": v.Os().String() + "/" + v.Arch().String(),
	}

	v.Features().ForEach(func(category VersionFeatureCategory) {
		var fts []string
		category.ForEach(func(feature VersionFeature) {
			fts = append(fts, feature.Name())
		})
		result["features-"+category.Name()] = strings.Join(fts, ",")
	})

	return result
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
