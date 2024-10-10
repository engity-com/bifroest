package main

import (
	"fmt"
	"iter"
	"regexp"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
)

var (
	versionPattern = regexp.MustCompile("^\\w[\\w.-]{0,127}$")

	versionNormalizePattern = regexp.MustCompile("[^\\w]+")
)

type version struct {
	semver *semver.Version
	raw    string

	latestMajor bool
	latestMinor bool
	latestPatch bool
}

func (this *version) Set(plain string) error {
	var buf version

	if plain != "" {
		if !versionPattern.MatchString(plain) {
			return fmt.Errorf("invalid version: %s", plain)
		}

		buf.raw = plain
		if strings.HasPrefix(plain, "v") {
			v, err := semver.NewVersion(plain[1:])
			if err == nil {
				buf.semver = v
			}
		}
	}

	*this = buf
	return nil
}

func (this version) String() string {
	return this.raw
}

func (this version) tags(prefix string, rootTag string) iter.Seq[string] {
	return func(yield func(string) bool) {
		smv := this.semver
		if smv == nil {
			yield(this.raw)
			return
		}

		f := func(root string, vs ...uint64) string {
			result := prefix
			if len(vs) == 0 {
				result = root
			}
			for i, v := range vs {
				if i > 0 {
					result += "."
				}
				result += strconv.FormatUint(v, 10)
			}
			if v := smv.Prerelease(); v != "" {
				result += "-" + v
			}
			if v := smv.Metadata(); v != "" {
				result += "+" + v
			}
			return result
		}

		if !yield(prefix + smv.String()) {
			return
		}

		if this.latestPatch {
			if !yield(f("", smv.Major(), smv.Minor())) {
				return
			}
		} else {
			return
		}

		if this.latestMinor {
			if !yield(f("", smv.Major())) {
				return
			}
		} else {
			return
		}

		if this.latestMajor && rootTag != "" {
			if !yield(f(rootTag)) {
				return
			}
		} else {
			return
		}
	}
}

func (this *version) evaluateLatest(i iter.Seq2[*semver.Version, error]) error {
	fail := func(err error) error {
		return fmt.Errorf("cannot evaluate version's %v latest states: %w", this, err)
	}

	tv := this.semver
	if tv == nil {
		return nil
	}

	major, minor, patch := true, true, true

	for ov, err := range i {
		if err != nil {
			return fail(err)
		}

		if ov.Major() > tv.Major() {
			major = false
		} else if ov.Major() == tv.Major() {
			if ov.Minor() > tv.Minor() {
				major = false
				minor = false
			} else if ov.Minor() == tv.Minor() {
				if ov.Patch() > tv.Patch() {
					major = false
					minor = false
					patch = false
				}
			}
		}

		if !major && !minor && !patch {
			break
		}
	}

	this.latestMajor = major
	this.latestMinor = minor
	this.latestPatch = patch

	return nil
}
