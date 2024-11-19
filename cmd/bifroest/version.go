package main

import (
	"fmt"
	goos "os"
	"runtime"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/sys"
)

var (
	title    = "Engity's Bifröst"
	version  = "development"
	revision = "HEAD"
	edition  = ""
	buildAt  = ""
	vendor   = "unknown"
	os       = runtime.GOOS
	arch     = runtime.GOARCH

	osV      sys.Os
	archV    sys.Arch
	editionV sys.Edition
	buildAtV time.Time
)

var (
	long = true
)

var _ = registerCommand(func(app *kingpin.Application) {
	cmd := app.Command("version", "Show version details of this executable.").
		Action(func(*kingpin.ParseContext) error {
			return doVersion()
		})
	cmd.Flag("long", "Configuration which should be used to serve the service. Default: "+fmt.Sprint(long)).
		PlaceHolder("<true|false>").
		BoolVar(&long)

	app.Flag("version", "Show version details of this executable.").
		Action(func(*kingpin.ParseContext) error {
			defer goos.Exit(1)
			return doVersion()
		}).
		Bool()
})

func doVersion() error {
	f := sys.VersionFormatShort
	if long {
		f = sys.VersionFormatLong
	}
	fmt.Println(sys.FormatVersion(versionV, f))
	return nil
}

func init() {
	if err := editionV.Set(edition); err != nil {
		panic(fmt.Errorf("illegal main.edidtion value (%q): %w", edition, err))
	}
	if err := osV.Set(os); err != nil {
		panic(fmt.Errorf("illegal main.os value (%q): %w", arch, err))
	}
	if err := archV.Set(arch); err != nil {
		panic(fmt.Errorf("illegal main.arch value (%q): %w", arch, err))
	}
	//goland:noinspection GoBoolExpressions
	if buildAt == "" {
		buildAtV = time.Now()
	} else if v, err := time.Parse(time.RFC3339, buildAt); err != nil {
		panic(fmt.Errorf("illegal main.buildAt value (%q): %w", buildAt, err))
	} else {
		buildAtV = v
	}
}

var versionV = &versionT{}

type versionT struct{}

func (this versionT) Title() string {
	return title
}

func (this versionT) Version() string {
	return version
}

func (this versionT) Revision() string {
	return revision
}

func (this versionT) Edition() sys.Edition {
	return editionV
}

func (this versionT) BuildAt() time.Time {
	return buildAtV
}

func (this versionT) Vendor() string {
	return vendor
}

func (this versionT) GoVersion() string {
	return strings.TrimPrefix(runtime.Version(), "go")
}

func (this versionT) Arch() sys.Arch {
	return archV
}

func (this versionT) Os() sys.Os {
	return osV
}

func (this versionT) Features() sys.VersionFeatures {
	return featuresV
}
