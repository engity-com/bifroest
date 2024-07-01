package main

import (
	"fmt"
	"github.com/alecthomas/kingpin"
	"github.com/engity-com/bifroest/pkg/common"
	"os"
	"runtime"
	"strings"
	"time"
)

var (
	title    = "Enity's Bifröst"
	version  = "development"
	revision = "HEAD"
	edition  = ""
	buildAt  = ""
	vendor   = "unknown"

	editionV common.VersionEdition
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
			defer os.Exit(1)
			return doVersion()
		}).
		Bool()
})

func doVersion() error {
	f := common.VersionFormatShort
	if long {
		f = common.VersionFormatLong
	}
	fmt.Println(common.FormatVersion(versionV, f))
	return nil
}

func init() {
	if err := editionV.Set(edition); err != nil {
		panic(fmt.Errorf("illegal main.edidtion value (%q): %w", edition, err))
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

func (this versionT) Edition() common.VersionEdition {
	return editionV
}

func (this versionT) BuildAt() time.Time {
	return buildAtV
}

func (this versionT) Vendor() string {
	return vendor
}

func (this versionT) GoVersion() string {
	v := runtime.Version()
	strings.TrimPrefix(v, "go")
	return v
}

func (this versionT) Platform() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}
