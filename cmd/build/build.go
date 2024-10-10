package main

import (
	"context"
	"fmt"
	"iter"
	gos "os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alecthomas/kingpin"
	"github.com/echocat/slf4g"

	"github.com/engity-com/bifroest/pkg/common"
)

func newBuild(b *base) *build {
	result := &build{
		base: b,

		vendor:    "unknown",
		dest:      "var/dist",
		prefix:    "bifroest",
		rawStages: nil,
		oses:      allOsVariants,
		archs:     allArchVariants,
		editions:  allEditionVariants,
		testing:   false,

		updateCaCerts:        true,
		wslBuildDistribution: "",
	}
	result.binary = newBuildBinary(result)
	result.archive = newBuildArchive(result)
	result.image = newBuildImage(result)
	result.digest = newBuildDigest(result)
	return result
}

type build struct {
	*base
	binary  *buildBinary
	archive *buildArchive
	image   *buildImage
	digest  *buildDigest

	vendor    string
	dest      string
	prefix    string
	rawStages buildStages
	oses      oses
	archs     archs
	editions  editions
	testing   bool

	updateCaCerts        bool
	wslBuildDistribution string

	timeP         atomic.Pointer[time.Time]
	buildContextP atomic.Pointer[buildContext]
	stagesP       atomic.Pointer[buildStages]
}

func (this *build) init(ctx context.Context, app *kingpin.Application) {
	attach := func(cmd *kingpin.CmdClause) {
		cmd.Flag("vendor", "").
			Envar("BIFROEST_VENDOR").
			PlaceHolder("<name>").
			StringVar(&this.vendor)
		cmd.Flag("dest", "").
			Default(this.dest).
			PlaceHolder("<path>").
			StringVar(&this.dest)
		cmd.Flag("prefix", "").
			PlaceHolder("<prefix>").
			Default(this.prefix).
			StringVar(&this.prefix)
		cmd.Flag("stages", "").
			PlaceHolder("<" + strings.Join(allBuildStageVariants.Strings(), "|") + ">[,...]").
			SetValue(&this.rawStages)
		cmd.Flag("os", "").
			PlaceHolder("<" + strings.Join(allOsVariants.Strings(), "|") + ">[,...]").
			Default(this.oses.String()).
			SetValue(&this.oses)
		cmd.Flag("arch", "").
			PlaceHolder("<" + strings.Join(allArchVariants.Strings(), "|") + ">[,...]").
			Default(this.archs.String()).
			SetValue(&this.archs)
		cmd.Flag("edition", "").
			PlaceHolder("<" + strings.Join(allEditionVariants.Strings(), "|") + ">[,...]").
			Default(this.editions.String()).
			SetValue(&this.editions)
		cmd.Flag("testing", "").
			BoolVar(&this.testing)
		cmd.Flag("updateCaCerts", "").
			BoolVar(&this.updateCaCerts)

		cmd.Flag("wslBuildDistribution", "").
			PlaceHolder("<distroName>").
			Default(this.wslBuildDistribution).
			StringVar(&this.wslBuildDistribution)

		this.binary.attach(cmd)
		this.archive.attach(cmd)
		this.image.attach(cmd)
		this.digest.attach(cmd)
	}

	attach(app.Command("evaluate-environment", "").
		Action(func(*kingpin.ParseContext) error {
			return this.evaluateEnvironment(ctx)
		}))

	attach(app.Command("build", "").
		Action(func(*kingpin.ParseContext) (rErr error) {
			as, err := this.buildAll(ctx, this.testing)
			if err != nil {
				return err
			}
			defer common.KeepCloseError(&rErr, as)

			return nil
		}))
}

func (this *build) allPlatforms(forTesting bool) iter.Seq[*platform] {
	return func(yield func(*platform) bool) {
		for p := range allBinaryPlatforms(forTesting, this.assumedBuildOs(), this.assumedBuildArch()) {
			if slices.Contains(this.oses, p.os) &&
				slices.Contains(this.archs, p.arch) && slices.Contains(this.editions, p.edition) {
				if !yield(p) {
					return
				}
			}
		}
	}
}

func (this *build) evaluateEnvironment(ctx context.Context) error {
	commit, err := this.commit(ctx)
	if err != nil {
		return err
	}
	ref, err := this.ref(ctx)
	if err != nil {
		return err
	}
	ver, err := this.version(ctx)
	if err != nil {
		return err
	}
	pr := this.pr()
	stages, err := this.stages(ctx)
	if err != nil {
		return err
	}

	log.With("commit", commit).
		With("version", ver).
		With("ref", ref).
		With("pr", pr).
		With("stages", stages).
		Info()
	prStr := strconv.FormatUint(uint64(pr), 10)

	if fn := this.optionsOutputFilename; fn != "" {
		f, err := gos.OpenFile(fn, gos.O_CREATE|gos.O_APPEND|gos.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer common.IgnoreCloseError(f)

		if _, err = fmt.Fprint(f, ""+
			"commit="+commit+"\n"+
			"version="+ver.String()+"\n"+
			"ref="+ref+"\n"+
			"pr="+prStr+"\n",
		); err != nil {
			return err
		}

		for _, stage := range allBuildStageVariants {
			if _, err = fmt.Fprintf(f, "stage-%v=%v\n", stage, stages.contains(stage)); err != nil {
				return err
			}
		}

		log.With("file", fn).
			Info("options output created")
	}

	if fn := this.summaryOutputFilename; fn != "" {
		f, err := gos.OpenFile(fn, gos.O_CREATE|gos.O_APPEND|gos.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer common.IgnoreCloseError(f)

		baseUrl := "https://" + this.repo.fullName()

		if _, err = fmt.Fprint(f, "## Build environment\n"+
			"| Name | Value |\n"+
			"| ---- | ----- |\n"+
			"| Commit | [`"+commit+"`]("+baseUrl+"/commit/"+commit+") |\n"+
			"| Version | `"+ver.String()+"` |\n"+
			"| Ref | [`"+ref+"`]("+baseUrl+"/tree/"+ref+") |\n"+
			"| PR | [`"+prStr+"`]("+baseUrl+"/pull/"+prStr+") |\n"+
			"\n",
			"## Available stages\n"+
				"| Name | Enabled |\n"+
				"| ---- | ------- |\n",
		); err != nil {
			return err
		}

		for _, stage := range allBuildStageVariants {
			if _, err = fmt.Fprintf(f, "| `%v` | `%v` |\n", stage, stages.contains(stage)); err != nil {
				return err
			}
		}

		log.With("file", fn).
			Info("summary output created")
	}

	return nil
}

func (this *build) buildAll(ctx context.Context, forTesting bool) (artifacts buildArtifacts, _ error) {
	stages, err := this.stages(ctx)
	if err != nil {
		return nil, err
	}

	if this.updateCaCerts {
		if err := this.dependencies.caCerts.generatePem(ctx); err != nil {
			return nil, err
		}
	}
	success := false
	defer common.IgnoreCloseErrorIfFalse(&success, artifacts)

	for a := range this.allPlatforms(forTesting) {
		vs, err := this.buildSingle(ctx, a)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, vs...)
	}

	if stages.contains(buildStageImage) {
		var err error
		artifacts, err = this.image.merge(ctx, artifacts)
		if err != nil {
			return nil, err
		}
	}

	if stages.contains(buildStageDigest) {
		var err error
		artifacts, err = this.digest.create(ctx, artifacts)
		if err != nil {
			return nil, err
		}
	}

	if stages.contains(buildStagePublish) {
		if err := this.publish(ctx, artifacts); err != nil {
			return nil, err
		}
	}

	success = true
	return artifacts, nil
}

func (this *build) buildSingle(ctx context.Context, p *platform) (artifacts buildArtifacts, _ error) {
	fail := func(err error) ([]*buildArtifact, error) {
		return nil, fmt.Errorf("cannot build %v: %w", *p, err)
	}

	stages, err := this.stages(ctx)
	if err != nil {
		return nil, err
	}

	l := log.With("platform", p)

	success := false
	common.IgnoreCloseErrorIfFalse(&success, artifacts)

	var ba *buildArtifact
	if stages.contains(buildStageBinary) && p.isBinarySupported(this.assumedBuildOs(), this.assumedBuildArch()) {
		var err error
		ba, err = this.binary.compile(ctx, p)
		if err != nil {
			return fail(err)
		}
		artifacts = append(artifacts, ba)

	} else {
		l.With("stage", buildStageBinary).Info("build binary skipped")
	}

	if ba != nil && stages.contains(buildStageArchive) {
		aa, err := this.archive.create(ctx, ba)
		if err != nil {
			return fail(err)
		}
		artifacts = append(artifacts, aa)
	} else {
		l.With("stage", buildStageArchive).Info("build archive skipped")
	}

	if ba != nil && stages.contains(buildStageImage) && ba.isImageSupported() {
		aas, err := this.image.create(ctx, ba)
		if err != nil {
			return fail(err)
		}
		artifacts = append(artifacts, aas...)
	} else {
		l.With("stage", buildStageImage).Info("build image skipped")
	}

	success = true
	return artifacts, nil
}

func (this *build) publish(ctx context.Context, as buildArtifacts) error {
	fail := func(err error) error {
		return fmt.Errorf("cannot publish: %w", err)
	}

	if err := this.image.publish(ctx, as); err != nil {
		return fail(err)
	}

	release, err := this.repo.releases.findCurrent(ctx)
	if err != nil {
		return fail(err)
	}

	if release == nil {
		log.Info("outside of release; publish artifacts skipped")
		return nil
	}

	l := log.With("release", release)

	start := time.Now()
	l.Debug("publish release...")

	for a := range as.filter(func(candidate *buildArtifact) bool {
		return candidate.t.canBePublished()
	}) {
		if _, err := release.uploadAsset(ctx, a.name(), a.mediaType(), "", a.filepath); err != nil {
			return fail(err)
		}
	}

	ll := l.With("duration", time.Since(start).Truncate(time.Millisecond))
	if l.IsDebugEnabled() {
		ll.Info("publish release...DONE!")
	} else {
		ll.Info("release published")
	}

	return nil
}

func (this *build) time() time.Time {
	for {
		if v := this.timeP.Load(); v != nil {
			return *v
		}
		v := time.Now()
		if this.timeP.CompareAndSwap(nil, &v) {
			return v
		}
		runtime.Gosched()
	}
}

func (this *build) getBuildContext(ctx context.Context) (*buildContext, error) {
	for {
		if v := this.buildContextP.Load(); v != nil {
			return v, nil
		}
		versions, err := this.version(ctx)
		if err != nil {
			return nil, err
		}
		revision, err := this.commit(ctx)
		if err != nil {
			return nil, err
		}

		v := &buildContext{
			this,
			versions,
			this.time(),
			this.vendor,
			revision,
		}
		if this.buildContextP.CompareAndSwap(nil, v) {
			return v, nil
		}
		runtime.Gosched()
	}
}

func (this *build) newBuildFileArtifact(ctx context.Context, p *platform, t buildArtifactType, fn string) (*buildArtifact, error) {
	success := false
	result, err := this.newBuildArtifact(ctx, p, t)
	if err != nil {
		return nil, err
	}
	defer common.IgnoreCloseErrorIfFalse(&success, result)

	result.filepath = result.buildContext.filepath(fn)

	success = true
	return result, nil
}

func (this *build) newBuildArtifact(ctx context.Context, p *platform, t buildArtifactType) (*buildArtifact, error) {
	bc, err := this.getBuildContext(ctx)
	if err != nil {
		return nil, err
	}

	return &buildArtifact{
		platform:     p,
		buildContext: bc,
		t:            t,
	}, nil
}

func (this *build) assumedBuildOs() os {
	if goos == osWindows && this.wslBuildDistribution != "" {
		return osLinux
	}
	return goos
}

func (this *build) assumedBuildArch() arch {
	return goarch
}

func (this *build) translateToWslPath(in string) (string, error) {
	if goos != osWindows {
		return "", fmt.Errorf("can only translate %q to wsl path if os is: %v; but is: %v", in, osWindows, goos)
	}
	abs, err := filepath.Abs(in)
	if err != nil {
		return "", err
	}

	return "/mnt/" + strings.ToLower(abs[0:1]) + filepath.ToSlash(abs[2:]), nil
}

func (this *build) stages(ctx context.Context) (buildStages, error) {
	for {
		v := this.stagesP.Load()
		if v != nil {
			return *v, nil
		}
		nv, err := this.resolveStages(ctx)
		if err != nil {
			return nil, err
		}
		if this.stagesP.CompareAndSwap(nil, &nv) {
			return nv, nil
		}
		runtime.Gosched()
	}
}

func (this *build) resolveStages(ctx context.Context) (buildStages, error) {
	if v := this.rawStages; len(v) > 0 {
		return v, nil
	}

	ver, err := this.version(ctx)
	if err != nil {
		return nil, err
	}

	// Assume release...
	if ver.semver != nil {
		log.With("version", ver).
			Infof("as this is a release version; stage %v was implicitly enabled", buildStagePublish)
		return allBuildStageVariants, nil
	}

	// Check if the PR is allowed to have images...
	if v := this.pr(); v > 0 {
		pr, err := this.repo.prs.byId(ctx, v)
		if err != nil {
			return nil, err
		}
		// Ok, in this case allow images...
		if pr.isOpen() && pr.hasLabel(this.repo.prs.testPublishLabel) {
			log.With("pr", v).
				Infof("as this is a PR and it was the label %v; stage %v was implicitly enabled", this.repo.prs.testPublishLabel, buildStagePublish)
			return allBuildStageVariants, nil
		}
	}

	// Never publish this states...
	return allBuildStageVariants.filter(func(v buildStage) bool {
		return v != buildStagePublish
	}), nil

}

type buildContext struct {
	build *build

	version  version
	time     time.Time
	vendor   string
	revision string
}

func (this buildContext) filepath(fn string) string {
	dir := filepath.Join(this.build.dest, this.version.String())
	_ = gos.MkdirAll(dir, 0755)
	return filepath.Join(dir, fn)
}

func (this buildContext) toLdFlags(testing bool) string {
	testPrefix := ""
	testSuffix := ""
	if testing {
		testPrefix = "TEST"
		testSuffix = "TEST"
	}
	return "-X main.version=" + testPrefix + this.version.String() + testSuffix +
		" -X main.revision=" + this.revision +
		" -X " + strconv.Quote("main.vendor="+this.vendor) +
		" -X main.buildAt=" + this.time.Format(time.RFC3339)
}
