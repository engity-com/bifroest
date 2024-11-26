package main

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/echocat/slf4g"
	"github.com/echocat/slf4g/fields"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	gcv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/google/go-github/v65/github"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/internal/build/images"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	ImageAnnotationEdition  = "org.engity.bifroest.edition"
	ImageAnnotationPlatform = "org.engity.bifroest.platform"
)

func newBuildImage(b *build) *buildImage {
	return &buildImage{
		build: b,
	}
}

type buildImage struct {
	*build

	pushToDockerDaemon bool
}

func (this *buildImage) attach(cmd *kingpin.CmdClause) {
	cmd.Flag("pushToDockerDaemon", "").
		BoolVar(&this.pushToDockerDaemon)
}

func (this *buildImage) create(ctx context.Context, binary *buildArtifact) (_ buildArtifacts, rErr error) {
	var result buildArtifacts

	success := false
	a, err := this.createPart(ctx, binary)
	if err != nil {
		return nil, err
	}
	defer common.IgnoreCloseErrorIfFalse(&success, a)
	result = append(result, a)

	success = true
	return result, nil
}

func (this *buildImage) createPart(ctx context.Context, binary *buildArtifact) (_ *buildArtifact, rErr error) {
	success := false
	a, err := this.build.newBuildArtifact(ctx, binary.Platform, buildArtifactTypeImage)
	if err != nil {
		return nil, err
	}
	defer common.IgnoreCloseErrorIfFalse(&success, a)

	fail := func(err error) (*buildArtifact, error) {
		return nil, fmt.Errorf("cannot create %v: %w", a, err)
	}
	failf := func(msg string, args ...any) (*buildArtifact, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	var from string
	if from, err = a.SourceOciImage(); err != nil {
		return fail(err)
	}

	l := log.With("platform", a.Platform).
		With("from", from).
		With("stage", buildStageImage)

	start := time.Now()
	l.Debug("building image...")

	bifroestTargetFileLocation := sys.BifroestBinaryFileLocation(a.Os)
	if bifroestTargetFileLocation == "" {
		return failf("cannot find binary file location for os: %v", a.Os)
	}
	bifroestTargetDirLocation := sys.BifroestBinaryDirLocation(a.Os)
	if bifroestTargetDirLocation == "" {
		return failf("cannot find binary dir location for os: %v", a.Os)
	}

	buildRequest := images.BuildRequest{
		From:                 from,
		Os:                   a.Os,
		Arch:                 a.Arch,
		BifroestBinarySource: binary.filepath,
		PathEnv:              []string{bifroestTargetDirLocation},
		EntryPoint:           []string{bifroestTargetFileLocation},
		Cmd:                  []string{"run"},
		ExposedPorts: map[string]struct{}{
			"22/tcp": {},
		},
		AddDummyConfiguration: true,
		AddSkeletonStructure:  true,
		Time:                  a.time,
		Vendor:                this.vendor,
	}

	deps, err := this.dependencies.imagesFiles.downloadFilesFor(ctx, a.Os, a.Arch)
	if err != nil {
		return fail(err)
	}
	if len(deps) > 0 {
		if buildRequest.Contents != nil {
			buildRequest.Contents = common.JoinSeq2(buildRequest.Contents, common.Seq2ErrOf(deps.ToLayerItems()...))
		} else {
			buildRequest.Contents = common.Seq2ErrOf(deps.ToLayerItems()...)
		}
	}

	if buildRequest.Annotations, err = this.createAnnotations(ctx, a.Edition, func(v version, rm *github.Repository, m map[string]string) error {
		m[ImageAnnotationPlatform] = a.Platform.String()
		return nil
	}); err != nil {
		return fail(err)
	}
	buildRequest.Labels = buildRequest.Annotations

	img, err := images.Build(ctx, buildRequest)
	if err != nil {
		return fail(err)
	}

	defer common.IgnoreCloseErrorIfFalse(&success, img)
	binary.addCloser(img.Close)

	if this.pushToDockerDaemon {
		tag, err := name.NewTag(fmt.Sprintf("%s:build-%v-%v-%v-%v", this.repo.fullImageName(), a.version, a.Os, a.Arch, a.Edition))
		if err != nil {
			return fail(err)
		}

		if _, err := daemon.Write(tag, img, daemon.WithContext(ctx)); err != nil {
			return fail(err)
		}
	}

	a.ociImage = img

	ld := l.With("duration", time.Since(start).Truncate(time.Millisecond))
	if l.IsDebugEnabled() {
		ld.Debug("building image... DONE!")
	} else {
		ld.Info("image built")
	}

	success = true
	return a, nil
}

func (this *buildImage) merge(ctx context.Context, as buildArtifacts) (_ buildArtifacts, rErr error) {
	result := slices.Collect(as.withoutType(buildArtifactTypeImage))

	success := false
	for _, e := range sys.AllEditionVariants() {
		a, err := this.createdMerged(ctx, e, as)
		if err != nil {
			return nil, err
		}
		//goland:noinspection GoDeferInLoop
		defer common.IgnoreCloseErrorIfFalse(&success, a)
		if a != nil {
			result = append(result, a)
		}
	}

	success = true
	return result, nil
}

func (this *buildImage) createAnnotations(ctx context.Context, e sys.Edition, additional func(version, *github.Repository, map[string]string) error) (map[string]string, error) {
	rm, err := this.repo.meta(ctx)
	if err != nil {
		return nil, err
	}

	ver, err := this.version(ctx)
	if err != nil {
		return nil, err
	}
	commit, err := this.commit(ctx)
	if err != nil {
		return nil, err
	}

	result := map[string]string{
		v1.AnnotationCreated:       this.time().Format(time.RFC3339),
		v1.AnnotationURL:           rm.GetHTMLURL() + "/pkgs/container/" + this.repo.name.String(),
		v1.AnnotationDocumentation: rm.GetHomepage(),
		v1.AnnotationSource:        rm.GetHTMLURL(),
		v1.AnnotationVersion:       ver.String(),
		v1.AnnotationRevision:      commit,
		v1.AnnotationVendor:        this.vendor,
		v1.AnnotationTitle:         this.title,
		v1.AnnotationDescription:   rm.GetDescription(),
		ImageAnnotationEdition:     e.String(),
	}

	if l := rm.GetLicense(); l != nil {
		result[v1.AnnotationLicenses] = l.GetSPDXID()
	}

	for tag := range ver.tags(e.String()+"-", e.String()) {
		result[v1.AnnotationRefName] = tag
		break
	}

	if additional != nil {
		if err := additional(ver, rm, result); err != nil {
			return nil, err
		}
	}

	return result, err
}

func (this *buildImage) createdMerged(ctx context.Context, e sys.Edition, as buildArtifacts) (result *buildArtifact, _ error) {
	l := log.With("edition", e).
		With("stage", buildStageImage)

	start := time.Now()
	l.Debug("merge images...")

	annotations, err := this.createAnnotations(ctx, e, nil)
	if err != nil {
		return nil, err
	}

	var manifest gcv1.ImageIndex = empty.Index
	manifest = mutate.IndexMediaType(manifest, types.DockerManifestList)
	manifest = mutate.Annotations(manifest, annotations).(gcv1.ImageIndex)

	var adds []mutate.IndexAddendum
	var refA *buildArtifact

	for aa := range as.filter(func(candidate *buildArtifact) bool {
		return candidate.Edition == e && candidate.t == buildArtifactTypeImage
	}) {
		fail := func(err error) (*buildArtifact, error) {
			return nil, fmt.Errorf("cannot merge artifact %v: %w", aa, err)
		}

		cf, err := aa.ociImage.ConfigFile()
		if err != nil {
			return fail(err)
		}

		newDesc, err := partial.Descriptor(aa.ociImage)
		if err != nil {
			return fail(err)
		}
		newDesc.Platform = cf.Platform()
		adds = append(adds, mutate.IndexAddendum{
			Add:        aa.ociImage,
			Descriptor: *newDesc,
		})
		refA = aa
	}

	success := false
	if refA != nil {
		result = &buildArtifact{
			Platform: &bib.Platform{
				Edition: e,
				Testing: refA.Testing,
			},
			buildContext: refA.buildContext,
			t:            buildArtifactTypeImagePlatform,
			ociIndex:     mutate.AppendManifests(manifest, adds...),
		}
		defer common.IgnoreCloseErrorIfFalse(&success, result)
	}

	ld := l.With("duration", time.Since(start).Truncate(time.Millisecond))
	if l.IsDebugEnabled() {
		if result != nil {
			ld.Debug("merge images... DONE!")
		} else {
			ld.Debug("merge images... SKIPPED! (none found)")
		}
	} else if result != nil {
		ld.Info("images merged")
	}
	success = true
	return result, nil
}

func (this *buildImage) publish(ctx context.Context, as buildArtifacts) (rErr error) {
	fail := func(err error) error {
		return fmt.Errorf("cannot publish artifacts: %w", err)
	}

	for a := range as.onlyOfType(buildArtifactTypeImagePlatform) {
		l := log.With("edition", a.Edition).
			With("stage", buildStagePublish)

		start := time.Now()
		l.Debug("push images...")

		refs, err := this.refs(ctx, a.Edition)
		if err != nil {
			return fail(err)
		}
		l = l.With("refs", this.lazyRefs(&refs))

		for _, ref := range refs {
			if err := remote.WriteIndex(ref, a.ociIndex,
				remote.WithContext(ctx),
				remote.WithAuth(&authn.Basic{
					Username: this.actor,
					Password: this.repo.githubToken,
				}),
			); err != nil {
				return fail(err)
			}
		}

		ld := l.With("duration", time.Since(start).Truncate(time.Millisecond))
		if l.IsDebugEnabled() {
			ld.Debug("push images... DONE!")
		} else {
			ld.Info("images pushed")
		}
	}

	return nil
}

func (this *buildImage) refs(ctx context.Context, e sys.Edition) ([]name.Reference, error) {
	v, err := this.version(ctx)
	if err != nil {
		return nil, err
	}

	var rs []name.Reference
	prefix := e.String() + "-"
	root := e.String()
	for tag := range v.tags(prefix, root) {
		r, err := name.ParseReference(this.repo.fullImageName() + ":" + tag)
		if err != nil {
			return nil, err
		}
		rs = append(rs, r)
	}

	if e == sys.EditionGeneric {
		for tag := range v.tags("", "latest") {
			r, err := name.ParseReference(this.repo.fullImageName() + ":" + tag)
			if err != nil {
				return nil, err
			}
			rs = append(rs, r)
		}
	}

	return rs, nil
}

func (this *buildImage) lazyRefs(p *[]name.Reference) fields.Lazy {
	return fields.LazyFunc(func() any {
		if p == nil || len(*p) == 0 {
			return fields.Exclude
		}
		result := make([]string, len(*p))
		for i, r := range *p {
			result[i] = r.String()
		}
		if len(result) == 1 {
			return result[0]
		}
		return result
	})
}
