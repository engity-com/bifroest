package main

import (
	"context"
	"fmt"
	"iter"
	"net/http"
	gos "os"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/alecthomas/kingpin"
	log "github.com/echocat/slf4g"
	"github.com/google/go-github/v65/github"

	"github.com/engity-com/bifroest/pkg/common"
)

func newRepoReleases(r *repo) *repoReleases {
	return &repoReleases{
		repo: r,
	}
}

func (this *repoReleases) init(_ context.Context, _ *kingpin.Application) {}

type repoReleases struct {
	*repo
}

func (this *repoReleases) findCurrent(ctx context.Context) (*repoRelease, error) {
	ref, err := this.ref(ctx)
	if err != nil {
		return nil, err
	}
	v, resp, err := this.client().Repositories.GetReleaseByTag(ctx, this.owner.String(), this.name.String(), ref)
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve current release: %w", err)
	}
	return &repoRelease{v, this}, nil
}

func (this *repoReleases) all(ctx context.Context) iter.Seq2[*repoRelease, error] {
	return func(yield func(*repoRelease, error) bool) {
		var opts github.ListOptions
		opts.PerPage = 100

		for {
			candidates, rsp, err := this.client().Repositories.ListReleases(ctx, this.owner.String(), this.name.String(), &opts)
			if err != nil {
				yield(nil, fmt.Errorf("cannot retrieve releases (page: %d): %w", opts.Page, err))
				return
			}
			for _, v := range candidates {
				if !yield(&repoRelease{v, this}, nil) {
					return
				}
			}
			if rsp.NextPage == 0 {
				return
			}
			opts.Page = rsp.NextPage
		}
	}
}

func (this *repoReleases) allSemver(ctx context.Context) iter.Seq2[*semver.Version, error] {
	return func(yield func(*semver.Version, error) bool) {
		for r, err := range this.all(ctx) {
			if err != nil && !yield(nil, err) {
				return
			}

			if r.TagName == nil {
				continue
			}
			if !strings.HasPrefix(*r.TagName, "v") {
				continue
			}

			rsmv, err := semver.NewVersion((*r.TagName)[1:])
			if err != nil {
				if yield(nil, err) {
					continue
				} else {
					return
				}
			} else if !yield(rsmv, nil) {
				return
			}
		}
	}
}

type repoRelease struct {
	*github.RepositoryRelease

	parent *repoReleases
}

func (this *repoRelease) String() string {
	return fmt.Sprintf("%s(%d)@%v", *this.Name, *this.ID, this.parent.repo)
}

func (this *repoRelease) uploadAsset(ctx context.Context, name, mediaType, label, fn string) (*repoReleaseAsset, error) {
	fail := func(err error) (*repoReleaseAsset, error) {
		return nil, fmt.Errorf("cannot upload asset %q: %w", name, err)
	}

	f, err := gos.Open(fn)
	if err != nil {
		return fail(err)
	}
	defer common.IgnoreCloseError(f)

	l := log.With("release", this).
		With("name", name).
		With("mediaType", mediaType).
		With("label", label)

	start := time.Now()
	l.Debug("uploading asset...")

	asset, _, err := this.parent.client().Repositories.UploadReleaseAsset(ctx, this.parent.owner.String(), this.parent.name.String(), this.GetID(), &github.UploadOptions{
		Name:      name,
		Label:     label,
		MediaType: mediaType,
	}, f)
	if err != nil {
		return fail(err)
	}

	ll := l.With("duration", time.Since(start).Truncate(time.Millisecond))
	if l.IsDebugEnabled() {
		ll.Info("uploading asset... DONE!")
	} else {
		ll.Info("asset uploaded")
	}

	return &repoReleaseAsset{asset, this.parent}, nil
}

type repoReleaseAsset struct {
	*github.ReleaseAsset

	parent *repoReleases
}
