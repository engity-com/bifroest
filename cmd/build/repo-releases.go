package main

import (
	"context"
	"fmt"
	"iter"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/alecthomas/kingpin"
	"github.com/google/go-github/v65/github"
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
