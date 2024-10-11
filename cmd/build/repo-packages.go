package main

import (
	"context"
	"fmt"
	"iter"
	"slices"

	"github.com/alecthomas/kingpin"
	"github.com/echocat/slf4g"
	"github.com/google/go-github/v65/github"
)

func newRepoPackages(r *repo) *repoPackages {
	return &repoPackages{
		repo: r,
	}
}

type repoPackages struct {
	*repo
}

func (this *repoPackages) init(_ context.Context, _ *kingpin.Application) {}

func (this *repoPackages) deleteVersionsWithTags(ctx context.Context, tags ...string) error {
	del := func(sub string) error {
		for candidate, err := range this.versionsWithAtLeastOneTag(ctx, sub, tags) {
			if err != nil {
				return err
			}

			l := log.With("packageVersion", *candidate.ID).
				With("packageVersionUrl", *candidate.HTMLURL)
			if err := candidate.delete(ctx); err != nil {
				l.WithError(err).Warn()
			} else {
				l.Info("successfully deleted")
			}
		}
		return nil
	}

	if err := del(""); err != nil {
		return err
	}

	return nil
}

func (this *repoPackages) versions(ctx context.Context, sub string) iter.Seq2[*repoPackageVersion, error] {
	return func(yield func(*repoPackageVersion, error) bool) {
		var opts github.PackageListOptions
		opts.PerPage = 100

		for {
			candidates, rsp, err := this.client().Organizations.PackageGetAllVersions(
				ctx,
				this.owner.String(),
				"container",
				this.SubName(sub),
				&opts,
			)
			if err != nil {
				yield(nil, fmt.Errorf("cannot retrieve package versions information for %s (page: %d): %w", this.SubString(sub), opts.Page, err))
				return
			}
			for _, v := range candidates {
				if !yield(&repoPackageVersion{v, sub, this}, nil) {
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

func (this *repoPackages) versionsWithAtLeastOneTag(ctx context.Context, sub string, tags []string) iter.Seq2[*repoPackageVersion, error] {
	return func(yield func(*repoPackageVersion, error) bool) {
		for candidate, err := range this.versions(ctx, sub) {
			if err != nil {
				yield(nil, err)
				return
			}
			if candidate.Metadata != nil && candidate.Metadata.Container != nil {
				if slices.ContainsFunc(candidate.Metadata.Container.Tags, func(s string) bool {
					return slices.Contains(tags, s)
				}) {
					if !yield(candidate, nil) {
						return
					}
				}
			}
		}
	}
}

type repoPackageVersion struct {
	*github.PackageVersion
	sub    string
	parent *repoPackages
}

func (this *repoPackageVersion) delete(ctx context.Context) error {
	if _, err := this.parent.client().Organizations.PackageDeleteVersion(
		ctx,
		this.parent.owner.String(),
		"container",
		this.parent.base.repo.SubName(this.sub),
		*this.ID,
	); err != nil {
		return fmt.Errorf("cannot delete package version %v: %w", this, err)
	}

	return nil
}

func (this repoPackageVersion) String() string {
	return fmt.Sprintf("%s(%d)@%s", *this.Name, *this.ID, this.parent.SubString(this.sub))
}
