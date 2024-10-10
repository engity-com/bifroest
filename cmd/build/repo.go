package main

import (
	"context"
	"fmt"
	gos "os"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"

	"github.com/alecthomas/kingpin"
	"github.com/google/go-github/v65/github"
)

const (
	fallbackOwner = "engity-com"
	fallbackRepo  = "bifroest"
)

var (
	defaultOwner, defaultRepo = func() (owner, repo string) {
		v, ok := gos.LookupEnv("GITHUB_REPOSITORY")
		if !ok {
			return fallbackOwner, fallbackRepo
		}
		parts := strings.Split(v, "/")
		if len(parts) != 2 {
			return fallbackOwner, fallbackRepo
		}
		return parts[0], parts[1]
	}()
)

func newRepo(b *base) *repo {
	result := &repo{
		base: b,
	}
	result.packages = newRepoPackages(result)
	result.prs = newRepoPrs(result)
	result.actions = newRepoActions(result)
	result.releases = newRepoReleases(result)
	return result
}

func (this *repo) init(ctx context.Context, app *kingpin.Application) {
	app.Flag("githubToken", "").
		Envar("GITHUB_TOKEN").
		Required().
		PlaceHolder("<token>").
		StringVar(&this.githubToken)
	app.Flag("owner", "").
		Default(defaultOwner).
		PlaceHolder("<owner>").
		SetValue(&this.owner)
	app.Flag("repo", "").
		Default(defaultRepo).
		PlaceHolder("<repo>").
		SetValue(&this.name)
	this.packages.init(ctx, app)
	this.prs.init(ctx, app)
	this.actions.init(ctx, app)
	this.releases.init(ctx, app)
}

type repo struct {
	*base

	githubToken string
	owner       owner
	name        repoName

	packages *repoPackages
	prs      *repoPrs
	actions  *repoActions
	releases *repoReleases

	clientP atomic.Pointer[github.Client]
	metaP   atomic.Pointer[github.Repository]
}

func (this *repo) String() string {
	return fmt.Sprintf("%s/%s", this.owner, this.name)
}

func (this *repo) fullName() string {
	return fmt.Sprintf("github.com/%s/%s", this.owner, this.name)
}

func (this *repo) fullImageName() string {
	return fmt.Sprintf("ghcr.io/%s/%s", this.owner, this.name)
}

func (this *repo) SubName(sub string) string {
	if sub == "" {
		return this.name.String()
	}
	return fmt.Sprintf("%v%%2F%s", this.name, sub)
}

func (this *repo) SubString(sub string) string {
	if sub == "" {
		return this.String()
	}
	return fmt.Sprintf("%v/%s", this, sub)
}

func (this *repo) client() *github.Client {
	for {
		v := this.clientP.Load()
		if v != nil {
			return v
		}
		v = github.NewClient(nil).
			WithAuthToken(this.githubToken)
		if this.clientP.CompareAndSwap(nil, v) {
			return v
		}
		runtime.Gosched()
	}
}

func (this *repo) meta(ctx context.Context) (*github.Repository, error) {
	for {
		v := this.metaP.Load()
		if v != nil {
			return v, nil
		}
		v, _, err := this.client().Repositories.Get(ctx, this.owner.String(), this.name.String())
		if err != nil {
			return nil, err
		}
		if this.metaP.CompareAndSwap(nil, v) {
			return v, nil
		}
		runtime.Gosched()
	}
}

type owner string

func (this owner) String() string {
	return string(this)
}

var ownerRegex = regexp.MustCompile("^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$")

func (this *owner) Set(v string) error {
	buf := owner(v)
	if err := buf.Validate(); err != nil {
		return err
	}
	*this = buf
	return nil
}

func (this owner) Validate() error {
	if this == "" {
		return fmt.Errorf("no owner provided")
	}
	if !ownerRegex.MatchString(string(this)) {
		return fmt.Errorf("illegal owner: %s", this)
	}
	return nil
}

type repoName string

func (this repoName) String() string {
	return string(this)
}

var repoNameRegex = regexp.MustCompile("^[a-zA-Z0-9-_.]+$")

func (this *repoName) Set(v string) error {
	buf := repoName(v)
	if err := buf.Validate(); err != nil {
		return err
	}
	*this = repoName(v)
	return nil
}

func (this repoName) Validate() error {
	if this == "" {
		return fmt.Errorf("no repo name provided")
	}
	if !repoNameRegex.MatchString(string(this)) {
		return fmt.Errorf("illegal repo name: %s", this)
	}
	return nil
}
