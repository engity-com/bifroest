package main

import (
	"context"
	"fmt"
	"math"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/echocat/slf4g"
)

var (
	currentUserName = func() string {
		current, err := user.Current()
		if err != nil {
			return "johndoe"
		}
		return current.Username
	}()
)

func newBase() *base {
	result := &base{
		waitTimeout: time.Second * 3,
		actor:       currentUserName,
		title:       "Engity's Bifröst",
	}
	result.repo = newRepo(result)
	result.build = newBuild(result)
	result.exec = newExec(result)
	result.dependencies = newDependencies(result)
	return result
}

type base struct {
	repo  *repo
	build *build
	*exec
	dependencies *dependencies

	waitTimeout time.Duration
	actor       string
	title       string
	rawCommit   string
	rawRef      string
	rawHeadRef  string
	rawPr       uint

	optionsOutputFilename string
	summaryOutputFilename string

	versionP atomic.Pointer[version]
	commitP  atomic.Pointer[string]
	refP     atomic.Pointer[string]
	prP      atomic.Pointer[uint]
}

func (this *base) init(ctx context.Context, app *kingpin.Application) {
	app.Flag("waitTimeout", "").
		PlaceHolder("<duration>").
		DurationVar(&this.waitTimeout)
	app.Flag("actor", "").
		Default(this.actor).
		Envar("GITHUB_ACTOR").
		PlaceHolder("<actor-name>").
		StringVar(&this.actor)
	app.Flag("title", "").
		Default(this.title).
		PlaceHolder("<title>").
		StringVar(&this.title)
	app.Flag("commit", "").
		Envar("GITHUB_SHA").
		PlaceHolder("<sha>").
		StringVar(&this.rawCommit)
	app.Flag("ref", "").
		Envar("GITHUB_REF_NAME").
		PlaceHolder("<ref>").
		StringVar(&this.rawRef)
	app.Flag("headRef", "").
		Envar("GITHUB_HEAD_REF").
		PlaceHolder("<ref>").
		StringVar(&this.rawHeadRef)
	app.Flag("pr", "").
		PlaceHolder("<prNumber>").
		UintVar(&this.rawPr)
	app.Flag("optionsOutputFilename", "").
		Envar("GITHUB_OUTPUT").
		PlaceHolder("<filename>").
		StringVar(&this.optionsOutputFilename)
	app.Flag("summaryOutputFilename", "").
		Envar("GITHUB_STEP_SUMMARY").
		PlaceHolder("<filename>").
		StringVar(&this.summaryOutputFilename)

	app.Command("status", "").
		Action(func(*kingpin.ParseContext) error {
			return this.status(ctx)
		})

	this.repo.init(ctx, app)
	this.build.init(ctx, app)
	this.exec.init(ctx, app)
	this.dependencies.init(ctx, app)
}

func (this *base) status(ctx context.Context) error {
	commit, err := this.commit(ctx)
	if err != nil {
		return err
	}
	ref, err := this.ref(ctx)
	if err != nil {
		return err
	}
	v, err := this.version(ctx)
	if err != nil {
		return err
	}

	log.With("commit", commit).
		With("version", v).
		With("ref", ref).
		Info()

	return nil
}

func (this *base) version(ctx context.Context) (version, error) {
	for {
		if v := this.versionP.Load(); v != nil {
			return *v, nil
		}

		ref, err := this.ref(ctx)
		if err != nil {
			return version{}, err
		}

		var v version
		if strings.HasPrefix(ref, "v") && v.Set(ref) == nil {
			if err := v.evaluateLatest(this.repo.releases.allSemver(ctx)); err != nil {
				return version{}, err
			}
		} else if pr := this.pr(); pr > 0 {
			v.raw = fmt.Sprintf("pr-%d", pr)
		} else {
			v.raw = versionNormalizePattern.ReplaceAllString(ref, "-") + "-development"
		}

		if this.versionP.CompareAndSwap(nil, &v) {
			return v, nil
		}
		runtime.Gosched()
	}
}

func (this *base) ref(ctx context.Context) (string, error) {
	for {
		v := this.refP.Load()
		if v != nil {
			return *v, nil
		}
		nv, err := this.resolveRef(ctx)
		if err != nil {
			return "", err
		}
		if this.refP.CompareAndSwap(nil, &nv) {
			return nv, nil
		}
		runtime.Gosched()
	}
}

func (this *base) resolveRef(ctx context.Context) (string, error) {
	if v := this.rawHeadRef; v != "" {
		return v, nil
	}
	if v := this.rawRef; v != "" {
		return v, nil
	}
	v, err := this.exec.execute(ctx, "git", "rev-parse", "--abbrev-ref", "HEAD").
		doAndGet()
	if err != nil {
		return "", fmt.Errorf("cannot retrieve current ref: %w", err)
	}
	return v, nil
}

func (this *base) pr() uint {
	for {
		v := this.prP.Load()
		if v != nil {
			return *v
		}
		nv := this.resolvePr()
		if this.prP.CompareAndSwap(nil, &nv) {
			return nv
		}
		runtime.Gosched()
	}
}

func (this *base) resolvePr() uint {
	if v := this.rawPr; v != 0 {
		return v
	}
	if v := this.rawRef; v != "" {
		if !strings.HasSuffix(v, "/merge") {
			return 0
		}
		n, _ := strconv.ParseUint(strings.TrimSuffix(v, "/merge"), 10, 64)
		if n > uint64(math.MaxUint) {
			return 0 // or handle the error appropriately
		}
		return uint(n)
	}
	return 0
}

func (this *base) commit(ctx context.Context) (string, error) {
	for {
		v := this.commitP.Load()
		if v != nil {
			return *v, nil
		}
		nv, err := this.resolveCommit(ctx)
		if err != nil {
			return "", err
		}
		if this.commitP.CompareAndSwap(nil, &nv) {
			return nv, nil
		}
		runtime.Gosched()
	}
}

func (this *base) resolveCommit(ctx context.Context) (string, error) {
	if v := this.rawCommit; v != "" {
		return v, nil
	}
	v, err := this.execute(ctx, "git", "rev-parse", "--verify", "HEAD").
		doAndGet()
	if err != nil {
		return "", fmt.Errorf("cannot retrieve current commit: %w", err)
	}
	return v, nil
}
