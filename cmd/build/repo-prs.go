package main

import (
	"context"
	"fmt"
	gos "os"
	"slices"
	"strings"
	"time"

	"github.com/alecthomas/kingpin"
	"github.com/echocat/slf4g"
	"github.com/google/go-github/v65/github"
)

func newRepoPrs(r *repo) *repoPrs {
	return &repoPrs{
		repo: r,
	}
}

func (this *repoPrs) init(ctx context.Context, app *kingpin.Application) {
	var prNumber int
	var workflowFn string
	var label string

	cmdRpw := app.Command("rerun-pr-workflow", "")
	cmdRpw.Arg("prNumber", "").
		Required().
		IntVar(&prNumber)
	cmdRpw.Arg("workflowFilename", "").
		Required().
		StringVar(&workflowFn)
	cmdRpw.Action(func(*kingpin.ParseContext) error {
		return this.rerunLatestWorkflowCmd(ctx, prNumber, workflowFn)
	})

	cmdHpl := app.Command("has-pr-label", "")
	cmdHpl.Arg("prNumber", "").
		Required().
		IntVar(&prNumber)
	cmdHpl.Arg("label", "").
		Required().
		StringVar(&label)
	cmdHpl.Action(func(*kingpin.ParseContext) error {
		return this.hasLabelCmd(ctx, prNumber, label)
	})

	cmdIpo := app.Command("is-pr-open", "")
	cmdIpo.Arg("prNumber", "").
		Required().
		IntVar(&prNumber)
	cmdIpo.Action(func(*kingpin.ParseContext) error {
		return this.isOpenCmd(ctx, prNumber)
	})
}

func (this *repoPrs) Validate() error { return nil }

type repoPrs struct {
	*repo
}

func (this *repoPrs) rerunLatestWorkflowCmd(ctx context.Context, prNumber int, workflowFn string) error {
	v, err := this.byId(ctx, prNumber)
	if err != nil {
		return err
	}

	l := log.With("pr", prNumber).
		With("workflowFn", workflowFn)

	start := time.Now()
	for ctx.Err() == nil {
		wfr, err := v.latestWorkflowRun(ctx, workflowFn)
		if err != nil {
			return err
		}
		lw := l.With("workflowRun", wfr)
		if wfr.Status != nil && strings.EqualFold(*wfr.Status, "completed") {
			if err := wfr.rerun(ctx); err != nil {
				return err
			}
			lw.With("workflowRunUrl", *wfr.HTMLURL).
				With("prUrl", *v.HTMLURL).
				Info("rerun of workflow run was successfully triggered")
			return nil
		}
		lw.With("duration", time.Since(start).Truncate(time.Second)).
			Info("latest workflow run is still running - continue waiting...")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(this.base.waitTimeout):
		}
	}

	return ctx.Err()
}

func (this *repoPrs) hasLabelCmd(ctx context.Context, prNumber int, label string) error {
	v, err := this.byId(ctx, prNumber)
	if err != nil {
		return err
	}

	l := log.With("pr", prNumber).
		With("label", label)
	if v.hasLabel(label) {
		l.Info("label is present")
		gos.Exit(0)
	} else {
		l.Info("label is absent")
		gos.Exit(1)
	}

	return nil
}

func (this *repoPrs) isOpenCmd(ctx context.Context, prNumber int) error {
	v, err := this.byId(ctx, prNumber)
	if err != nil {
		return err
	}

	l := log.With("pr", prNumber)
	if v.isOpen() {
		l.Info("pr is open")
		gos.Exit(0)
	} else {
		l.Info("pr is closed")
		gos.Exit(1)
	}

	return nil
}

func (this *repoPrs) byId(ctx context.Context, number int) (*repoPr, error) {
	v, _, err := this.client().PullRequests.Get(ctx, this.owner.String(), this.name.String(), number)
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve pull request %d from %v: %w", number, this.base, err)
	}
	return &repoPr{
		v,
		this,
	}, nil
}

type repoPr struct {
	*github.PullRequest

	parent *repoPrs
}

func (this *repoPr) String() string {
	return fmt.Sprintf("%d@%v", *this.ID, this.parent.base.repo)
}

func (this *repoPr) hasLabel(label string) bool {
	return slices.ContainsFunc(this.Labels, func(candidate *github.Label) bool {
		if candidate == nil {
			return false
		}
		return candidate.Name != nil && *candidate.Name == label
	})
}

func (this *repoPr) isOpen() bool {
	return this.State != nil && strings.EqualFold(*this.State, "open")
}

func (this *repoPr) latestWorkflowRun(ctx context.Context, workflowFn string) (*repoWorkflowRun, error) {
	wf, err := this.parent.actions.workflowByFilename(ctx, workflowFn)
	if err != nil {
		return nil, fmt.Errorf("cannot get workflow %s of %v: %w", workflowFn, this, err)
	}
	for candidate, err := range wf.runs(ctx) {
		if err != nil {
			return nil, fmt.Errorf("cannot retrieve workflow runs for pr %v: %w", this, err)
		}
		if slices.ContainsFunc(candidate.PullRequests, func(cpr *github.PullRequest) bool {
			return cpr != nil && cpr.ID != nil && *cpr.ID == *this.ID
		}) {
			return candidate, nil
		}
	}
	return nil, nil
}
