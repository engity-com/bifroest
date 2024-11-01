package main

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/echocat/slf4g"
	"github.com/google/go-github/v65/github"
)

func newRepoPrs(r *repo) *repoPrs {
	return &repoPrs{
		repo: r,

		testPublishLabel: "test_publish",
	}
}

type repoPrs struct {
	*repo

	testPublishLabel string
}

func (this *repoPrs) Validate() error { return nil }

func (this *repoPrs) init(ctx context.Context, app *kingpin.Application) {
	app.Flag("label-test-publish", "").
		Default(this.testPublishLabel).
		StringVar(&this.testPublishLabel)

	var eventAction string
	var prNumber uint
	var label string

	cmdIu := app.Command("inspect-pr-action", "")
	cmdIu.Arg("eventAction", "").
		Required().
		StringVar(&eventAction)
	cmdIu.Arg("prNumber", "").
		Required().
		UintVar(&prNumber)
	cmdIu.Arg("label", "").
		StringVar(&label)
	cmdIu.Action(func(*kingpin.ParseContext) error {
		return this.inspectAction(ctx, eventAction, prNumber, label)
	})
}

func (this *repoPrs) inspectAction(ctx context.Context, eventAction string, prNumber uint, label string) error {
	if prNumber == 0 {
		prNumber = this.pr()
	}
	if prNumber == 0 {
		return fmt.Errorf("neither the environment does not contain a pr reference nor the command was called with it")
	}

	pr, err := this.byId(ctx, prNumber)
	if err != nil {
		return err
	}

	if (eventAction == "labeled" || eventAction == "unlabeled") && label == "" {
		return fmt.Errorf("for labeled and unlabeled actions the label argument is required")
	}

	if eventAction == "labeled" && label == this.testPublishLabel && pr.isOpen() {
		log.With("pr", pr).
			With("label", this.testPublishLabel).
			Info("PR received label for being allowed to publish; rerun the latest workflow to enable them now...")

		if err := pr.rerunLatestCiWorkflow(ctx); err != nil {
			return err
		}
	}

	if (eventAction == "unlabeled" && label == this.testPublishLabel && pr.isOpen()) ||
		eventAction == "closed" {

		log.With("pr", pr).
			With("label", this.testPublishLabel).
			Info("PR was unlabeled or closed; therefore delete all images that might be related to this PR...")

		if err := pr.deleteRelatedArtifacts(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (this *repoPrs) byId(ctx context.Context, number uint) (*repoPr, error) {
	v, _, err := this.client().PullRequests.Get(ctx, this.owner.String(), this.name.String(), int(number))
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

func (this *repoPr) rerunLatestCiWorkflow(ctx context.Context) error {
	return this.rerunLatestWorkflow(ctx, this.parent.actions.ciWorkflow)
}

func (this *repoPr) rerunLatestWorkflow(ctx context.Context, workflowLoader func(context.Context) (*repoWorkflow, error)) error {
	l := log.With("pr", this.GetID())

	start := time.Now()
	for ctx.Err() == nil {
		wfr, err := this.latestWorkflowRun(ctx, workflowLoader)
		if err != nil {
			return err
		}
		lw := l.With("workflowRun", wfr)
		if wfr.Status != nil && strings.EqualFold(*wfr.Status, "completed") {
			if err := wfr.rerun(ctx); err != nil {
				return err
			}
			lw.With("workflowRunUrl", *wfr.HTMLURL).
				With("prUrl", this.GetHTMLURL()).
				Info("rerun of workflow run was successfully triggered")
			return nil
		}
		lw.With("duration", time.Since(start).Truncate(time.Second)).
			Info("latest workflow run is still running - continue waiting...")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(this.parent.base.waitTimeout):
		}
	}

	return ctx.Err()
}

func (this *repoPr) latestWorkflowRun(ctx context.Context, workflowLoader func(context.Context) (*repoWorkflow, error)) (*repoWorkflowRun, error) {
	wf, err := workflowLoader(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot get workflow of %v: %w", this, err)
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

func (this *repoPr) deleteRelatedArtifacts(ctx context.Context) error {
	fail := func(err error) error {
		return fmt.Errorf("cannot delete artifacts for %v: %w", this, err)
	}

	docsTag := fmt.Sprintf("docs/pr-%d", this.GetID())
	if err := this.parent.execute(ctx, "git", "push", "--delete", "origin", docsTag).
		do(); err != nil {
		log.With("pr", this.GetID()).
			With("tag", docsTag).
			WithError(err).
			Info("cannot delete tag in Git; this can be a problem or simply mean that the tag does not exist; ignoring...")
	}

	do := func(tag string) error {
		return this.parent.actions.packages.deleteVersionsWithTags(ctx, tag)
	}

	mainTag := fmt.Sprintf("pr-%d", this.GetID())

	if err := do(mainTag); err != nil {
		return fail(err)
	}
	for _, ed := range allEditionVariants {
		if err := do(ed.String() + "-" + mainTag); err != nil {
			return fail(err)
		}
	}

	return nil
}
