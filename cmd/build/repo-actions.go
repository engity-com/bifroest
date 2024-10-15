package main

import (
	"context"
	"fmt"
	"iter"

	"github.com/alecthomas/kingpin/v2"
	"github.com/google/go-github/v65/github"
)

func newRepoActions(r *repo) *repoActions {
	return &repoActions{
		repo: r,

		workflowFilenameCi: "ci.yml",
	}
}

type repoActions struct {
	*repo

	workflowFilenameCi string
}

func (this *repoActions) init(_ context.Context, app *kingpin.Application) {
	app.Flag("workflow-filename-ci", "").
		Default(this.workflowFilenameCi).
		StringVar(&this.workflowFilenameCi)
}

func (this *repoActions) ciWorkflow(ctx context.Context) (*repoWorkflow, error) {
	return this.workflowByFilename(ctx, this.workflowFilenameCi)
}

func (this *repoActions) workflowByFilename(ctx context.Context, fn string) (*repoWorkflow, error) {
	v, _, err := this.client().Actions.GetWorkflowByFileName(ctx, this.owner.String(), this.name.String(), fn)
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve workflow %s from %v: %w", fn, this.base, err)
	}
	return &repoWorkflow{
		v,
		this,
	}, nil
}

type repoWorkflow struct {
	*github.Workflow

	parent *repoActions
}

func (this *repoWorkflow) String() string {
	return fmt.Sprintf("%s(%d)@%v", *this.Name, *this.ID, this.parent.repo)
}

func (this *repoWorkflow) runs(ctx context.Context) iter.Seq2[*repoWorkflowRun, error] {
	return func(yield func(*repoWorkflowRun, error) bool) {
		var opts github.ListWorkflowRunsOptions
		opts.PerPage = 100

		for {
			candidates, rsp, err := this.parent.client().Actions.ListWorkflowRunsByID(ctx, this.parent.owner.String(), this.parent.name.String(), *this.ID, &opts)
			if err != nil {
				yield(nil, fmt.Errorf("cannot retrieve workflow runs of %v (page: %d): %w", this, opts.Page, err))
				return
			}
			for _, v := range candidates.WorkflowRuns {
				if !yield(&repoWorkflowRun{v, this}, nil) {
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

type repoWorkflowRun struct {
	*github.WorkflowRun
	parent *repoWorkflow
}

func (this *repoWorkflowRun) rerun(ctx context.Context) error {
	_, err := this.parent.parent.client().Actions.RerunWorkflowByID(ctx, this.parent.parent.owner.String(), this.parent.parent.name.String(), *this.ID)
	if err != nil {
		return fmt.Errorf("cannot rerun workflow run %v: %w", this, err)
	}
	return nil
}

func (this repoWorkflowRun) String() string {
	return fmt.Sprintf("%d@%v", *this.ID, this.parent)
}
