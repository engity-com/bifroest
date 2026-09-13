// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	gos "os"
	"regexp"
	"slices"
	"strings"

	log "github.com/echocat/slf4g"
	"github.com/google/go-github/v65/github"
)

const (
	dependencyPullRequestBranchPrefix = "automation/dependencies/"
	dependencyPullRequestTitle        = "Update managed dependencies"
	dependencyPullRequestMarker       = "<!-- bifroest-dependency-update:v1 -->"
	dependencyPullRequestLabel        = "dependencies"
)

var dependencyPullRequestBranchPattern = regexp.MustCompile(`^` + regexp.QuoteMeta(dependencyPullRequestBranchPrefix) + `[0-9a-f]{16}$`)

type dependencyCheck struct {
	name     string
	source   string
	previous string
	current  string
	files    []string
	details  []string
	changed  bool
}

type dependencyUpdatePlan struct {
	baseSha      string
	baseBranch   string
	files        map[string][]byte
	checks       []dependencyCheck
	changedFiles []string
}

func (this *dependencies) updatePr(ctx context.Context) error {
	repository := this.base.repo
	if !strings.EqualFold(strings.TrimSpace(gos.Getenv("GITHUB_ACTIONS")), "true") {
		return fmt.Errorf("dependencies update-pr can only run in GitHub Actions")
	}
	if actual := strings.TrimSpace(gos.Getenv("GITHUB_REPOSITORY")); actual == "" || actual != repository.String() {
		return fmt.Errorf("GITHUB_REPOSITORY %q does not match configured repository %q", actual, repository.String())
	}
	if this.caCerts.targetFile != defaultCaCertsTargetFn {
		return fmt.Errorf("dependencies update-pr only supports CA certificate target %q", defaultCaCertsTargetFn)
	}
	appSlug := strings.TrimSpace(gos.Getenv("DEPENDENCY_UPDATES_APP_SLUG"))
	if appSlug == "" || !isSafeDependencyIdentifier(appSlug) {
		return fmt.Errorf("DEPENDENCY_UPDATES_APP_SLUG is missing or invalid")
	}
	actor := appSlug + "[bot]"
	user, _, err := this.base.repo.client().Users.Get(ctx, actor)
	if err != nil {
		return fmt.Errorf("cannot resolve dependency update actor %q: %w", actor, err)
	}
	if user.GetLogin() != actor || user.GetID() == 0 || user.GetType() != "Bot" {
		return fmt.Errorf("dependency update actor %q is not the expected GitHub App bot", actor)
	}
	return this.updatePrInRepository(ctx, actor)
}

func (this *dependencies) updatePrInRepository(ctx context.Context, actor string) error {
	repository := this.base.repo
	baseBranch, err := repository.dependencyDefaultBranch(ctx)
	if err != nil {
		return err
	}
	baseSha, err := repository.dependencyRefSha(ctx, "heads/"+baseBranch)
	if err != nil {
		return err
	}
	plan, err := this.prepareUpdatePlan(ctx, baseBranch, baseSha)
	if err != nil {
		return err
	}
	if err := repository.ensureDependencyBaseCurrent(ctx, baseBranch, baseSha); err != nil {
		return err
	}
	pullRequests, err := repository.listDependencyPullRequests(ctx, actor)
	if err != nil {
		return err
	}
	if len(plan.changedFiles) == 0 {
		if err := repository.ensureDependencyBaseCurrent(ctx, baseBranch, baseSha); err != nil {
			return err
		}
		if err := repository.closeDependencyPullRequests(ctx, pullRequests, ""); err != nil {
			return err
		}
		log.Info("Managed dependencies are current")
		return nil
	}

	branch := dependencyPullRequestBranch(baseSha, plan.files)
	body := plan.pullRequestBody()
	var current *github.PullRequest
	for _, pullRequest := range pullRequests {
		if pullRequest.GetHead().GetRef() == branch {
			current = pullRequest
			break
		}
	}
	if current != nil {
		unchanged, err := repository.dependencyPullRequestIsCurrent(ctx, current, baseBranch, baseSha, plan.files)
		if err != nil {
			return err
		}
		if unchanged {
			if err := repository.ensureDependencyBaseCurrent(ctx, baseBranch, baseSha); err != nil {
				return err
			}
			if current.GetTitle() != dependencyPullRequestTitle || current.GetBody() != body {
				if _, _, err := repository.client().PullRequests.Edit(ctx, repository.owner.String(), repository.name.String(), current.GetNumber(), &github.PullRequest{
					Title: github.String(dependencyPullRequestTitle),
					Body:  github.String(body),
				}); err != nil {
					return fmt.Errorf("cannot refresh dependency update pull request #%d: %w", current.GetNumber(), err)
				}
			}
			if err := repository.ensureDependencyBaseCurrent(ctx, baseBranch, baseSha); err != nil {
				return err
			}
			if err := repository.ensureDependencyLabel(ctx, current.GetNumber()); err != nil {
				return err
			}
			if err := repository.ensureDependencyBaseCurrent(ctx, baseBranch, baseSha); err != nil {
				return err
			}
			if err := repository.closeDependencyPullRequests(ctx, pullRequests, branch); err != nil {
				return err
			}
			log.With("pullRequest", current.GetHTMLURL()).Info("Dependency update pull request is current")
			return nil
		}
	}

	if err := repository.ensureDependencyBaseCurrent(ctx, baseBranch, baseSha); err != nil {
		return err
	}
	author, err := repository.dependencyCommitAuthor(ctx, actor)
	if err != nil {
		return err
	}
	commitMessage := plan.commitMessage(author)
	commitSha, treeSha, err := repository.createDependencyCommit(ctx, baseSha, plan.files, commitMessage, author)
	if err != nil {
		return err
	}
	if err := repository.ensureDependencyBaseCurrent(ctx, baseBranch, baseSha); err != nil {
		return err
	}
	if err := repository.createDependencyBranch(ctx, branch, baseSha, commitSha, treeSha, current != nil, commitMessage, author); err != nil {
		return err
	}
	if err := repository.ensureDependencyBaseCurrent(ctx, baseBranch, baseSha); err != nil {
		return errors.Join(err, repository.deleteDependencyBranchIfUnchanged(ctx, branch, commitSha))
	}

	if current == nil {
		created, _, err := repository.client().PullRequests.Create(ctx, repository.owner.String(), repository.name.String(), &github.NewPullRequest{
			Title:               github.String(dependencyPullRequestTitle),
			Head:                github.String(branch),
			Base:                github.String(baseBranch),
			Body:                github.String(body),
			MaintainerCanModify: github.Bool(false),
		})
		if err != nil {
			refreshed, listErr := repository.listDependencyPullRequests(ctx, actor)
			if listErr != nil {
				return errors.Join(fmt.Errorf("cannot create dependency update pull request: %w", err), listErr)
			}
			for _, candidate := range refreshed {
				if candidate.GetHead().GetRef() == branch {
					current = candidate
					break
				}
			}
			if current == nil {
				cleanupErr := repository.deleteDependencyBranchIfUnchanged(ctx, branch, commitSha)
				return errors.Join(fmt.Errorf("cannot create dependency update pull request: %w", err), cleanupErr)
			}
		} else {
			current = created
		}
	} else {
		updated, _, err := repository.client().PullRequests.Edit(ctx, repository.owner.String(), repository.name.String(), current.GetNumber(), &github.PullRequest{
			Title: github.String(dependencyPullRequestTitle),
			Body:  github.String(body),
			Base:  &github.PullRequestBranch{Ref: github.String(baseBranch)},
		})
		if err != nil {
			return fmt.Errorf("cannot update dependency update pull request #%d: %w", current.GetNumber(), err)
		}
		current = updated
	}
	if err := repository.ensureDependencyBaseCurrent(ctx, baseBranch, baseSha); err != nil {
		return err
	}
	if err := repository.ensureDependencyLabel(ctx, current.GetNumber()); err != nil {
		return err
	}
	if err := repository.ensureDependencyBaseCurrent(ctx, baseBranch, baseSha); err != nil {
		return err
	}
	if err := repository.closeDependencyPullRequests(ctx, pullRequests, branch); err != nil {
		return err
	}
	log.With("pullRequest", current.GetHTMLURL()).Info("Dependency update pull request ready")
	return nil
}

func (this *dependencies) prepareUpdatePlan(ctx context.Context, baseBranch, baseSha string) (*dependencyUpdatePlan, error) {
	paths := []string{defaultCaCertsTargetFn}
	for _, image := range dependencyImages {
		for _, location := range image.locations {
			paths = append(paths, location.path)
		}
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)

	original := make(map[string][]byte, len(paths))
	updated := make(map[string][]byte, len(paths))
	for _, path := range paths {
		content, err := this.base.repo.loadFileAtRef(ctx, path, baseSha)
		if err != nil {
			return nil, err
		}
		original[path] = content
		updated[path] = slices.Clone(content)
	}
	checks, err := this.applyImageUpdates(ctx, updated)
	if err != nil {
		return nil, err
	}

	source, err := this.caCerts.loadSource(ctx)
	if err != nil {
		return nil, err
	}
	bundle, err := buildCaCertsBundle(ctx, source, this.caCerts.now().UTC())
	if err != nil {
		return nil, err
	}
	caUpdate, err := prepareCaCertsUpdate(original[defaultCaCertsTargetFn], bundle)
	if err != nil {
		return nil, err
	}
	this.caCerts.logComparison(source, caUpdate.existing, bundle, caUpdate.diff)
	if caUpdate.changed {
		updated[defaultCaCertsTargetFn] = caUpdate.generated
	}
	existingState := formatFingerprint(caCertificatesStateHash(caUpdate.existing))
	generatedState := formatFingerprint(caCertificatesStateHash(bundle.certificates))
	checks = append(checks, dependencyCheck{
		name:     "Mozilla CA certificates",
		source:   source.url,
		previous: fmt.Sprintf("%d certificates (state SHA-256 %s)", len(caUpdate.existing), existingState),
		current:  fmt.Sprintf("%d certificates (state SHA-256 %s)", len(bundle.certificates), generatedState),
		files:    []string{defaultCaCertsTargetFn},
		details: []string{
			fmt.Sprintf("Mozilla source revision: `%s`", source.revision),
			fmt.Sprintf("Certificates added: %d", len(caUpdate.diff.added)),
			fmt.Sprintf("Certificates removed: %d", len(caUpdate.diff.removed)),
		},
		changed: caUpdate.changed,
	})

	changedFiles := make([]string, 0, len(updated))
	files := make(map[string][]byte)
	for _, path := range paths {
		if bytes.Equal(original[path], updated[path]) {
			continue
		}
		changedFiles = append(changedFiles, path)
		files[path] = updated[path]
	}
	return &dependencyUpdatePlan{
		baseSha:      baseSha,
		baseBranch:   baseBranch,
		files:        files,
		checks:       checks,
		changedFiles: changedFiles,
	}, nil
}

func (this *dependencyUpdatePlan) pullRequestBody() string {
	var body strings.Builder
	body.WriteString(dependencyPullRequestMarker + "\n\n")
	body.WriteString("This pull request atomically reconciles all dependencies managed by the daily dependency workflow.\n\n")
	body.WriteString("| Dependency | Status | Previous | Resolved |\n")
	body.WriteString("| --- | --- | --- | --- |\n")
	for _, check := range this.checks {
		status := "Current"
		if check.changed {
			status = "Updated"
		}
		fmt.Fprintf(&body, "| %s | %s | `%s` | `%s` |\n", check.name, status, check.previous, check.current)
	}
	for _, check := range this.checks {
		body.WriteString("\n### " + check.name + "\n\n")
		fmt.Fprintf(&body, "- Source: `%s`\n", check.source)
		fmt.Fprintf(&body, "- Files: `%s`\n", strings.Join(check.files, "`, `"))
		for _, detail := range check.details {
			body.WriteString("- " + detail + "\n")
		}
	}
	body.WriteString("\nThe update is intentionally not auto-merged. Review source revisions, image digests, checks, and the complete diff before merging.\n\n")
	body.WriteString("Generated by `go run ./cmd/build dependencies update-pr`.\n")
	return body.String()
}

func (this *dependencyUpdatePlan) commitMessage(author *github.CommitAuthor) string {
	var message strings.Builder
	message.WriteString("Update managed dependencies\n\n")
	for _, check := range this.checks {
		if !check.changed {
			continue
		}
		fmt.Fprintf(&message, "- %s: %s -> %s\n", check.name, check.previous, check.current)
	}
	fmt.Fprintf(&message, "\nSigned-off-by: %s <%s>\n", author.GetName(), author.GetEmail())
	return message.String()
}

func dependencyPullRequestBranch(baseSha string, files map[string][]byte) string {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	digest := sha256.New()
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(baseSha)))
	_, _ = digest.Write(size[:])
	_, _ = digest.Write([]byte(baseSha))
	for _, path := range paths {
		binary.BigEndian.PutUint64(size[:], uint64(len(path)))
		_, _ = digest.Write(size[:])
		_, _ = digest.Write([]byte(path))
		binary.BigEndian.PutUint64(size[:], uint64(len(files[path])))
		_, _ = digest.Write(size[:])
		_, _ = digest.Write(files[path])
	}
	return dependencyPullRequestBranchPrefix + fmt.Sprintf("%x", digest.Sum(nil))[:16]
}

func isSafeDependencyIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return true
}

func (this *repo) listDependencyPullRequests(ctx context.Context, actor string) ([]*github.PullRequest, error) {
	var result []*github.PullRequest
	options := &github.PullRequestListOptions{State: "open", Base: "", ListOptions: github.ListOptions{PerPage: 100}}
	for {
		pullRequests, response, err := this.client().PullRequests.List(ctx, this.owner.String(), this.name.String(), options)
		if err != nil {
			return nil, fmt.Errorf("cannot list dependency update pull requests: %w", err)
		}
		for _, pullRequest := range pullRequests {
			if this.isDependencyPullRequest(pullRequest, actor) {
				result = append(result, pullRequest)
			}
		}
		if response == nil || response.NextPage == 0 {
			break
		}
		options.Page = response.NextPage
	}
	return result, nil
}

func (this *repo) isDependencyPullRequest(pullRequest *github.PullRequest, actor string) bool {
	if pullRequest == nil || pullRequest.GetUser().GetLogin() != actor || !strings.Contains(pullRequest.GetBody(), dependencyPullRequestMarker) {
		return false
	}
	head := pullRequest.GetHead()
	return head != nil && head.GetRepo().GetFullName() == this.owner.String()+"/"+this.name.String() && dependencyPullRequestBranchPattern.MatchString(head.GetRef())
}

func (this *repo) dependencyPullRequestHasFiles(ctx context.Context, pullRequest *github.PullRequest, expected map[string][]byte) (bool, error) {
	var files []*github.CommitFile
	options := &github.ListOptions{PerPage: 100}
	for {
		page, response, err := this.client().PullRequests.ListFiles(ctx, this.owner.String(), this.name.String(), pullRequest.GetNumber(), options)
		if err != nil {
			return false, fmt.Errorf("cannot inspect dependency update pull request #%d: %w", pullRequest.GetNumber(), err)
		}
		files = append(files, page...)
		if response == nil || response.NextPage == 0 {
			break
		}
		options.Page = response.NextPage
	}
	if len(files) != len(expected) {
		return false, nil
	}
	for _, file := range files {
		expectedContent, exists := expected[file.GetFilename()]
		if !exists || file.GetStatus() == "removed" || file.GetPreviousFilename() != "" {
			return false, nil
		}
		actual, err := this.loadFileAtRef(ctx, file.GetFilename(), pullRequest.GetHead().GetSHA())
		if err != nil {
			return false, err
		}
		if !bytes.Equal(actual, expectedContent) {
			return false, nil
		}
	}
	return true, nil
}

func (this *repo) dependencyPullRequestIsCurrent(ctx context.Context, pullRequest *github.PullRequest, baseBranch, baseSha string, expected map[string][]byte) (bool, error) {
	if pullRequest.GetBase().GetRef() != baseBranch || pullRequest.GetHead().GetSHA() == "" {
		return false, nil
	}
	commit, _, err := this.client().Git.GetCommit(ctx, this.owner.String(), this.name.String(), pullRequest.GetHead().GetSHA())
	if err != nil {
		return false, fmt.Errorf("cannot inspect dependency update pull request #%d head: %w", pullRequest.GetNumber(), err)
	}
	if len(commit.Parents) != 1 || commit.Parents[0].GetSHA() != baseSha {
		return false, nil
	}
	return this.dependencyPullRequestHasFiles(ctx, pullRequest, expected)
}

func (this *repo) loadFileAtRef(ctx context.Context, path, ref string) ([]byte, error) {
	file, directory, _, err := this.client().Repositories.GetContents(ctx, this.owner.String(), this.name.String(), path, &github.RepositoryContentGetOptions{Ref: ref})
	if err != nil {
		return nil, fmt.Errorf("cannot load %s at %s: %w", path, ref, err)
	}
	if file == nil || len(directory) != 0 {
		return nil, fmt.Errorf("expected %s at %s to be a file", path, ref)
	}
	content, err := file.GetContent()
	if err != nil {
		return nil, fmt.Errorf("cannot decode %s at %s: %w", path, ref, err)
	}
	return []byte(content), nil
}

func (this *repo) dependencyDefaultBranch(ctx context.Context) (string, error) {
	metadata, err := this.meta(ctx)
	if err != nil {
		return "", fmt.Errorf("cannot identify repository default branch: %w", err)
	}
	if metadata.GetDefaultBranch() == "" {
		return "", fmt.Errorf("repository has no default branch")
	}
	return metadata.GetDefaultBranch(), nil
}

func (this *repo) dependencyRefSha(ctx context.Context, refName string) (string, error) {
	ref, _, err := this.client().Git.GetRef(ctx, this.owner.String(), this.name.String(), refName)
	if err != nil {
		return "", fmt.Errorf("cannot resolve repository ref %s: %w", refName, err)
	}
	if ref.GetObject().GetSHA() == "" {
		return "", fmt.Errorf("repository ref %s has no SHA", refName)
	}
	return ref.GetObject().GetSHA(), nil
}

func (this *repo) dependencyCommitAuthor(ctx context.Context, actor string) (*github.CommitAuthor, error) {
	user, _, err := this.client().Users.Get(ctx, actor)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve commit author %q: %w", actor, err)
	}
	if user.GetID() == 0 {
		return nil, fmt.Errorf("commit author %q has no GitHub user ID", actor)
	}
	return &github.CommitAuthor{Name: github.String(actor), Email: github.String(fmt.Sprintf("%d+%s@users.noreply.github.com", user.GetID(), actor))}, nil
}

func (this *repo) createDependencyCommit(ctx context.Context, baseSha string, files map[string][]byte, message string, author *github.CommitAuthor) (string, string, error) {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	entries := make([]*github.TreeEntry, 0, len(paths))
	for _, path := range paths {
		entries = append(entries, &github.TreeEntry{Path: github.String(path), Mode: github.String("100644"), Type: github.String("blob"), Content: github.String(string(files[path]))})
	}
	baseCommit, _, err := this.client().Git.GetCommit(ctx, this.owner.String(), this.name.String(), baseSha)
	if err != nil {
		return "", "", fmt.Errorf("cannot load dependency update base commit %s: %w", baseSha, err)
	}
	if baseCommit.GetTree().GetSHA() == "" {
		return "", "", fmt.Errorf("dependency update base commit %s has no tree", baseSha)
	}
	tree, _, err := this.client().Git.CreateTree(ctx, this.owner.String(), this.name.String(), baseCommit.GetTree().GetSHA(), entries)
	if err != nil {
		return "", "", fmt.Errorf("cannot create dependency update tree: %w", err)
	}
	commit, _, err := this.client().Git.CreateCommit(ctx, this.owner.String(), this.name.String(), &github.Commit{Message: github.String(message), Tree: tree, Parents: []*github.Commit{{SHA: github.String(baseSha)}}, Author: author, Committer: author}, nil)
	if err != nil {
		return "", "", fmt.Errorf("cannot create dependency update commit: %w", err)
	}
	if commit.GetSHA() == "" {
		return "", "", fmt.Errorf("dependency update commit has no SHA")
	}
	return commit.GetSHA(), tree.GetSHA(), nil
}

func (this *repo) createDependencyBranch(ctx context.Context, branch, baseSha, commitSha, treeSha string, hasPullRequest bool, expectedMessage string, author *github.CommitAuthor) error {
	refName := "refs/heads/" + branch
	shortRef := "heads/" + branch
	ref, _, err := this.client().Git.GetRef(ctx, this.owner.String(), this.name.String(), shortRef)
	if err != nil {
		if githubError, ok := err.(*github.ErrorResponse); !ok || githubError.Response == nil || githubError.Response.StatusCode != 404 {
			return fmt.Errorf("cannot inspect dependency update branch %s: %w", branch, err)
		}
		if _, _, err := this.client().Git.CreateRef(ctx, this.owner.String(), this.name.String(), &github.Reference{Ref: github.String(refName), Object: &github.GitObject{SHA: github.String(commitSha)}}); err != nil {
			return fmt.Errorf("cannot create dependency update branch %s: %w", branch, err)
		}
		return nil
	}
	if hasPullRequest {
		return fmt.Errorf("refusing to overwrite dependency update branch %s because its pull request is not current", branch)
	}
	referenced, err := this.dependencyBranchIsReferenced(ctx, branch)
	if err != nil {
		return err
	}
	if referenced {
		return fmt.Errorf("refusing to reuse dependency update branch %s because a pull request already references it", branch)
	}
	owned, err := this.dependencyBranchIsOwnedOrphan(ctx, branch, ref.GetObject().GetSHA(), baseSha, treeSha, expectedMessage, author)
	if err != nil {
		return err
	}
	if !owned {
		return fmt.Errorf("refusing to reuse dependency update branch %s because it is not an expected bot-owned orphan", branch)
	}
	return nil
}

func (this *repo) dependencyBranchIsOwnedOrphan(ctx context.Context, branch, commitSha, baseSha, expectedTreeSha, expectedMessage string, author *github.CommitAuthor) (bool, error) {
	commit, _, err := this.client().Git.GetCommit(ctx, this.owner.String(), this.name.String(), commitSha)
	if err != nil {
		return false, fmt.Errorf("cannot inspect commit %s for branch %s: %w", commitSha, branch, err)
	}
	if commit.GetTree().GetSHA() != expectedTreeSha || commit.GetMessage() != expectedMessage || commit.GetAuthor().GetName() != author.GetName() || commit.GetAuthor().GetEmail() != author.GetEmail() || commit.GetCommitter().GetName() != author.GetName() || commit.GetCommitter().GetEmail() != author.GetEmail() {
		return false, nil
	}
	parents := commit.Parents
	return len(parents) == 1 && parents[0].GetSHA() == baseSha, nil
}

func (this *repo) deleteDependencyBranchIfUnchanged(ctx context.Context, branch, expectedSha string) error {
	referenced, err := this.dependencyBranchIsReferenced(ctx, branch)
	if err != nil {
		return err
	}
	if referenced {
		return fmt.Errorf("refusing to clean up failed dependency update branch %s because a pull request references it", branch)
	}
	ref, response, err := this.client().Git.GetRef(ctx, this.owner.String(), this.name.String(), "heads/"+branch)
	if err != nil {
		if response != nil && response.StatusCode == http.StatusNotFound {
			return nil
		}
		return fmt.Errorf("cannot inspect failed dependency update branch %s: %w", branch, err)
	}
	if ref.GetObject().GetSHA() != expectedSha {
		return fmt.Errorf("refusing to clean up failed dependency update branch %s because its head changed", branch)
	}
	if _, err := this.client().Git.DeleteRef(ctx, this.owner.String(), this.name.String(), "heads/"+branch); err != nil {
		return fmt.Errorf("cannot clean up failed dependency update branch %s: %w", branch, err)
	}
	return nil
}

func (this *repo) dependencyBranchIsReferenced(ctx context.Context, branch string) (bool, error) {
	pullRequests, _, err := this.client().PullRequests.List(ctx, this.owner.String(), this.name.String(), &github.PullRequestListOptions{
		State: "all",
		Head:  this.owner.String() + ":" + branch,
		ListOptions: github.ListOptions{
			PerPage: 1,
		},
	})
	if err != nil {
		return false, fmt.Errorf("cannot inspect pull requests for dependency update branch %s: %w", branch, err)
	}
	return len(pullRequests) != 0, nil
}

func (this *repo) closeDependencyPullRequests(ctx context.Context, pullRequests []*github.PullRequest, keepBranch string) error {
	for _, pullRequest := range pullRequests {
		branch := pullRequest.GetHead().GetRef()
		if branch == keepBranch {
			continue
		}
		ref, response, err := this.client().Git.GetRef(ctx, this.owner.String(), this.name.String(), "heads/"+branch)
		if err != nil && (response == nil || response.StatusCode != http.StatusNotFound) {
			return fmt.Errorf("cannot verify superseded dependency update branch %s: %w", branch, err)
		}
		if err == nil && ref.GetObject().GetSHA() != pullRequest.GetHead().GetSHA() {
			return fmt.Errorf("refusing to close dependency update pull request #%d because branch %s changed", pullRequest.GetNumber(), branch)
		}
		if _, _, err := this.client().PullRequests.Edit(ctx, this.owner.String(), this.name.String(), pullRequest.GetNumber(), &github.PullRequest{State: github.String("closed")}); err != nil {
			return fmt.Errorf("cannot close superseded dependency update pull request #%d: %w", pullRequest.GetNumber(), err)
		}
		if err == nil {
			ref, response, err = this.client().Git.GetRef(ctx, this.owner.String(), this.name.String(), "heads/"+branch)
		}
		if err == nil && ref.GetObject().GetSHA() != pullRequest.GetHead().GetSHA() {
			return fmt.Errorf("refusing to delete superseded dependency update branch %s because its head changed", branch)
		}
		if err == nil {
			response, err = this.client().Git.DeleteRef(ctx, this.owner.String(), this.name.String(), "heads/"+branch)
		}
		if err != nil && (response == nil || response.StatusCode != http.StatusNotFound) {
			return fmt.Errorf("cannot delete superseded dependency update branch %s: %w", branch, err)
		}
	}
	return nil
}

func (this *repo) ensureDependencyLabel(ctx context.Context, pullRequest int) error {
	if _, _, err := this.client().Issues.AddLabelsToIssue(ctx, this.owner.String(), this.name.String(), pullRequest, []string{dependencyPullRequestLabel}); err != nil {
		return fmt.Errorf("cannot label dependency update pull request #%d: %w", pullRequest, err)
	}
	return nil
}

func (this *repo) ensureDependencyBaseCurrent(ctx context.Context, branch, expectedSha string) error {
	metadata, _, err := this.client().Repositories.Get(ctx, this.owner.String(), this.name.String())
	if err != nil {
		return fmt.Errorf("cannot recheck repository metadata: %w", err)
	}
	if metadata.GetDefaultBranch() != branch {
		return fmt.Errorf("default branch changed from %s to %s while preparing dependency update", branch, metadata.GetDefaultBranch())
	}
	actualSha, err := this.dependencyRefSha(ctx, "heads/"+branch)
	if err != nil {
		return err
	}
	if actualSha != expectedSha {
		return fmt.Errorf("base branch %s changed from %s to %s while preparing dependency update", branch, expectedSha, actualSha)
	}
	return nil
}
