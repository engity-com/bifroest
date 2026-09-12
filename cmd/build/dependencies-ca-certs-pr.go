package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	gos "os"
	"strings"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/google/go-github/v65/github"
)

const (
	caCertsRepositoryPath = "pkg/crypto/ca-certs.crt"
	caCertsPrBranchPrefix = "automation/ca-certificates/"
	caCertsPrMarker       = "<!-- bifroest-ca-certificates-update -->"
	caCertsPrTitle        = "Update Mozilla CA certificates"
	caCertsPrLabel        = "dependencies"
)

func (this *dependenciesCaCerts) updatePr(ctx context.Context) error {
	repository := this.dependencies.base.repo
	if gos.Getenv("GITHUB_ACTIONS") != "true" {
		return fmt.Errorf("ca-certs update-pr can only run in GitHub Actions")
	}
	if actual := gos.Getenv("GITHUB_REPOSITORY"); actual == "" || actual != repository.String() {
		return fmt.Errorf("GITHUB_REPOSITORY %q does not match configured repository %q", actual, repository.String())
	}
	if this.targetFile != defaultCaCertsTargetFn {
		return fmt.Errorf("ca-certs update-pr only supports target %q", defaultCaCertsTargetFn)
	}
	appSlug := strings.TrimSpace(gos.Getenv("CA_CERTIFICATES_APP_SLUG"))
	if appSlug == "" || strings.ContainsAny(appSlug, "[]/\\") {
		return fmt.Errorf("CA_CERTIFICATES_APP_SLUG is missing or invalid")
	}
	return this.updatePrInRepository(ctx, appSlug+"[bot]")
}

func (this *dependenciesCaCerts) updatePrInRepository(ctx context.Context, actor string) error {
	repository := this.dependencies.base.repo
	owner := repository.owner.String()
	name := repository.name.String()
	client := repository.client()

	metadata, err := repository.meta(ctx)
	if err != nil {
		return fmt.Errorf("cannot retrieve target repository metadata: %w", err)
	}
	baseBranch := metadata.GetDefaultBranch()
	if baseBranch == "" {
		return fmt.Errorf("target repository %s has no default branch", repository)
	}
	baseRef, _, err := client.Git.GetRef(ctx, owner, name, "heads/"+baseBranch)
	if err != nil {
		return fmt.Errorf("cannot retrieve default branch %s of %s: %w", baseBranch, repository, err)
	}
	baseSHA := baseRef.GetObject().GetSHA()
	if baseSHA == "" {
		return fmt.Errorf("default branch %s of %s has no commit", baseBranch, repository)
	}
	baseCommit, _, err := client.Git.GetCommit(ctx, owner, name, baseSHA)
	if err != nil {
		return fmt.Errorf("cannot retrieve commit %s of %s: %w", baseSHA, repository, err)
	}
	if baseCommit.GetTree().GetSHA() == "" {
		return fmt.Errorf("commit %s of %s has no tree", baseSHA, repository)
	}

	existingRaw, err := loadRepositoryFile(ctx, client, owner, name, caCertsRepositoryPath, baseSHA)
	if err != nil {
		return fmt.Errorf("cannot read %s at %s: %w", caCertsRepositoryPath, baseSHA, err)
	}
	source, err := this.loadSource(ctx)
	if err != nil {
		return err
	}
	bundle, err := buildCaCertsBundle(ctx, source, this.now().UTC())
	if err != nil {
		return err
	}
	update, err := prepareCaCertsUpdate(existingRaw, bundle)
	if err != nil {
		return fmt.Errorf("cannot prepare CA certificate update: %w", err)
	}
	this.logComparison(source, update.existing, bundle, update.diff)

	openPrs, err := listCaCertsPullRequests(ctx, client, owner, name, repository.String(), actor)
	if err != nil {
		return err
	}
	if !update.changed {
		if err := ensureCaCertsBaseIsCurrent(ctx, client, owner, name, baseBranch, baseSHA); err != nil {
			return err
		}
		if err := closeSupersededCaCertsPullRequests(ctx, client, owner, name, "", openPrs); err != nil {
			return err
		}
		log.With("repository", repository).Info("CA certificate bundle is already current; no pull request required")
		return nil
	}

	branch := caCertsPullRequestBranch(update.generated)
	var currentPr *github.PullRequest
	existingBranchSHA := ""
	for _, candidate := range openPrs {
		if candidate.GetHead().GetRef() == branch {
			currentPr = candidate
			existingBranchSHA = candidate.GetHead().GetSHA()
			current, err := caCertsPullRequestIsCurrent(ctx, client, owner, name, candidate, baseBranch, baseSHA, update.generated)
			if err != nil {
				return err
			}
			if current {
				if err := ensureCaCertsBaseIsCurrent(ctx, client, owner, name, baseBranch, baseSHA); err != nil {
					return err
				}
				if err := ensureCaCertsPullRequestLabel(ctx, client, owner, name, candidate.GetNumber()); err != nil {
					return err
				}
				if err := closeSupersededCaCertsPullRequests(ctx, client, owner, name, branch, openPrs); err != nil {
					return err
				}
				log.With("pullRequest", candidate.GetHTMLURL()).Info("CA certificate update pull request is already current")
				return nil
			}
			break
		}
	}
	if err := ensureCaCertsBaseIsCurrent(ctx, client, owner, name, baseBranch, baseSHA); err != nil {
		return err
	}
	author, err := caCertsCommitIdentity(ctx, client, actor)
	if err != nil {
		return err
	}
	commit, err := createCaCertsCommit(ctx, client, owner, name, baseSHA, baseCommit.GetTree().GetSHA(), update.generated, author)
	if err != nil {
		return err
	}
	if err := ensureCaCertsBaseIsCurrent(ctx, client, owner, name, baseBranch, baseSHA); err != nil {
		return err
	}
	if currentPr != nil && currentPr.GetBase().GetRef() != baseBranch {
		currentPrNumber := currentPr.GetNumber()
		currentPr, _, err = client.PullRequests.Edit(ctx, owner, name, currentPrNumber, &github.PullRequest{
			Base: &github.PullRequestBranch{Ref: github.String(baseBranch)},
		})
		if err != nil {
			return fmt.Errorf("cannot retarget CA certificate pull request %d to %s: %w", currentPrNumber, baseBranch, err)
		}
		if err := ensureCaCertsBaseIsCurrent(ctx, client, owner, name, baseBranch, baseSHA); err != nil {
			return err
		}
	}
	if err := createOrUpdateCaCertsBranch(ctx, client, owner, name, branch, commit, baseSHA, existingBranchSHA, author); err != nil {
		return err
	}

	if currentPr == nil {
		body := caCertsPullRequestBody(bundle, update.diff)
		currentPr, _, err = client.PullRequests.Create(ctx, owner, name, &github.NewPullRequest{
			Title:               github.String(caCertsPrTitle),
			Head:                github.String(branch),
			Base:                github.String(baseBranch),
			Body:                github.String(body),
			MaintainerCanModify: github.Bool(true),
		})
		if err != nil {
			refreshed, listErr := listCaCertsPullRequests(ctx, client, owner, name, repository.String(), actor)
			if listErr != nil {
				return errors.Join(fmt.Errorf("cannot create CA certificate update pull request: %w", err), listErr)
			}
			for _, candidate := range refreshed {
				if candidate.GetHead().GetRef() == branch {
					currentPr = candidate
					break
				}
			}
			if currentPr == nil {
				cleanupErr := deleteCaCertsBranchIfUnchanged(ctx, client, owner, name, branch, commit.GetSHA())
				return errors.Join(fmt.Errorf("cannot create CA certificate update pull request: %w", err), cleanupErr)
			}
		}
	} else {
		currentPrNumber := currentPr.GetNumber()
		currentPr, _, err = client.PullRequests.Edit(ctx, owner, name, currentPrNumber, &github.PullRequest{
			Title: github.String(caCertsPrTitle),
			Body:  github.String(caCertsPullRequestBody(bundle, update.diff)),
			Base:  &github.PullRequestBranch{Ref: github.String(baseBranch)},
		})
		if err != nil {
			return fmt.Errorf("cannot update CA certificate pull request %d: %w", currentPrNumber, err)
		}
	}
	if err := ensureCaCertsPullRequestLabel(ctx, client, owner, name, currentPr.GetNumber()); err != nil {
		return err
	}
	if err := closeSupersededCaCertsPullRequests(ctx, client, owner, name, branch, openPrs); err != nil {
		return err
	}
	log.With("pullRequest", currentPr.GetHTMLURL()).With("branch", branch).Info("CA certificate update pull request is ready")
	return nil
}

func ensureCaCertsPullRequestLabel(ctx context.Context, client *github.Client, owner, name string, number int) error {
	if _, _, err := client.Issues.AddLabelsToIssue(ctx, owner, name, number, []string{caCertsPrLabel}); err != nil {
		return fmt.Errorf("cannot label CA certificate pull request %d: %w", number, err)
	}
	return nil
}

func loadRepositoryFile(ctx context.Context, client *github.Client, owner, name, filename, revision string) ([]byte, error) {
	file, directory, _, err := client.Repositories.GetContents(ctx, owner, name, filename, &github.RepositoryContentGetOptions{Ref: revision})
	if err != nil {
		return nil, err
	}
	if file == nil || directory != nil {
		return nil, fmt.Errorf("expected a file")
	}
	content, err := file.GetContent()
	if err != nil {
		return nil, err
	}
	return []byte(content), nil
}

func caCertsPullRequestBranch(generated []byte) string {
	fingerprint := sha256.Sum256(generated)
	return fmt.Sprintf("%s%x", caCertsPrBranchPrefix, fingerprint[:8])
}

func caCertsPullRequestBody(bundle *caCertsBundle, diff caCertsDiff) string {
	return fmt.Sprintf("%s\n\nUpdates the embedded Mozilla CA certificate bundle.\n\n"+
		"- Source revision: `%s`\n"+
		"- Source committed at: `%s`\n"+
		"- Policy evaluated at: `%s`\n"+
		"- Certificates added: %d\n"+
		"- Certificates removed: %d\n\n"+
		"Generated by `go run ./cmd/build ca-certs update-pr`.\n",
		caCertsPrMarker,
		bundle.source.revision,
		bundle.source.committedAt.Format(time.RFC3339),
		bundle.evaluatedAt.Format(time.RFC3339),
		len(diff.added),
		len(diff.removed),
	)
}

func listCaCertsPullRequests(ctx context.Context, client *github.Client, owner, name, repository, actor string) ([]*github.PullRequest, error) {
	options := &github.PullRequestListOptions{
		State: "open",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}
	var result []*github.PullRequest
	for {
		pullRequests, response, err := client.PullRequests.List(ctx, owner, name, options)
		if err != nil {
			return nil, fmt.Errorf("cannot list CA certificate update pull requests: %w", err)
		}
		for _, pullRequest := range pullRequests {
			if isCaCertsPullRequest(pullRequest, repository, actor) {
				result = append(result, pullRequest)
			}
		}
		if response == nil || response.NextPage == 0 {
			return result, nil
		}
		options.Page = response.NextPage
	}
}

func isCaCertsPullRequest(pullRequest *github.PullRequest, repository, actor string) bool {
	if pullRequest == nil || pullRequest.GetUser().GetLogin() != actor ||
		!strings.Contains(pullRequest.GetBody(), caCertsPrMarker) ||
		pullRequest.GetHead().GetRepo().GetFullName() != repository {
		return false
	}
	branch := pullRequest.GetHead().GetRef()
	suffix := strings.TrimPrefix(branch, caCertsPrBranchPrefix)
	decoded, err := hex.DecodeString(suffix)
	return strings.HasPrefix(branch, caCertsPrBranchPrefix) && len(suffix) == 16 && len(decoded) == 8 && err == nil && hex.EncodeToString(decoded) == suffix
}

func caCertsPullRequestIsCurrent(ctx context.Context, client *github.Client, owner, name string, pullRequest *github.PullRequest, baseBranch, baseSHA string, generated []byte) (bool, error) {
	if pullRequest.GetBase().GetRef() != baseBranch {
		return false, nil
	}
	headSHA := pullRequest.GetHead().GetSHA()
	if headSHA == "" {
		return false, nil
	}
	commit, _, err := client.Git.GetCommit(ctx, owner, name, headSHA)
	if err != nil {
		return false, fmt.Errorf("cannot retrieve commit of CA certificate pull request %d: %w", pullRequest.GetNumber(), err)
	}
	if len(commit.Parents) != 1 || commit.Parents[0].GetSHA() != baseSHA {
		return false, nil
	}

	options := &github.ListOptions{PerPage: 100}
	files := 0
	for {
		page, response, err := client.PullRequests.ListFiles(ctx, owner, name, pullRequest.GetNumber(), options)
		if err != nil {
			return false, fmt.Errorf("cannot inspect files of CA certificate pull request %d: %w", pullRequest.GetNumber(), err)
		}
		for _, file := range page {
			files++
			if file.GetFilename() != caCertsRepositoryPath {
				return false, nil
			}
		}
		if response == nil || response.NextPage == 0 {
			break
		}
		options.Page = response.NextPage
	}
	if files != 1 {
		return false, nil
	}
	current, err := loadRepositoryFile(ctx, client, owner, name, caCertsRepositoryPath, headSHA)
	if err != nil {
		return false, fmt.Errorf("cannot read CA certificate pull request %d: %w", pullRequest.GetNumber(), err)
	}
	return bytes.Equal(current, generated), nil
}

func ensureCaCertsBaseIsCurrent(ctx context.Context, client *github.Client, owner, name, branch, expectedSHA string) error {
	metadata, _, err := client.Repositories.Get(ctx, owner, name)
	if err != nil {
		return fmt.Errorf("cannot recheck repository metadata: %w", err)
	}
	if actual := metadata.GetDefaultBranch(); actual != branch {
		return fmt.Errorf("default branch changed from %s to %s while preparing CA certificate update; retry required", branch, actual)
	}
	reference, _, err := client.Git.GetRef(ctx, owner, name, "heads/"+branch)
	if err != nil {
		return fmt.Errorf("cannot recheck default branch %s: %w", branch, err)
	}
	if actual := reference.GetObject().GetSHA(); actual != expectedSHA {
		return fmt.Errorf("default branch %s changed from %s to %s while preparing CA certificate update; retry required", branch, expectedSHA, actual)
	}
	return nil
}

func caCertsCommitIdentity(ctx context.Context, client *github.Client, actor string) (*github.CommitAuthor, error) {
	user, _, err := client.Users.Get(ctx, actor)
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve GitHub App bot identity %s: %w", actor, err)
	}
	if user.GetID() <= 0 || user.GetLogin() != actor {
		return nil, fmt.Errorf("GitHub App bot identity %s is incomplete", actor)
	}
	return &github.CommitAuthor{
		Name:  github.String(actor),
		Email: github.String(fmt.Sprintf("%d+%s@users.noreply.github.com", user.GetID(), actor)),
	}, nil
}

func createCaCertsCommit(ctx context.Context, client *github.Client, owner, name, parentSHA, baseTreeSHA string, generated []byte, author *github.CommitAuthor) (*github.Commit, error) {
	tree, _, err := client.Git.CreateTree(ctx, owner, name, baseTreeSHA, []*github.TreeEntry{{
		Path:    github.String(caCertsRepositoryPath),
		Mode:    github.String("100644"),
		Type:    github.String("blob"),
		Content: github.String(string(generated)),
	}})
	if err != nil {
		return nil, fmt.Errorf("cannot create CA certificate update tree: %w", err)
	}
	commitMessage := fmt.Sprintf("%s\n\nSigned-off-by: %s <%s>", caCertsPrTitle, author.GetName(), author.GetEmail())
	commit, _, err := client.Git.CreateCommit(ctx, owner, name, &github.Commit{
		Message:   github.String(commitMessage),
		Tree:      tree,
		Parents:   []*github.Commit{{SHA: github.String(parentSHA)}},
		Author:    author,
		Committer: author,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create CA certificate update commit: %w", err)
	}
	if commit.GetSHA() == "" {
		return nil, fmt.Errorf("created CA certificate update commit has no SHA")
	}
	return commit, nil
}

func createOrUpdateCaCertsBranch(ctx context.Context, client *github.Client, owner, name, branch string, commit *github.Commit, baseSHA, expectedExistingSHA string, author *github.CommitAuthor) error {
	commitSHA := commit.GetSHA()
	reference := &github.Reference{
		Ref: github.String("refs/heads/" + branch),
		Object: &github.GitObject{
			SHA: github.String(commitSHA),
		},
	}
	existing, response, err := client.Git.GetRef(ctx, owner, name, "heads/"+branch)
	if err == nil {
		if expectedExistingSHA == "" {
			owned, ownershipErr := caCertsBranchIsOwnedOrphan(ctx, client, owner, name, existing.GetObject().GetSHA(), baseSHA, commit.GetTree().GetSHA(), author)
			if ownershipErr != nil {
				return ownershipErr
			}
			if !owned {
				return fmt.Errorf("refusing to overwrite CA certificate branch %s without a matching bot pull request", branch)
			}
		}
		if expectedExistingSHA != "" && existing.GetObject().GetSHA() != expectedExistingSHA {
			return fmt.Errorf("refusing to overwrite CA certificate branch %s because its head changed", branch)
		}
		if _, _, err := client.Git.UpdateRef(ctx, owner, name, reference, true); err != nil {
			return fmt.Errorf("cannot update CA certificate branch %s: %w", branch, err)
		}
		return nil
	}
	if response == nil || response.StatusCode != 404 {
		return fmt.Errorf("cannot inspect CA certificate branch %s: %w", branch, err)
	}
	if _, _, err := client.Git.CreateRef(ctx, owner, name, reference); err != nil {
		return fmt.Errorf("cannot create CA certificate branch %s: %w", branch, err)
	}
	return nil
}

func caCertsBranchIsOwnedOrphan(ctx context.Context, client *github.Client, owner, name, commitSHA, baseSHA, expectedTreeSHA string, author *github.CommitAuthor) (bool, error) {
	commit, _, err := client.Git.GetCommit(ctx, owner, name, commitSHA)
	if err != nil {
		return false, fmt.Errorf("cannot inspect existing CA certificate branch commit %s: %w", commitSHA, err)
	}
	expectedMessage := fmt.Sprintf("%s\n\nSigned-off-by: %s <%s>", caCertsPrTitle, author.GetName(), author.GetEmail())
	return commit.GetTree().GetSHA() == expectedTreeSHA &&
		len(commit.Parents) == 1 && commit.Parents[0].GetSHA() == baseSHA &&
		commit.GetAuthor().GetName() == author.GetName() && commit.GetAuthor().GetEmail() == author.GetEmail() &&
		commit.GetCommitter().GetName() == author.GetName() && commit.GetCommitter().GetEmail() == author.GetEmail() &&
		commit.GetMessage() == expectedMessage, nil
}

func deleteCaCertsBranchIfUnchanged(ctx context.Context, client *github.Client, owner, name, branch, expectedSHA string) error {
	reference, response, err := client.Git.GetRef(ctx, owner, name, "heads/"+branch)
	if err != nil {
		if response != nil && response.StatusCode == 404 {
			return nil
		}
		return fmt.Errorf("cannot inspect failed CA certificate branch %s: %w", branch, err)
	}
	if reference.GetObject().GetSHA() != expectedSHA {
		return fmt.Errorf("refusing to clean up failed CA certificate branch %s because its head changed", branch)
	}
	if _, err := client.Git.DeleteRef(ctx, owner, name, "heads/"+branch); err != nil {
		return fmt.Errorf("cannot clean up failed CA certificate branch %s: %w", branch, err)
	}
	return nil
}

func closeSupersededCaCertsPullRequests(ctx context.Context, client *github.Client, owner, name, keepBranch string, pullRequests []*github.PullRequest) error {
	for _, pullRequest := range pullRequests {
		branch := pullRequest.GetHead().GetRef()
		if branch == keepBranch {
			continue
		}
		reference, response, err := client.Git.GetRef(ctx, owner, name, "heads/"+branch)
		if err != nil && (response == nil || response.StatusCode != 404) {
			return fmt.Errorf("cannot inspect superseded CA certificate branch %s: %w", branch, err)
		}
		if err == nil && reference.GetObject().GetSHA() != pullRequest.GetHead().GetSHA() {
			return fmt.Errorf("refusing to delete superseded CA certificate branch %s because its head changed", branch)
		}
		if _, _, err := client.PullRequests.Edit(ctx, owner, name, pullRequest.GetNumber(), &github.PullRequest{State: github.String("closed")}); err != nil {
			return fmt.Errorf("cannot close superseded CA certificate pull request %d: %w", pullRequest.GetNumber(), err)
		}
		if err == nil {
			response, err = client.Git.DeleteRef(ctx, owner, name, "heads/"+branch)
		}
		if err != nil && (response == nil || response.StatusCode != 404) {
			return fmt.Errorf("cannot delete superseded CA certificate branch %s: %w", branch, err)
		}
		log.With("pullRequest", pullRequest.GetHTMLURL()).With("branch", branch).Info("Superseded CA certificate update pull request closed")
	}
	return nil
}
