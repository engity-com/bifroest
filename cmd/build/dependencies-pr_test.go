// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v65/github"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/internal/mozilla/certdata"
)

func TestApplyImageUpdatesReconcilesEveryManagedLocation(t *testing.T) {
	old := "sha256:" + strings.Repeat("1", 64)
	resolved := map[string]string{
		"ghcr.io/engity-com/build-images/build:debian12": "sha256:" + strings.Repeat("2", 64),
		"docker.io/library/ubuntu:26.04":                 "sha256:" + strings.Repeat("3", 64),
		"docker.io/library/alpine:latest":                "sha256:" + strings.Repeat("4", 64),
		"mcr.microsoft.com/windows/nanoserver:ltsc2022":  "sha256:" + strings.Repeat("5", 64),
	}
	files := map[string][]byte{
		dependencyCiWorkflowPath:      []byte("ghcr.io/engity-com/build-images/go@" + old),
		dependencyReleaseWorkflowPath: []byte("ghcr.io/engity-com/build-images/go@" + old),
		dependencyBuildArchPath: []byte("docker.io/library/ubuntu:26.04@" + old + "\n" +
			"mcr.microsoft.com/windows/nanoserver:ltsc2022@" + old),
		dependencyBuildImagesPath: []byte("docker.io/library/alpine:latest@" + old + "\n" +
			"mcr.microsoft.com/windows/nanoserver:ltsc2022@" + old),
		dependencyE2eHarnessPath: []byte("docker.io/library/alpine@" + old),
	}
	dependencies := &dependencies{resolveImageDigest: func(_ context.Context, source string) (string, error) {
		return resolved[source], nil
	}}

	checks, err := dependencies.applyImageUpdates(t.Context(), files)

	require.NoError(t, err)
	require.Len(t, checks, len(dependencyImages))
	for _, check := range checks {
		require.True(t, check.changed, check.name)
		require.Contains(t, check.current, resolved[check.source])
	}
	require.Contains(t, string(files[dependencyCiWorkflowPath]), "build:debian12@"+resolved[dependencyImages[0].source])
	require.Contains(t, string(files[dependencyBuildArchPath]), "ubuntu:26.04@"+resolved[dependencyImages[1].source])
	require.Contains(t, string(files[dependencyBuildImagesPath]), "alpine:latest@"+resolved[dependencyImages[2].source])
	require.Contains(t, string(files[dependencyE2eHarnessPath]), "alpine:latest@"+resolved[dependencyImages[2].source])
	require.Contains(t, string(files[dependencyBuildArchPath]), "nanoserver:ltsc2022@"+resolved[dependencyImages[3].source])
}

func TestApplyImageUpdatesFailsClosedWhenLocationDrifts(t *testing.T) {
	files := map[string][]byte{
		dependencyCiWorkflowPath:      []byte("no managed reference"),
		dependencyReleaseWorkflowPath: []byte("no managed reference"),
		dependencyBuildArchPath:       []byte("no managed reference"),
		dependencyBuildImagesPath:     []byte("no managed reference"),
		dependencyE2eHarnessPath:      []byte("no managed reference"),
	}
	dependencies := &dependencies{resolveImageDigest: func(context.Context, string) (string, error) {
		return "sha256:" + strings.Repeat("2", 64), nil
	}}

	_, err := dependencies.applyImageUpdates(t.Context(), files)

	require.ErrorContains(t, err, "expected 1 reference(s)")
}

func TestFindDependencyImageReferencesRequiresExactToken(t *testing.T) {
	reference := "docker.io/library/alpine:latest"
	digest := "sha256:" + strings.Repeat("a", 64)
	valid := reference + "@" + digest
	content := []byte(strings.Join([]string{
		"evil.example/" + valid,
		valid + "suffix",
		valid,
		reference + "@sha256:" + strings.Repeat("A", 64),
	}, "\n"))

	matches := findDependencyImageReferences(content, []string{reference})

	require.Equal(t, []dependencyImageReference{{
		start: len("evil.example/") + len(valid) + 1 + len(valid) + len("suffix") + 1,
		end:   len("evil.example/") + len(valid) + 1 + len(valid) + len("suffix") + 1 + len(valid),
		value: valid,
	}}, matches)
	require.Equal(t, strings.Join([]string{
		"evil.example/" + valid,
		valid + "suffix",
		"replacement",
		reference + "@sha256:" + strings.Repeat("A", 64),
	}, "\n"), string(replaceDependencyImageReferences(content, matches, "replacement")))
}

func TestDependencyPullRequestBranchDependsOnEveryGeneratedFile(t *testing.T) {
	first := dependencyPullRequestBranch("base", map[string][]byte{"a": []byte("first"), "b": []byte("second")})
	reordered := dependencyPullRequestBranch("base", map[string][]byte{"b": []byte("second"), "a": []byte("first")})
	changed := dependencyPullRequestBranch("base", map[string][]byte{"a": []byte("first"), "b": []byte("changed")})
	rebased := dependencyPullRequestBranch("new-base", map[string][]byte{"a": []byte("first"), "b": []byte("second")})

	require.True(t, strings.HasPrefix(first, dependencyPullRequestBranchPrefix))
	require.Equal(t, first, reordered)
	require.NotEqual(t, first, changed)
	require.NotEqual(t, first, rebased)
}

func TestDependencyPullRequestDocumentsAllChecksAndChanges(t *testing.T) {
	plan := &dependencyUpdatePlan{checks: []dependencyCheck{
		{name: "Changed image", source: "registry.example/image:tag", previous: "old", current: "new", files: []string{"a", "b"}, changed: true},
		{name: "Current image", source: "registry.example/current:tag", previous: "same", current: "same", files: []string{"c"}},
	}}
	author := &github.CommitAuthor{Name: github.String("dependency-bot[bot]"), Email: github.String("1+dependency-bot[bot]@users.noreply.github.com")}

	body := plan.pullRequestBody()
	message := plan.commitMessage(author)

	require.Contains(t, body, dependencyPullRequestMarker)
	require.Contains(t, body, "| Changed image | Updated | `old` | `new` |")
	require.Contains(t, body, "| Current image | Current | `same` | `same` |")
	require.Contains(t, body, "`a`, `b`")
	require.Contains(t, message, "Changed image: old -> new")
	require.NotContains(t, message, "Current image")
	require.Contains(t, message, "Signed-off-by: "+author.GetName()+" <"+author.GetEmail()+">")
}

func TestIsDependencyPullRequestRequiresActorMarkerRepositoryAndBranch(t *testing.T) {
	repository := &repo{owner: owner("engity-com"), name: repoName("bifroest")}
	valid := func() *github.PullRequest {
		return &github.PullRequest{
			Body: github.String(dependencyPullRequestMarker),
			User: &github.User{Login: github.String("dependency-bot[bot]")},
			Head: &github.PullRequestBranch{
				Ref:  github.String(dependencyPullRequestBranchPrefix + "0123456789abcdef"),
				Repo: &github.Repository{FullName: github.String("engity-com/bifroest")},
			},
		}
	}

	require.True(t, repository.isDependencyPullRequest(valid(), "dependency-bot[bot]"))
	withoutMarker := valid()
	withoutMarker.Body = github.String("manual")
	require.False(t, repository.isDependencyPullRequest(withoutMarker, "dependency-bot[bot]"))
	wrongBranch := valid()
	wrongBranch.Head.Ref = github.String("manual/update")
	require.False(t, repository.isDependencyPullRequest(wrongBranch, "dependency-bot[bot]"))
	fromFork := valid()
	fromFork.Head.Repo.FullName = github.String("somebody/bifroest")
	require.False(t, repository.isDependencyPullRequest(fromFork, "dependency-bot[bot]"))
	wrongActor := valid()
	wrongActor.User.Login = github.String("somebody")
	require.False(t, repository.isDependencyPullRequest(wrongActor, "dependency-bot[bot]"))
}

func TestCreateDependencyCommitWritesSortedFilesOnBaseTree(t *testing.T) {
	author := &github.CommitAuthor{Name: github.String("dependency-bot[bot]"), Email: github.String("1+dependency-bot[bot]@users.noreply.github.com")}
	client := newDependencyTestGitHubClient(t, func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/repos/owner/repository/git/commits/base":
			_, _ = response.Write([]byte(`{"sha":"base","tree":{"sha":"base-tree"}}`))
		case "/repos/owner/repository/git/trees":
			var tree struct {
				BaseTree string              `json:"base_tree"`
				Tree     []*github.TreeEntry `json:"tree"`
			}
			require.NoError(t, json.NewDecoder(request.Body).Decode(&tree))
			require.Equal(t, "base-tree", tree.BaseTree)
			require.Equal(t, []string{"a.txt", "z.txt"}, []string{tree.Tree[0].GetPath(), tree.Tree[1].GetPath()})
			_, _ = response.Write([]byte(`{"sha":"new-tree"}`))
		case "/repos/owner/repository/git/commits":
			var commit struct {
				Message string   `json:"message"`
				Tree    string   `json:"tree"`
				Parents []string `json:"parents"`
			}
			require.NoError(t, json.NewDecoder(request.Body).Decode(&commit))
			require.Equal(t, "message", commit.Message)
			require.Equal(t, "new-tree", commit.Tree)
			require.Equal(t, []string{"base"}, commit.Parents)
			_, _ = response.Write([]byte(`{"sha":"new-commit"}`))
		default:
			http.NotFound(response, request)
		}
	})
	repository := newDependencyTestRepo(client)

	actual, tree, err := repository.createDependencyCommit(t.Context(), "base", map[string][]byte{"z.txt": []byte("z"), "a.txt": []byte("a")}, "message", author)

	require.NoError(t, err)
	require.Equal(t, "new-commit", actual)
	require.Equal(t, "new-tree", tree)
}

func TestDependencyPullRequestHasFilesRejectsExtraFile(t *testing.T) {
	client := newDependencyTestGitHubClient(t, func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		require.Equal(t, "/repos/owner/repository/pulls/7/files", request.URL.Path)
		_, _ = response.Write([]byte(`[{"filename":"managed.txt","status":"modified"},{"filename":"unexpected.txt","status":"modified"}]`))
	})
	repository := newDependencyTestRepo(client)
	pullRequest := &github.PullRequest{Number: github.Int(7), Head: &github.PullRequestBranch{SHA: github.String("head")}}

	actual, err := repository.dependencyPullRequestHasFiles(t.Context(), pullRequest, map[string][]byte{"managed.txt": []byte("managed")})

	require.NoError(t, err)
	require.False(t, actual)
}

func TestCreateOrUpdateDependencyBranchDoesNotOverwriteUnownedRef(t *testing.T) {
	requests := 0
	branch := dependencyPullRequestBranchPrefix + "0123456789abcdef"
	client := newDependencyTestGitHubClient(t, func(response http.ResponseWriter, request *http.Request) {
		requests++
		require.Equal(t, http.MethodGet, request.Method)
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/repos/owner/repository/git/ref/heads/" + branch:
			_, _ = response.Write([]byte(`{"ref":"refs/heads/` + branch + `","object":{"sha":"existing"}}`))
		case "/repos/owner/repository/pulls":
			_, _ = response.Write([]byte(`[]`))
		case "/repos/owner/repository/git/commits/existing":
			_, _ = response.Write([]byte(`{"sha":"existing","message":"manual","tree":{"sha":"manual-tree"},"parents":[{"sha":"base"}]}`))
		default:
			http.NotFound(response, request)
		}
	})
	repository := newDependencyTestRepo(client)
	author := &github.CommitAuthor{Name: github.String("dependency-bot[bot]"), Email: github.String("1+dependency-bot[bot]@users.noreply.github.com")}

	err := repository.createDependencyBranch(t.Context(), branch, "base", "new", "expected-tree", false, "expected", author)

	require.ErrorContains(t, err, "not an expected bot-owned orphan")
	require.Equal(t, 3, requests)
}

func TestCreateDependencyBranchDoesNotOverwriteStalePullRequestHead(t *testing.T) {
	branch := dependencyPullRequestBranchPrefix + "0123456789abcdef"
	gets := 0
	client := newDependencyTestGitHubClient(t, func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/repos/owner/repository/git/ref/heads/" + branch:
			require.Equal(t, http.MethodGet, request.Method)
			gets++
			_, _ = response.Write([]byte(`{"ref":"refs/heads/` + branch + `","object":{"sha":"expected-head"}}`))
		default:
			http.NotFound(response, request)
		}
	})
	repository := newDependencyTestRepo(client)
	author := &github.CommitAuthor{Name: github.String("dependency-bot[bot]"), Email: github.String("1+dependency-bot[bot]@users.noreply.github.com")}

	err := repository.createDependencyBranch(t.Context(), branch, "base", "new", "tree", true, "message", author)

	require.ErrorContains(t, err, "pull request is not current")
	require.Equal(t, 1, gets)
}

func TestDependencyPullRequestIsNotCurrentWithWrongParent(t *testing.T) {
	client := newDependencyTestGitHubClient(t, func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		require.Equal(t, "/repos/owner/repository/git/commits/head", request.URL.Path)
		_, _ = response.Write([]byte(`{"sha":"head","parents":[{"sha":"old-base"}]}`))
	})
	repository := newDependencyTestRepo(client)
	pullRequest := &github.PullRequest{
		Number: github.Int(7),
		Head:   &github.PullRequestBranch{SHA: github.String("head")},
		Base:   &github.PullRequestBranch{Ref: github.String("main")},
	}

	actual, err := repository.dependencyPullRequestIsCurrent(t.Context(), pullRequest, "main", "base", map[string][]byte{"managed.txt": []byte("managed")})

	require.NoError(t, err)
	require.False(t, actual)
}

func TestDeleteDependencyBranchIfUnchanged(t *testing.T) {
	branch := dependencyPullRequestBranchPrefix + "0123456789abcdef"
	deleted := false
	client := newDependencyTestGitHubClient(t, func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/repository/pulls":
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodGet:
			_, _ = response.Write([]byte(`{"ref":"refs/heads/` + branch + `","object":{"sha":"expected"}}`))
		case request.Method == http.MethodDelete:
			deleted = true
			response.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(response, request)
		}
	})
	repository := newDependencyTestRepo(client)

	err := repository.deleteDependencyBranchIfUnchanged(t.Context(), branch, "expected")

	require.NoError(t, err)
	require.True(t, deleted)
}

func TestDependencyPullRequestHasFilesAcceptsExactContents(t *testing.T) {
	client := newDependencyTestGitHubClient(t, func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/repos/owner/repository/pulls/7/files":
			_, _ = response.Write([]byte(`[{"filename":"b.txt","status":"modified"},{"filename":"a.txt","status":"modified"}]`))
		case "/repos/owner/repository/contents/a.txt":
			_, _ = fmt.Fprintf(response, `{"type":"file","encoding":"base64","content":%q}`, base64.StdEncoding.EncodeToString([]byte("a")))
		case "/repos/owner/repository/contents/b.txt":
			_, _ = fmt.Fprintf(response, `{"type":"file","encoding":"base64","content":%q}`, base64.StdEncoding.EncodeToString([]byte("b")))
		default:
			http.NotFound(response, request)
		}
	})
	repository := newDependencyTestRepo(client)
	pullRequest := &github.PullRequest{Number: github.Int(7), Head: &github.PullRequestBranch{SHA: github.String("head")}}
	expected := map[string][]byte{"a.txt": []byte("a"), "b.txt": []byte("b")}

	actual, err := repository.dependencyPullRequestHasFiles(t.Context(), pullRequest, expected)

	require.NoError(t, err)
	require.True(t, actual)
}

func TestUpdatePrDoesNotWriteWhenEveryDependencyIsCurrent(t *testing.T) {
	now := time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)
	source := testCaCertsSource(t, testCaCertData{label: "Root", serial: 1, trust: certdata.TrustTrustedDelegator})
	bundle, err := buildCaCertsBundle(t.Context(), source, now)
	require.NoError(t, err)
	var certificates strings.Builder
	require.NoError(t, bundle.writeTo(&certificates))

	digests := map[string]string{
		dependencyImages[0].source: "sha256:" + strings.Repeat("2", 64),
		dependencyImages[1].source: "sha256:" + strings.Repeat("3", 64),
		dependencyImages[2].source: "sha256:" + strings.Repeat("4", 64),
		dependencyImages[3].source: "sha256:" + strings.Repeat("5", 64),
	}
	files := map[string]string{
		defaultCaCertsTargetFn:        certificates.String(),
		dependencyCiWorkflowPath:      dependencyImages[0].source + "@" + digests[dependencyImages[0].source],
		dependencyReleaseWorkflowPath: dependencyImages[0].source + "@" + digests[dependencyImages[0].source],
		dependencyBuildArchPath: dependencyImages[1].source + "@" + digests[dependencyImages[1].source] + "\n" +
			dependencyImages[3].source + "@" + digests[dependencyImages[3].source],
		dependencyBuildImagesPath: dependencyImages[2].source + "@" + digests[dependencyImages[2].source] + "\n" +
			dependencyImages[3].source + "@" + digests[dependencyImages[3].source],
		dependencyE2eHarnessPath: dependencyImages[2].source + "@" + digests[dependencyImages[2].source],
	}
	writes := 0
	var serverURL string
	client := newDependencyTestGitHubClient(t, func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writes++
		}
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.URL.Path == "/repos/owner/repository":
			_, _ = response.Write([]byte(`{"default_branch":"main"}`))
		case request.URL.Path == "/repos/owner/repository/git/ref/heads/main":
			_, _ = response.Write([]byte(`{"ref":"refs/heads/main","object":{"sha":"base"}}`))
		case strings.HasPrefix(request.URL.Path, "/repos/owner/repository/contents/"):
			filename := strings.TrimPrefix(request.URL.Path, "/repos/owner/repository/contents/")
			content, exists := files[filename]
			require.True(t, exists, filename)
			require.Equal(t, "base", request.URL.Query().Get("ref"))
			_, _ = fmt.Fprintf(response, `{"type":"file","encoding":"base64","content":%q}`, base64.StdEncoding.EncodeToString([]byte(content)))
		case request.URL.Path == "/repos/mozilla-firefox/firefox/commits":
			_, _ = fmt.Fprintf(response, `[{"sha":%q,"commit":{"committer":{"date":%q}}}]`, source.revision, source.committedAt.Format(time.RFC3339))
		case request.URL.Path == "/repos/mozilla-firefox/firefox/contents/"+path.Dir(caCertsSourcePath):
			_, _ = fmt.Fprintf(response, `[{"type":"file","name":"certdata.txt","path":%q,"download_url":%q}]`, caCertsSourcePath, serverURL+"/raw/certdata.txt")
		case request.URL.Path == "/raw/certdata.txt":
			_, _ = response.Write(source.raw)
		case request.URL.Path == "/repos/owner/repository/pulls":
			_, _ = response.Write([]byte(`[]`))
		default:
			http.NotFound(response, request)
		}
	})
	serverURL = strings.TrimSuffix(client.BaseURL.String(), "/")
	repository := newDependencyTestRepo(client)
	dependencies := newDependencies(repository.base)
	dependencies.caCerts.now = func() time.Time { return now }
	dependencies.resolveImageDigest = func(_ context.Context, image string) (string, error) { return digests[image], nil }

	err = dependencies.updatePrInRepository(t.Context(), "dependency-bot[bot]")

	require.NoError(t, err)
	require.Zero(t, writes)
}

func newDependencyTestRepo(client *github.Client) *repo {
	base := &base{}
	repository := newRepo(base)
	repository.owner = owner("owner")
	repository.name = repoName("repository")
	repository.clientP.Store(client)
	base.repo = repository
	return repository
}

func newDependencyTestGitHubClient(t *testing.T, handler http.HandlerFunc) *github.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client := github.NewClient(server.Client())
	baseURL, err := url.Parse(server.URL + "/")
	require.NoError(t, err)
	client.BaseURL = baseURL
	client.UploadURL = baseURL
	return client
}

func TestManagedDependencyPathsStayUnique(t *testing.T) {
	var paths []string
	for _, image := range dependencyImages {
		for _, location := range image.locations {
			paths = append(paths, location.path+"\x00"+strings.Join(location.references, "\x00"))
		}
	}
	sorted := slices.Clone(paths)
	slices.Sort(sorted)
	require.Equal(t, sorted, slices.Compact(slices.Clone(sorted)))
}
