// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v65/github"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/internal/mozilla/certdata"
)

func TestCaCertsPullRequestBranchDependsOnGeneratedContent(t *testing.T) {
	first := caCertsPullRequestBranch([]byte("first"))
	second := caCertsPullRequestBranch([]byte("second"))

	require.True(t, strings.HasPrefix(first, caCertsPrBranchPrefix))
	require.Equal(t, first, caCertsPullRequestBranch([]byte("first")))
	require.NotEqual(t, first, second)
}

func TestCaCertsPullRequestBody(t *testing.T) {
	source := testCaCertsSource(t,
		testCaCertData{label: "Added", serial: 1, trust: certdata.TrustTrustedDelegator},
	)
	bundle, err := buildCaCertsBundle(t.Context(), source, time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	body := caCertsPullRequestBody(bundle, caCertsDiff{
		added:   []caCertificate{{}},
		removed: []caCertsRemoval{{}, {}},
	})

	require.Contains(t, body, caCertsPrMarker)
	require.Contains(t, body, source.revision)
	require.Contains(t, body, "Certificates added: 1")
	require.Contains(t, body, "Certificates removed: 2")
}

func TestIsCaCertsPullRequest(t *testing.T) {
	valid := func() *github.PullRequest {
		return &github.PullRequest{
			Body: github.String(caCertsPrMarker),
			User: &github.User{Login: github.String("ca-bot[bot]")},
			Head: &github.PullRequestBranch{
				Ref:  github.String(caCertsPrBranchPrefix + "0123456789abcdef"),
				Repo: &github.Repository{FullName: github.String("engity-com/bifroest")},
			},
			Base: &github.PullRequestBranch{Ref: github.String("main")},
		}
	}

	require.True(t, isCaCertsPullRequest(valid(), "engity-com/bifroest", "ca-bot[bot]"))

	withoutMarker := valid()
	withoutMarker.Body = github.String("manual pull request")
	require.False(t, isCaCertsPullRequest(withoutMarker, "engity-com/bifroest", "ca-bot[bot]"))

	wrongBranch := valid()
	wrongBranch.Head.Ref = github.String("manual/update")
	require.False(t, isCaCertsPullRequest(wrongBranch, "engity-com/bifroest", "ca-bot[bot]"))

	fromFork := valid()
	fromFork.Head.Repo.FullName = github.String("somebody/bifroest")
	require.False(t, isCaCertsPullRequest(fromFork, "engity-com/bifroest", "ca-bot[bot]"))

	wrongActor := valid()
	wrongActor.User.Login = github.String("somebody")
	require.False(t, isCaCertsPullRequest(wrongActor, "engity-com/bifroest", "ca-bot[bot]"))

	invalidHash := valid()
	invalidHash.Head.Ref = github.String(caCertsPrBranchPrefix + "not-a-hash")
	require.False(t, isCaCertsPullRequest(invalidHash, "engity-com/bifroest", "ca-bot[bot]"))
}

func TestCreateCaCertsCommit(t *testing.T) {
	generated := []byte("generated certificates")
	author := &github.CommitAuthor{
		Name:  github.String("ca-bot[bot]"),
		Email: github.String("123+ca-bot[bot]@users.noreply.github.com"),
	}
	requests := 0
	client := newCaCertsTestGitHubClient(t, func(response http.ResponseWriter, request *http.Request) {
		requests++
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/repos/owner/repository/git/trees":
			var tree struct {
				BaseTree string              `json:"base_tree"`
				Tree     []*github.TreeEntry `json:"tree"`
			}
			require.NoError(t, json.NewDecoder(request.Body).Decode(&tree))
			require.Equal(t, "base-tree", tree.BaseTree)
			require.Len(t, tree.Tree, 1)
			require.Equal(t, caCertsRepositoryPath, tree.Tree[0].GetPath())
			require.Equal(t, string(generated), tree.Tree[0].GetContent())
			_, _ = response.Write([]byte(`{"sha":"new-tree"}`))
		case "/repos/owner/repository/git/commits":
			var commit struct {
				Message string               `json:"message"`
				Tree    string               `json:"tree"`
				Parents []string             `json:"parents"`
				Author  *github.CommitAuthor `json:"author"`
			}
			require.NoError(t, json.NewDecoder(request.Body).Decode(&commit))
			require.Equal(t, "new-tree", commit.Tree)
			require.Len(t, commit.Parents, 1)
			require.Equal(t, "parent", commit.Parents[0])
			require.Equal(t, author.GetName(), commit.Author.GetName())
			require.Contains(t, commit.Message, "Signed-off-by: "+author.GetName()+" <"+author.GetEmail()+">")
			_, _ = response.Write([]byte(`{"sha":"new-commit"}`))
		default:
			http.NotFound(response, request)
		}
	})

	actual, err := createCaCertsCommit(t.Context(), client, "owner", "repository", "parent", "base-tree", generated, author)

	require.NoError(t, err)
	require.Equal(t, "new-commit", actual.GetSHA())
	require.Equal(t, 2, requests)
}

func TestEnsureCaCertsPullRequestLabel(t *testing.T) {
	client := newCaCertsTestGitHubClient(t, func(response http.ResponseWriter, request *http.Request) {
		require.Equal(t, http.MethodPost, request.Method)
		require.Equal(t, "/repos/owner/repository/issues/7/labels", request.URL.Path)
		var labels []string
		require.NoError(t, json.NewDecoder(request.Body).Decode(&labels))
		require.Equal(t, []string{caCertsPrLabel}, labels)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`[{"name":"dependencies"}]`))
	})

	err := ensureCaCertsPullRequestLabel(t.Context(), client, "owner", "repository", 7)

	require.NoError(t, err)
}

func TestUpdatePrDoesNotWriteWithoutEffectiveChange(t *testing.T) {
	source := testCaCertsSource(t, testCaCertData{label: "Root", serial: 1, trust: certdata.TrustTrustedDelegator})
	bundle, err := buildCaCertsBundle(t.Context(), source, time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	var existing strings.Builder
	require.NoError(t, bundle.writeTo(&existing))

	writes := 0
	var serverURL string
	client := newCaCertsTestGitHubClient(t, func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writes++
		}
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/repos/owner/repository":
			_, _ = response.Write([]byte(`{"default_branch":"main"}`))
		case "/repos/owner/repository/git/ref/heads/main":
			_, _ = response.Write([]byte(`{"ref":"refs/heads/main","object":{"sha":"base"}}`))
		case "/repos/owner/repository/git/commits/base":
			_, _ = response.Write([]byte(`{"sha":"base","tree":{"sha":"base-tree"}}`))
		case "/repos/owner/repository/contents/" + caCertsRepositoryPath:
			require.Equal(t, "base", request.URL.Query().Get("ref"))
			_, _ = fmt.Fprintf(response, `{"type":"file","encoding":"base64","content":%q}`, base64.StdEncoding.EncodeToString([]byte(existing.String())))
		case "/repos/mozilla-firefox/firefox/commits":
			_, _ = fmt.Fprintf(response, `[{"sha":%q,"commit":{"committer":{"date":%q}}}]`, source.revision, source.committedAt.Format(time.RFC3339))
		case "/repos/mozilla-firefox/firefox/contents/" + path.Dir(caCertsSourcePath):
			require.Equal(t, source.revision, request.URL.Query().Get("ref"))
			_, _ = fmt.Fprintf(response, `[{"type":"file","name":"certdata.txt","path":%q,"download_url":%q}]`, caCertsSourcePath, serverURL+"/raw/certdata.txt")
		case "/raw/certdata.txt":
			_, _ = response.Write(source.raw)
		case "/repos/owner/repository/pulls":
			_, _ = response.Write([]byte(`[]`))
		default:
			http.NotFound(response, request)
		}
	})
	serverURL = client.BaseURL.String()
	serverURL = strings.TrimSuffix(serverURL, "/")

	base := &base{}
	repository := newRepo(base)
	repository.owner = owner("owner")
	repository.name = repoName("repository")
	repository.clientP.Store(client)
	base.repo = repository
	dependencies := newDependencies(base)
	dependencies.caCerts.now = func() time.Time { return time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC) }

	err = dependencies.caCerts.updatePrInRepository(t.Context(), "ca-bot[bot]")

	require.NoError(t, err)
	require.Zero(t, writes)
}

func TestCreateOrUpdateCaCertsBranchDoesNotOverwriteUnownedRef(t *testing.T) {
	requests := 0
	client := newCaCertsTestGitHubClient(t, func(response http.ResponseWriter, request *http.Request) {
		requests++
		require.Equal(t, http.MethodGet, request.Method)
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/repos/owner/repository/git/ref/heads/automation/ca-certificates/0123456789abcdef":
			_, _ = response.Write([]byte(`{"ref":"refs/heads/automation/ca-certificates/0123456789abcdef","object":{"sha":"existing"}}`))
		case "/repos/owner/repository/git/commits/existing":
			_, _ = response.Write([]byte(`{"sha":"existing","message":"manual","tree":{"sha":"manual-tree"},"parents":[{"sha":"base"}]}`))
		default:
			http.NotFound(response, request)
		}
	})
	author := &github.CommitAuthor{Name: github.String("ca-bot[bot]"), Email: github.String("123+ca-bot[bot]@users.noreply.github.com")}
	commit := &github.Commit{SHA: github.String("new"), Tree: &github.Tree{SHA: github.String("new-tree")}}

	err := createOrUpdateCaCertsBranch(t.Context(), client, "owner", "repository", caCertsPrBranchPrefix+"0123456789abcdef", commit, "base", "", author)

	require.ErrorContains(t, err, "refusing to overwrite")
	require.Equal(t, 2, requests)
}

func TestCreateOrUpdateCaCertsBranchRecoversOwnedOrphan(t *testing.T) {
	author := &github.CommitAuthor{Name: github.String("ca-bot[bot]"), Email: github.String("123+ca-bot[bot]@users.noreply.github.com")}
	expectedMessage := fmt.Sprintf("%s\n\nSigned-off-by: %s <%s>", caCertsPrTitle, author.GetName(), author.GetEmail())
	updated := false
	client := newCaCertsTestGitHubClient(t, func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/git/ref/heads/"):
			_, _ = response.Write([]byte(`{"ref":"refs/heads/automation/ca-certificates/0123456789abcdef","object":{"sha":"orphan"}}`))
		case request.Method == http.MethodGet && request.URL.Path == "/repos/owner/repository/git/commits/orphan":
			_, _ = fmt.Fprintf(response, `{"sha":"orphan","message":%q,"tree":{"sha":"new-tree"},"parents":[{"sha":"base"}],"author":{"name":%q,"email":%q},"committer":{"name":%q,"email":%q}}`,
				expectedMessage, author.GetName(), author.GetEmail(), author.GetName(), author.GetEmail())
		case request.Method == http.MethodPatch && strings.Contains(request.URL.Path, "/git/refs/heads/"):
			updated = true
			_, _ = response.Write([]byte(`{"ref":"refs/heads/automation/ca-certificates/0123456789abcdef","object":{"sha":"new"}}`))
		default:
			http.NotFound(response, request)
		}
	})
	commit := &github.Commit{SHA: github.String("new"), Tree: &github.Tree{SHA: github.String("new-tree")}}

	err := createOrUpdateCaCertsBranch(t.Context(), client, "owner", "repository", caCertsPrBranchPrefix+"0123456789abcdef", commit, "base", "", author)

	require.NoError(t, err)
	require.True(t, updated)
}

func TestCaCertsPullRequestIsCurrentRequiresSingleFileAndCurrentBase(t *testing.T) {
	generated := []byte("generated certificates")
	pullRequest := &github.PullRequest{
		Number: github.Int(7),
		Head:   &github.PullRequestBranch{SHA: github.String("head")},
		Base:   &github.PullRequestBranch{Ref: github.String("main")},
	}
	client := newCaCertsTestGitHubClient(t, func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/repos/owner/repository/git/commits/head":
			_, _ = response.Write([]byte(`{"sha":"head","parents":[{"sha":"base"}]}`))
		case "/repos/owner/repository/pulls/7/files":
			_, _ = response.Write([]byte(`[{"filename":"pkg/crypto/ca-certs.crt"}]`))
		case "/repos/owner/repository/contents/pkg/crypto/ca-certs.crt":
			require.Equal(t, "head", request.URL.Query().Get("ref"))
			_, _ = fmt.Fprintf(response, `{"type":"file","encoding":"base64","content":%q}`, base64.StdEncoding.EncodeToString(generated))
		default:
			http.NotFound(response, request)
		}
	})

	actual, err := caCertsPullRequestIsCurrent(t.Context(), client, "owner", "repository", pullRequest, "main", "base", generated)
	require.NoError(t, err)
	require.True(t, actual)

	pullRequest.Base.Ref = github.String("old-main")
	actual, err = caCertsPullRequestIsCurrent(t.Context(), client, "owner", "repository", pullRequest, "main", "base", generated)
	require.NoError(t, err)
	require.False(t, actual)

	pullRequest.Base.Ref = github.String("main")
	extraFileClient := newCaCertsTestGitHubClient(t, func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/repos/owner/repository/git/commits/head":
			_, _ = response.Write([]byte(`{"sha":"head","parents":[{"sha":"base"}]}`))
		case "/repos/owner/repository/pulls/7/files":
			_, _ = response.Write([]byte(`[{"filename":"pkg/crypto/ca-certs.crt"},{"filename":"README.md"}]`))
		default:
			http.NotFound(response, request)
		}
	})
	actual, err = caCertsPullRequestIsCurrent(t.Context(), extraFileClient, "owner", "repository", pullRequest, "main", "base", generated)
	require.NoError(t, err)
	require.False(t, actual)
}

func newCaCertsTestGitHubClient(t *testing.T, handler http.HandlerFunc) *github.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	baseURL, err := url.Parse(server.URL + "/")
	require.NoError(t, err)
	client := github.NewClient(server.Client())
	client.BaseURL = baseURL
	return client
}
