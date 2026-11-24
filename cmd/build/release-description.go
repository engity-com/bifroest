package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/google/go-github/v65/github"

	"github.com/engity-com/bifroest/pkg/common"
)

const releaseDescriptionMaxInput = 8 << 20

type releaseDescriptionOptions struct {
	repository *repo
	tag        string
	output     string
	snapshot   string
	bodyFile   string
}

func initReleaseDescription(ctx context.Context, app *kingpin.Application, repository *repo) {
	command := app.Command("release-description", "Preview or update the managed release artifact section.")
	command.Flag("githubToken", "Optional for public previews; required for updates. Also accepts GH_TOKEN.").Envar("GITHUB_TOKEN").StringVar(&repository.githubToken)
	command.Flag("owner", "GitHub repository owner.").Default(defaultOwner).SetValue(&repository.owner)
	command.Flag("repo", "GitHub repository name.").Default(defaultRepo).SetValue(&repository.name)
	for _, name := range []string{"preview", "update"} {
		options := &releaseDescriptionOptions{repository: repository}
		help := "Generate local HTML, Markdown and an offline snapshot; never edit GitHub."
		if name == "update" {
			help = "Update only the managed artifact section of a published GitHub Release."
		}
		entry := command.Command(name, help)
		entry.Arg("version", "Exact release version, with or without the leading v.").Required().StringVar(&options.tag)
		if name == "preview" {
			entry.Flag("output", "Preview directory; defaults to var/release-preview/<tag>.").StringVar(&options.output)
			entry.Flag("snapshot", "Read release.json and the manifest from a previous preview, without network access.").StringVar(&options.snapshot)
			entry.Flag("body-file", "Use a local Markdown description instead of the published body; preview only.").StringVar(&options.bodyFile)
		}
		entry.Action(func(*kingpin.ParseContext) error {
			if repository.githubToken == "" {
				repository.githubToken = os.Getenv("GH_TOKEN")
			}
			return options.run(ctx, name == "update")
		})
	}
}

func (this *releaseDescriptionOptions) run(ctx context.Context, update bool) error {
	if !strings.HasPrefix(this.tag, "v") {
		this.tag = "v" + this.tag
	}
	if !releaseVersionPattern.MatchString(this.tag) {
		return fmt.Errorf("invalid release tag %q", this.tag)
	}
	if update && this.repository.githubToken == "" {
		return fmt.Errorf("release updates require GITHUB_TOKEN or GH_TOKEN")
	}
	if update && (this.snapshot != "" || this.bodyFile != "" || this.output != "") {
		return fmt.Errorf("snapshot, body-file and output are preview-only options")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var source releaseDescriptionSource
	var err error
	if this.snapshot != "" {
		source, err = readReleaseDescriptionSnapshot(this.snapshot)
	} else {
		source, err = this.repository.releases.descriptionSource(ctx, this.tag)
	}
	if err != nil {
		return err
	}
	if err := validateReleaseDescriptionSource(source, this.repository.String(), this.tag); err != nil {
		return err
	}
	view, err := newReleaseDescriptionView(source)
	if err != nil {
		return err
	}
	fragment := renderReleaseDescription(view)
	if update {
		changed, err := this.repository.releases.updateDescription(ctx, source.Release, fragment)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "Release %s description updated: %t\n", this.tag, changed)
		return nil
	}
	if this.bodyFile != "" {
		raw, err := readReleaseDescriptionFile(this.bodyFile)
		if err != nil {
			return err
		}
		source.Release.Body = github.String(string(raw))
	}
	body, err := replaceReleaseArtifacts(source.Release.GetBody(), fragment)
	if err != nil {
		return err
	}
	if this.output == "" {
		this.output = filepath.Join("var", "release-preview", this.tag)
	}
	if err := writeReleaseDescriptionPreview(this.output, source, view, fragment, body); err != nil {
		return err
	}
	filename, err := filepath.Abs(filepath.Join(this.output, "preview.html"))
	if err != nil {
		return err
	}
	fileURL := filepath.ToSlash(filename)
	if !strings.HasPrefix(fileURL, "/") {
		fileURL = "/" + fileURL
	}
	fmt.Fprintln(os.Stdout, "Local preview (no GitHub changes):", (&url.URL{Scheme: "file", Path: fileURL}).String())
	fmt.Fprintln(os.Stdout, "Complete proposed description:", filepath.Join(this.output, "release-notes.md"))
	return nil
}

func (this *repoReleases) descriptionSource(ctx context.Context, tag string) (releaseDescriptionSource, error) {
	var source releaseDescriptionSource
	release, _, err := this.client().Repositories.GetReleaseByTag(ctx, this.owner.String(), this.name.String(), tag)
	if err != nil {
		return source, fmt.Errorf("cannot read release %s: %w", tag, err)
	}
	options := &github.ListOptions{PerPage: 100, Page: 1}
	var assets []*github.ReleaseAsset
	for {
		page, response, err := this.client().Repositories.ListReleaseAssets(ctx, this.owner.String(), this.name.String(), release.GetID(), options)
		if err != nil {
			return source, fmt.Errorf("cannot list release assets: %w", err)
		}
		assets = append(assets, page...)
		if response.NextPage == 0 {
			break
		}
		options.Page = response.NextPage
	}
	release.Assets = assets
	var manifestAsset *github.ReleaseAsset
	for _, asset := range assets {
		if asset.GetName() == releaseManifestFilename {
			if manifestAsset != nil {
				return source, fmt.Errorf("release has duplicate manifest assets")
			}
			manifestAsset = asset
		}
	}
	if manifestAsset == nil {
		return source, fmt.Errorf("release %s has no %s; an artifact manifest is required", tag, releaseManifestFilename)
	}
	reader, _, err := this.client().Repositories.DownloadReleaseAsset(ctx, this.owner.String(), this.name.String(), manifestAsset.GetID(), &http.Client{Timeout: 30 * time.Second})
	if err != nil {
		return source, fmt.Errorf("cannot download release manifest: %w", err)
	}
	defer common.IgnoreCloseError(reader)
	raw, err := readReleaseDescriptionInput(reader)
	if err != nil {
		return source, err
	}
	manifest, err := decodeReleaseDescriptionManifest(raw)
	if err != nil {
		return source, err
	}
	return releaseDescriptionSource{Release: release, Manifest: manifest}, nil
}

func (this *repoReleases) updateDescription(ctx context.Context, previous *github.RepositoryRelease, fragment string) (bool, error) {
	// Re-read the body instead of overwriting edits made since the workflow event.
	current, _, err := this.client().Repositories.GetReleaseByTag(ctx, this.owner.String(), this.name.String(), previous.GetTagName())
	if err != nil {
		return false, fmt.Errorf("cannot re-read release description: %w", err)
	}
	if current.GetID() != previous.GetID() || current.GetTagName() != previous.GetTagName() || current.GetDraft() || current.GetPrerelease() != previous.GetPrerelease() {
		return false, fmt.Errorf("release identity or publication status changed before description update")
	}
	body, err := replaceReleaseArtifacts(current.GetBody(), fragment)
	if err != nil {
		return false, err
	}
	if body == current.GetBody() {
		return false, nil
	}
	_, _, err = this.client().Repositories.EditRelease(ctx, this.owner.String(), this.name.String(), current.GetID(), &github.RepositoryRelease{Body: github.String(body)})
	if err != nil {
		return false, fmt.Errorf("cannot update release description: %w", err)
	}
	return true, nil
}

func readReleaseDescriptionInput(reader io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, releaseDescriptionMaxInput+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > releaseDescriptionMaxInput {
		return nil, fmt.Errorf("release metadata exceeds %d bytes", releaseDescriptionMaxInput)
	}
	return raw, nil
}

func readReleaseDescriptionFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer common.IgnoreCloseError(file)
	return readReleaseDescriptionInput(file)
}

func readReleaseDescriptionSnapshot(directory string) (releaseDescriptionSource, error) {
	var source releaseDescriptionSource
	raw, err := readReleaseDescriptionFile(filepath.Join(directory, "release.json"))
	if err != nil {
		return source, err
	}
	if err := json.Unmarshal(raw, &source.Release); err != nil {
		return source, err
	}
	raw, err = readReleaseDescriptionFile(filepath.Join(directory, releaseManifestFilename))
	if err != nil {
		return source, err
	}
	source.Manifest, err = decodeReleaseDescriptionManifest(raw)
	return source, err
}

func writeReleaseDescriptionPreview(directory string, source releaseDescriptionSource, view releaseDescriptionView, fragment, body string) error {
	var preview bytes.Buffer
	if err := renderReleaseDescriptionPreview(&preview, view); err != nil {
		return err
	}
	release, err := json.MarshalIndent(source.Release, "", "  ")
	if err != nil {
		return err
	}
	manifest, err := json.MarshalIndent(source.Manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	for _, file := range []struct {
		name string
		raw  []byte
	}{
		{"preview.html", preview.Bytes()},
		{releaseDescriptionDownloadIconFilename, releaseDescriptionDownloadIcon},
		{releaseDescriptionUnavailableIconFilename, releaseDescriptionUnavailableIcon},
		{releaseDescriptionSeparatorIconFilename, releaseDescriptionSeparatorIcon},
		{"artifacts.md", []byte(fragment)},
		{"release-notes.md", []byte(body)},
		{"release.json", release},
		{releaseManifestFilename, manifest},
	} {
		if err := os.WriteFile(filepath.Join(directory, file.name), file.raw, 0644); err != nil {
			return err
		}
	}
	return nil
}
