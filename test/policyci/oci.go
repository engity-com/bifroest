package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/internal/build/images"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

const ociRunLabel = "org.engity.bifroest.policy-ci"

type ociCaseResult struct {
	Name       string     `json:"name"`
	Native     caseResult `json:"native"`
	Container  caseResult `json:"container"`
	Equivalent bool       `json:"equivalent"`
}

type ociManifest struct {
	Scope             string            `json:"scope"`
	Platform          string            `json:"platform"`
	Runtime           string            `json:"runtime"`
	Build             processResult     `json:"build"`
	BinarySHA256      string            `json:"binarySha256,omitempty"`
	ImageID           string            `json:"imageId,omitempty"`
	ImageConfigDigest string            `json:"imageConfigDigest,omitempty"`
	Inputs            map[string]string `json:"inputSha256,omitempty"`
	Cases             []ociCaseResult   `json:"cases"`
	Passed            bool              `json:"passed"`
	Error             string            `json:"error,omitempty"`
}

func runOCI(ctx context.Context, output, engine string) (resultErr error) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return fmt.Errorf("OCI parity requires a native Linux amd64/arm64 host; no cross-platform execution is inferred")
	}
	if filepath.Base(engine) != "docker" && filepath.Base(engine) != "podman" {
		return fmt.Errorf("OCI runtime must be docker or podman")
	}
	uid, gid := os.Getuid(), os.Getgid()
	if uid <= 0 || gid < 0 {
		return fmt.Errorf("run the OCI parity harness as a non-root Linux user so bind-mounted private reports retain usable ownership")
	}
	if _, err := os.Stat("pkg/test/examples/ssh/green-unix_bftest.lua"); err != nil {
		return fmt.Errorf("run policyci from the repository root: %w", err)
	}
	root, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(root), 0700); err != nil {
		return err
	}
	if err := os.Mkdir(root, 0700); err != nil {
		return fmt.Errorf("output must be a new directory: %w", err)
	}
	root, err = sys.CanonicalPath(root)
	if err != nil {
		return err
	}
	reports, private := filepath.Join(root, "reports"), filepath.Join(root, "private")
	for _, directory := range []string{reports, private, filepath.Join(reports, "native"), filepath.Join(reports, "oci")} {
		if err := os.Mkdir(directory, 0700); err != nil {
			return err
		}
	}
	platform := bib.Platform{Os: sys.OsLinux, Edition: sys.EditionGeneric}
	if err := platform.Arch.Set(runtime.GOARCH); err != nil {
		return err
	}
	record := ociManifest{Scope: "regular-generic-layout-local-parity-not-a-release-attestation", Platform: platform.Oci(), Runtime: filepath.Base(engine)}
	defer func() {
		record.Passed = resultErr == nil
		if resultErr != nil {
			record.Error = resultErr.Error()
		}
		raw, err := json.MarshalIndent(record, "", "  ")
		if err == nil {
			err = createFile(filepath.Join(reports, "manifest.json"), append(raw, '\n'))
		}
		resultErr = errors.Join(resultErr, err)
	}()
	workspace := filepath.Join(private, "workspace")
	infoArgs := []string{"version", "--format", "{{json .Server}}"}
	if filepath.Base(engine) == "podman" {
		infoArgs = []string{"info", "--format=json"}
	}
	info, err := runProcess(ctx, reports, "runtime-info", engine, infoArgs, runtimeEnvironment())
	if err != nil {
		return err
	}
	if info.ExitCode != 0 {
		return fmt.Errorf("cannot inspect local runtime platform: exit %d", info.ExitCode)
	}
	infoRaw, err := os.ReadFile(filepath.Join(reports, "runtime-info.stdout.txt"))
	if err != nil {
		return err
	}
	if err := validateRuntimePlatform(infoRaw, filepath.Base(engine), platform); err != nil {
		return err
	}
	if err := stageWorkspace(workspace); err != nil {
		return err
	}
	record.Inputs, err = workspaceHashes(workspace)
	if err != nil {
		return err
	}
	binary := filepath.Join(private, "bifroest")
	env := processEnvironment(true)
	var buildEnv []string
	for _, entry := range env {
		if !strings.HasPrefix(entry, "CGO_ENABLED=") {
			buildEnv = append(buildEnv, entry)
		}
	}
	buildEnv = append(buildEnv, "CGO_ENABLED=0", "GOENV=off", "GOWORK=off")
	record.Build, err = runProcess(ctx, reports, "build", "go", []string{"build", "-p=1", "-trimpath", "-buildvcs=false", "-ldflags", platform.ToLdFlags(), "-o", binary, "./cmd/bifroest"}, buildEnv)
	if err != nil {
		return err
	}
	if record.Build.ExitCode != 0 {
		return fmt.Errorf("generic binary build exited %d", record.Build.ExitCode)
	}
	rawBinary, err := os.ReadFile(binary)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(rawBinary)
	record.BinarySHA256 = hex.EncodeToString(digest[:])
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	token := hex.EncodeToString(random[:])
	tag, err := name.NewTag("localhost/bifroest:policy-" + token + "-generic")
	if err != nil {
		return err
	}
	request, err := images.BifroestBuildRequest(platform, binary)
	if err != nil {
		return err
	}
	if request.From != images.ImageScratch {
		return fmt.Errorf("local parity expects the regular Generic scratch base, got %q", request.From)
	}
	request.Time = time.Now().UTC()
	request.Labels = map[string]string{ociRunLabel: token, "org.engity.bifroest.edition": "generic"}
	img, err := images.Build(ctx, request)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, img.Close()) }()
	configHash, err := img.ConfigName()
	if err != nil {
		return err
	}
	record.ImageConfigDigest = configHash.String()
	archive := filepath.Join(private, "image.tar")
	if err := tarball.WriteToFile(archive, tag, img); err != nil {
		return err
	}
	loaded, err := runProcess(ctx, reports, "image-load", engine, []string{"load", "--input", archive}, runtimeEnvironment())
	if err != nil {
		return err
	}
	if loaded.ExitCode != 0 {
		return fmt.Errorf("local image load exited %d", loaded.ExitCode)
	}
	// Only the unique tag created here is removed. Shared images/layers and
	// preexisting containers are never pruned or deleted.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		process, err := runProcess(cleanup, reports, "image-remove", engine, []string{"image", "rm", tag.Name()}, runtimeEnvironment())
		if err == nil && process.ExitCode != 0 {
			err = fmt.Errorf("cannot remove owned image tag: exit %d", process.ExitCode)
		}
		resultErr = errors.Join(resultErr, err)
	}()
	imageInspect, err := runProcess(ctx, reports, "image-inspect", engine, []string{"image", "inspect", tag.Name()}, runtimeEnvironment())
	if err != nil {
		return err
	}
	if imageInspect.ExitCode != 0 {
		return fmt.Errorf("cannot inspect loaded image: exit %d", imageInspect.ExitCode)
	}
	imageRaw, err := os.ReadFile(filepath.Join(reports, "image-inspect.stdout.txt"))
	if err != nil {
		return err
	}
	record.ImageID, err = validateLoadedImage(imageRaw, request.EntryPoint, platform)
	if err != nil {
		return err
	}
	// Docker's containerd image store may identify the image by its manifest,
	// unlike classic stores' config IDs. Verify exported config/rootfs identity
	// against our archive rather than equating these two kinds of digest.
	savedArchive := filepath.Join(private, "loaded-image.tar")
	saved, err := runProcess(ctx, reports, "image-save", engine, []string{"image", "save", "--output", savedArchive, tag.Name()}, runtimeEnvironment())
	if err != nil {
		return err
	}
	if saved.ExitCode != 0 {
		return fmt.Errorf("cannot export loaded image for identity verification: exit %d", saved.ExitCode)
	}
	loadedImage, err := tarball.ImageFromPath(savedArchive, &tag)
	if err != nil {
		return err
	}
	loadedConfig, err := loadedImage.ConfigName()
	if err != nil {
		return err
	}
	if loadedConfig != configHash {
		return fmt.Errorf("loaded image config/rootfs differs from the built artifact")
	}
	for _, test := range policyScenarios("_generated/invalid_bftest.lua", "unix") {
		native, nativeErr := runPolicyCase(filepath.Join(reports, "native"), test, func(folder string, args []string) (processResult, error) {
			return runProcessIn(ctx, workspace, folder, "cli", binary, args, processEnvironment(false))
		})
		container, containerErr := runPolicyCase(filepath.Join(reports, "oci"), test, func(folder string, args []string) (processResult, error) {
			mapped := mapReportArguments(args, folder)
			containerName := "bifroest-policy-" + token + "-" + test.name
			runArgs := containerArguments(filepath.Base(engine), containerName, token, record.ImageID, platform.Oci(), workspace, folder, fmt.Sprintf("%d:%d", uid, gid), mapped)
			process, runErr := runProcess(ctx, folder, "cli", engine, runArgs, runtimeEnvironment())
			inspect, inspectErr := runProcess(ctx, folder, "inspect", engine, []string{"inspect", containerName}, runtimeEnvironment())
			if inspectErr != nil || inspect.ExitCode != 0 {
				return process, errors.Join(runErr, inspectErr, fmt.Errorf("container inspection failed: exit %d", inspect.ExitCode))
			}
			raw, readErr := os.ReadFile(filepath.Join(folder, "inspect.stdout.txt"))
			if readErr != nil {
				return process, errors.Join(runErr, readErr)
			}
			actual, inspectErr := inspectContainer(raw, token, record.ImageID, record.ImageConfigDigest)
			if actual != nil {
				cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				removed, err := runProcess(cleanup, folder, "remove", engine, []string{"rm", "--force", actual.ID}, runtimeEnvironment())
				if err == nil && removed.ExitCode != 0 {
					err = fmt.Errorf("cannot remove owned container: exit %d", removed.ExitCode)
				}
				runErr = errors.Join(runErr, err)
			}
			if inspectErr != nil {
				return process, errors.Join(runErr, inspectErr)
			}
			return process, errors.Join(runErr, validateContainer(*actual, request.EntryPoint, mapped, workspace, folder, fmt.Sprintf("%d:%d", uid, gid), process.ExitCode))
		})
		pairErr := errors.Join(nativeErr, containerErr)
		if pairErr == nil {
			pairErr = compareExecutions(filepath.Join(reports, "native", test.name), filepath.Join(reports, "oci", test.name), workspace, test)
		}
		record.Cases = append(record.Cases, ociCaseResult{Name: test.name, Native: native, Container: container, Equivalent: pairErr == nil})
		if pairErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("%s: %w", test.name, pairErr))
		}
	}
	after, err := workspaceHashes(workspace)
	if err != nil {
		return errors.Join(resultErr, err)
	}
	if !equalJSON(record.Inputs, after) {
		resultErr = errors.Join(resultErr, fmt.Errorf("read-only fixture snapshot changed during execution"))
	}
	return resultErr
}

func stageWorkspace(workspace string) error {
	examples := filepath.Join("pkg", "test", "examples")
	if err := os.MkdirAll(filepath.Join(workspace, examples), 0755); err != nil {
		return err
	}
	for _, directory := range []string{"ssh", "oidc", "http"} {
		if err := os.CopyFS(filepath.Join(workspace, examples, directory), os.DirFS(filepath.Join(examples, directory))); err != nil {
			return err
		}
	}
	if err := os.Mkdir(filepath.Join(workspace, "_generated"), 0755); err != nil {
		return err
	}
	if err := createFile(filepath.Join(workspace, "_generated", "invalid_bftest.lua"), []byte("suite {\n")); err != nil {
		return err
	}
	return filepath.WalkDir(workspace, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, 0555)
		}
		if entry.Type().IsRegular() {
			return os.Chmod(path, 0444)
		}
		return fmt.Errorf("unexpected nonregular parity fixture %q", path)
	})
}

func workspaceHashes(workspace string) (map[string]string, error) {
	result := map[string]string{}
	err := filepath.WalkDir(workspace, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected nonregular parity input %q", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(workspace, path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		result[filepath.ToSlash(relative)] = hex.EncodeToString(digest[:])
		return nil
	})
	return result, err
}

func runtimeEnvironment() []string {
	result := processEnvironment(false)
	for _, key := range []string{"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "CONTAINER_HOST", "XDG_RUNTIME_DIR"} {
		if value, ok := os.LookupEnv(key); ok {
			result = append(result, key+"="+value)
		}
	}
	return result
}

func mapReportArguments(args []string, folder string) []string {
	result := append([]string{}, args...)
	for i, value := range result {
		plain, root := filepath.ToSlash(value), filepath.ToSlash(folder)
		if plain == root || strings.HasPrefix(plain, root+"/") {
			result[i] = "/reports" + strings.TrimPrefix(plain, root)
		}
	}
	return result
}

func containerArguments(engine, name, token, image, platform, workspace, reports, user string, cli []string) []string {
	args := []string{"run", "--name", name, "--label", ociRunLabel + "=" + token, "--pull=never", "--platform", platform,
		"--network=none", "--read-only", "--user", user, "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--pids-limit=64", "--memory=256m", "--cpus=1", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
		"--mount", bindMount(workspace, "/workspace", true), "--mount", bindMount(reports, "/reports", false),
		"--workdir=/workspace", "--env=TMPDIR=/tmp"}
	if engine == "podman" {
		args = append(args, "--userns=keep-id")
	}
	return append(append(args, image), cli...)
}

func bindMount(source, destination string, readOnly bool) string {
	fields := []string{"type=bind", "src=" + source, "dst=" + destination}
	if readOnly {
		fields = append(fields, "readonly")
	}
	var encoded strings.Builder
	writer := csv.NewWriter(&encoded)
	_ = writer.Write(fields) // strings.Builder cannot fail.
	writer.Flush()
	return strings.TrimSuffix(encoded.String(), "\n")
}
