package main

import (
	"bytes"
	"encoding/json"
	gos "os"
	goexec "os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/stretchr/testify/require"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/internal/build/binary"
	"github.com/engity-com/bifroest/internal/build/browser"
	"github.com/engity-com/bifroest/pkg/sys"
)

type groupedBinaryMatrixEntry struct {
	Os       string   `json:"os"`
	Arch     string   `json:"arch"`
	Runner   string   `json:"runner"`
	Image    string   `json:"image"`
	Editions []string `json:"editions"`
}

func runBinaryMatrixGrouping(t *testing.T, input []byte) ([]byte, string, error) {
	t.Helper()
	node, err := goexec.LookPath("node")
	if err != nil {
		t.Skip("Node is required to exercise the workflow's matrix grouping")
	}
	file := filepath.Join(t.TempDir(), "environment")
	require.NoError(t, gos.WriteFile(file, input, 0o600))
	command := goexec.CommandContext(t.Context(), node, "../../.github/scripts/group-binary-matrices.mjs", file)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err = command.Run()
	return stdout.Bytes(), stderr.String(), err
}

func binaryMatrixOutputs(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	result := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		name, value, ok := strings.Cut(strings.TrimSuffix(line, "\r"), "=")
		require.True(t, ok)
		require.NotContains(t, result, name)
		result[name] = value
	}
	return result
}

func TestBinaryTargetGroupingRetainsEverySourceVariantAndItsBuildEnvironment(t *testing.T) {
	b := newBase()
	b.rawCommit, b.rawRef = "historical", "ci-inventory"
	b.build.rawStages = buildStages{buildStageBinary}
	b.optionsOutputFilename = filepath.Join(t.TempDir(), "environment")
	require.NoError(t, b.build.evaluateEnvironment(t.Context()))
	current, err := gos.ReadFile(b.optionsOutputFilename)
	require.NoError(t, err)
	// Captured by executing the unmodified tag's evaluate-environment CLI offline
	// with --ref=ci-inventory --commit=historical --stages=binary.
	historical, err := gos.ReadFile("testdata/binary-matrices-v1.0.0-beta3.txt")
	require.NoError(t, err)
	// Beta2 has different image pins and no Node pin; preserve its own inventory.
	// Captured with its unchanged ci:evaluate-environment task, not a new task.
	older, err := gos.ReadFile("testdata/binary-matrices-v1.0.0-beta2.txt")
	require.NoError(t, err)
	for name, raw := range map[string][]byte{"current": current, "v1.0.0-beta3": historical, "v1.0.0-beta2": older} {
		// The captured text fixture may itself use CRLF in a Windows checkout.
		raw = []byte(strings.ReplaceAll(string(raw), "\r\n", "\n"))
		for label, newline := range map[string]string{"LF": "\n", "CRLF": "\r\n"} {
			t.Run(name+"/"+label, func(t *testing.T) {
				input := []byte(strings.ReplaceAll(string(raw), "\n", newline))
				output, log, err := runBinaryMatrixGrouping(t, input)
				require.NoError(t, err, log)
				before, after := binaryMatrixOutputs(t, input), binaryMatrixOutputs(t, output)
				var sourceVariants, builtVariants []string
				seen := map[string]bool{}
				for _, kind := range []string{"host", "container"} {
					key := "binary-" + kind + "-matrix"
					var source buildMatrix[buildBinaryMatrixEntry]
					require.NoError(t, json.Unmarshal([]byte(before[key]), &source))
					for _, entry := range source.Include {
						sourceVariants = append(sourceVariants, entry.Os+"/"+entry.Arch+"/"+entry.Edition)
					}
					var grouped buildMatrix[groupedBinaryMatrixEntry]
					require.NoError(t, json.Unmarshal([]byte(after[key]), &grouped))
					if kind == "host" {
						require.Len(t, grouped.Include, 6)
					} else {
						require.Len(t, grouped.Include, 4)
					}
					for _, entry := range grouped.Include {
						target := entry.Os + "/" + entry.Arch
						require.False(t, seen[target], "exactly one job per OS/arch, including across host/container")
						seen[target] = true
						var os sys.Os
						var arch sys.Arch
						require.NoError(t, os.Set(entry.Os))
						require.NoError(t, arch.Set(entry.Arch))
						build := newBuild(&base{})
						build.oses, build.archs = sys.Oses{os}, sys.Archs{arch}
						// The prepared Linux images run on amd64; Darwin uses native runners.
						hostOs, hostArch := os, arch
						if os == sys.OsLinux {
							hostArch = sys.ArchAmd64
							require.Equal(t, "ubuntu-latest", entry.Runner)
						}
						if kind == "container" {
							var sourceImage string
							for _, original := range source.Include {
								if original.Os == entry.Os && original.Arch == entry.Arch {
									sourceImage = original.Image
									require.Equal(t, original.Runner, entry.Runner)
								}
							}
							require.NotEmpty(t, sourceImage)
							require.Equal(t, sourceImage, entry.Image, "use the source ref's image, not a workflow-side replacement")
							require.Equal(t, []string{"extended", "generic"}, entry.Editions)
						} else {
							require.Empty(t, entry.Image)
							require.Equal(t, []string{"generic"}, entry.Editions)
						}
						var editions []string
						// Exercise the CLI's existing OS/arch filter and default editions.
						for p := range build.platforms(false, hostOs, hostArch) {
							editions = append(editions, p.Edition.String())
							builtVariants = append(builtVariants, p.String())
							env := (binary.BuildRequest{Platform: *p, AssumedBuildOs: hostOs, AssumedBuildArch: hostArch}).Environment()
							cgo := "0"
							if p.Edition == sys.EditionExtended {
								cgo = "1"
								if arch != hostArch {
									require.NotEmpty(t, env["CC"])
								}
							}
							require.Equal(t, cgo, env["CGO_ENABLED"])
						}
						require.ElementsMatch(t, entry.Editions, editions)
					}
					delete(before, key)
					delete(after, key)
				}
				require.Equal(t, before, after, "commit/version/stages and independent test matrices are unchanged")
				require.Len(t, seen, 10)
				require.Len(t, sourceVariants, 14)
				require.ElementsMatch(t, sourceVariants, builtVariants)
				var expected []string
				for p := range b.build.distributablePlatforms(false) {
					expected = append(expected, p.String())
				}
				require.ElementsMatch(t, expected, builtVariants)
			})
		}
	}
}

func TestBinaryTargetGroupingFailsClosedOnAmbiguousOrIncompleteInventory(t *testing.T) {
	entry := `{"os":"linux","arch":"amd64","edition":"generic","runner":"ubuntu-latest","image":""}`
	valid := "binary-host-matrix={\"include\":[" + entry + "]}\nbinary-container-matrix={\"include\":[]}\n"
	for name, input := range map[string]string{
		"missing matrix":    strings.Split(valid, "\n")[0],
		"duplicate matrix":  valid + valid,
		"duplicate variant": strings.Replace(valid, entry, entry+","+entry, 1),
		"runner conflict":   strings.Replace(valid, entry, entry+","+strings.ReplaceAll(strings.ReplaceAll(entry, "generic", "extended"), "ubuntu-latest", "another-runner"), 1),
		"image conflict":    "binary-host-matrix={\"include\":[]}\nbinary-container-matrix={\"include\":[" + strings.ReplaceAll(entry, `"image":""`, `"image":"first"`) + "," + strings.ReplaceAll(strings.ReplaceAll(entry, "generic", "extended"), `"image":""`, `"image":"second"`) + "]}\n",
		"empty inventory":   "binary-host-matrix={\"include\":[]}\nbinary-container-matrix={\"include\":[]}\n",
		"unknown field":     strings.Replace(valid, `"edition":"generic"`, `"edition":"generic","extra":true`, 1),
		"invalid selector":  strings.Replace(valid, "amd64", "amd64;exit 0", 1),
	} {
		t.Run(name, func(t *testing.T) {
			output, _, err := runBinaryMatrixGrouping(t, []byte(input))
			require.Error(t, err)
			require.Empty(t, output, "never publish partially grouped matrices")
		})
	}
}

func TestBinaryTargetJobsPrepareOnceAndUploadAllVariantsWithoutBypassingFailures(t *testing.T) {
	jobs := readGoJobsWorkflow(t)
	for _, name := range []string{"binary-host", "binary-container"} {
		job := jobs[name]
		require.False(t, job.ContinueOnError)
		require.Equal(t, "Binary ${{ matrix.os }}/${{ matrix.arch }}", job.Name)
		build := goJobsStepContaining(t, job, "mise run build:go:binary")
		require.Equal(t, "mise run build:go:binary -- --os=${{ matrix.os }} --arch=${{ matrix.arch }}", job.Steps[build].Run)
		counts := map[string]int{}
		for i, step := range job.Steps {
			require.Empty(t, step.If)
			require.False(t, step.ContinueOnError)
			if strings.HasPrefix(step.Uses, "jdx/mise-action@") || strings.HasPrefix(step.Uses, "actions/checkout@") || strings.HasPrefix(step.Uses, "actions/download-artifact@") || strings.Contains(step.Run, "mise run install:go") || step.Run == "mise run ci:write-build-epoch" {
				require.Less(t, i, build)
			}
			switch {
			case strings.HasPrefix(step.Uses, "actions/checkout@") && step.With["path"] == "":
				counts["checkout"]++
			case strings.HasPrefix(step.Uses, "jdx/mise-action@"):
				counts["mise"]++
			case strings.Contains(step.Run, "mise run install:go"):
				counts["dependencies"]++
			case step.Run == "mise run ci:write-build-epoch":
				counts["epoch"]++
			case strings.HasPrefix(step.Uses, "actions/download-artifact@"):
				counts["assets"]++
				require.Equal(t, "browser-assets", step.With["name"])
			case strings.Contains(step.Run, "mise run build:go:binary"):
				counts["build"]++
			case strings.HasPrefix(step.Uses, "actions/upload-artifact@"):
				counts["upload"]++
				require.Greater(t, i, build)
				require.Equal(t, "binary-${{ matrix.os }}-${{ matrix.arch }}", step.With["name"])
				require.Equal(t, "var/dist", step.With["path"], "include binaries, notices, browser manifests and metadata for all editions")
				require.Equal(t, "error", step.With["if-no-files-found"])
			}
		}
		require.Equal(t, map[string]int{"checkout": 1, "mise": 1, "dependencies": 1, "epoch": 1, "assets": 1, "build": 1, "upload": 1}, counts)
	}
	packageJob := jobs["package"]
	var download goJobsWorkflowStep
	for _, step := range packageJob.Steps {
		if strings.HasPrefix(step.Uses, "actions/download-artifact@") {
			download = step
		}
	}
	require.Equal(t, map[string]string{"pattern": "binary-*", "merge-multiple": "true", "path": "var/dist"}, download.With)
}

func TestBinaryTargetEvaluationUsesWorkflowHelperWithOldSourceTasks(t *testing.T) {
	bash, err := goexec.LookPath("bash")
	if err != nil {
		t.Skip("Bash is required to exercise the evaluation step")
	}
	if _, err := goexec.LookPath("node"); err != nil {
		t.Skip("Node is required to exercise the grouping helper")
	}
	helper, err := gos.ReadFile("../../.github/scripts/group-binary-matrices.mjs")
	require.NoError(t, err)
	fixture, err := gos.ReadFile("testdata/binary-matrices-v1.0.0-beta2.txt")
	require.NoError(t, err)
	for _, file := range []string{"ci.yml", "release.yml"} {
		job := readGoJobsWorkflowFile(t, file)["evaluate"]
		step := job.Steps[goJobsStepContaining(t, job, "mise run ci:evaluate-environment")]
		require.Contains(t, step.Run, "mise exec node@26.9.0 -- node", "old source refs need no Node pin or new MISE task")
		for _, status := range []string{"0", "23"} {
			directory := t.TempDir()
			scriptPath := ".github/scripts/group-binary-matrices.mjs"
			if file == "release.yml" {
				scriptPath = "var/ci-workflow/" + scriptPath
			}
			require.NoError(t, gos.MkdirAll(filepath.Dir(filepath.Join(directory, scriptPath)), 0o700))
			require.NoError(t, gos.WriteFile(filepath.Join(directory, scriptPath), helper, 0o600))
			require.NoError(t, gos.WriteFile(filepath.Join(directory, "source.environment"), fixture, 0o600))
			outputPath := filepath.Join(directory, "github.output")
			require.NoError(t, gos.WriteFile(outputPath, nil, 0o600))
			// Only the old source CLI is stubbed. Run the workflow's shell and its
			// actual helper; the release source checkout has no new helper/task.
			script := `git() { [ "$*" = 'rev-parse HEAD' ] || return 42; printf source-revision; }
mise() {
  case "$*" in
    'run ci:evaluate-environment')
      [ "$EVALUATE_EXIT" = 0 ] || return "$EVALUATE_EXIT"
      cat source.environment >> "$GITHUB_OUTPUT"
      ;;
    'exec node@26.9.0 -- node '*) shift 3; "$@" ;;
    *) return 42 ;;
  esac
}
` + step.Run
			path := filepath.Join(directory, "evaluate.sh")
			require.NoError(t, gos.WriteFile(path, []byte(script), 0o600))
			command := goexec.CommandContext(t.Context(), bash, "--noprofile", "--norc", "-e", "-o", "pipefail", filepath.ToSlash(path))
			command.Dir = directory
			command.Env = append(gos.Environ(), "RUNNER_TEMP="+filepath.ToSlash(directory), "GITHUB_OUTPUT="+filepath.ToSlash(outputPath), "EVALUATE_EXIT="+status)
			log, runErr := command.CombinedOutput()
			output, err := gos.ReadFile(outputPath)
			require.NoError(t, err)
			if status == "23" {
				var exit *goexec.ExitError
				require.ErrorAs(t, runErr, &exit)
				require.Equal(t, 23, exit.ExitCode())
				require.Empty(t, output)
				continue
			}
			require.NoError(t, runErr, string(log))
			values := binaryMatrixOutputs(t, output)
			var host, container buildMatrix[groupedBinaryMatrixEntry]
			require.NoError(t, json.Unmarshal([]byte(values["binary-host-matrix"]), &host))
			require.NoError(t, json.Unmarshal([]byte(values["binary-container-matrix"]), &container))
			require.Len(t, host.Include, 6)
			require.Len(t, container.Include, 4)
			require.Equal(t, "historical", values["commit"])
		}
	}
}

func TestBinaryTargetWorkflowPropagatesBuildFailure(t *testing.T) {
	bash, err := goexec.LookPath("bash")
	if err != nil {
		t.Skip("Bash is required to exercise the build step")
	}
	for _, name := range []string{"binary-host", "binary-container"} {
		job := readGoJobsWorkflow(t)[name]
		step := job.Steps[goJobsStepContaining(t, job, "mise run build:go:binary")]
		for _, status := range []string{"0", "23"} {
			script := "mise() { printf '%s\\n' \"$*\"; return " + status + "; }\n" + step.Run
			script = strings.ReplaceAll(strings.ReplaceAll(script, "${{ matrix.os }}", "linux"), "${{ matrix.arch }}", "amd64")
			path := filepath.Join(t.TempDir(), "build.sh")
			require.NoError(t, gos.WriteFile(path, []byte(script), 0o600))
			command := goexec.CommandContext(t.Context(), bash, "--noprofile", "--norc", "-e", "-o", "pipefail", filepath.ToSlash(path))
			output, err := command.CombinedOutput()
			require.Equal(t, "run build:go:binary -- --os=linux --arch=amd64\n", string(output))
			if status == "0" {
				require.NoError(t, err)
			} else {
				var exit *goexec.ExitError
				require.ErrorAs(t, err, &exit)
				require.Equal(t, 23, exit.ExitCode())
			}
		}
	}
}

func TestBinaryTargetCLIFailsWhenOneEditionCannotCompile(t *testing.T) {
	if bib.Goos != sys.OsLinux || bib.Goarch != sys.ArchAmd64 {
		t.Skip("the fake compiler exercises the Linux amd64 grouped target")
	}
	raw, err := gos.ReadFile("../../internal/build/browser/testdata/minimal.json")
	require.NoError(t, err)
	manifest, err := browser.Decode(raw)
	require.NoError(t, err)
	directory := t.TempDir()
	for _, file := range manifest.Assets {
		path := filepath.Join(directory, browserAssetDirectory, file.Name)
		require.NoError(t, gos.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, gos.WriteFile(path, nil, 0o600))
	}
	for _, file := range manifest.Inputs {
		require.NoError(t, gos.WriteFile(filepath.Join(directory, file.Name), nil, 0o600))
	}
	require.NoError(t, gos.WriteFile(filepath.Join(directory, browserAssetDirectory, browser.Filename), raw, 0o600))
	compiler := "#!/bin/sh\n[ \"$CGO_ENABLED\" = 1 ] || exit 42\nprintf 'extended compiler failure\\n' >&2\nexit 23\n"
	require.NoError(t, gos.WriteFile(filepath.Join(directory, "go"), []byte(compiler), 0o700))
	t.Setenv("PATH", directory+string(gos.PathListSeparator)+gos.Getenv("PATH"))
	for _, name := range secretEnvironmentNames {
		t.Setenv(name, "")
	}
	t.Chdir(directory)
	build, bc := testReleaseManifestBuild(t)
	bc.revision = manifest.Revision
	build.buildContextP.Store(bc)
	app := kingpin.New("build", "test")
	build.init(t.Context(), app)
	// No edition filter: the real CLI selects Extended + Generic and propagates
	// the first compiler error rather than treating the target as successful.
	_, err = app.Parse([]string{"build-binary", "--os=linux", "--arch=amd64"})
	require.ErrorContains(t, err, "cannot build linux/amd64/extended")
	require.ErrorContains(t, err, "Go command failed with 23")
	files, err := filepath.Glob(filepath.Join(build.dest, "*", "*.binary-build.json"))
	require.NoError(t, err)
	require.Empty(t, files)
}
