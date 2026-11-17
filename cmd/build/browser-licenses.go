package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/alecthomas/kingpin/v2"
)

type browserLicenseFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Text   string `json:"text"`
}

type browserLicenseModule struct {
	Module  string               `json:"module"`
	License string               `json:"license"`
	Files   []browserLicenseFile `json:"files"`
}

func initBrowserLicenses(ctx context.Context, app *kingpin.Application) {
	var entry string
	command := app.Command("browser-licenses", "Collect Go/WASM licenses using the shared license policy.")
	command.Flag("package", "Go/WASM entry package.").Required().StringVar(&entry)
	command.Action(func(*kingpin.ParseContext) error {
		modules, err := collectBrowserLicenses(ctx, entry)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(modules)
	})
}

func collectBrowserLicenses(ctx context.Context, entry string) (_ []browserLicenseModule, resultErr error) {
	policy, err := readThirdPartyLicensePolicy(thirdPartyLicensePolicyRaw)
	if err != nil {
		return nil, err
	}
	tool, err := verifiedGoTool("go-licenses", "github.com/google/go-licenses/v2", goLicensesVersion)
	if err != nil {
		return nil, err
	}
	environment := append(os.Environ(), "GOOS=js", "GOARCH=wasm", "CGO_ENABLED=0")
	run := func(executable string, args ...string) ([]byte, error) {
		command := osexec.CommandContext(ctx, executable, args...)
		command.Env = environment
		var stderr bytes.Buffer
		command.Stderr = &stderr
		output, err := command.Output()
		if err != nil {
			return nil, fmt.Errorf("%s: %w\n%s", command, err, stderr.String())
		}
		return output, nil
	}
	graph, err := run("go", "list", "-deps", "-json", entry)
	if err != nil {
		return nil, err
	}
	modules, err := browserLicenseModules(bytes.NewReader(graph))
	if err != nil {
		return nil, err
	}
	report, err := run(tool, "report", "--ignore="+projectModule, "--template="+goLicensesTemplate, entry)
	if err != nil {
		return nil, err
	}
	records, err := parseThirdPartyLicenseRecords(report)
	if err != nil {
		return nil, err
	}
	temporary, err := os.MkdirTemp("", "bifroest-browser-licenses-*")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := os.RemoveAll(temporary); resultErr == nil && err != nil {
			resultErr = err
		}
	}()
	saved := filepath.Join(temporary, "licenses")
	if _, err := run(tool, "save", "--ignore="+projectModule, "--save_path="+saved, entry); err != nil {
		return nil, err
	}
	components, err := reconcileThirdPartyComponents(modules, records, saved, policy)
	if err != nil {
		return nil, err
	}
	return browserLicenseInventory(components)
}

// Go resolves these modules from go.mod/go.sum under the same js/wasm target as
// the browser build. No independently maintained module or version list.
func browserLicenseModules(reader io.Reader) ([]*thirdPartyModule, error) {
	decoder := json.NewDecoder(reader)
	modules := make(map[string]*thirdPartyModule)
	for {
		var pkg struct {
			Module *struct {
				Path    string
				Version string
				Main    bool
				Replace *json.RawMessage
			}
		}
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("cannot decode browser Go module graph: %w", err)
		}
		module := pkg.Module
		if module == nil {
			continue
		}
		if module.Replace != nil {
			return nil, fmt.Errorf("browser Go module %q is replaced", module.Path)
		}
		if module.Main && module.Path == projectModule {
			continue
		}
		if module.Path == "" || module.Version == "" || module.Main {
			return nil, fmt.Errorf("browser Go module %q has no release version", module.Path)
		}
		if previous := modules[module.Path]; previous != nil && previous.version != module.Version {
			return nil, fmt.Errorf("browser Go module %q has conflicting versions", module.Path)
		}
		modules[module.Path] = &thirdPartyModule{matches: []string{module.Path}, component: module.Path, version: module.Version}
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("browser Go module graph has no dependencies")
	}
	result := make([]*thirdPartyModule, 0, len(modules))
	for _, module := range modules {
		result = append(result, module)
	}
	slices.SortFunc(result, func(a, b *thirdPartyModule) int { return strings.Compare(a.component, b.component) })
	return result, nil
}

func browserLicenseInventory(components []thirdPartyComponent) ([]browserLicenseModule, error) {
	result := make([]browserLicenseModule, 0, len(components))
	for _, component := range components {
		versions := sortedSet(component.versions)
		if len(versions) != 1 || len(component.licenses) == 0 {
			return nil, fmt.Errorf("browser Go module %q has incomplete license information", component.name)
		}
		module := browserLicenseModule{Module: component.name + "@" + versions[0]}
		licenses := make(map[string]struct{})
		for _, text := range component.licenses {
			for license := range text.licenses {
				licenses[license] = struct{}{}
			}
			module.Files = append(module.Files, browserLicenseFile{Path: "LICENSE-" + text.hash + ".txt", SHA256: text.hash, Text: text.text})
		}
		for _, notice := range component.notices {
			module.Files = append(module.Files, browserLicenseFile{Path: notice.name, SHA256: notice.hash, Text: notice.text})
		}
		module.License = strings.Join(sortedSet(licenses), " AND ")
		slices.SortFunc(module.Files, func(a, b browserLicenseFile) int { return strings.Compare(a.Path, b.Path) })
		result = append(result, module)
	}
	slices.SortFunc(result, func(a, b browserLicenseModule) int { return strings.Compare(a.Module, b.Module) })
	return result, nil
}
