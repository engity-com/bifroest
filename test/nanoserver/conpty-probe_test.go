//go:build conpty_probe

package nanoserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestConPTYProbeOverlayDoesNotEditSourcesOrAssertions(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	before := map[string][]byte{}
	for _, file := range []string{"internal/conpty/library_windows.go", "pkg/environment/local_conpty_relay_windows.go", "pkg/environment/local_conpty_windows_test.go"} {
		filename := filepath.Join(root, filepath.FromSlash(file))
		raw, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		before[filename] = raw
	}
	filename := writeConPTYProbeOverlay(t, root, t.TempDir())
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	var overlay struct{ Replace map[string]string }
	if err := json.Unmarshal(raw, &overlay); err != nil {
		t.Fatal(err)
	}
	if len(overlay.Replace) != 2 {
		t.Fatalf("expected only library and relay observations: %v", overlay.Replace)
	}
	for original, replacement := range overlay.Replace {
		if _, ok := before[original]; !ok || strings.HasSuffix(original, "_test.go") {
			t.Fatalf("unexpected overlay file: %s", original)
		}
		if _, err := parser.ParseFile(token.NewFileSet(), replacement, nil, parser.AllErrors); err != nil {
			t.Fatal(err)
		}
	}
	for filename, expected := range before {
		actual, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(expected, actual) {
			t.Fatalf("diagnostic edited original file: %s", filename)
		}
	}
}

func TestConPTYProbeOverlayCompilesForWindows(t *testing.T) {
	if os.Getenv("BIFROEST_TEST_CONPTY_PROBE_BUILDS") != "1" {
		t.Skip("set BIFROEST_TEST_CONPTY_PROBE_BUILDS=1 for the cross-build check")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	overlay := writeConPTYProbeOverlay(t, root, work)
	command := exec.CommandContext(t.Context(), "go", "test", "-c", "-tags=nanoserver_integration",
		"-overlay", overlay, "-o", filepath.Join(work, "observed.exe"), "./pkg/environment")
	command.Dir = root
	command.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("observed Windows executable: %v\n%s", err, output)
	}
}

func writeConPTYProbeOverlay(t *testing.T, root, work string) string {
	t.Helper()
	replacements := map[string]string{}
	for _, file := range []string{"internal/conpty/library_windows.go", "pkg/environment/local_conpty_relay_windows.go"} {
		filename := filepath.Join(root, filepath.FromSlash(file))
		raw, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		source := string(raw)
		replace := func(before, after string) {
			t.Helper()
			if count := strings.Count(source, before); count != 1 {
				t.Fatalf("diagnostic overlay %s: expected one occurrence of %q, got %d", file, before, count)
			}
			source = strings.Replace(source, before, after, 1)
		}
		phase := func(name string) string { return "\tconptyProbePhase(" + fmt.Sprintf("%q", name) + ")\n" }
		if strings.HasPrefix(file, "internal/") {
			replace("\t\"runtime\"\n", "\t\"runtime\"\n\t\"time\"\n")
			replace("\tlibrary := &Library{}\n", phase("library.begin")+"\tlibrary := &Library{}\n")
			replace("\tparent, err := sys.CanonicalPath(os.TempDir())\n", phase("library.verified")+"\tparent, err := sys.CanonicalPath(os.TempDir())\n")
			replace("\tlibrary.directory, err = bfcrypto.CreateProtectedTempDirectory", phase("library.directory.begin")+"\tlibrary.directory, err = bfcrypto.CreateProtectedTempDirectory")
			replace("\tlibrary.directoryFile, err = bfcrypto.EnsurePrivateDirectory", phase("library.directory.created")+"\tlibrary.directoryFile, err = bfcrypto.EnsurePrivateDirectory")
			replace("\tif err := bfcrypto.WriteBootstrapFile", phase("library.bootstrap.begin")+"\tif err := bfcrypto.WriteBootstrapFile")
			replace("\tlibrary.payloadFile, err = lockPayload", phase("library.bootstrap.done")+"\tlibrary.payloadFile, err = lockPayload")
			replace("\thandle, err := windows.LoadLibraryEx", phase("library.load.begin")+"\thandle, err := windows.LoadLibraryEx")
			replace("\tlibrary.dll = &windows.DLL", phase("library.load.done")+"\tlibrary.dll = &windows.DLL")
			replace("\treturn library, nil\n", phase("library.ready")+"\treturn library, nil\n")
		} else {
			replace("\t\"sync\"\n", "\t\"sync\"\n\t\"time\"\n")
			replace("\tlibrary, err := conpty.Load()\n", phase("relay.library.begin")+"\tlibrary, err := conpty.Load()\n"+phase("relay.library.done"))
			replace("\tconsole, err := library.Create(windows.Coord{X: int16(cols), Y: int16(rows)}, inputRead, outputWrite)\n",
				phase("relay.console.begin")+"\tconsole, err := library.Create(windows.Coord{X: int16(cols), Y: int16(rows)}, inputRead, outputWrite)\n"+phase("relay.console.done"))
			replace("\t\twritten, err := io.Copy(os.Stdout, outputReader)\n",
				"\t"+phase("relay.output.begin")+"\t\twritten, err := io.Copy(os.Stdout, outputReader)\n"+"\t"+phase("relay.output.done"))
			replace("\tvar proc windows.ProcessInformation\n", phase("relay.process.begin")+"\tvar proc windows.ProcessInformation\n")
			replace("\tdefer func() { _ = windows.CloseHandle(proc.Process) }()\n",
				phase("relay.process.created")+"\tdefer func() { _ = windows.CloseHandle(proc.Process) }()\n")
			replace("\tif _, err := windows.ResumeThread(proc.Thread); err != nil {\n\t\treturn -1, fmt.Errorf(\"resume shell: %w\", err)\n\t}\n",
				phase("relay.resume.begin")+"\tif _, err := windows.ResumeThread(proc.Thread); err != nil {\n\t\treturn -1, fmt.Errorf(\"resume shell: %w\", err)\n\t}\n"+phase("relay.resume.done"))
		}
		source += "\nfunc conptyProbePhase(phase string) {\n" +
			"\tfmt.Fprintf(os.Stderr, \"conpty-probe pid=%d time_ns=%d phase=%s\\n\", os.Getpid(), time.Now().UnixNano(), phase)\n}\n"
		target := filepath.Join(work, filepath.Base(filename))
		if err := os.WriteFile(target, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		replacements[filename] = target
	}
	raw, err := json.Marshal(map[string]any{"Replace": replacements})
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(work, "overlay.json")
	if err := os.WriteFile(filename, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return filename
}
