package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/engity-com/bifroest/internal/conpty"
	"github.com/stretchr/testify/require"
)

type conptyTestTransport func(*http.Request) (*http.Response, error)

func (f conptyTestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func testConptyHTTPClient(t *testing.T, respond func(*http.Request) ([]byte, int)) *http.Client {
	t.Helper()
	return &http.Client{Transport: conptyTestTransport(func(request *http.Request) (*http.Response, error) {
		require.Empty(t, request.Header.Get("Authorization"), "GitHub App token must never be sent to NuGet")
		require.Equal(t, "https", request.URL.Scheme)
		require.Equal(t, "api.nuget.org", request.URL.Host)
		raw, status := respond(request)
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header), Request: request}, nil
	})}
}

func testConptyManagedFiles(t *testing.T) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
	for _, filename := range dependencyConptyPaths() {
		raw, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(filename)))
		require.NoError(t, err)
		files[filename] = raw
	}
	// A synthetic old pin keeps discovery tests independent of future automatic
	// version bumps; the real checked-in DLLs still exercise PE/hash validation.
	pin, err := conpty.ParsePin(files[dependencyConptyPinPath])
	require.NoError(t, err)
	pin.Version = "1.0.0"
	files[dependencyConptyPinPath], err = pin.Marshal()
	require.NoError(t, err)
	return files
}

func testConptyUpdatePackage(t *testing.T, version, license string) []byte {
	t.Helper()
	var raw bytes.Buffer
	archive := zip.NewWriter(&raw)
	file, err := archive.Create(conpty.Name + ".nuspec")
	require.NoError(t, err)
	_, err = fmt.Fprintf(file, `<package><metadata><id>%s</id><version>%s</version><license type="expression">%s</license></metadata></package>`, conpty.Name, version, license)
	require.NoError(t, err)
	files := testConptyManagedFiles(t)
	for _, payload := range conpty.Payloads {
		data := bytes.Clone(files[path.Join("internal/conpty", payload.Filename())])
		// Test-only changed bytes outside PE headers: never executed or installed.
		data[len(data)-1] ^= 1
		file, err := archive.Create(payload.Source)
		require.NoError(t, err)
		_, err = file.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, archive.Close())
	return raw.Bytes()
}

func TestConptyUpdatesAllPinsAndDLLsTogetherWithoutPreviewOrDowngrade(t *testing.T) {
	files := testConptyManagedFiles(t)
	const next = "1.25.261110001"
	archive := testConptyUpdatePackage(t, next, "MIT")
	packageDownloads := 0
	dependencies := &dependencies{conptyHTTPClient: testConptyHTTPClient(t, func(request *http.Request) ([]byte, int) {
		if request.URL.String() == conpty.VersionIndexURL {
			return []byte(`{"versions":["1.25.261109001","1.26.261109003-preview","` + next + `"]}`), http.StatusOK
		}
		require.Equal(t, conpty.PackageURLForVersion(next), request.URL.String())
		packageDownloads++
		return archive, http.StatusOK
	})}
	check, err := dependencies.applyConptyUpdate(t.Context(), files)
	require.NoError(t, err)
	require.True(t, check.changed)
	require.Equal(t, next, check.current)
	require.Len(t, check.files, 4)
	pin, err := conpty.ParsePin(files[dependencyConptyPinPath])
	require.NoError(t, err)
	require.Equal(t, next, pin.Version)
	for index, payload := range pin.Payloads {
		require.NoError(t, payload.Verify(files[path.Join("internal/conpty", payload.Filename())]))
		require.NotEqual(t, conpty.Payloads[index].SHA256, payload.SHA256)
	}
	check, err = dependencies.applyConptyUpdate(t.Context(), files)
	require.NoError(t, err)
	require.False(t, check.changed)
	require.Equal(t, 1, packageDownloads, "an unchanged pin must not download or rewrite packages")
}

func TestConptyUpdateFailsWithoutPartialPlanMutation(t *testing.T) {
	for _, failure := range []string{"download", "oversized index", "invalid package", "license", "existing payload drift"} {
		t.Run(failure, func(t *testing.T) {
			files := testConptyManagedFiles(t)
			if failure == "existing payload drift" {
				files[dependencyConptyPaths()[1]] = []byte("drift")
			}
			before := make(map[string][]byte)
			for name, raw := range files {
				before[name] = bytes.Clone(raw)
			}
			dependencies := &dependencies{conptyHTTPClient: testConptyHTTPClient(t, func(request *http.Request) ([]byte, int) {
				if failure == "download" {
					return nil, http.StatusServiceUnavailable
				}
				if failure == "oversized index" {
					return []byte(strings.Repeat(" ", 1<<20+1)), http.StatusOK
				}
				if request.URL.String() == conpty.VersionIndexURL {
					return []byte(`{"versions":["1.25.261110001"]}`), http.StatusOK
				}
				if failure == "license" {
					return testConptyUpdatePackage(t, "1.25.261110001", "Changed"), http.StatusOK
				}
				return []byte("not a NuGet package"), http.StatusOK
			})}
			_, err := dependencies.applyConptyUpdate(t.Context(), files)
			require.Error(t, err)
			require.Equal(t, before, files)
		})
	}
}
