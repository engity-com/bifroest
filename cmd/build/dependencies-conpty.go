package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"

	"github.com/engity-com/bifroest/internal/conpty"
)

const dependencyConptyPinPath = "internal/conpty/pin.json"

func dependencyConptyPaths() []string {
	paths := []string{dependencyConptyPinPath}
	for _, payload := range conpty.Payloads {
		paths = append(paths, path.Join("internal/conpty", payload.Filename()))
	}
	return paths
}

func (this *dependencies) conptyDownload(ctx context.Context, url string, maximum int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := this.conptyHTTPClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("download ConPTY metadata/package: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download ConPTY metadata/package: HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maximum {
		return nil, fmt.Errorf("ConPTY response exceeds size limit")
	}
	return raw, nil
}

func (this *dependencies) applyConptyUpdate(ctx context.Context, files map[string][]byte) (dependencyCheck, error) {
	current, err := conpty.ParsePin(files[dependencyConptyPinPath])
	if err != nil {
		return dependencyCheck{}, fmt.Errorf("read managed ConPTY pin: %w", err)
	}
	for _, payload := range current.Payloads {
		if err := payload.Verify(files[path.Join("internal/conpty", payload.Filename())]); err != nil {
			return dependencyCheck{}, err
		}
	}
	check := dependencyCheck{name: conpty.Name, source: conpty.PackageURLForVersion(current.Version), previous: current.Version, current: current.Version, files: dependencyConptyPaths()}
	index, err := this.conptyDownload(ctx, conpty.VersionIndexURL, 1<<20)
	if err != nil {
		return check, err
	}
	version, err := conpty.LatestStable(current.Version, index)
	if err != nil {
		return check, err
	}
	if version == current.Version {
		return check, nil
	}
	packageURL := conpty.PackageURLForVersion(version)
	raw, err := this.conptyDownload(ctx, packageURL, conpty.MaximumPackageBytes)
	if err != nil {
		return check, err
	}
	pin, payloads, err := conpty.InspectPackage(version, raw, "")
	if err != nil {
		return check, err
	}
	pinJSON, err := pin.Marshal()
	if err != nil {
		return check, err
	}
	// Mutate the update plan only after every member and the pin are validated.
	files[dependencyConptyPinPath] = pinJSON
	for filename, data := range payloads {
		files[path.Join("internal/conpty", filename)] = data
	}
	check.changed, check.current, check.source = true, version, packageURL
	check.details = append(check.details, "Stable NuGet releases only; no automatic merge.", "Source package SHA-256: `"+pin.PackageSHA256+"` (not a DLL digest).")
	for _, payload := range pin.Payloads {
		check.details = append(check.details, fmt.Sprintf("%s DLL SHA-256: `%s`", payload.Arch, payload.SHA256))
	}
	return check, nil
}
