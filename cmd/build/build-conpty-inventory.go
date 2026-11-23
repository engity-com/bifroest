package main

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/engity-com/bifroest/internal/conpty"
	"github.com/engity-com/bifroest/pkg/sys"
)

func appendConptyNotices(artifact *buildArtifact, source fs.FS, target io.Writer, policy thirdPartyLicensePolicy) error {
	if artifact.Os != sys.OsWindows {
		return nil
	}
	if decision := policy.licenseDecision("MIT"); decision != thirdPartyLicenseAllowed {
		return fmt.Errorf("ConPTY license MIT is %s under the release license policy", decision)
	}
	binary, err := os.ReadFile(artifact.filepath)
	if err != nil {
		return err
	}
	for _, payload := range conpty.Payloads {
		raw, err := fs.ReadFile(source, payload.Filename())
		if err != nil {
			return err
		}
		if err := payload.Verify(raw); err != nil {
			return err
		}
		if !bytes.Contains(binary, raw) {
			return fmt.Errorf("built Windows binary does not embed pinned ConPTY %s", payload.Arch)
		}
	}
	if _, err := fmt.Fprintf(target, "\n%s %s (interface DLL subset; inbox console host)\nSource NuGet package: %s\nSource package SHA256: %s (not a shipped DLL digest)\n", conpty.Name, conpty.Version, conpty.PackageURL, conpty.PackageSHA256); err != nil {
		return err
	}
	for _, payload := range conpty.Payloads {
		if _, err := fmt.Fprintf(target, "Embedded %s: SHA256 %s\n", payload.Filename(), payload.SHA256); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(target, conpty.License)
	return err
}

func enrichConptySbom(document map[string]any, format, subjectName string, inventory *thirdPartyLicenseInventory) error {
	if !inventory.conPTY {
		return nil
	}
	const spdxID = "SPDXRef-Bifroest-ConPTY"
	const cdxRef = "urn:bifroest:component:conpty"
	sourceInfo := "unmodified interface DLL subset embedded in the Windows binary; inbox console host; OpenConsole.exe is not shipped; source NuGet package SHA256: " + conpty.PackageSHA256
	purl := "pkg:nuget/" + conpty.Name + "@" + conpty.Version
	var additions []any
	switch format {
	case "spdx-json@2.3":
		packages, _ := document["packages"].([]any)
		rootID := ""
		for _, raw := range packages {
			if pkg, ok := raw.(map[string]any); ok && pkg["name"] == subjectName {
				rootID, _ = pkg["SPDXID"].(string)
				break
			}
		}
		if rootID == "" {
			return fmt.Errorf("ConPTY SBOM has no SPDX root")
		}
		additions = append(additions, map[string]any{"SPDXID": spdxID, "name": conpty.Name, "versionInfo": conpty.Version, "downloadLocation": conpty.PackageURL, "filesAnalyzed": false, "licenseConcluded": spdxNoAssertion, "licenseDeclared": "MIT", "copyrightText": "Copyright (c) Microsoft Corporation", "sourceInfo": sourceInfo, "externalRefs": []any{map[string]any{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}}})
		relationships, _ := document["relationships"].([]any)
		relationships = appendSpdxRelationshipIfMissing(relationships, rootID, "CONTAINS", spdxID)
		for _, payload := range conpty.Payloads {
			id := spdxID + "-" + payload.Arch
			additions = append(additions, map[string]any{"SPDXID": id, "name": "embedded-conpty/" + payload.Arch + "/conpty.dll", "downloadLocation": spdxNoAssertion, "filesAnalyzed": false, "licenseConcluded": spdxNoAssertion, "licenseDeclared": "MIT", "copyrightText": "Copyright (c) Microsoft Corporation", "checksums": []any{map[string]any{"algorithm": "SHA256", "checksumValue": payload.SHA256}}})
			relationships = appendSpdxRelationshipIfMissing(relationships, spdxID, "CONTAINS", id)
		}
		objects, err := appendSbomObjects(document["packages"], additions, "SPDXID")
		if err != nil {
			return err
		}
		document["packages"], document["relationships"] = objects, relationships
	case "cyclonedx-json@1.6":
		metadata, _ := document["metadata"].(map[string]any)
		root, _ := metadata["component"].(map[string]any)
		rootRef, _ := root["bom-ref"].(string)
		if rootRef == "" {
			return fmt.Errorf("ConPTY SBOM has no CycloneDX root")
		}
		additions = append(additions, map[string]any{"bom-ref": cdxRef, "type": "library", "name": conpty.Name, "version": conpty.Version, "purl": purl, "licenses": cycloneDxLicenses("MIT"), "properties": []any{map[string]any{"name": "bifroest:source", "value": sourceInfo}}})
		var refs []string
		for _, payload := range conpty.Payloads {
			ref := cdxRef + ":" + payload.Arch
			additions = append(additions, map[string]any{"bom-ref": ref, "type": "file", "name": "embedded-conpty/" + payload.Arch + "/conpty.dll", "licenses": cycloneDxLicenses("MIT"), "hashes": []any{map[string]any{"alg": "SHA-256", "content": payload.SHA256}}})
			refs = append(refs, ref)
		}
		objects, err := appendSbomObjects(document["components"], additions, "bom-ref")
		if err != nil {
			return err
		}
		document["components"] = objects
		document["dependencies"] = appendCycloneDxDependencies(document["dependencies"], rootRef, []string{cdxRef})
		document["dependencies"] = appendCycloneDxDependencies(document["dependencies"], cdxRef, refs)
	default:
		return fmt.Errorf("unsupported ConPTY SBOM format")
	}
	return nil
}
