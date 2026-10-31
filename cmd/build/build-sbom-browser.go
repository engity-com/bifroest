package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/engity-com/bifroest/internal/build/browser"
)

const browserSbomSource = "conservative browser production dependency/WASM inventory; not exact tree-shaken usage, source-equivalence or signed provenance; npm integrity identifies the locked source archive, not shipped bundle bytes; license supplements prove text only; see BROWSER_BUILD.json and bundled notices"

func browserComponentID(component browser.Component) string {
	hash := sha256.Sum256([]byte(component.Ecosystem + "/" + component.Name + "@" + component.Version))
	return hex.EncodeToString(hash[:])
}

func browserPurl(component browser.Component) string {
	if component.Ecosystem == "go-runtime" {
		return ""
	}
	parts := strings.Split(component.Name, "/")
	for index, part := range parts {
		parts[index] = strings.ReplaceAll(url.PathEscape(part), "@", "%40")
	}
	return "pkg:" + component.Ecosystem + "/" + strings.Join(parts, "/") + "@" + url.PathEscape(component.Version)
}

func appendBrowserSbomObjects(existing any, additions []any, id string) ([]any, error) {
	objects, ok := existing.([]any)
	if !ok {
		return nil, fmt.Errorf("SBOM has no object list")
	}
	for _, addition := range additions {
		candidate := addition.(map[string]any)
		found := false
		for _, raw := range objects {
			object, ok := raw.(map[string]any)
			if ok && object[id] == candidate[id] {
				before, beforeErr := json.Marshal(object)
				after, afterErr := json.Marshal(candidate)
				if beforeErr != nil || afterErr != nil || !bytes.Equal(before, after) {
					return nil, fmt.Errorf("conflicting browser SBOM object %s", candidate[id])
				}
				found = true
				break
			}
		}
		if !found {
			objects = append(objects, addition)
		}
	}
	return objects, nil
}

func enrichBrowserSbom(document map[string]any, format, subjectName string, inventory *thirdPartyLicenseInventory) error {
	if inventory.browser == nil {
		return nil
	} // Go-only test/native inventory.
	m := inventory.browser
	if err := m.Validate(); err != nil {
		return err
	}
	digest, digestErr := hex.DecodeString(strings.TrimPrefix(inventory.browserDigest, "sha256:"))
	if !strings.HasPrefix(inventory.browserDigest, "sha256:") || digestErr != nil || len(digest) != 32 {
		return fmt.Errorf("browser inventory has no manifest digest")
	}
	const spdxBundle = "SPDXRef-BifroestBrowserBundle"
	const cdxBundle = "urn:bifroest:browser:bundle"
	var additions []any
	switch format {
	case "spdx-json@2.3":
		var root map[string]any
		packages, _ := document["packages"].([]any)
		for _, raw := range packages {
			if item, ok := raw.(map[string]any); ok && item["name"] == subjectName {
				root = item
				break
			}
		}
		if root == nil || root["SPDXID"] == "" {
			return fmt.Errorf("browser SBOM has no SPDX root")
		}
		bundle := map[string]any{"SPDXID": spdxBundle, "name": "Bifroest embedded browser resources", "downloadLocation": spdxNoAssertion, "filesAnalyzed": false, "licenseConcluded": spdxNoAssertion, "licenseDeclared": spdxNoAssertion, "copyrightText": spdxNoAssertion, "sourceInfo": browserSbomSource + "; manifest " + inventory.browserDigest + "; revision " + m.Revision + fmt.Sprintf("; dirty %t", m.Dirty)}
		additions = append(additions, bundle)
		relationships, _ := document["relationships"].([]any)
		relationships = appendSpdxRelationshipIfMissing(relationships, root["SPDXID"].(string), "CONTAINS", spdxBundle)
		for _, component := range m.Components {
			id := "SPDXRef-BifroestBrowser-" + browserComponentID(component)
			pkg := map[string]any{"SPDXID": id, "name": component.Name, "versionInfo": component.Version, "downloadLocation": spdxNoAssertion, "filesAnalyzed": false, "licenseConcluded": spdxNoAssertion, "licenseDeclared": component.License, "copyrightText": spdxNoAssertion, "licenseComments": "license text source: " + component.LicenseTextSource, "sourceInfo": browserSbomSource + "; artifacts: " + strings.Join(component.Artifacts, ", ") + "; source archive integrity: " + component.Integrity}
			if purl := browserPurl(component); purl != "" {
				pkg["externalRefs"] = []any{map[string]any{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}}
			}
			additions = append(additions, pkg)
			relationships = appendSpdxRelationshipIfMissing(relationships, spdxBundle, "DEPENDS_ON", id)
		}
		for _, asset := range append(append([]browser.File{}, m.Assets...), browser.File{Name: browser.ArchiveFilename, SHA256: strings.TrimPrefix(inventory.browserDigest, "sha256:")}) {
			hash := sha256.Sum256([]byte(asset.Name))
			id := "SPDXRef-BifroestBrowserAsset-" + hex.EncodeToString(hash[:])
			additions = append(additions, map[string]any{"SPDXID": id, "name": "embedded-browser/" + asset.Name, "downloadLocation": spdxNoAssertion, "filesAnalyzed": false, "licenseConcluded": spdxNoAssertion, "licenseDeclared": spdxNoAssertion, "copyrightText": spdxNoAssertion, "checksums": []any{map[string]any{"algorithm": "SHA256", "checksumValue": asset.SHA256}}})
			relationships = appendSpdxRelationshipIfMissing(relationships, spdxBundle, "CONTAINS", id)
		}
		packages, err := appendBrowserSbomObjects(document["packages"], additions, "SPDXID")
		if err != nil {
			return err
		}
		document["packages"], document["relationships"] = packages, relationships
	case "cyclonedx-json@1.6":
		metadata, _ := document["metadata"].(map[string]any)
		root, _ := metadata["component"].(map[string]any)
		rootRef, _ := root["bom-ref"].(string)
		if rootRef == "" {
			return fmt.Errorf("browser SBOM has no CycloneDX root")
		}
		additions = append(additions, map[string]any{"bom-ref": cdxBundle, "type": "application", "name": "Bifroest embedded browser resources", "properties": []any{map[string]any{"name": "bifroest:browser:scope", "value": browserSbomSource}, map[string]any{"name": "bifroest:browser:manifest", "value": inventory.browserDigest}, map[string]any{"name": "bifroest:browser:revision", "value": m.Revision}, map[string]any{"name": "bifroest:browser:dirty", "value": fmt.Sprint(m.Dirty)}}})
		var references []string
		for _, component := range m.Components {
			id := "urn:bifroest:browser:" + browserComponentID(component)
			item := map[string]any{"bom-ref": id, "type": "library", "name": component.Name, "version": component.Version, "licenses": cycloneDxLicenses(component.License), "properties": []any{map[string]any{"name": "bifroest:browser:artifacts", "value": strings.Join(component.Artifacts, ", ")}, map[string]any{"name": "bifroest:browser:license-text-source", "value": component.LicenseTextSource}, map[string]any{"name": "bifroest:browser:source-archive-integrity", "value": component.Integrity}}}
			if purl := browserPurl(component); purl != "" {
				item["purl"] = purl
			}
			additions = append(additions, item)
			references = append(references, id)
		}
		for _, asset := range append(append([]browser.File{}, m.Assets...), browser.File{Name: browser.ArchiveFilename, SHA256: strings.TrimPrefix(inventory.browserDigest, "sha256:")}) {
			hash := sha256.Sum256([]byte(asset.Name))
			id := "urn:bifroest:browser-asset:" + hex.EncodeToString(hash[:])
			additions = append(additions, map[string]any{"bom-ref": id, "type": "file", "name": "embedded-browser/" + asset.Name, "hashes": []any{map[string]any{"alg": "SHA-256", "content": asset.SHA256}}})
			references = append(references, id)
		}
		components, err := appendBrowserSbomObjects(document["components"], additions, "bom-ref")
		if err != nil {
			return err
		}
		document["components"] = components
		document["dependencies"] = appendCycloneDxDependencies(document["dependencies"], rootRef, []string{cdxBundle})
		document["dependencies"] = appendCycloneDxDependencies(document["dependencies"], cdxBundle, references)
	default:
		return fmt.Errorf("unsupported browser SBOM format")
	}
	return nil
}
