package main

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

const (
	projectLicenseExpression      = "Apache-2.0"
	goStandardLibraryLicense      = "BSD-3-Clause"
	modifiedGoSourcesLicense      = "BSD-3-Clause"
	mozillaCaDataLicense          = "MPL-2.0"
	licenseDetectionComment       = "validated from the built binary with go-licenses " + goLicensesVersion
	spdxNoAssertion               = "NOASSERTION"
	modifiedGoSourcesSpdxID       = "SPDXRef-BifroestBundled-ModifiedGoSources"
	mozillaCaDataSpdxID           = "SPDXRef-BifroestBundled-MozillaNssCaData"
	modifiedGoSourcesCycloneDxRef = "urn:bifroest:component:modified-go-sources"
	mozillaCaDataCycloneDxRef     = "urn:bifroest:component:mozilla-nss-ca-data"
)

type bundledLicenseComponent struct {
	spdxID       string
	cycloneDxRef string
	name         string
	version      string
	typeName     string
	license      string
	sourceInfo   string
}

var bundledLicenseComponents = []bundledLicenseComponent{
	{
		spdxID:       modifiedGoSourcesSpdxID,
		cycloneDxRef: modifiedGoSourcesCycloneDxRef,
		name:         "Modified Go standard library sources",
		version:      modifiedGoSourcesVersion,
		typeName:     "library",
		license:      modifiedGoSourcesLicense,
		sourceInfo:   "derived sources in internal/fmtsort and internal/text/template",
	},
	{
		spdxID:       mozillaCaDataSpdxID,
		cycloneDxRef: mozillaCaDataCycloneDxRef,
		name:         "Mozilla NSS CA certificate data",
		typeName:     "data",
		license:      mozillaCaDataLicense,
		sourceInfo:   "generated and modified data embedded from pkg/crypto/ca-certs.crt",
	},
}

func enrichSbomLicenses(document map[string]any, format, subjectName string, inventory *thirdPartyLicenseInventory) error {
	switch format {
	case "spdx-json@2.3":
		return enrichSpdxSbomLicenses(document, subjectName, inventory)
	case "cyclonedx-json@1.6":
		return enrichCycloneDxSbomLicenses(document, subjectName, inventory)
	default:
		return fmt.Errorf("unsupported SBOM format %q", format)
	}
}

func enrichSpdxSbomLicenses(document map[string]any, subjectName string, inventory *thirdPartyLicenseInventory) error {
	packages, ok := document["packages"].([]any)
	if !ok {
		return fmt.Errorf("SPDX document has no packages")
	}
	matched := make([]bool, len(inventory.modules))
	rootID := ""
	projectID := ""
	for _, rawPackage := range packages {
		pkg, ok := rawPackage.(map[string]any)
		if !ok {
			return fmt.Errorf("SPDX document contains an invalid package")
		}
		name, _ := pkg["name"].(string)
		if name == subjectName {
			if err := setSpdxDeclaredLicense(pkg, projectLicenseExpression, "declared by the Bifroest project"); err != nil {
				return err
			}
			rootID, _ = pkg["SPDXID"].(string)
			continue
		}
		moduleName, _, found, err := spdxGoPackageCoordinates(pkg)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if moduleName == projectModule {
			projectID, _ = pkg["SPDXID"].(string)
			if err := setSpdxDeclaredLicense(pkg, projectLicenseExpression, "declared by the Bifroest project"); err != nil {
				return err
			}
		}
	}
	if rootID == "" {
		return fmt.Errorf("SPDX document has no root package %q with an SPDXID", subjectName)
	}
	if projectID == "" {
		return fmt.Errorf("SPDX document has no project module %q with an SPDXID", projectModule)
	}
	projectDependencies := spdxProjectDependencies(document["relationships"], projectID)
	standardLibraryFound := false
	for _, rawPackage := range packages {
		pkg, ok := rawPackage.(map[string]any)
		if !ok {
			continue
		}
		packageID, _ := pkg["SPDXID"].(string)
		if !slices.Contains(projectDependencies, packageID) {
			continue
		}
		moduleName, moduleVersion, found, err := spdxGoPackageCoordinates(pkg)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if moduleName == "stdlib" {
			standardLibraryFound = true
			if err := setSpdxDeclaredLicense(pkg, goStandardLibraryLicense, "declared by the Go standard library"); err != nil {
				return err
			}
			continue
		}
		license, index, err := inventory.licenseFor(moduleName, moduleVersion)
		if err != nil {
			return fmt.Errorf("cannot resolve license for SPDX Go package %s@%s: %w", moduleName, moduleVersion, err)
		}
		matched[index] = true
		if err := setSpdxDeclaredLicense(pkg, license, licenseDetectionComment); err != nil {
			return err
		}
	}
	if !standardLibraryFound {
		return fmt.Errorf("SPDX document has no Go standard library package")
	}
	if err := requireAllThirdPartyModulesMatched(inventory, matched); err != nil {
		return err
	}

	relationships, _ := document["relationships"].([]any)
	for _, component := range bundledLicenseComponents {
		found := false
		for _, rawPackage := range packages {
			pkg, ok := rawPackage.(map[string]any)
			if ok && pkg["SPDXID"] == component.spdxID {
				found = true
				if err := setSpdxDeclaredLicense(pkg, component.license, licenseDetectionComment); err != nil {
					return err
				}
			}
		}
		if !found {
			pkg := map[string]any{
				"SPDXID":           component.spdxID,
				"copyrightText":    spdxNoAssertion,
				"downloadLocation": spdxNoAssertion,
				"filesAnalyzed":    false,
				"licenseConcluded": spdxNoAssertion,
				"licenseDeclared":  component.license,
				"licenseComments":  licenseDetectionComment,
				"name":             component.name,
				"sourceInfo":       component.sourceInfo,
			}
			if component.version != "" {
				pkg["versionInfo"] = component.version
			}
			packages = append(packages, pkg)
		}
		relationships = appendSpdxRelationshipIfMissing(relationships, rootID, "CONTAINS", component.spdxID)
	}
	document["packages"] = packages
	document["relationships"] = relationships
	return nil
}

func enrichCycloneDxSbomLicenses(document map[string]any, subjectName string, inventory *thirdPartyLicenseInventory) error {
	metadata, ok := document["metadata"].(map[string]any)
	if !ok {
		return fmt.Errorf("CycloneDX document has no metadata")
	}
	root, ok := metadata["component"].(map[string]any)
	if !ok || root["name"] != subjectName {
		return fmt.Errorf("CycloneDX document has no root component %q", subjectName)
	}
	if err := setCycloneDxLicense(root, projectLicenseExpression); err != nil {
		return err
	}

	components, ok := document["components"].([]any)
	if !ok {
		return fmt.Errorf("CycloneDX document has no components")
	}
	matched := make([]bool, len(inventory.modules))
	projectRef := ""
	for _, rawComponent := range components {
		component, ok := rawComponent.(map[string]any)
		if !ok {
			return fmt.Errorf("CycloneDX document contains an invalid component")
		}
		purl, _ := component["purl"].(string)
		moduleName, _, found, err := parseGoPackagePurl(purl)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if moduleName == projectModule {
			projectRef, _ = component["bom-ref"].(string)
			if err := setCycloneDxLicense(component, projectLicenseExpression); err != nil {
				return err
			}
		}
	}
	if projectRef == "" {
		return fmt.Errorf("CycloneDX document has no project module %q with a bom-ref", projectModule)
	}
	projectDependencies := cycloneDxProjectDependencies(document["dependencies"], projectRef)
	standardLibraryFound := false
	for _, rawComponent := range components {
		component, ok := rawComponent.(map[string]any)
		if !ok {
			continue
		}
		componentRef, _ := component["bom-ref"].(string)
		if !slices.Contains(projectDependencies, componentRef) {
			continue
		}
		purl, _ := component["purl"].(string)
		moduleName, moduleVersion, found, err := parseGoPackagePurl(purl)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if moduleName == "stdlib" {
			standardLibraryFound = true
			if err := setCycloneDxLicense(component, goStandardLibraryLicense); err != nil {
				return err
			}
			continue
		}
		license, index, err := inventory.licenseFor(moduleName, moduleVersion)
		if err != nil {
			return fmt.Errorf("cannot resolve license for CycloneDX Go component %s@%s: %w", moduleName, moduleVersion, err)
		}
		matched[index] = true
		if err := setCycloneDxLicense(component, license); err != nil {
			return err
		}
	}
	if !standardLibraryFound {
		return fmt.Errorf("CycloneDX document has no Go standard library component")
	}
	if err := requireAllThirdPartyModulesMatched(inventory, matched); err != nil {
		return err
	}

	bundledRefs := make([]string, 0, len(bundledLicenseComponents))
	for _, bundled := range bundledLicenseComponents {
		bundledRefs = append(bundledRefs, bundled.cycloneDxRef)
		found := false
		for _, rawComponent := range components {
			component, ok := rawComponent.(map[string]any)
			if ok && component["bom-ref"] == bundled.cycloneDxRef {
				found = true
				if err := setCycloneDxLicense(component, bundled.license); err != nil {
					return err
				}
			}
		}
		if !found {
			component := map[string]any{
				"bom-ref":  bundled.cycloneDxRef,
				"licenses": cycloneDxLicenses(bundled.license),
				"name":     bundled.name,
				"properties": []map[string]string{{
					"name":  "bifroest:source",
					"value": bundled.sourceInfo,
				}},
				"scope": "required",
				"type":  bundled.typeName,
			}
			if bundled.version != "" {
				component["version"] = bundled.version
			}
			components = append(components, component)
		}
	}
	document["components"] = components
	document["dependencies"] = appendCycloneDxDependencies(document["dependencies"], projectRef, bundledRefs)
	return nil
}

func (this *thirdPartyLicenseInventory) licenseFor(name, version string) (string, int, error) {
	match := -1
	for index, module := range this.modules {
		nameMatches := false
		for _, candidate := range module.names {
			if strings.EqualFold(name, candidate) {
				nameMatches = true
				break
			}
		}
		if !nameMatches || normalizeGoModuleVersion(version) != normalizeGoModuleVersion(module.version) {
			continue
		}
		if match >= 0 {
			return "", -1, fmt.Errorf("matches multiple license inventory modules")
		}
		match = index
	}
	if match < 0 {
		return "", -1, fmt.Errorf("has no matching license inventory module")
	}
	return this.modules[match].licenseExpression, match, nil
}

func normalizeGoModuleVersion(value string) string {
	return strings.TrimSuffix(value, "+incompatible")
}

func requireAllThirdPartyModulesMatched(inventory *thirdPartyLicenseInventory, matched []bool) error {
	for index, found := range matched {
		if !found {
			module := inventory.modules[index]
			return fmt.Errorf("license inventory module %s@%s is missing from SBOM", strings.Join(module.names, ", "), module.version)
		}
	}
	return nil
}

func spdxGoPackageCoordinates(pkg map[string]any) (string, string, bool, error) {
	references, _ := pkg["externalRefs"].([]any)
	for _, rawReference := range references {
		reference, ok := rawReference.(map[string]any)
		if !ok || reference["referenceType"] != "purl" {
			continue
		}
		value, _ := reference["referenceLocator"].(string)
		name, version, found, err := parseGoPackagePurl(value)
		if err != nil {
			return "", "", false, err
		}
		if found {
			return name, version, true, nil
		}
	}
	return "", "", false, nil
}

func parseGoPackagePurl(value string) (string, string, bool, error) {
	const prefix = "pkg:golang/"
	if !strings.HasPrefix(value, prefix) {
		return "", "", false, nil
	}
	coordinates := strings.TrimPrefix(value, prefix)
	if index := strings.IndexAny(coordinates, "?#"); index >= 0 {
		coordinates = coordinates[:index]
	}
	version := ""
	if index := strings.LastIndex(coordinates, "@"); index >= 0 {
		version = coordinates[index+1:]
		coordinates = coordinates[:index]
	}
	name, err := url.PathUnescape(coordinates)
	if err != nil {
		return "", "", false, fmt.Errorf("cannot decode Go package purl %q: %w", value, err)
	}
	version, err = url.PathUnescape(version)
	if err != nil {
		return "", "", false, fmt.Errorf("cannot decode Go package purl %q: %w", value, err)
	}
	if name == "" {
		return "", "", false, fmt.Errorf("package URL for Go %q has no name", value)
	}
	return name, version, true, nil
}

func setSpdxDeclaredLicense(pkg map[string]any, expression, comment string) error {
	if current, _ := pkg["licenseDeclared"].(string); current != "" && current != spdxNoAssertion && current != expression {
		return fmt.Errorf("SPDX package %q declares license %q instead of %q", pkg["name"], current, expression)
	}
	pkg["licenseDeclared"] = expression
	pkg["licenseComments"] = comment
	return nil
}

func spdxProjectDependencies(raw any, projectID string) []string {
	relationships, _ := raw.([]any)
	var result []string
	for _, rawRelationship := range relationships {
		relationship, ok := rawRelationship.(map[string]any)
		if !ok {
			continue
		}
		source, _ := relationship["spdxElementId"].(string)
		target, _ := relationship["relatedSpdxElement"].(string)
		switch relationship["relationshipType"] {
		case "DEPENDENCY_OF":
			if target == projectID && source != "" && !slices.Contains(result, source) {
				result = append(result, source)
			}
		case "DEPENDS_ON":
			if source == projectID && target != "" && !slices.Contains(result, target) {
				result = append(result, target)
			}
		}
	}
	return result
}

func appendSpdxRelationshipIfMissing(relationships []any, source, relationshipType, target string) []any {
	for _, rawRelationship := range relationships {
		relationship, ok := rawRelationship.(map[string]any)
		if ok && relationship["spdxElementId"] == source && relationship["relationshipType"] == relationshipType && relationship["relatedSpdxElement"] == target {
			return relationships
		}
	}
	return append(relationships, map[string]any{
		"spdxElementId":      source,
		"relationshipType":   relationshipType,
		"relatedSpdxElement": target,
	})
}

func setCycloneDxLicense(component map[string]any, expression string) error {
	if raw, exists := component["licenses"]; exists {
		current, found := cycloneDxLicenseExpression(raw)
		if !found {
			return fmt.Errorf("CycloneDX component %q has unsupported license information", component["name"])
		}
		if current != expression {
			return fmt.Errorf("CycloneDX component %q declares license %q instead of %q", component["name"], current, expression)
		}
	}
	component["licenses"] = cycloneDxLicenses(expression)
	return nil
}

func cycloneDxLicenseExpression(raw any) (string, bool) {
	licenses, ok := raw.([]any)
	if !ok || len(licenses) != 1 {
		return "", false
	}
	entry, ok := licenses[0].(map[string]any)
	if !ok {
		return "", false
	}
	if expression, ok := entry["expression"].(string); ok {
		return expression, true
	}
	license, ok := entry["license"].(map[string]any)
	if !ok {
		return "", false
	}
	id, ok := license["id"].(string)
	return id, ok
}

func cycloneDxLicenses(expression string) []map[string]any {
	if strings.Contains(expression, " AND ") || strings.Contains(expression, " OR ") {
		return []map[string]any{{"expression": expression}}
	}
	return []map[string]any{{"license": map[string]string{"id": expression}}}
}

func cycloneDxProjectDependencies(raw any, projectRef string) []string {
	dependencies, _ := raw.([]any)
	for _, rawDependency := range dependencies {
		dependency, ok := rawDependency.(map[string]any)
		if ok && dependency["ref"] == projectRef {
			return stringsFromJsonArray(dependency["dependsOn"])
		}
	}
	return nil
}

func appendCycloneDxDependencies(raw any, projectRef string, additional []string) []any {
	dependencies, _ := raw.([]any)
	for _, rawDependency := range dependencies {
		dependency, ok := rawDependency.(map[string]any)
		if !ok || dependency["ref"] != projectRef {
			continue
		}
		dependsOn := stringsFromJsonArray(dependency["dependsOn"])
		for _, reference := range additional {
			if !slices.Contains(dependsOn, reference) {
				dependsOn = append(dependsOn, reference)
			}
		}
		slices.Sort(dependsOn)
		dependency["dependsOn"] = dependsOn
		return dependencies
	}
	additional = slices.Clone(additional)
	slices.Sort(additional)
	return append(dependencies, map[string]any{"ref": projectRef, "dependsOn": additional})
}

func stringsFromJsonArray(raw any) []string {
	values, _ := raw.([]any)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if str, ok := value.(string); ok {
			result = append(result, str)
		}
	}
	return result
}
