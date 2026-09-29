// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	gos "os"
	osexec "os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/pkg/sys"
)

func (this *buildBinary) prepareDarwinBinary(ctx context.Context, artifact *buildArtifact) (rErr error) {
	if artifact.Os != sys.OsDarwin {
		return nil
	}
	certificateConfigured := this.darwinCertificate != "" || this.darwinCertificatePass != ""
	if certificateConfigured && (this.darwinCertificate == "" || this.darwinCertificatePass == "" || this.darwinSigningIdentity == "") {
		return fmt.Errorf("darwin signing certificate, password, and identity must be configured together")
	}
	notaryConfigured := this.darwinNotaryKey != "" || this.darwinNotaryKeyId != "" || this.darwinNotaryIssuer != ""
	if notaryConfigured && (this.darwinNotaryKey == "" || this.darwinNotaryKeyId == "" || this.darwinNotaryIssuer == "") {
		return fmt.Errorf("darwin notarization key, key ID, and issuer ID must be configured together")
	}
	if notaryConfigured && this.darwinSigningIdentity == "" {
		return fmt.Errorf("darwin notarization requires a signing identity")
	}
	if this.darwinReleaseRequired && (!certificateConfigured || !notaryConfigured) {
		return fmt.Errorf("darwin release binaries require a signing certificate and notarization credentials")
	}
	if err := validateDarwinBinary(ctx, artifact); err != nil {
		return err
	}
	if this.darwinSigningIdentity == "" {
		return nil
	}

	temporaryDirectory, err := gos.MkdirTemp("", "bifroest-darwin-release-")
	if err != nil {
		return err
	}
	defer func() { _ = gos.RemoveAll(temporaryDirectory) }()

	if certificateConfigured {
		keychain := filepath.Join(temporaryDirectory, "signing.keychain-db")
		password, err := randomDarwinKeychainPassword()
		if err != nil {
			return err
		}
		certificate := filepath.Join(temporaryDirectory, "developer-id.p12")
		if err := decodeDarwinCertificate(this.darwinCertificate, certificate); err != nil {
			return err
		}
		searchList, err := runDarwinBuildCommand(ctx, "security", "list-keychains", "-d", "user")
		if err != nil {
			return err
		}
		originalKeychains, err := parseDarwinKeychainSearchList(searchList)
		if err != nil {
			return err
		}
		if _, err := runDarwinBuildCommand(ctx, "security", "create-keychain", "-p", password, keychain); err != nil {
			return err
		}
		defer func() {
			if _, err := runDarwinBuildCommand(context.Background(), "security", "delete-keychain", keychain); rErr == nil && err != nil {
				rErr = err
			}
		}()
		defer func() {
			args := append([]string{"list-keychains", "-d", "user", "-s"}, originalKeychains...)
			if _, err := runDarwinBuildCommand(context.Background(), "security", args...); rErr == nil && err != nil {
				rErr = err
			}
		}()
		commands := [][]string{
			{"set-keychain-settings", "-lut", "21600", keychain},
			{"unlock-keychain", "-p", password, keychain},
			{"import", certificate, "-k", keychain, "-P", this.darwinCertificatePass, "-T", "/usr/bin/codesign"},
			{"set-key-partition-list", "-S", "apple-tool:,apple:", "-s", "-k", password, keychain},
			{"list-keychains", "-d", "user", "-s", keychain},
		}
		for _, args := range commands {
			if _, err := runDarwinBuildCommand(ctx, "security", args...); err != nil {
				return err
			}
		}
		identities, err := runDarwinBuildCommand(ctx, "security", "find-identity", "-v", "-p", "codesigning", keychain)
		if err != nil {
			return err
		}
		if !strings.Contains(identities, this.darwinSigningIdentity) {
			return fmt.Errorf("imported keychain does not contain signing identity %q", this.darwinSigningIdentity)
		}
	}

	if err := this.signDarwin(ctx, artifact); err != nil {
		return err
	}
	if this.darwinReleaseRequired {
		if err := validateDarwinSignature(ctx, artifact); err != nil {
			return err
		}
	}
	if notaryConfigured {
		if err := this.notarizeDarwin(ctx, artifact, temporaryDirectory); err != nil {
			return err
		}
	}
	return nil
}

func validateDarwinBinary(ctx context.Context, artifact *buildArtifact) error {
	if _, err := runDarwinBuildCommand(ctx, artifact.filepath, "version", "--no-long"); err != nil {
		return err
	}
	machoArchitecture := map[sys.Arch]string{
		sys.ArchAmd64: "x86_64",
		sys.ArchArm64: "arm64",
	}[artifact.Arch]
	if machoArchitecture == "" {
		return fmt.Errorf("unsupported Darwin architecture: %s", artifact.Arch)
	}
	architectures, err := runDarwinBuildCommand(ctx, "lipo", "-archs", artifact.filepath)
	if err != nil {
		return err
	}
	if architectures != machoArchitecture {
		return fmt.Errorf("darwin binary has architectures %q instead of %q", architectures, machoArchitecture)
	}
	fileType, err := runDarwinBuildCommand(ctx, "file", "-b", artifact.filepath)
	if err != nil {
		return err
	}
	if fileType != "Mach-O 64-bit executable "+machoArchitecture {
		return fmt.Errorf("unexpected Darwin binary type %q", fileType)
	}
	buildVersion, err := runDarwinBuildCommand(ctx, "vtool", "-show-build", artifact.filepath)
	if err != nil {
		return err
	}
	minimumPattern := regexp.MustCompile(`(?m)minos\s+` + regexp.QuoteMeta(bib.DefaultMacosDeploymentTarget) + `(?:\s|$)`)
	if !minimumPattern.MatchString(buildVersion) {
		return fmt.Errorf("darwin binary does not target macOS %s", bib.DefaultMacosDeploymentTarget)
	}
	dependencies, err := runDarwinBuildCommand(ctx, "otool", "-L", artifact.filepath)
	if err != nil {
		return err
	}
	if !strings.Contains(dependencies, "/usr/lib/libpam.2.dylib") {
		return fmt.Errorf("darwin binary is not linked to system PAM")
	}
	for index, line := range strings.Split(dependencies, "\n") {
		if index == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		dependency := strings.Fields(line)[0]
		if !strings.HasPrefix(dependency, "/usr/lib/") && !strings.HasPrefix(dependency, "/System/Library/") {
			return fmt.Errorf("darwin binary has non-system dependency %q", dependency)
		}
	}
	symbols, err := runDarwinBuildCommand(ctx, "nm", "-m", artifact.filepath)
	if err != nil {
		return err
	}
	for _, symbol := range []string{"_pam_start", "_pam_authenticate", "_pam_acct_mgmt"} {
		if !strings.Contains(symbols, "(undefined) external "+symbol+" (from libpam)") {
			return fmt.Errorf("darwin binary does not resolve PAM symbol %s dynamically", symbol)
		}
	}
	binaryStrings, err := runDarwinBuildCommand(ctx, "strings", artifact.filepath)
	if err != nil {
		return err
	}
	if regexp.MustCompile(`/Applications/Xcode|/Library/Developer|MacOSX[^/]*\.sdk`).MatchString(binaryStrings) {
		return fmt.Errorf("darwin binary embeds an Apple SDK or Xcode path")
	}
	return nil
}

func validateDarwinSignature(ctx context.Context, artifact *buildArtifact) error {
	signature, err := runDarwinBuildCommand(ctx, "codesign", "--display", "--verbose=4", artifact.filepath)
	if err != nil {
		return err
	}
	patterns := []string{
		`(?m)^Authority=Developer ID Application: Engity GmbH \([A-Z0-9]+\)$`,
		`(?m)^TeamIdentifier=[A-Z0-9]+$`,
		`(?m)^CodeDirectory .*flags=.*\(.*runtime.*\)`,
		`(?m)^Timestamp=.+$`,
	}
	for _, pattern := range patterns {
		if !regexp.MustCompile(pattern).MatchString(signature) {
			return fmt.Errorf("darwin release signature does not match %q", pattern)
		}
	}
	return nil
}

func (this *buildBinary) signDarwin(ctx context.Context, artifact *buildArtifact) error {
	if artifact.Os != sys.OsDarwin || this.darwinSigningIdentity == "" {
		return nil
	}
	for _, args := range [][]string{
		{"--force", "--sign", this.darwinSigningIdentity, "--options", "runtime", "--timestamp", artifact.filepath},
		{"--verify", "--strict", "--verbose=2", artifact.filepath},
	} {
		if _, err := runDarwinBuildCommand(ctx, "codesign", args...); err != nil {
			return err
		}
	}
	return nil
}

func (this *buildBinary) notarizeDarwin(ctx context.Context, artifact *buildArtifact, temporaryDirectory string) error {
	apiKey := filepath.Join(temporaryDirectory, "AuthKey_"+this.darwinNotaryKeyId+".p8")
	if err := gos.WriteFile(apiKey, []byte(this.darwinNotaryKey), 0600); err != nil {
		return err
	}
	submission := filepath.Join(temporaryDirectory, filepath.Base(artifact.filepath)+".zip")
	if _, err := runDarwinBuildCommand(ctx, "ditto", "-c", "-k", "--keepParent", artifact.filepath, submission); err != nil {
		return err
	}
	result, err := runDarwinBuildCommand(ctx, "xcrun", "notarytool", "submit", submission,
		"--key", apiKey,
		"--key-id", this.darwinNotaryKeyId,
		"--issuer", this.darwinNotaryIssuer,
		"--wait", "--timeout", "30m", "--output-format", "json")
	if err != nil {
		return err
	}
	var submissionResult struct {
		Id     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(result), &submissionResult); err != nil {
		return fmt.Errorf("cannot decode Darwin notarization result: %w", err)
	}
	if submissionResult.Status != "Accepted" {
		return fmt.Errorf("darwin notarization %q finished with status %q", submissionResult.Id, submissionResult.Status)
	}
	if this.darwinReleaseRequired {
		status, err := runDarwinBuildCommand(ctx, "spctl", "--status")
		if err != nil {
			return err
		}
		if !strings.Contains(status, "assessments enabled") {
			return fmt.Errorf("gatekeeper assessments are not enabled: %s", status)
		}
		assessment, err := runDarwinBuildCommand(ctx, "spctl", "--assess", "--type", "execute", "--verbose=4", artifact.filepath)
		if err != nil {
			return err
		}
		if !strings.Contains(assessment, "source=Notarized Developer ID") {
			return fmt.Errorf("gatekeeper did not report a notarized Developer ID: %s", assessment)
		}
	}
	return nil
}

func parseDarwinKeychainSearchList(raw string) ([]string, error) {
	var result []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, `"`) {
			decoded, err := strconv.Unquote(line)
			if err != nil {
				return nil, fmt.Errorf("cannot parse Darwin keychain search list entry %q: %w", line, err)
			}
			line = decoded
		}
		result = append(result, line)
	}
	return result, nil
}

func decodeDarwinCertificate(encoded, target string) error {
	source := base64.NewDecoder(base64.StdEncoding, strings.NewReader(encoded))
	file, err := gos.OpenFile(target, gos.O_CREATE|gos.O_EXCL|gos.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(file, source); err != nil {
		_ = file.Close()
		return fmt.Errorf("cannot decode Darwin signing certificate: %w", err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	return nil
}

func randomDarwinKeychainPassword() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func runDarwinBuildCommand(ctx context.Context, executable string, args ...string) (string, error) {
	command := osexec.CommandContext(ctx, executable, args...)
	for _, value := range gos.Environ() {
		name, _, _ := strings.Cut(value, "=")
		if slices.Contains(darwinSecretEnvironment, name) {
			continue
		}
		command.Env = append(command.Env, value)
	}
	output, err := command.CombinedOutput()
	plain := strings.TrimSpace(string(output))
	if err != nil {
		return plain, fmt.Errorf("%s %s failed: %w: %s", executable, args[0], err, plain)
	}
	return plain, nil
}
