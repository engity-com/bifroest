package main

import (
	"context"
	"fmt"
	gos "os"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/echocat/slf4g"

	bib "github.com/engity-com/bifroest/internal/build"
	"github.com/engity-com/bifroest/internal/build/binary"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	darwinCertificateEnvironment         = "BIFROEST_DARWIN_CERTIFICATE"
	darwinCertificatePasswordEnvironment = "BIFROEST_DARWIN_CERTIFICATE_PASSWORD"
	darwinNotaryKeyEnvironment           = "BIFROEST_DARWIN_NOTARY_KEY"
)

var secretEnvironmentNames = []string{
	darwinCertificateEnvironment,
	darwinCertificatePasswordEnvironment,
	darwinNotaryKeyEnvironment,
}

func newBuildBinary(b *build) *buildBinary {
	return &buildBinary{
		build: b,
	}
}

type buildBinary struct {
	*build

	darwinSigningIdentity string
	darwinCertificate     string
	darwinCertificatePass string
	darwinNotaryKey       string
	darwinNotaryKeyId     string
	darwinNotaryIssuer    string
	darwinReleaseRequired bool
}

func (this *buildBinary) attach(cmd *kingpin.CmdClause) {
	cmd.Flag("darwinSigningIdentity", "Developer ID Application identity used to sign native Darwin binaries.").
		Envar("BIFROEST_DARWIN_SIGNING_IDENTITY").
		PlaceHolder("<identity>").
		StringVar(&this.darwinSigningIdentity)
	cmd.Flag("darwin.certificate", "Base64-encoded Developer ID certificate imported into a temporary keychain.").
		Envar(darwinCertificateEnvironment).
		PlaceHolder("<base64>").
		StringVar(&this.darwinCertificate)
	cmd.Flag("darwin.certificate.password", "Password of the Developer ID certificate.").
		Envar(darwinCertificatePasswordEnvironment).
		PlaceHolder("<password>").
		StringVar(&this.darwinCertificatePass)
	cmd.Flag("darwin.notary.key", "App Store Connect API private key used for notarization.").
		Envar(darwinNotaryKeyEnvironment).
		PlaceHolder("<key>").
		StringVar(&this.darwinNotaryKey)
	cmd.Flag("darwin.notary.keyId", "App Store Connect API key ID used for notarization.").
		Envar("BIFROEST_DARWIN_NOTARY_KEY_ID").
		PlaceHolder("<id>").
		StringVar(&this.darwinNotaryKeyId)
	cmd.Flag("darwin.notary.issuer", "App Store Connect issuer ID used for notarization.").
		Envar("BIFROEST_DARWIN_NOTARY_ISSUER_ID").
		PlaceHolder("<id>").
		StringVar(&this.darwinNotaryIssuer)
	cmd.Flag("darwin.release.required", "Require Developer ID signing and notarization for Darwin binaries.").
		Envar("BIFROEST_DARWIN_RELEASE_REQUIRED").
		BoolVar(&this.darwinReleaseRequired)
}

func (this *buildBinary) compile(ctx context.Context, p *bib.Platform) (*buildArtifact, *buildArtifact, error) {
	fail := func(err error) (*buildArtifact, *buildArtifact, error) {
		return nil, nil, fmt.Errorf("cannot build %v: %w", *p, err)
	}

	assumedBuildOs := this.assumedBuildOs()
	assumedBuildArch := this.assumedBuildArch()
	if err := p.AssertBinarySupported(assumedBuildOs, assumedBuildArch); err != nil {
		return fail(err)
	}

	fn := p.Os.AppendExtToFilename(p.FilenamePrefix(this.prefix))

	success := false
	a, err := this.newBuildFileArtifact(ctx, p, buildArtifactTypeBinary, fn)
	if err != nil {
		return fail(err)
	}
	defer common.IgnoreCloseErrorIfFalse(&success, a)

	l := log.With("platform", p).
		With("stage", buildStageBinary).
		With("file", a.filepath)

	req := binary.BuildRequest{
		Platform:             *a.Platform,
		Time:                 a.time,
		Version:              a.version.String(),
		Vendor:               a.vendor,
		Revision:             a.revision,
		TargetFile:           a.filepath,
		WslBuildDistribution: this.wslBuildDistribution,
		AssumedBuildOs:       assumedBuildOs,
		AssumedBuildArch:     assumedBuildArch,
	}

	start := time.Now()
	l.Debug("building binary...")

	if err := binary.Build(ctx, req); err != nil {
		return fail(err)
	}
	if p.Os == sys.OsWindows {
		if err := this.addWindowsResources(a); err != nil {
			return fail(err)
		}
	}
	notice, err := this.newBuildFileArtifact(ctx, p, buildArtifactTypeNotice, p.FilenamePrefix(this.prefix)+".third-party-notices.txt")
	if err != nil {
		return fail(err)
	}
	defer common.IgnoreCloseErrorIfFalse(&success, notice)
	if err := this.createThirdPartyNotices(ctx, req, a, notice.filepath); err != nil {
		return fail(err)
	}
	a.thirdPartyNoticesFilepath = notice.filepath
	if p.Os == sys.OsDarwin {
		if err := this.prepareDarwinBinary(ctx, a); err != nil {
			return fail(err)
		}
	}

	ld := l.With("duration", time.Since(start).Truncate(time.Millisecond))
	if l.IsDebugEnabled() {
		ld.Debug("building binary... DONE!")
	} else {
		ld.Info("binary built")
	}

	success = true
	return a, notice, nil
}

func (this *buildBinary) clearSecretsFromEnvironment() {
	for _, name := range secretEnvironmentNames {
		_ = gos.Unsetenv(name)
	}
}
