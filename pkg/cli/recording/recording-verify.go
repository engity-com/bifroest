package recording

import (
	"context"
	goerrors "errors"
	"fmt"
	"io"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/audit"
	audit2 "github.com/engity-com/bifroest/pkg/cli/audit"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/recording"
)

type verifyCommandOptions struct {
	common.RequireFullVerificationOpts
	common.DecryptionIdentityFilesOpts
	common.ExecutableConfigurationOpts
	File               string        `argument:"fileOrAuditlog" description:"Configured auditlog name or copied Recording file path."`
	RecordingID        string        `argument:"recordingId" description:"Recording UUID when selecting an auditlog."`
	ExpectedProducerID string        `flag:"expectedProducerId" description:"Independently trusted producer ID."`
	Format             format.Format `flag:"format" default:"table" enum:"table|json|yaml|cbor" description:"Output format."`

	// Set by the remote handler, independently of the local source selector.
	expectedRecordingID recording.Id
}

type managementVerifyOptions struct {
	selectedAuditlog
	recordingIDOptions
	common.RequireFullVerificationOpts
	format.Opts
}

func createVerifyCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[managementVerifyOptions]("verify", "Verify a signed session Recording.").
			WithProfiles(common.ProfileManagement).
			WithHandler(handleManagementVerify),
		cli.NewCommand[verifyCommandOptions]("verify", "Verify a signed session Recording.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(func(ctx context.Context, o verifyCommandOptions) error {
				return doRecordingVerify(ctx, o, cli.StdoutOfContext(ctx))
			}),
		cli.NewCommand[verifyCommandOptions]("verify", "Verify a signed session Recording.").
			WithProfiles(common.ProfileRemote).
			WithHandler(remoteHandleVerify),
	}
}

func handleManagementVerify(ctx context.Context, opts managementVerifyOptions) error {
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.Recording == nil {
		return fmt.Errorf("management recording repository is unavailable")
	}
	scope, err := access.Recording.Verify(ctx, opts.Auditlog, opts.ID, opts.RequireFull)
	if err != nil {
		return err
	}
	return format.WriteVerification(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, opts.Format), scope)
}

func doRecordingVerify(ctx context.Context, opts verifyCommandOptions, stdout io.Writer) (rErr error) {
	if stdout == nil {
		return fmt.Errorf("nil Recording verification output")
	}
	filePath, auditlogName, localConfiguration, err := resolveRecordingSelection(ctx, opts.File, opts.RecordingID, opts.ExpectedProducerID, opts)
	if err != nil {
		return err
	}
	var expected audit.ProducerId
	if !auditlogName.IsZero() {
		expected, err = configuredRecordingProducerId(auditlogName, localConfiguration, filePath)
	} else {
		expected, err = recordingExportTrust(opts.ExpectedProducerID, false)
	}
	if err != nil {
		return err
	}
	input, initial, err := OpenRecordingInput(filePath)
	if err != nil {
		return err
	}
	defer func() { rErr = goerrors.Join(rErr, input.Close()) }()
	snapshot, err := snapshotRecordingInput(input, initial.Size())
	if err != nil {
		return fmt.Errorf("cannot snapshot Recording %q: %w", filePath, err)
	}
	defer func() { rErr = goerrors.Join(rErr, snapshot.Close()) }()
	if err := ValidateRecordingInput(filePath, input, initial); err != nil {
		return err
	}
	inspection, err := recording.Inspect(snapshot, initial.Size(), recording.InspectOptions{Context: ctx, ExpectedProducerId: expected})
	if err != nil {
		return fmt.Errorf("cannot verify Recording %q: %w", filePath, err)
	}
	if err := validateExpectedRecordingID(inspection, opts.expectedRecordingID); err != nil {
		return err
	}
	if !auditlogName.IsZero() {
		if err := validateConfiguredSealedRecording(filePath, inspection); err != nil {
			return err
		}
	}
	scope := "full"
	if inspection.Format == recording.FormatBECastCBOR {
		scope = "outer"
		if len(opts.DecryptionIdentityFiles) != 0 {
			identities, err := loadRecordingDecryptionIdentities(opts.DecryptionIdentityFiles)
			if err != nil {
				return err
			}
			if _, err := recording.VerifyNativeRecordingFull(snapshot, initial.Size(), identities, recording.NativeRecordingVerifyOptions{Context: ctx, ExpectedProducerId: expected}); err != nil {
				return fmt.Errorf("cannot fully verify encrypted Recording: %w", err)
			}
			scope = "full"
		}
	}
	if opts.RequireFull && scope != "full" {
		return fmt.Errorf("full verification of encrypted Recording requires --decryptionIdentityFile")
	}
	if err := ValidateRecordingInput(filePath, input, initial); err != nil {
		return err
	}
	if !auditlogName.IsZero() {
		if err := audit2.EnsureAuditDestinationSafe("-", stdout, localConfiguration.Filename, localConfiguration, opts.DecryptionIdentityFiles); err != nil {
			return err
		}
	}
	if err := EnsureRecordingStandardOutputSafe(stdout, input, opts.DecryptionIdentityFiles); err != nil {
		return err
	}
	selected := opts.Format
	if selected == "" {
		selected = format.Text
	}
	return format.WriteVerification(stdout, selected, scope)
}
