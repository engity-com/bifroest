package recording

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/engity-com/bifroest/pkg/audit"
	caudit "github.com/engity-com/bifroest/pkg/cli/audit"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/recording"
)

type recordingContentOptions struct {
	common.WithSensitiveOpts
	common.DecryptionIdentityFilesOpts
	common.ExecutableConfigurationOpts
	File               string `argument:"fileOrAuditlog" description:"Configured auditlog name or copied Recording file path."`
	RecordingID        string `argument:"recordingId" description:"Recording UUID when selecting an auditlog."`
	ExpectedProducerID string `flag:"expectedProducerId" description:"Independently trusted producer ID."`
	AllowUntrusted     bool   `flag:"allowUntrusted" description:"Explicitly accept a self-signed Recording."`

	// Set by the remote handler, independently of the local source selector.
	expectedRecordingID recording.Id
}

type verifiedRecordingContent struct {
	writeTo        func(io.Writer) error
	validateOutput func(string, io.Writer) error
}

// withRecordingContent keeps the input and verified snapshot open until the
// consumer finishes. The consumer validates its final destination before writing.
func withRecordingContent(ctx context.Context, opts recordingContentOptions, consume func(verifiedRecordingContent) error) (resultErr error) {
	if !opts.WithSensitive {
		return fmt.Errorf("recording content requires --with-sensitive")
	}
	file, auditlogName, localConfiguration, err := resolveRecordingSelection(ctx, opts.File, opts.RecordingID, opts.ExpectedProducerID, opts)
	if err != nil {
		return err
	}
	var expectedProducerId audit.ProducerId
	if !auditlogName.IsZero() {
		if opts.AllowUntrusted {
			return fmt.Errorf("local Recording selection cannot be combined with --allowUntrusted")
		}
		expectedProducerId, err = configuredRecordingProducerId(auditlogName, localConfiguration, file)
	} else {
		expectedProducerId, err = recordingExportTrust(opts.ExpectedProducerID, opts.AllowUntrusted)
	}
	if err != nil {
		return err
	}
	input, initial, err := OpenRecordingInput(file)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, input.Close()) }()
	snapshot, err := snapshotRecordingInput(input, initial.Size())
	if err != nil {
		return fmt.Errorf("cannot snapshot Recording %q: %w", file, err)
	}
	defer func() { resultErr = errors.Join(resultErr, snapshot.Close()) }()
	if err := ValidateRecordingInput(file, input, initial); err != nil {
		return err
	}
	inspectOptions := recording.InspectOptions{
		Context: ctx, ExpectedProducerId: expectedProducerId, AllowUntrusted: opts.AllowUntrusted,
	}
	inspection, err := recording.Inspect(snapshot, initial.Size(), inspectOptions)
	if err != nil {
		return fmt.Errorf("cannot verify Recording %q before reading content: %w", file, err)
	}
	if err := validateExpectedRecordingID(inspection, opts.expectedRecordingID); err != nil {
		return err
	}
	if !auditlogName.IsZero() {
		if err := validateConfiguredSealedRecording(file, inspection); err != nil {
			return err
		}
	}
	if inspection.Format == recording.FormatBECastCBOR {
		identities, err := loadRecordingDecryptionIdentities(opts.DecryptionIdentityFiles)
		if err != nil {
			return err
		}
		if _, err := recording.VerifyNativeRecordingFull(snapshot, initial.Size(), identities, recording.NativeRecordingVerifyOptions{
			Context: ctx, ExpectedProducerId: expectedProducerId, AllowUntrusted: opts.AllowUntrusted,
		}); err != nil {
			return fmt.Errorf("cannot fully verify encrypted Recording before reading content: %w", err)
		}
	}
	return consume(verifiedRecordingContent{
		writeTo: func(output io.Writer) error {
			return exportRecordingPayload(snapshot, initial.Size(), output, inspection, inspectOptions, opts.DecryptionIdentityFiles)
		},
		validateOutput: func(path string, output io.Writer) error {
			if err := ValidateRecordingInput(file, input, initial); err != nil {
				return err
			}
			if !auditlogName.IsZero() {
				if err := caudit.EnsureAuditDestinationSafe(path, output, localConfiguration.Filename, localConfiguration, opts.DecryptionIdentityFiles); err != nil {
					return err
				}
			}
			if path == "-" {
				return EnsureRecordingStandardOutputSafe(output, input, opts.DecryptionIdentityFiles)
			}
			if err := caudit.EnsureAuditOutputDoesNotReplaceFile(path, file, "Recording input"); err != nil {
				return err
			}
			return common.EnsureBootstrapOutputIsNotPrivateKey(path, opts.DecryptionIdentityFiles...)
		},
	})
}
