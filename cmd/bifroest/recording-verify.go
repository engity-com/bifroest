package main

import (
	"context"
	goerrors "errors"
	"fmt"
	"io"
	goos "os"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/recording"
)

type recordingVerifyOpts struct {
	file                    string
	recordingId             string
	auditlog                configuration.AuditlogName
	configuration           string
	expectedProducerId      string
	decryptionIdentityFiles []string
	requireFull             bool
}

func registerRecordingVerifyCmd(parent *kingpin.CmdClause) {
	opts := recordingVerifyOpts{}
	cmd := parent.Command("verify", "Verify a Recording against a trusted producer without exporting it.").
		Action(func(*kingpin.ParseContext) error { return doRecordingVerify(&opts, goos.Stdout) })
	cmd.Flag("configuration", "Configuration for a local Recording (defaults to "+defaultConfigurationRef+").").Short('c').PlaceHolder("<path>").StringVar(&opts.configuration)
	cmd.Flag("expectedProducerId", "Independently trusted 64-hex producer ID for an offline artifact.").PlaceHolder("<producer-id>").StringVar(&opts.expectedProducerId)
	cmd.Flag("decryptionIdentityFile", "Private SSH key for full verification of .becast; repeat for multiple keys.").PlaceHolder("<path>").StringsVar(&opts.decryptionIdentityFiles)
	cmd.Flag("require-full", "Fail if encrypted content cannot be fully verified.").BoolVar(&opts.requireFull)
	cmd.Arg("fileOrAuditlog", "Configured auditlog name or copied Recording file path.").StringVar(&opts.file)
	cmd.Arg("recordingId", "Recording UUID when selecting a local auditlog.").StringVar(&opts.recordingId)
}

func doRecordingVerify(opts *recordingVerifyOpts, stdout io.Writer) (rErr error) {
	if opts == nil || stdout == nil {
		return fmt.Errorf("nil Recording verification options or output")
	}
	filePath, auditlogName, err := resolveRecordingSelection(opts.file, opts.recordingId, opts.auditlog, opts.configuration, opts.expectedProducerId)
	if err != nil {
		return err
	}
	if opts.configuration != "" && auditlogName.IsZero() {
		return fmt.Errorf("--configuration requires a local auditlog name and Recording ID")
	}
	var expected audit.ProducerId
	var localConfiguration configuration.Ref
	if !auditlogName.IsZero() {
		if opts.expectedProducerId != "" {
			return fmt.Errorf("local Recording selection cannot be combined with --expectedProducerId")
		}
		expected, err = configuredRecordingProducerId(auditlogName, opts.configuration, filePath, &localConfiguration)
	} else {
		expected, err = recordingExportTrust(opts.expectedProducerId, false)
	}
	if err != nil {
		return err
	}
	input, initial, err := openRecordingInput(filePath)
	if err != nil {
		return err
	}
	defer func() { rErr = goerrors.Join(rErr, input.Close()) }()
	snapshot, err := snapshotRecordingInput(input, initial.Size())
	if err != nil {
		return fmt.Errorf("cannot snapshot Recording %q: %w", filePath, err)
	}
	defer func() { rErr = goerrors.Join(rErr, snapshot.Close()) }()
	if err := validateRecordingInput(filePath, input, initial); err != nil {
		return err
	}
	inspection, err := recording.Inspect(snapshot, initial.Size(), recording.InspectOptions{Context: context.Background(), ExpectedProducerId: expected})
	if err != nil {
		return fmt.Errorf("cannot verify Recording %q: %w", filePath, err)
	}
	if !auditlogName.IsZero() {
		if err := validateConfiguredSealedRecording(filePath, inspection); err != nil {
			return err
		}
	}
	scope := "full"
	if inspection.Format == recording.FormatBECastCBOR {
		scope = "outer"
		if len(opts.decryptionIdentityFiles) != 0 {
			identities, err := loadRecordingDecryptionIdentities(opts.decryptionIdentityFiles)
			if err != nil {
				return err
			}
			if _, err := recording.VerifyNativeRecordingFull(snapshot, initial.Size(), identities, recording.NativeRecordingVerifyOptions{Context: context.Background(), ExpectedProducerId: expected}); err != nil {
				return fmt.Errorf("cannot fully verify encrypted Recording: %w", err)
			}
			scope = "full"
		}
	}
	if opts.requireFull && scope != "full" {
		return fmt.Errorf("full verification of encrypted Recording requires --decryptionIdentityFile")
	}
	if err := validateRecordingInput(filePath, input, initial); err != nil {
		return err
	}
	if !auditlogName.IsZero() {
		if err := ensureAuditDestinationSafe("-", stdout, localConfiguration.GetFilename(), localConfiguration.Get(), opts.decryptionIdentityFiles); err != nil {
			return err
		}
	}
	if err := ensureRecordingStandardOutputSafe(stdout, input, opts.decryptionIdentityFiles); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "verified (scope: %s)\n", scope)
	return err
}
