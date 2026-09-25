package main

import (
	"context"
	goerrors "errors"
	"fmt"
	"io"
	stdos "os"
	"path/filepath"
	"reflect"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/recording"
)

type recordingExportOpts struct {
	file                    string
	output                  string
	force                   bool
	withSensitive           bool
	auditlog                configuration.AuditlogName
	configuration           string
	expectedProducerId      string
	allowUntrusted          bool
	decryptionIdentityFiles []string
}

func registerRecordingExportCmd(parent *kingpin.CmdClause) {
	opts := recordingExportOpts{output: "-"}
	cmd := parent.Command("export", "Verify and export a session Recording as asciicast v3.").
		Action(func(*kingpin.ParseContext) error { return doRecordingExport(&opts, stdos.Stdout) })
	registerAuditOutputFlags(cmd, &opts.output, &opts.force)
	cmd.Flag("with-sensitive", "Explicitly authorize exporting sensitive Recording content.").
		BoolVar(&opts.withSensitive)
	cmd.Flag("auditlog", "Trust the signing identity of a configured local Recording repository.").
		PlaceHolder("<auditlogName>").
		SetValue(&opts.auditlog)
	cmd.Flag("configuration", "Configuration for --auditlog (defaults to "+defaultConfigurationRef+").").
		Short('c').PlaceHolder("<path>").
		StringVar(&opts.configuration)
	cmd.Flag("expectedProducerId", "Trusted producer ID containing exactly 64 hexadecimal characters.").
		PlaceHolder("<producer-id>").
		StringVar(&opts.expectedProducerId)
	cmd.Flag("allowUntrusted", "Export a cryptographically valid self-signed Recording without trusting its producer identity.").
		BoolVar(&opts.allowUntrusted)
	cmd.Flag("decryptionIdentityFile", "Private SSH key for decrypting .becast; repeat for multiple keys.").
		PlaceHolder("<path>").
		StringsVar(&opts.decryptionIdentityFiles)
	cmd.Arg("file", "Sealed .bcast or .becast Recording artifact, or signed standalone .cast.").
		Required().
		StringVar(&opts.file)
}

func doRecordingExport(opts *recordingExportOpts, stdout io.Writer) (rErr error) {
	if opts == nil {
		return fmt.Errorf("nil options")
	}
	if !opts.withSensitive {
		return fmt.Errorf("recording export requires --with-sensitive")
	}
	if stdout == nil {
		return fmt.Errorf("nil stdout")
	}
	if opts.configuration != "" && opts.auditlog.IsZero() {
		return fmt.Errorf("--configuration requires --auditlog for recording export")
	}
	var expectedProducerId audit.ProducerId
	var localConfiguration configuration.Ref
	var err error
	if !opts.auditlog.IsZero() {
		if opts.expectedProducerId != "" || opts.allowUntrusted {
			return fmt.Errorf("--auditlog cannot be combined with --expectedProducerId or --allowUntrusted")
		}
		expectedProducerId, err = configuredRecordingProducerId(opts.auditlog, opts.configuration, opts.file, &localConfiguration)
	} else {
		expectedProducerId, err = recordingExportTrust(opts.expectedProducerId, opts.allowUntrusted)
	}
	if err != nil {
		return err
	}
	input, initial, err := openRecordingInput(opts.file)
	if err != nil {
		return err
	}
	defer func() { rErr = goerrors.Join(rErr, input.Close()) }()
	snapshot, err := snapshotRecordingInput(input, initial.Size())
	if err != nil {
		return fmt.Errorf("cannot snapshot Recording %q: %w", opts.file, err)
	}
	defer func() { rErr = goerrors.Join(rErr, snapshot.Close()) }()
	if err := validateRecordingInput(opts.file, input, initial); err != nil {
		return err
	}
	inspectOptions := recording.InspectOptions{
		Context:            context.Background(),
		ExpectedProducerId: expectedProducerId,
		AllowUntrusted:     opts.allowUntrusted,
	}
	inspection, err := recording.Inspect(snapshot, initial.Size(), inspectOptions)
	if err != nil {
		return fmt.Errorf("cannot verify Recording %q before export: %w", opts.file, err)
	}
	if !opts.auditlog.IsZero() {
		if inspection.Native == nil {
			return fmt.Errorf("--auditlog requires a native sealed Recording artifact")
		}
		suffix := ".bcast"
		if inspection.Format == recording.FormatBECastCBOR {
			suffix = ".becast"
		}
		if filepath.Base(opts.file) != recording.Id(inspection.Native.Header.RecordingId).String()+suffix {
			return fmt.Errorf("--auditlog requires the canonical sealed Recording file name")
		}
	}
	if inspection.Format == recording.FormatBECastCBOR {
		identities, err := loadRecordingDecryptionIdentities(opts.decryptionIdentityFiles)
		if err != nil {
			return err
		}
		if _, err := recording.VerifyNativeRecordingFull(snapshot, initial.Size(), identities, recording.NativeRecordingVerifyOptions{
			Context: inspectOptions.Context, ExpectedProducerId: inspectOptions.ExpectedProducerId,
			AllowUntrusted: inspectOptions.AllowUntrusted,
		}); err != nil {
			return fmt.Errorf("cannot fully verify encrypted Recording before export: %w", err)
		}
	}
	requestedOutput := opts.output
	if requestedOutput == "" {
		requestedOutput = "-"
	}
	output, err := canonicalAuditOutput(requestedOutput)
	if err != nil {
		return err
	}
	validate := func() error {
		if err := validateRecordingInput(opts.file, input, initial); err != nil {
			return err
		}
		if !opts.auditlog.IsZero() {
			if err := ensureAuditDestinationSafe(output, stdout, localConfiguration.GetFilename(), localConfiguration.Get(), opts.decryptionIdentityFiles); err != nil {
				return err
			}
		}
		if output == "-" {
			return ensureRecordingStandardOutputSafe(stdout, input, opts.decryptionIdentityFiles)
		}
		if err := ensureAuditOutputDoesNotReplaceFile(output, opts.file, "Recording input"); err != nil {
			return err
		}
		return ensureBootstrapOutputIsNotPrivateKey(output, opts.decryptionIdentityFiles...)
	}
	if err := validate(); err != nil {
		return err
	}
	produce := func(target io.Writer) error {
		return exportRecordingPayload(snapshot, initial.Size(), target, inspection, inspectOptions, opts.decryptionIdentityFiles)
	}
	if output != "-" {
		if err := writeProtectedOutputFile(output, opts.force, validate, func(target *stdos.File) error { return produce(target) }); err != nil {
			return fmt.Errorf("cannot install Recording export at %q: %w", output, err)
		}
		return nil
	}
	if err := produce(stdout); err != nil {
		return err
	}
	if err := validate(); err != nil {
		return err
	}
	return nil
}

func ensureRecordingStandardOutputSafe(stdout io.Writer, input *stdos.File, identityFiles []string) error {
	output, ok := stdout.(*stdos.File)
	if !ok {
		return nil
	}
	outputInfo, err := output.Stat()
	if err != nil {
		return fmt.Errorf("cannot inspect standard output: %w", err)
	}
	inputInfo, err := input.Stat()
	if err != nil {
		return fmt.Errorf("cannot inspect Recording input: %w", err)
	}
	if stdos.SameFile(outputInfo, inputInfo) {
		return fmt.Errorf("standard output must not replace Recording input")
	}
	for _, path := range identityFiles {
		identityInfo, err := stdos.Stat(path)
		if goerrors.Is(err, stdos.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("cannot inspect Recording decryption identity %q: %w", path, err)
		}
		if stdos.SameFile(outputInfo, identityInfo) {
			return fmt.Errorf("standard output must not replace Recording decryption identity %q", path)
		}
	}
	return nil
}

func validateRecordingSnapshotSize(input io.ReaderAt, size int64) error {
	format, err := recording.DetectFormat(input, size)
	if err != nil {
		return err
	}
	var maximum int64
	switch format {
	case recording.FormatCast:
		maximum = recording.DefaultMaximumCastBytes
	case recording.FormatBcast, recording.FormatBECastCBOR:
		maximum = recording.DefaultMaximumNativeRecordingBytes
	default:
		return fmt.Errorf("unsupported Recording format %q", format)
	}
	if size > maximum {
		return fmt.Errorf("recording input size %d exceeds the %d-byte limit for %s", size, maximum, format)
	}
	return nil
}

func recordingExportTrust(raw string, allowUntrusted bool) (audit.ProducerId, error) {
	if raw == "" {
		if !allowUntrusted {
			return audit.ProducerId{}, fmt.Errorf("--expectedProducerId is required unless --allowUntrusted is explicitly set")
		}
		return audit.ProducerId{}, nil
	}
	if allowUntrusted {
		return audit.ProducerId{}, fmt.Errorf("--expectedProducerId and --allowUntrusted are mutually exclusive")
	}
	var result audit.ProducerId
	if err := result.Set(raw); err != nil {
		return audit.ProducerId{}, fmt.Errorf("illegal --expectedProducerId: %w", err)
	}
	if result.IsZero() {
		return audit.ProducerId{}, fmt.Errorf("--expectedProducerId must not be zero")
	}
	return result, nil
}

func configuredRecordingProducerId(name configuration.AuditlogName, configPath, filePath string, ref *configuration.Ref) (audit.ProducerId, error) {
	if configPath == "" {
		configPath = defaultConfigurationRef
	}
	if err := ref.Set(configPath); err != nil {
		return audit.ProducerId{}, fmt.Errorf("cannot load recording configuration: %w", err)
	}
	configured, err := findConfiguredAuditlog(ref.Get(), name)
	if err != nil {
		return audit.ProducerId{}, err
	}
	if !configured.Recording.Enabled {
		return audit.ProducerId{}, fmt.Errorf("recording for auditlog %q is not enabled", name)
	}
	sealed, err := filepath.Abs(filepath.Join(configured.Recording.Directory, "sealed"))
	if err != nil {
		return audit.ProducerId{}, err
	}
	sealed, err = filepath.EvalSymlinks(sealed)
	if err != nil {
		return audit.ProducerId{}, fmt.Errorf("cannot inspect configured Recording repository: %w", err)
	}
	file, err := filepath.Abs(filePath)
	if err != nil {
		return audit.ProducerId{}, err
	}
	file, err = filepath.EvalSymlinks(file)
	if err != nil {
		return audit.ProducerId{}, err
	}
	if filepath.Dir(file) != sealed {
		return audit.ProducerId{}, fmt.Errorf("--auditlog requires a file in the configured Recording sealed directory")
	}
	privateKey, err := loadAuditPrivateKey(configured.IdentityFile)
	if err != nil {
		return audit.ProducerId{}, fmt.Errorf("cannot load identity of auditlog %q: %w", name, err)
	}
	identity, err := audit.NewIdentity(privateKey)
	if err != nil {
		return audit.ProducerId{}, fmt.Errorf("cannot use identity of auditlog %q: %w", name, err)
	}
	return identity.ProducerId(), nil
}

func exportRecordingPayload(source io.ReaderAt, size int64, output io.Writer, inspection *recording.Inspection, inspectOptions recording.InspectOptions, identityFiles []string) error {
	if source == nil || output == nil || inspection == nil {
		return fmt.Errorf("nil Recording export input")
	}
	switch inspection.Format {
	case recording.FormatBcast, recording.FormatBECastCBOR:
		if inspection.Native == nil {
			return fmt.Errorf("recording inspection has no native result")
		}
		var identities *bfcrypto.AgeSshIdentities
		if inspection.Format == recording.FormatBECastCBOR {
			var err error
			identities, err = loadRecordingDecryptionIdentities(identityFiles)
			if err != nil {
				return err
			}
		}
		verified, err := recording.ExportNativeRecordingCast(source, size, identities, output, recording.NativeRecordingVerifyOptions{
			Context: inspectOptions.Context, MaximumContainerBytes: inspectOptions.MaximumContainerBytes,
			MaximumCastBytes: inspectOptions.MaximumCastBytes, MaximumChunks: inspectOptions.MaximumChunks,
			ExpectedProducerId: inspectOptions.ExpectedProducerId, AllowUntrusted: inspectOptions.AllowUntrusted,
		})
		if err != nil {
			return fmt.Errorf("cannot export native Recording: %w", err)
		}
		if !reflect.DeepEqual(verified, inspection.Native) {
			return fmt.Errorf("recording input changed between inspection and native export")
		}
	case recording.FormatCast:
		if inspection.Cast == nil {
			return fmt.Errorf("recording inspection has no Cast result")
		}
		written, err := io.Copy(output, io.NewSectionReader(source, 0, size))
		if err != nil {
			return fmt.Errorf("cannot copy Cast Recording: %w", err)
		}
		if written != size {
			return fmt.Errorf("recording input changed while exporting Cast")
		}
	default:
		return fmt.Errorf("unsupported Recording format %q", inspection.Format)
	}
	return nil
}

func loadRecordingDecryptionIdentities(paths []string) (*bfcrypto.AgeSshIdentities, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("encrypted Recording export requires at least one --decryptionIdentityFile")
	}
	keys := make([]bfcrypto.PrivateKey, 0, len(paths))
	for _, path := range paths {
		key, err := loadAuditPrivateKey(path)
		if err != nil {
			return nil, fmt.Errorf("cannot load Recording decryption identity %q: %w", path, err)
		}
		keys = append(keys, key)
	}
	identities, err := bfcrypto.NewAgeSshIdentities(keys)
	if err != nil {
		return nil, fmt.Errorf("cannot use Recording decryption identities: %w", err)
	}
	return identities, nil
}
