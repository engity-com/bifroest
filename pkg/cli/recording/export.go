package recording

import (
	"context"
	goerrors "errors"
	"fmt"
	"io"
	stdos "os"
	"path/filepath"
	"reflect"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/audit"
	caudit "github.com/engity-com/bifroest/pkg/cli/audit"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/recording"
)

type exportCommandOptions struct {
	common.WithSensitiveOpts
	common.DecryptionIdentityFilesOpts
	common.ExecutableConfigurationOpts
	File               string `argument:"fileOrAuditlog" description:"Configured auditlog name or copied Recording file path."`
	RecordingID        string `argument:"recordingId" description:"Recording UUID when selecting an auditlog."`
	Output             string `flag:"output" default:"-" description:"Export destination, or - for stdout."`
	Force              bool   `flag:"force" description:"Replace an existing output."`
	ExpectedProducerID string `flag:"expectedProducerId" description:"Independently trusted producer ID."`
	AllowUntrusted     bool   `flag:"allowUntrusted" description:"Explicitly accept a self-signed Recording."`
}

type managementExportOptions struct {
	selectedAuditlog
	recordingIDOptions
	common.WithSensitiveOpts
}

func createExportCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[managementExportOptions]("export", "Verify and export a session Recording as asciicast v3.").
			WithProfiles(common.ProfileManagement).
			WithHandler(handleManagementExport),
		cli.NewCommand[exportCommandOptions]("export", "Verify and export a session Recording as asciicast v3.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(func(ctx context.Context, o exportCommandOptions) error {
				return doRecordingExport(ctx, o, cli.StdoutOfContext(ctx))
			}),
		cli.NewCommand[exportCommandOptions]("export", "Verify and export a session Recording as asciicast v3.").
			WithProfiles(common.ProfileRemote).
			WithHandler(remoteHandleExport),
	}
}

func handleManagementExport(ctx context.Context, opts managementExportOptions) error {
	if !opts.WithSensitive {
		return fmt.Errorf("recording export requires --with-sensitive")
	}
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.Recording == nil {
		return fmt.Errorf("management recording repository is unavailable")
	}
	return access.Recording.Export(ctx, opts.Auditlog, opts.ID, cli.StdoutOfContext(ctx))
}

func doRecordingExport(ctx context.Context, opts exportCommandOptions, stdout io.Writer) (rErr error) {
	if !opts.WithSensitive {
		return fmt.Errorf("recording export requires --with-sensitive")
	}
	if stdout == nil {
		return fmt.Errorf("nil stdout")
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
	defer func() { rErr = goerrors.Join(rErr, input.Close()) }()
	snapshot, err := snapshotRecordingInput(input, initial.Size())
	if err != nil {
		return fmt.Errorf("cannot snapshot Recording %q: %w", file, err)
	}
	defer func() { rErr = goerrors.Join(rErr, snapshot.Close()) }()
	if err := ValidateRecordingInput(file, input, initial); err != nil {
		return err
	}
	inspectOptions := recording.InspectOptions{
		Context:            ctx,
		ExpectedProducerId: expectedProducerId,
		AllowUntrusted:     opts.AllowUntrusted,
	}
	inspection, err := recording.Inspect(snapshot, initial.Size(), inspectOptions)
	if err != nil {
		return fmt.Errorf("cannot verify Recording %q before export: %w", file, err)
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
			Context: inspectOptions.Context, ExpectedProducerId: inspectOptions.ExpectedProducerId,
			AllowUntrusted: inspectOptions.AllowUntrusted,
		}); err != nil {
			return fmt.Errorf("cannot fully verify encrypted Recording before export: %w", err)
		}
	}
	requestedOutput := opts.Output
	if requestedOutput == "" {
		requestedOutput = "-"
	}
	output, err := caudit.CanonicalAuditOutput(requestedOutput)
	if err != nil {
		return err
	}
	validate := func() error {
		if err := ValidateRecordingInput(file, input, initial); err != nil {
			return err
		}
		if !auditlogName.IsZero() {
			if err := caudit.EnsureAuditDestinationSafe(output, stdout, localConfiguration.Filename, localConfiguration, opts.DecryptionIdentityFiles); err != nil {
				return err
			}
		}
		if output == "-" {
			return EnsureRecordingStandardOutputSafe(stdout, input, opts.DecryptionIdentityFiles)
		}
		if err := caudit.EnsureAuditOutputDoesNotReplaceFile(output, file, "Recording input"); err != nil {
			return err
		}
		return common.EnsureBootstrapOutputIsNotPrivateKey(output, opts.DecryptionIdentityFiles...)
	}
	if err := validate(); err != nil {
		return err
	}
	produce := func(target io.Writer) error {
		return exportRecordingPayload(snapshot, initial.Size(), target, inspection, inspectOptions, opts.DecryptionIdentityFiles)
	}
	if output != "-" {
		if err := caudit.WriteProtectedOutputFile(output, opts.Force, validate, func(target *stdos.File) error {
			return produce(target)
		}); err != nil {
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

func validateConfiguredSealedRecording(path string, inspection *recording.Inspection) error {
	if inspection == nil || inspection.Native == nil {
		return fmt.Errorf("local auditlog requires a native sealed Recording artifact")
	}
	suffix := ".bcast"
	if inspection.Format == recording.FormatBECastCBOR {
		suffix = ".becast"
	}
	if filepath.Base(path) != recording.Id(inspection.Native.Header.RecordingId).String()+suffix {
		return fmt.Errorf("local auditlog requires the canonical sealed Recording file name")
	}
	return nil
}

func resolveRecordingSelection(ctx context.Context, source, recordingId, expectedProducerId string, options common.ConfigurationOptions) (string, configuration.AuditlogName, *configuration.Configuration, error) {
	if recordingId == "" {
		if source == "" {
			return "", "", nil, fmt.Errorf("recording input file or local auditlog and recording ID is required")
		}
		if options.GetConfiguration() != nil {
			return "", "", nil, fmt.Errorf("--configuration requires a local auditlog name and Recording ID")
		}
		return source, "", nil, nil
	}
	if expectedProducerId != "" {
		return "", "", nil, fmt.Errorf("local Recording ID cannot be combined with --expectedProducerId")
	}
	name := configuration.AuditlogName(source)
	if err := name.Validate(); err != nil {
		return "", "", nil, err
	}
	var id recording.Id
	if err := id.UnmarshalText([]byte(recordingId)); err != nil {
		return "", "", nil, err
	}
	conf, err := common.ResolveConfiguration(ctx, options)
	if err != nil {
		return "", "", nil, err
	}
	selected, err := findSealedRecording(conf, name, id)
	return selected, name, conf, err
}

func findSealedRecording(conf *configuration.Configuration, name configuration.AuditlogName, id recording.Id) (string, error) {
	configured, err := caudit.FindConfigured(conf, name)
	if err != nil {
		return "", err
	}
	if !configured.Recording.Enabled {
		return "", fmt.Errorf("recording for auditlog %q is not enabled", name)
	}
	sealed := filepath.Join(configured.Recording.Directory, "sealed")
	var selected string
	for _, suffix := range []string{".bcast", ".becast"} {
		candidate := filepath.Join(sealed, id.String()+suffix)
		if _, err := stdos.Lstat(candidate); err == nil {
			if selected != "" {
				return "", fmt.Errorf("recording %q has both clear and encrypted sealed artifacts", id)
			}
			selected = candidate
		} else if !goerrors.Is(err, stdos.ErrNotExist) {
			return "", fmt.Errorf("cannot inspect Recording %q: %w", candidate, err)
		}
	}
	if selected == "" {
		return "", fmt.Errorf("sealed Recording %q does not exist in auditlog %q", id, name)
	}
	return selected, nil
}

func EnsureRecordingStandardOutputSafe(stdout io.Writer, input *stdos.File, identityFiles []string) error {
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

func configuredRecordingProducerId(name configuration.AuditlogName, conf *configuration.Configuration, filePath string) (audit.ProducerId, error) {
	configured, err := caudit.FindConfigured(conf, name)
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
		return audit.ProducerId{}, fmt.Errorf("local Recording selection requires a file in the configured Recording sealed directory")
	}
	privateKey, err := caudit.LoadAuditPrivateKey(configured.IdentityFile)
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
		key, err := caudit.LoadAuditPrivateKey(path)
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
