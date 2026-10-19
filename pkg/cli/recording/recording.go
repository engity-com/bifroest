package recording

import (
	"context"
	goerrors "errors"
	"fmt"
	goos "os"
	"path/filepath"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/audit"
	claudit "github.com/engity-com/bifroest/pkg/cli/audit"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/recording"
)

type selectedAuditlog struct {
	Auditlog configuration.AuditlogName `argument:"auditlog" required:"true" description:"Configured auditlog name."`
}

type recordingIDOptions struct {
	ID recording.Id `argument:"id" required:"true" description:"Recording UUID."`
}

type browseOptions struct {
	common.ExecutableConfigurationOpts
	format.Opts
	selectedAuditlog
}

type listOptions struct {
	browseOptions
	Limit uint         `flag:"limit" default:"100" description:"Recordings per page (1-1000), ordered by Recording ID."`
	After recording.Id `flag:"after" description:"Continue after this Recording ID; use the last ID of the previous page."`
}

type showOptions struct {
	browseOptions
	recordingIDOptions
}

func CreateCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewSimpleCommand("recording", "Inspect sealed session recordings.").
			WithProfiles(common.ProfileExecutable, common.ProfileRemote, common.ProfileManagement).
			WithCommand(createInspectCommands()...).
			WithCommand(createVerifyCommands()...).
			WithCommand(createExportCommands()...).
			WithCommand(createPlayCommands()...).
			WithCommand(createBrowseCommands()...),
	}
}

func createBrowseCommands() []cli.CommandRequirementLike {
	return []cli.CommandRequirementLike{
		cli.NewCommand[listOptions]("ls", "List sealed Recordings in one auditlog.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(handleList),
		cli.NewCommand[listOptions]("ls", "List sealed Recordings in one auditlog.").
			WithProfiles(common.ProfileRemote).
			WithHandler(remoteHandleList),
		cli.NewCommand[listOptions]("ls", "List sealed Recordings in one auditlog.").
			WithProfiles(common.ProfileManagement).
			WithHandler(handleManagementList),

		cli.NewCommand[showOptions]("show", "Show verified metadata of a sealed Recording.").
			WithProfiles(common.ProfileExecutable).
			WithHandler(handleShow),
		cli.NewCommand[showOptions]("show", "Show verified metadata of a sealed Recording.").
			WithProfiles(common.ProfileRemote).
			WithHandler(remoteHandleShow),
		cli.NewCommand[showOptions]("show", "Show verified metadata of a sealed Recording.").
			WithProfiles(common.ProfileManagement).
			WithHandler(handleManagementShow),
	}
}

func handleManagementList(ctx context.Context, opts listOptions) error {
	page := recording.SealedPageOptions{After: opts.After, Limit: opts.Limit}
	if err := page.Validate(); err != nil {
		return err
	}
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.Recordings == nil {
		return fmt.Errorf("management recording repository is unavailable")
	}
	if access.WireFormat && !access.WireStream {
		return fmt.Errorf("recording ls requires the streaming SSH transport")
	}
	selected := common.FormatForInvocation(ctx, opts.Format)
	if access.WireStream {
		selected = format.WireCborStream
	}
	return writeRecordingPage(ctx, opts, selected, func(consume func(RecordingView) error) error {
		return access.Recordings.Visit(ctx, opts.Auditlog, page, consume)
	})
}

func handleList(ctx context.Context, opts listOptions) error {
	page := recording.SealedPageOptions{After: opts.After, Limit: opts.Limit}
	if err := page.Validate(); err != nil {
		return err
	}
	conf, err := common.ResolveConfiguration(ctx, opts)
	if err != nil {
		return err
	}
	if err := common.EnsureStandardOutputSafe(ctx, cli.StdoutOfContext(ctx), conf.Filename, conf, nil); err != nil {
		return err
	}
	return writeRecordingPage(ctx, opts, opts.Format, func(consume func(RecordingView) error) error {
		return visitLocalRecordings(ctx, conf, opts.Auditlog, page, consume)
	})
}

func remoteHandleList(ctx context.Context, opts listOptions) error {
	if opts.Configuration != nil {
		return fmt.Errorf("--configuration cannot be combined with a remote target")
	}
	if err := (recording.SealedPageOptions{After: opts.After, Limit: opts.Limit}).Validate(); err != nil {
		return err
	}
	target, err := common.RemoteTargetFromContext(ctx)
	if err != nil {
		return err
	}
	args := []string{"recording", "ls", opts.Auditlog.String(), "--format=" + string(opts.Format), fmt.Sprintf("--limit=%d", opts.Limit)}
	if !opts.After.IsZero() {
		args = append(args, "--after="+opts.After.String())
	}
	return target.Run(ctx, args...)
}

func writeRecordingPage(ctx context.Context, opts listOptions, selected format.Format, visit func(func(RecordingView) error) error) error {
	stream, err := format.NewRecordingListStream(cli.StdoutOfContext(ctx), selected)
	if err != nil {
		return err
	}
	var count uint
	var previous string
	if err := visit(func(entry RecordingView) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if count >= opts.Limit || previous != "" && entry.ID <= previous {
			return fmt.Errorf("recording stream violates its page limit or ID order")
		}
		if err := stream.Write(entry); err != nil {
			return err
		}
		count++
		previous = entry.ID
		return nil
	}); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return stream.Close()
}

func handleManagementShow(ctx context.Context, opts showOptions) error {
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.Recordings == nil {
		return fmt.Errorf("management recording repository is unavailable")
	}
	row, err := access.Recordings.Detail(ctx, opts.Auditlog, opts.ID)
	if err != nil {
		return err
	}
	return format.WriteRecordingDetail(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, opts.Format), row)
}

func handleShow(ctx context.Context, opts showOptions) error {
	conf, err := common.ResolveConfiguration(ctx, opts)
	if err != nil {
		return err
	}
	if err := common.EnsureStandardOutputSafe(ctx, cli.StdoutOfContext(ctx), conf.Filename, conf, nil); err != nil {
		return err
	}
	row, err := inspectLocalRecording(ctx, conf, opts.Auditlog, opts.ID)
	if err != nil {
		return err
	}
	return format.WriteRecordingDetail(cli.StdoutOfContext(ctx), opts.Format, row)
}

func remoteHandleShow(ctx context.Context, opts showOptions) error {
	if opts.Configuration != nil {
		return fmt.Errorf("--configuration cannot be combined with a remote target")
	}
	target, err := common.RemoteTargetFromContext(ctx)
	if err != nil {
		return err
	}
	return target.Run(ctx, "recording", "show", opts.Auditlog.String(), opts.ID.String(), "--format="+string(opts.Format))
}

func visitLocalRecordings(ctx context.Context, conf *configuration.Configuration, name configuration.AuditlogName, page recording.SealedPageOptions, consume func(RecordingView) error) error {
	if err := page.Validate(); err != nil {
		return err
	}
	for _, configured := range conf.Auditlogs {
		if configured.Name != name {
			continue
		}
		if !configured.Recording.Enabled {
			return fmt.Errorf("recording of auditlog %q is disabled", name)
		}
		key, err := claudit.LoadAuditPrivateKey(configured.IdentityFile)
		if err != nil {
			return err
		}
		identity, err := audit.NewIdentity(key)
		if err != nil {
			return err
		}
		root := filepath.Join(configured.Recording.Directory, "sealed")
		files, err := recording.ReadSealedRecordingPage(ctx, root, page)
		if goerrors.Is(err, goos.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, entry := range files {
			if err := ctx.Err(); err != nil {
				return err
			}
			filename := entry.Name
			path := filepath.Join(root, filename)
			file, initial, err := OpenRecordingInput(path)
			if err != nil {
				return err
			}
			view, err := InspectRecording(ctx, name, file, initial.Size(), identity.ProducerId())
			if err == nil {
				suffix := ".bcast"
				if view.Encrypted {
					suffix = ".becast"
				}
				if view.ID+suffix != filename {
					err = fmt.Errorf("recording %q does not match its signed ID or format", filename)
				}
			}
			if err == nil {
				err = ValidateRecordingInput(path, file, initial)
			}
			err = goerrors.Join(err, file.Close())
			if err != nil {
				return err
			}
			if err := consume(view); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("auditlog %q does not exist", name)
}

func inspectLocalRecording(ctx context.Context, conf *configuration.Configuration, name configuration.AuditlogName, id recording.Id) (result RecordingView, resultErr error) {
	path, err := findSealedRecording(conf, name, id)
	if err != nil {
		return result, err
	}
	expected, err := configuredRecordingProducerId(name, conf, path)
	if err != nil {
		return result, err
	}
	file, initial, err := OpenRecordingInput(path)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = goerrors.Join(resultErr, file.Close()) }()
	result, err = InspectRecording(ctx, name, file, initial.Size(), expected)
	if err != nil {
		return result, err
	}
	suffix := ".bcast"
	if result.Encrypted {
		suffix = ".becast"
	}
	if filepath.Base(path) != result.ID+suffix || result.ID != id.String() {
		return result, fmt.Errorf("recording %q does not match its signed ID or format", path)
	}
	if err := ValidateRecordingInput(path, file, initial); err != nil {
		return result, err
	}
	return result, nil
}
