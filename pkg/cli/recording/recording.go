package recording

import (
	"context"
	goerrors "errors"
	"fmt"
	goos "os"
	"path/filepath"
	"sort"
	"strings"

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

type listOptions struct {
	common.ExecutableConfigurationOpts
	format.Opts
	selectedAuditlog
}

type showOptions struct {
	listOptions
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
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.Recordings == nil {
		return fmt.Errorf("management recording repository is unavailable")
	}
	rows, err := access.Recordings.List(ctx, opts.Auditlog)
	if err != nil {
		return err
	}
	sortRecordings(rows)
	return format.WriteRecordingList(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, opts.Format), rows)
}

func handleList(ctx context.Context, opts listOptions) error {
	conf, err := common.ResolveConfiguration(ctx, opts)
	if err != nil {
		return err
	}
	rows, err := inspectLocalRecordings(ctx, conf, opts.Auditlog)
	if err != nil {
		return err
	}
	sortRecordings(rows)
	return format.WriteRecordingList(cli.StdoutOfContext(ctx), opts.Format, rows)
}

func remoteHandleList(ctx context.Context, opts listOptions) error {
	if opts.Configuration != nil {
		return fmt.Errorf("--configuration cannot be combined with a remote target")
	}
	target, err := common.RemoteTargetFromContext(ctx)
	if err != nil {
		return err
	}
	return target.Run(ctx, "recording", "ls", opts.Auditlog.String(), "--format="+string(opts.Format))
}

func sortRecordings(rows []RecordingView) {
	sort.Slice(rows, func(i, j int) bool { return rows[i].StartedAt.Before(rows[j].StartedAt) })
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

func inspectLocalRecordings(ctx context.Context, conf *configuration.Configuration, name configuration.AuditlogName) ([]RecordingView, error) {
	for _, configured := range conf.Auditlogs {
		if configured.Name != name {
			continue
		}
		if !configured.Recording.Enabled {
			return nil, fmt.Errorf("recording of auditlog %q is disabled", name)
		}
		key, err := claudit.LoadAuditPrivateKey(configured.IdentityFile)
		if err != nil {
			return nil, err
		}
		identity, err := audit.NewIdentity(key)
		if err != nil {
			return nil, err
		}
		root := filepath.Join(configured.Recording.Directory, "sealed")
		files, err := goos.ReadDir(root)
		if goerrors.Is(err, goos.ErrNotExist) {
			return []RecordingView{}, nil
		}
		if err != nil {
			return nil, err
		}
		result := make([]RecordingView, 0, len(files))
		for _, entry := range files {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			filename := entry.Name()
			idText := strings.TrimSuffix(strings.TrimSuffix(filename, ".bcast"), ".becast")
			var id recording.Id
			if idText == filename || id.UnmarshalText([]byte(idText)) != nil || !entry.Type().IsRegular() {
				return nil, fmt.Errorf("unexpected sealed recording entry %q", filename)
			}
			path := filepath.Join(root, filename)
			file, initial, err := OpenRecordingInput(path)
			if err != nil {
				return nil, err
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
				return nil, err
			}
			result = append(result, view)
		}
		return result, nil
	}
	return nil, fmt.Errorf("auditlog %q does not exist", name)
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
