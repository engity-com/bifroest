package recording

import (
	"context"
	goerrors "errors"
	"fmt"
	goos "os"
	"path/filepath"
	"strings"

	cli "github.com/echocat/cli4g"

	"github.com/engity-com/bifroest/pkg/audit"
	claudit "github.com/engity-com/bifroest/pkg/cli/audit"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/managementclient"
	"github.com/engity-com/bifroest/pkg/recording"
)

type selectedAuditlog struct {
	Auditlog configuration.AuditlogName `argument:"auditlog" required:"true" description:"Configured auditlog name."`
}

type recordingIDOptions struct {
	ID recording.Id `argument:"id" required:"true" description:"Recording UUID."`
}

type listOptions struct {
	configuration.EmptyStrOpts
	format.Opts
	selectedAuditlog
}

type showOptions struct {
	listOptions
	ID recording.Id `argument:"id" required:"true" description:"Recording UUID."`
}

type managementListOptions struct {
	format.Opts
	selectedAuditlog
}

type managementShowOptions struct {
	managementListOptions
	recordingIDOptions
}

func Register(_ context.Context, parent cli.ContainerRequirementSetters, usage common.Usage) {
	cmd := cli.NewSimpleCommand().
		WithName("recording").
		WithDescription("Inspect sealed session recordings.")
	if usage == common.UsageExecutable {
		registerRecordingInspectCmd(cmd)
		registerRecordingVerifyCmd(cmd)
		registerRecordingExportCmd(cmd)
		registerRecordingPlayCmd(cmd)
	}
	if usage == common.UsageManagement {
		registerManagementVerify(cmd)
		registerManagementExport(cmd)
		registerManagementPlay(cmd)
		cmd.AddCommand(
			cli.NewCommand[managementListOptions]().
				WithName("ls").
				WithDescription("List sealed Recordings in one auditlog.").
				WithHandler(handleManagementList),
		)
		cmd.AddCommand(
			cli.NewCommand[managementShowOptions]().
				WithName("show").
				WithDescription("Show verified metadata of a sealed Recording.").
				WithHandler(handleManagementShow),
		)
	} else {
		cmd.AddCommand(
			cli.NewCommand[listOptions]().
				WithName("ls").
				WithDescription("List sealed Recordings in one auditlog.").
				WithHandler(handleList),
		)
		cmd.AddCommand(
			cli.NewCommand[showOptions]().
				WithName("show").
				WithDescription("Show verified metadata of a sealed Recording.").
				WithHandler(handleShow),
		)
	}
	parent.AddCommand(cmd)
}

func handleManagementList(ctx context.Context, opts managementListOptions) error {
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.RecordingList == nil {
		return fmt.Errorf("management recording repository is unavailable")
	}
	rows, err := access.RecordingList(ctx, opts.Auditlog)
	if err != nil {
		return err
	}
	return format.WriteRecordingList(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, opts.Format), rows)
}

func handleManagementShow(ctx context.Context, opts managementShowOptions) error {
	access, ok := common.ManagementAccessFromContext(ctx)
	if !ok || access.RecordingDetail == nil {
		return fmt.Errorf("management recording repository is unavailable")
	}
	row, err := access.RecordingDetail(ctx, opts.Auditlog, opts.ID)
	if err != nil {
		return err
	}
	return format.WriteRecordingDetail(cli.StdoutOfContext(ctx), common.FormatForInvocation(ctx, opts.Format), row)
}

func handleList(ctx context.Context, opts listOptions) error {
	if target, remote := common.RemoteTargetFromContext(ctx); remote {
		if opts.Configuration != "" {
			return fmt.Errorf("--configuration cannot be combined with a remote target")
		}
		return managementclient.Run(ctx, target, []string{
			"recording", "ls", opts.Auditlog.String(), "--format=" + string(opts.Format),
		}, cli.StdoutOfContext(ctx))
	}
	rows, err := inspectLocalRecordings(ctx, opts.Configuration, opts.Auditlog)
	if err != nil {
		return err
	}
	return format.WriteRecordingList(cli.StdoutOfContext(ctx), opts.Format, rows)
}

func handleShow(ctx context.Context, opts showOptions) error {
	if target, remote := common.RemoteTargetFromContext(ctx); remote {
		if opts.Configuration != "" {
			return fmt.Errorf("--configuration cannot be combined with a remote target")
		}
		return managementclient.Run(ctx, target, []string{
			"recording", "show", opts.Auditlog.String(), opts.ID.String(), "--format=" + string(opts.Format),
		}, cli.StdoutOfContext(ctx))
	}
	row, err := inspectLocalRecording(ctx, opts.Configuration, opts.Auditlog, opts.ID)
	if err != nil {
		return err
	}
	return format.WriteRecordingDetail(cli.StdoutOfContext(ctx), opts.Format, row)
}

func inspectLocalRecordings(ctx context.Context, configPath string, name configuration.AuditlogName) ([]RecordingView, error) {
	conf, err := common.LoadManagementConfiguration(configPath)
	if err != nil {
		return nil, err
	}
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

func inspectLocalRecording(ctx context.Context, configPath string, name configuration.AuditlogName, id recording.Id) (result RecordingView, resultErr error) {
	path, _, err := ResolveRecordingSelection(name.String(), id.String(), "", configPath, "")
	if err != nil {
		return result, err
	}
	var ref configuration.Ref
	expected, err := configuredRecordingProducerId(name, configPath, path, &ref)
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
