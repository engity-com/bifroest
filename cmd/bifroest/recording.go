package main

import (
	"context"
	goerrors "errors"
	"fmt"
	goos "os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/kingpin/v2"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management"
	"github.com/engity-com/bifroest/pkg/recording"
)

var _ = registerCommand(func(app *kingpin.Application) {
	cmd := app.Command("recording", "Verify, inspect and export session Recording artifacts.")
	registerRecordingInspectCmd(cmd)
	registerRecordingVerifyCmd(cmd)
	registerRecordingExportCmd(cmd)
	registerRecordingPlayCmd(cmd)
	management.RegisterRecordingCommands(cmd, inspectLocalRecordings, inspectLocalRecording, context.Background(), goos.Stdout, true)
})

func inspectLocalRecordings(ctx context.Context, configPath string, name configuration.AuditlogName) ([]management.RecordingView, error) {
	conf, err := loadManagementConfiguration(configPath)
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
		key, err := loadAuditPrivateKey(configured.IdentityFile)
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
			return []management.RecordingView{}, nil
		}
		if err != nil {
			return nil, err
		}
		result := make([]management.RecordingView, 0, len(files))
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
			file, initial, err := openRecordingInput(path)
			if err != nil {
				return nil, err
			}
			view, err := management.InspectRecording(ctx, name, file, initial.Size(), identity.ProducerId())
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
				err = validateRecordingInput(path, file, initial)
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

func inspectLocalRecording(ctx context.Context, configPath string, name configuration.AuditlogName, id recording.Id) (result management.RecordingView, resultErr error) {
	path, _, err := resolveRecordingSelection(name.String(), id.String(), "", configPath, "")
	if err != nil {
		return result, err
	}
	var ref configuration.Ref
	expected, err := configuredRecordingProducerId(name, configPath, path, &ref)
	if err != nil {
		return result, err
	}
	file, initial, err := openRecordingInput(path)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = goerrors.Join(resultErr, file.Close()) }()
	result, err = management.InspectRecording(ctx, name, file, initial.Size(), expected)
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
	if err := validateRecordingInput(path, file, initial); err != nil {
		return result, err
	}
	return result, nil
}
