package service

import (
	"context"
	"fmt"
	"time"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/recording"
)

type sessionRecordingRepositoryFormat uint8

const (
	sessionRecordingRepositoryFormatCastZstd sessionRecordingRepositoryFormat = iota + 1
	sessionRecordingRepositoryFormatBECast
)

type sessionRecordingRepository struct {
	format   sessionRecordingRepositoryFormat
	castZstd *recording.LocalCastZstdRepository
	becast   *recording.LocalBECastRepository
}

type sessionRecordingStartupRecovery struct {
	recordingId   recording.Id
	status        recording.CastStatus
	truncated     bool
	alreadySealed bool
}

type activeSessionRecording struct {
	recordingSink
	checkpoint func() error
	seal       func(time.Duration, recording.CastResult, *uint32) error
	close      func() error
}

func newSessionRecordingRepository(ctx context.Context, directory string, identity *audit.Identity, encryptionPublicKey crypto.PublicKeys) (*sessionRecordingRepository, error) {
	if encryptionPublicKey.IsZero() {
		repository, err := recording.NewLocalCastZstdRepository(ctx, directory, identity, recording.CastZstdVerifyOptions{})
		if err != nil {
			return nil, err
		}
		return &sessionRecordingRepository{
			format:   sessionRecordingRepositoryFormatCastZstd,
			castZstd: repository,
		}, nil
	}

	keys, err := encryptionPublicKey.Get()
	if err != nil {
		return nil, fmt.Errorf("cannot parse Recording encryption public key: %w", err)
	}
	if len(keys) != 1 {
		return nil, errors.Config.Newf("Recording encryption requires exactly one SSH public key")
	}
	recipient, err := crypto.NewAgeSshRecipient(keys[0])
	if err != nil {
		return nil, fmt.Errorf("cannot create Recording encryption recipient: %w", err)
	}
	repository, err := recording.NewLocalBECastRepository(ctx, directory, identity, recipient, recording.BECastVerifyOptions{})
	if err != nil {
		return nil, err
	}
	return &sessionRecordingRepository{
		format: sessionRecordingRepositoryFormatBECast,
		becast: repository,
	}, nil
}

func (this *sessionRecordingRepository) createActive(ctx context.Context, header recording.CastHeader, metadata recording.CastMetadata, chunkSize int) (*activeSessionRecording, error) {
	if this == nil {
		return nil, errors.System.Newf("nil session Recording repository")
	}
	switch this.format {
	case sessionRecordingRepositoryFormatCastZstd:
		active, err := this.castZstd.CreateActive(ctx, header, metadata, chunkSize)
		if err != nil {
			return nil, err
		}
		return &activeSessionRecording{
			recordingSink: active,
			checkpoint:    active.Checkpoint,
			seal: func(elapsed time.Duration, result recording.CastResult, exitStatus *uint32) error {
				_, err := active.Seal(elapsed, result, exitStatus)
				return err
			},
			close: active.Close,
		}, nil
	case sessionRecordingRepositoryFormatBECast:
		active, err := this.becast.CreateActive(ctx, header, metadata, chunkSize)
		if err != nil {
			return nil, err
		}
		return &activeSessionRecording{
			recordingSink: active,
			checkpoint:    active.Checkpoint,
			seal: func(elapsed time.Duration, result recording.CastResult, exitStatus *uint32) error {
				_, err := active.Seal(elapsed, result, exitStatus)
				return err
			},
			close: active.Close,
		}, nil
	default:
		return nil, errors.System.Newf("illegal session Recording repository format %d", this.format)
	}
}

func (this *activeSessionRecording) Checkpoint() error {
	if this == nil || this.checkpoint == nil {
		return errors.System.Newf("nil active session Recording")
	}
	return this.checkpoint()
}

func (this *activeSessionRecording) Seal(elapsed time.Duration, result recording.CastResult, exitStatus *uint32) error {
	if this == nil || this.seal == nil {
		return errors.System.Newf("nil active session Recording")
	}
	return this.seal(elapsed, result, exitStatus)
}

func (this *activeSessionRecording) Close() error {
	if this == nil || this.close == nil {
		return nil
	}
	return this.close()
}

func (this *sessionRecordingRepository) startupRecoveries() []sessionRecordingStartupRecovery {
	if this == nil {
		return nil
	}
	switch this.format {
	case sessionRecordingRepositoryFormatCastZstd:
		recoveries := this.castZstd.StartupRecoveries()
		result := make([]sessionRecordingStartupRecovery, len(recoveries))
		for index, recovery := range recoveries {
			result[index] = sessionRecordingStartupRecovery{
				recordingId:   recovery.Summary.RecordingId,
				status:        recovery.Summary.Status,
				truncated:     recovery.Truncated,
				alreadySealed: recovery.AlreadySealed,
			}
		}
		return result
	case sessionRecordingRepositoryFormatBECast:
		recoveries := this.becast.StartupRecoveries()
		result := make([]sessionRecordingStartupRecovery, len(recoveries))
		for index, recovery := range recoveries {
			result[index] = sessionRecordingStartupRecovery{
				recordingId:   recovery.Summary.RecordingId,
				status:        recovery.Summary.Status,
				truncated:     recovery.Truncated,
				alreadySealed: recovery.AlreadySealed,
			}
		}
		return result
	default:
		return nil
	}
}

func (this *sessionRecordingRepository) Close() error {
	if this == nil {
		return nil
	}
	switch this.format {
	case sessionRecordingRepositoryFormatCastZstd:
		return this.castZstd.Close()
	case sessionRecordingRepositoryFormatBECast:
		return this.becast.Close()
	default:
		return nil
	}
}
