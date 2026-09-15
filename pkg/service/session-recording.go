package service

import (
	"context"
	"fmt"

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
