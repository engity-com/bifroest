package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

// VerifyLiveJournals exports a verified prefix bounded by the signed head read
// for each producer. Later appends and head replacements are not part of it.
// A producer ID must be supplied out of band; the head alone is not a trust root.
func VerifyLiveJournals(ctx context.Context, sources []JournalSource) (*Verification, error) {
	return verifyLiveJournals(ctx, sources, true, nil)
}

// SelectLiveJournalRecords verifies the same signed prefixes as VerifyLiveJournals,
// retaining only the selected records within the materialization budget.
// No selection is returned unless the entire verification succeeds.
func SelectLiveJournalRecords(ctx context.Context, sources []JournalSource, selection RecordSelection) (*Verification, error) {
	return verifyLiveJournals(ctx, sources, true, &verifiedRecordSelection{selection: selection})
}

func VerifyLiveJournalIntegrity(ctx context.Context, sources []JournalSource) error {
	_, err := verifyLiveJournals(ctx, sources, false, nil)
	return err
}

func verifyLiveJournals(ctx context.Context, sources []JournalSource, collect bool, selection *verifiedRecordSelection) (*Verification, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(sources) == 0 {
		return nil, errors.Config.Newf("no audit journals selected")
	}
	result := &Verification{Journals: make([]VerifiedJournal, 0, len(sources)), withSensitive: true}
	var directories []os.FileInfo
	var paths []string
	names := make(map[string]bool, len(sources))
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if source.Name == "" || source.Directory == "" || source.ExpectedProducerId.IsZero() || names[source.Name] {
			return nil, errors.Config.Newf("live audit sources require a unique name, directory and expected producer ID")
		}
		names[source.Name] = true
		path, err := filepath.EvalSymlinks(source.Directory)
		if err != nil {
			return nil, err
		}
		path, err = filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			return nil, errors.Config.Newf("invalid audit journal directory %q: %v", path, err)
		}
		for _, previous := range directories {
			if os.SameFile(previous, info) {
				return nil, errors.Config.Newf("audit journal directory %q is selected more than once", path)
			}
		}
		directories = append(directories, info)
		paths = append(paths, path)
	}
	budget := &verifierBudget{selection: selection}
	for i, source := range sources {
		source.Directory = paths[i]
		result.withSensitive = result.withSensitive && source.WithSensitive
		journal, records, err := verifyLiveJournal(ctx, source, collect, budget, paths)
		if err != nil {
			return nil, err
		}
		result.Journals = append(result.Journals, journal)
		result.records = append(result.records, records...)
	}
	if budget.selection != nil {
		result.records = budget.selection.materialize()
	}
	return result, nil
}

func verifyLiveJournal(ctx context.Context, source JournalSource, collect bool, budget *verifierBudget, selected []string) (VerifiedJournal, []VerifiedRecord, error) {
	producerName := source.ExpectedProducerId.String()
	err := forEachJournalDirectoryEntry(ctx, source.Directory, func(entry os.DirEntry) error {
		name := entry.Name()
		if name == journalLockFileName && entry.Type().IsRegular() ||
			(name == journalWorkDirectoryName || name == remoteDeliveryStateDirectoryName) && entry.IsDir() && entry.Type()&os.ModeSymlink == 0 ||
			name == producerName && entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
			return nil
		}
		var other ProducerId
		if entry.IsDir() && entry.Type()&os.ModeSymlink == 0 && other.UnmarshalText([]byte(name)) == nil {
			return fmt.Errorf("audit journal %q contains producer %s instead of expected producer %s", source.Name, other, source.ExpectedProducerId)
		}
		return fmt.Errorf("unsupported native audit root entry %q", name)
	})
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	directory := filepath.Join(source.Directory, producerName)
	producer, err := snapshotVerifierPath(directory)
	if err != nil || !producer.info.IsDir() {
		return VerifiedJournal{}, nil, fmt.Errorf("missing native audit producer %s: %v", producerName, err)
	}
	headPath := filepath.Join(directory, nativeHeadFileName)
	headBytes, _, err := readVerifierFile(headPath, nativeformat.MaxMetadataPayload)
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	head, err := evidence.CaptureAuditProducerHead(headBytes, source.ExpectedProducerId, false)
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	var identities *bfcrypto.AgeSshIdentities
	if len(source.DecryptionIdentities) > 0 {
		identities, err = bfcrypto.NewAgeSshIdentities(source.DecryptionIdentities)
		if err != nil {
			return VerifiedJournal{}, nil, err
		}
	}
	// Rotation can move active between inventory and open. Retry the same
	// captured checkpoint, never substitute a newer head on retry.
	for attempt := 0; attempt < 3; attempt++ {
		start := *budget
		if budget.selection != nil {
			budget.selection = budget.selection.clone()
		}
		records, segments, err := verifyLiveProducer(ctx, source, directory, head, identities, collect, budget, selected)
		if err == nil {
			return VerifiedJournal{Name: source.Name, Directory: source.Directory, ProducerCount: 1, SegmentCount: segments, RecordCount: budget.records - start.records}, records, nil
		}
		*budget = start
		if attempt == 2 || ctx.Err() != nil {
			return VerifiedJournal{}, nil, err
		}
	}
	panic("unreachable")
}

func verifyLiveProducer(ctx context.Context, source JournalSource, directory string, head *evidence.AuditProducerHead, identities *bfcrypto.AgeSshIdentities, collect bool, budget *verifierBudget, selected []string) ([]VerifiedRecord, uint64, error) {
	options := evidence.AuditProducerOptions{
		Auditlog: source.Name, ExpectedProducerId: source.ExpectedProducerId, AllowUntrusted: source.ExpectedProducerId.IsZero(),
		ExpectedEncryptionRecipient: source.ExpectedEncryptionRecipient, DecryptionIdentities: identities,
		WithSensitive: source.WithSensitive, Mode: evidence.AuditProducerCapturedPrefix,
	}
	capture := newNativeAuditProducerSnapshot(source, directory, head.ProducerId(), selected, true)
	var records []VerifiedRecord
	verified, err := evidence.InspectCapturedAuditProducer(ctx, capture, head, options, nativeAuditRecordVisitor(budget, collect, &records))
	if err != nil {
		return nil, 0, err
	}
	return records, verified.SegmentCount, nil
}
