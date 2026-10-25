package audit

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
	"github.com/engity-com/bifroest/pkg/errors"
)

func verifyNativeJournals(ctx context.Context, sources []JournalSource, collect bool, selection *verifiedRecordSelection) (*Verification, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(sources) == 0 {
		return nil, errors.Config.Newf("no audit journals selected")
	}
	result := &Verification{Journals: make([]VerifiedJournal, 0, len(sources))}
	result.withSensitive = true
	budget := &verifierBudget{selection: selection}
	names := map[string]bool{}
	var directories []os.FileInfo
	prepared := make([]JournalSource, 0, len(sources))
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if source.Name == "" || source.Directory == "" || names[source.Name] {
			return nil, errors.Config.Newf("missing or duplicate audit journal source")
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
		source.Directory = path
		prepared = append(prepared, source)
	}
	selectedDirectories := make([]string, len(prepared))
	for index, source := range prepared {
		selectedDirectories[index] = source.Directory
	}
	for _, source := range prepared {
		result.withSensitive = result.withSensitive && source.WithSensitive
		journal, records, err := verifyNativeJournal(ctx, source, collect, budget, selectedDirectories)
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

func verifyNativeJournal(ctx context.Context, source JournalSource, collect bool, budget *verifierBudget, selectedDirectories []string) (VerifiedJournal, []VerifiedRecord, error) {
	rootBefore, err := snapshotVerifierDirectory(ctx, source.Directory)
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	journal := VerifiedJournal{Name: source.Name, Directory: source.Directory}
	var records []VerifiedRecord
	verified := verifierDirectorySnapshot{}
	err = forEachJournalDirectoryEntry(ctx, source.Directory, func(entry os.DirEntry) error {
		name := entry.Name()
		if name == journalLockFileName || name == remoteDeliveryStateDirectoryName || name == journalWorkDirectoryName {
			if name == journalLockFileName && entry.Type().IsRegular() || name != journalLockFileName && entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
				return nil
			}
			return errors.Config.Newf("invalid native audit root entry %q", name)
		}
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return errors.Config.Newf("unsupported native audit root entry %q", name)
		}
		var id ProducerId
		if err := id.UnmarshalText([]byte(name)); err != nil {
			return err
		}
		if !source.ExpectedProducerId.IsZero() && id != source.ExpectedProducerId {
			return errors.System.Newf("audit journal %q contains producer %s instead of expected producer %s", source.Name, id, source.ExpectedProducerId)
		}
		before := budget.records
		found, count, snapshot, err := verifyNativeProducer(ctx, source, filepath.Join(source.Directory, name), id, collect, budget, selectedDirectories)
		if err != nil {
			return err
		}
		if journal.ProducerCount == math.MaxUint64 || count > math.MaxUint64-journal.SegmentCount || budget.records-before > math.MaxUint64-journal.RecordCount {
			return errors.System.Newf("native audit counters overflow")
		}
		journal.ProducerCount++
		journal.SegmentCount += count
		journal.RecordCount += budget.records - before
		records = append(records, found...)
		verified.addSnapshot(name, snapshot)
		return nil
	})
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	if journal.ProducerCount == 0 || !source.ExpectedProducerId.IsZero() && journal.ProducerCount != 1 {
		return VerifiedJournal{}, nil, errors.System.Newf("audit journal %q does not contain exactly one expected producer", source.Name)
	}
	after, err := snapshotNativeJournalContent(ctx, source.Directory)
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	rootAfter, err := snapshotVerifierDirectory(ctx, source.Directory)
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	if verified != after || rootBefore != rootAfter {
		return VerifiedJournal{}, nil, errors.System.Newf("audit journal %q changed during verification", source.Name)
	}
	return journal, records, nil
}

func verifyNativeProducer(ctx context.Context, source JournalSource, directory string, id ProducerId, collect bool, budget *verifierBudget, selectedDirectories []string) ([]VerifiedRecord, uint64, verifierDirectorySnapshot, error) {
	options, err := nativeAuditSnapshotOptions(source, evidence.AuditProducerComplete)
	if err != nil {
		return nil, 0, verifierDirectorySnapshot{}, err
	}
	capture := newNativeAuditProducerSnapshot(source, directory, id, selectedDirectories, false)
	var records []VerifiedRecord
	verified, err := evidence.InspectAuditProducerSnapshot(ctx, capture, options, nativeAuditRecordVisitor(budget, collect, &records))
	if err != nil {
		return nil, 0, verifierDirectorySnapshot{}, err
	}
	return records, verified.SegmentCount, capture.after, nil
}

func newNativeVerifierWorkspace(selectedDirectories []string) (*journalSegmentWorkspace, error) {
	temporary, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		return nil, fmt.Errorf("cannot resolve audit verification temporary directory: %w", err)
	}
	temporary, err = filepath.Abs(temporary)
	if err != nil {
		return nil, err
	}
	for _, journal := range selectedDirectories {
		journalInfo, err := os.Stat(journal)
		if err != nil {
			return nil, err
		}
		for parent := temporary; ; parent = filepath.Dir(parent) {
			parentInfo, err := os.Stat(parent)
			if err != nil {
				return nil, err
			}
			if os.SameFile(journalInfo, parentInfo) {
				return nil, fmt.Errorf("audit verification temporary directory %q is inside selected journal %q", temporary, journal)
			}
			if filepath.Dir(parent) == parent {
				break
			}
		}
	}
	return newJournalSegmentWorkspace(temporary)
}

func snapshotNativeProducerContent(ctx context.Context, directory string) (verifierDirectorySnapshot, error) {
	result := verifierDirectorySnapshot{}
	path, err := snapshotVerifierPath(directory)
	if err != nil || !path.info.IsDir() {
		return result, fmt.Errorf("native producer directory %q changed: %v", directory, err)
	}
	result.add(".", path)
	err = forEachJournalDirectoryEntry(ctx, directory, func(entry os.DirEntry) error {
		name := entry.Name()
		if name != nativeHeadFileName && name != nativeActiveClear && name != nativeActiveEncrypted {
			if _, _, clear := parseNativeSegmentName(name, false); !clear {
				if _, _, encrypted := parseNativeSegmentName(name, true); !encrypted {
					return fmt.Errorf("unsupported native audit producer entry %q", name)
				}
			}
		}
		snapshot, err := digestVerifierFile(ctx, filepath.Join(directory, name))
		if err != nil {
			return err
		}
		result.add(name, snapshot)
		return nil
	})
	return result, err
}

func snapshotNativeJournalContent(ctx context.Context, directory string) (verifierDirectorySnapshot, error) {
	result := verifierDirectorySnapshot{}
	err := forEachJournalDirectoryEntry(ctx, directory, func(entry os.DirEntry) error {
		name := entry.Name()
		if name == journalLockFileName || name == journalWorkDirectoryName || name == remoteDeliveryStateDirectoryName {
			return nil
		}
		var id ProducerId
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || id.UnmarshalText([]byte(name)) != nil {
			return fmt.Errorf("unsupported native audit root entry %q", name)
		}
		snapshot, err := snapshotNativeProducerContent(ctx, filepath.Join(directory, name))
		if err == nil {
			result.addSnapshot(name, snapshot)
		}
		return err
	})
	return result, err
}
