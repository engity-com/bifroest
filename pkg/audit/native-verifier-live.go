package audit

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

// VerifyLiveJournals exports a verified prefix bounded by the signed head read
// for each producer. Later appends and head replacements are not part of it.
// A producer ID must be supplied out of band; the head alone is not a trust root.
func VerifyLiveJournals(ctx context.Context, sources []JournalSource) (*Verification, error) {
	return verifyLiveJournals(ctx, sources, true)
}

func VerifyLiveJournalIntegrity(ctx context.Context, sources []JournalSource) error {
	_, err := verifyLiveJournals(ctx, sources, false)
	return err
}

func verifyLiveJournals(ctx context.Context, sources []JournalSource, collect bool) (*Verification, error) {
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
	budget := &verifierBudget{}
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
	headBytes, headInfo, err := readVerifierFile(headPath, nativeformat.MaxMetadataPayload)
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	unsigned, err := nativeformat.Unmarshal[nativeAuditHead](headBytes, nativeformat.MaxMetadataPayload)
	if err != nil {
		return VerifiedJournal{}, nil, err
	}
	identity, err := newJournalPublicIdentity(ProducerId(unsigned.ProducerId), unsigned.PublicKey)
	if err != nil || identity.ProducerId() != source.ExpectedProducerId {
		return VerifiedJournal{}, nil, fmt.Errorf("native audit head has invalid expected producer identity: %v", err)
	}
	head, err := decodeNativeAuditHead(headBytes, identity)
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
	checkpoint := journalHash(head.LastRecordHash)
	// Rotation can move active between inventory and open. Retry the same
	// captured checkpoint, never substitute a newer head on retry.
	for attempt := 0; attempt < 3; attempt++ {
		start := *budget
		records, segments, err := verifyLiveProducer(ctx, source, directory, identity, identities, checkpoint, headInfo, collect, budget, selected)
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

func verifyLiveProducer(ctx context.Context, source JournalSource, directory string, identity journalIdentity, identities *bfcrypto.AgeSshIdentities, checkpoint journalHash, headInfo verifierFileSnapshot, collect bool, budget *verifierBudget, selected []string) (result []VerifiedRecord, count uint64, resultErr error) {
	encrypted := source.ExpectedEncryptionRecipient != ""
	activeName := nativeActiveClear
	if encrypted {
		activeName = nativeActiveEncrypted
	}
	// The writer's atomic head replacement leaves a temporary file briefly.
	// Its contents are never used as evidence or as a checkpoint.
	temps, err := nativeHeadTempsForInventory(directory)
	if err != nil {
		return nil, 0, err
	}
	reserved := []os.FileInfo{headInfo.info}
	if lock, err := os.Lstat(filepath.Join(source.Directory, journalLockFileName)); err == nil {
		if !lock.Mode().IsRegular() || os.SameFile(lock, headInfo.info) {
			return nil, 0, fmt.Errorf("native audit lock aliases head or is not a regular file")
		}
		reserved = append(reserved, lock)
	} else if !os.IsNotExist(err) {
		return nil, 0, err
	}
	for name := range temps {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil || !info.Mode().IsRegular() {
			return nil, 0, fmt.Errorf("native audit head temp changed: %v", err)
		}
		for _, other := range reserved {
			if os.SameFile(info, other) {
				return nil, 0, fmt.Errorf("native audit head temp aliases repository data")
			}
		}
		reserved = append(reserved, info)
	}
	inventory, err := newNativeSegmentInventory(ctx, directory, activeName, encrypted, temps, func() (*journalSegmentWorkspace, error) {
		return newNativeVerifierWorkspace(selected)
	})
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		if closeErr := inventory.segments.Close(); closeErr != nil {
			result, count = nil, 0
			resultErr = closeErr
		}
	}()
	if !inventory.hasHead {
		return nil, 0, fmt.Errorf("native audit head missing from inventory")
	}
	var seq uint64
	reachedHead := false
	var segmentHash, last journalHash
	var activeInfo os.FileInfo
	if inventory.hasActive {
		info, err := os.Lstat(filepath.Join(directory, activeName))
		if err != nil || !info.Mode().IsRegular() {
			return nil, 0, fmt.Errorf("native active changed: %v", err)
		}
		activeInfo = info
		for _, other := range reserved {
			if os.SameFile(info, other) {
				return nil, 0, fmt.Errorf("native active aliases repository data")
			}
		}
	}
	for {
		entry, found, err := inventory.segments.Next(ctx)
		if err != nil {
			return nil, 0, err
		}
		if !found {
			break
		}
		info, err := os.Lstat(entry.path)
		if err != nil || !info.Mode().IsRegular() {
			return nil, 0, fmt.Errorf("native segment changed: %v", err)
		}
		for _, other := range reserved {
			if os.SameFile(info, other) {
				return nil, 0, fmt.Errorf("native audit segment aliases repository data")
			}
		}
		if activeInfo != nil && os.SameFile(info, activeInfo) {
			return nil, 0, fmt.Errorf("native audit segment aliases active")
		}
		if seq == math.MaxUint64 || entry.sequence != seq+1 {
			return nil, 0, fmt.Errorf("native audit segment sequence gap or duplicate")
		}
		data, _, err := readVerifierFile(entry.path, nativeMaxSize)
		if err != nil {
			return nil, 0, err
		}
		batch, hash, tip, sealed, reached, err := verifyNativeSegmentUntil(ctx, data, identity, source, identities, entry.sequence, segmentHash, last, budget, collect, &checkpoint, true, reachedHead)
		if err != nil || !sealed || hash != entry.hash {
			return nil, 0, fmt.Errorf("invalid native audit segment %q: %v", entry.path, err)
		}
		result = append(result, batch...)
		reachedHead = reached
		seq, segmentHash, last, count = entry.sequence, hash, tip, count+1
	}
	if reachedHead {
		return result, count, nil
	}
	if !inventory.hasActive || seq == math.MaxUint64 {
		return nil, 0, fmt.Errorf("signed native audit checkpoint not in available chain")
	}
	path := filepath.Join(directory, activeName)
	file, err := openVerifierFile(path)
	if err != nil {
		return nil, 0, err
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(info, activeInfo) || info.Size() < 0 || info.Size() > nativeMaxSize {
		_ = file.Close()
		return nil, 0, fmt.Errorf("native active changed or exceeds size cap: %v", err)
	}
	data := make([]byte, info.Size())
	_, err = io.ReadFull(io.NewSectionReader(file, 0, info.Size()), data)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return nil, 0, fmt.Errorf("cannot read native active: %v, %v", err, closeErr)
	}
	batch, _, _, _, reached, err := verifyNativeSegmentUntil(ctx, data, identity, source, identities, seq+1, segmentHash, last, budget, collect, &checkpoint, false, false)
	if err != nil || !reached {
		return nil, 0, fmt.Errorf("signed native audit checkpoint not verified in active: %v", err)
	}
	return append(result, batch...), count + 1, nil
}
