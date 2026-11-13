package audit

import (
	"bytes"
	"context"
	goerrors "errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/nativeformat"
)

// This adapter retains real native file proofs and the external sorted inventory.
// It does not emulate os.FileInfo or turn byte equality into filesystem identity.
type nativeAuditProducerSnapshot struct {
	source       JournalSource
	directory    string
	id           ProducerId
	selected     []string
	live         bool
	closed       bool
	initialized  bool
	exhausted    bool
	head         []byte
	headProof    verifierFileSnapshot
	inventory    *nativeSegmentInventory
	verified     verifierDirectorySnapshot
	after        verifierDirectorySnapshot
	lastInfo     os.FileInfo
	lastDigest   [32]byte
	lastSeq      uint64
	activeInfo   os.FileInfo
	headFile     *os.File
	headLease    os.FileInfo
	headIdentity [16]byte
	reserved     []os.FileInfo
}

func newNativeAuditProducerSnapshot(source JournalSource, directory string, id ProducerId, selected []string, live bool) *nativeAuditProducerSnapshot {
	return &nativeAuditProducerSnapshot{source: source, directory: directory, id: id, selected: append([]string(nil), selected...), live: live}
}

func nativeAuditSnapshotOptions(source JournalSource, mode evidence.AuditProducerMode) (evidence.AuditProducerOptions, error) {
	options := evidence.AuditProducerOptions{
		Auditlog: source.Name, ExpectedProducerId: source.ExpectedProducerId,
		// Legacy native callers allow integrity-only self-consistency without
		// an independently pinned producer. This must never become Trusted.
		AllowUntrusted: source.ExpectedProducerId.IsZero(), ExpectedEncryptionRecipient: source.ExpectedEncryptionRecipient,
		WithSensitive: source.WithSensitive, Mode: mode,
	}
	if len(source.DecryptionIdentities) > 0 {
		var err error
		options.DecryptionIdentities, err = bfcrypto.NewAgeSshIdentities(source.DecryptionIdentities)
		if err != nil {
			return evidence.AuditProducerOptions{}, err
		}
	}
	return options, nil
}

func nativeAuditRecordVisitor(budget *verifierBudget, collect bool, records *[]VerifiedRecord) func(VerifiedRecord, int64) error {
	return func(record VerifiedRecord, payloadBytes int64) error {
		if err := budget.consume(payloadBytes, collect && budget.selection == nil); err != nil {
			return err
		}
		if !collect {
			return nil
		}
		if budget.selection != nil {
			return budget.selection.add(record, payloadBytes)
		}
		*records = append(*records, record)
		return nil
	}
}

func (this *nativeAuditProducerSnapshot) Head(ctx context.Context) ([]byte, error) {
	if this.closed || this.live {
		return nil, fmt.Errorf("native audit snapshot does not own a complete captured head")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if this.head != nil {
		return bytes.Clone(this.head), nil
	}
	path := filepath.Join(this.directory, nativeHeadFileName)
	payload, proof, err := readVerifierFile(path, nativeformat.MaxMetadataPayload)
	if err != nil {
		return nil, err
	}
	head, err := nativeformat.Unmarshal[nativeAuditHead](payload, nativeformat.MaxMetadataPayload)
	if err != nil {
		return nil, err
	}
	if ProducerId(head.ProducerId) != this.id {
		return nil, errors.System.Newf("native audit head %q has invalid producer identity", path)
	}
	// Keep the captured inode leased until producer completion. Paths can still
	// be atomically replaced; final offline head/tree checks detect any change.
	this.headFile, err = openVerifierFile(path)
	if err != nil {
		return nil, err
	}
	this.headLease, err = this.headFile.Stat()
	if err != nil || !os.SameFile(proof.info, this.headLease) {
		return nil, fmt.Errorf("native audit head changed while capturing its lease: %v", err)
	}
	this.headIdentity, err = verifierFileIdentity(path, this.headFile, this.headLease)
	if err != nil || this.headIdentity != proof.identity {
		return nil, fmt.Errorf("native audit head identity changed while capturing its lease: %v", err)
	}
	this.head, this.headProof = payload, proof
	return bytes.Clone(payload), nil
}

func (this *nativeAuditProducerSnapshot) initialize(ctx context.Context) error {
	if this.closed {
		return fmt.Errorf("native audit producer snapshot is closed")
	}
	if this.initialized {
		return nil
	}
	var temps map[string]struct{}
	var err error
	if this.live {
		temps, err = nativeHeadTempsForInventory(this.directory)
		if err != nil {
			return err
		}
		path := filepath.Join(this.directory, nativeHeadFileName)
		this.headFile, err = openVerifierFile(path)
		if err != nil {
			return err
		}
		this.headLease, err = this.headFile.Stat()
		if err != nil || !this.headLease.Mode().IsRegular() {
			return fmt.Errorf("native audit head changed: %v", err)
		}
		this.headIdentity, err = verifierFileIdentity(path, this.headFile, this.headLease)
		if err != nil {
			return err
		}
		this.reserved = []os.FileInfo{this.headLease}
		if lock, err := os.Lstat(filepath.Join(this.source.Directory, journalLockFileName)); err == nil {
			if !lock.Mode().IsRegular() || os.SameFile(lock, this.headLease) {
				return fmt.Errorf("native audit lock aliases head or is not a regular file")
			}
			this.reserved = append(this.reserved, lock)
		} else if !os.IsNotExist(err) {
			return err
		}
		for name := range temps {
			info, err := os.Lstat(filepath.Join(this.directory, name))
			if err != nil || !info.Mode().IsRegular() {
				return fmt.Errorf("native audit head temp changed: %v", err)
			}
			for _, other := range this.reserved {
				if os.SameFile(info, other) {
					return fmt.Errorf("native audit head temp aliases repository data")
				}
			}
			this.reserved = append(this.reserved, info)
		}
	} else if this.head == nil {
		return fmt.Errorf("native audit snapshot has no captured head")
	}
	encrypted := this.source.ExpectedEncryptionRecipient != ""
	activeName := this.activeName()
	this.inventory, err = newNativeSegmentInventory(ctx, this.directory, activeName, encrypted, temps, func() (*journalSegmentWorkspace, error) {
		return newNativeVerifierWorkspace(this.selected)
	})
	if err != nil {
		return errors.System.Newf("invalid native audit inventory %q: %w", this.directory, err)
	}
	if !this.inventory.hasHead {
		return errors.System.Newf("invalid native audit inventory %q: missing head", this.directory)
	}
	if this.live {
		if this.inventory.hasActive {
			info, err := os.Lstat(filepath.Join(this.directory, activeName))
			if err != nil || !info.Mode().IsRegular() {
				return fmt.Errorf("native active changed: %v", err)
			}
			this.activeInfo = info
			for _, other := range this.reserved {
				if os.SameFile(info, other) {
					return fmt.Errorf("native active aliases repository data")
				}
			}
		}
	} else {
		proof, err := snapshotVerifierPath(this.directory)
		if err != nil || !proof.info.IsDir() {
			return errors.System.Newf("native producer directory %q changed", this.directory)
		}
		this.verified.add(".", proof)
		this.verified.add(nativeHeadFileName, this.headProof)
	}
	this.initialized = true
	return nil
}

func (this *nativeAuditProducerSnapshot) activeName() string {
	if this.source.ExpectedEncryptionRecipient != "" {
		return nativeActiveEncrypted
	}
	return nativeActiveClear
}

func (this *nativeAuditProducerSnapshot) NextPublished(ctx context.Context) (evidence.AuditPublishedSegment, bool, error) {
	if err := this.initialize(ctx); err != nil {
		return evidence.AuditPublishedSegment{}, false, err
	}
	entry, found, err := this.inventory.segments.Next(ctx)
	if err != nil || !found {
		if err == nil {
			this.exhausted = true
		}
		return evidence.AuditPublishedSegment{}, false, err
	}
	if this.live {
		info, err := os.Lstat(entry.path)
		if err != nil || !info.Mode().IsRegular() {
			return evidence.AuditPublishedSegment{}, false, fmt.Errorf("native segment changed: %v", err)
		}
		for _, other := range this.reserved {
			if os.SameFile(info, other) {
				return evidence.AuditPublishedSegment{}, false, fmt.Errorf("native audit segment aliases repository data")
			}
		}
		if this.activeInfo != nil && os.SameFile(info, this.activeInfo) {
			return evidence.AuditPublishedSegment{}, false, fmt.Errorf("native audit segment aliases active")
		}
	}
	data, proof, err := readVerifierFile(entry.path, nativeMaxSize)
	if err != nil {
		return evidence.AuditPublishedSegment{}, false, err
	}
	image, err := evidence.NewAuditSegmentImage(data)
	if err != nil {
		return evidence.AuditPublishedSegment{}, false, err
	}
	if !this.live {
		this.verified.add(filepath.Base(entry.path), proof)
	}
	this.lastInfo, this.lastDigest, this.lastSeq = proof.info, proof.digest, entry.sequence
	return evidence.AuditPublishedSegment{Sequence: entry.sequence, Hash: entry.hash, Image: image}, true, nil
}

func (this *nativeAuditProducerSnapshot) Active(ctx context.Context) (evidence.AuditActiveSegment, bool, error) {
	if err := this.initialize(ctx); err != nil {
		return evidence.AuditActiveSegment{}, false, err
	}
	if !this.exhausted {
		return evidence.AuditActiveSegment{}, false, fmt.Errorf("native audit inventory has not been exhausted")
	}
	if !this.inventory.hasActive {
		return evidence.AuditActiveSegment{}, false, nil
	}
	path := filepath.Join(this.directory, this.activeName())
	if this.live {
		file, err := openVerifierFile(path)
		if err != nil {
			return evidence.AuditActiveSegment{}, false, err
		}
		info, err := file.Stat()
		if err != nil || !os.SameFile(info, this.activeInfo) || info.Size() < 0 || info.Size() > nativeMaxSize {
			return evidence.AuditActiveSegment{}, false, goerrors.Join(fmt.Errorf("native active changed or exceeds size cap: %v", err), file.Close())
		}
		data := make([]byte, info.Size())
		_, readErr := io.ReadFull(io.NewSectionReader(file, 0, info.Size()), data)
		if err := goerrors.Join(readErr, file.Close()); err != nil {
			return evidence.AuditActiveSegment{}, false, fmt.Errorf("cannot read native active: %w", err)
		}
		image, err := evidence.NewAuditSegmentImage(data)
		return evidence.AuditActiveSegment{Image: image}, err == nil, err
	}
	data, proof, err := readVerifierFile(path, nativeMaxSize)
	if err != nil {
		return evidence.AuditActiveSegment{}, false, err
	}
	this.verified.add(this.activeName(), proof)
	if err := this.inventory.segments.Reset(); err != nil {
		return evidence.AuditActiveSegment{}, false, err
	}
	for {
		entry, found, err := this.inventory.segments.Next(ctx)
		if err != nil {
			return evidence.AuditActiveSegment{}, false, err
		}
		if !found {
			break
		}
		info, err := os.Lstat(entry.path)
		if err != nil {
			return evidence.AuditActiveSegment{}, false, err
		}
		if os.SameFile(info, proof.info) && entry.sequence != this.lastSeq {
			return evidence.AuditActiveSegment{}, false, fmt.Errorf("native active aliases an earlier published segment")
		}
	}
	var alias uint64
	if this.lastInfo != nil && os.SameFile(this.lastInfo, proof.info) {
		if this.lastDigest != proof.digest {
			return evidence.AuditActiveSegment{}, false, fmt.Errorf("native active alias changed during verification")
		}
		alias = this.lastSeq
	}
	image, err := evidence.NewAuditSegmentImage(data)
	return evidence.AuditActiveSegment{Image: image, AliasOfPublished: alias}, err == nil, err
}

func (this *nativeAuditProducerSnapshot) Revalidate(ctx context.Context) error {
	if this.closed || !this.initialized || !this.exhausted {
		return fmt.Errorf("native audit producer capture is incomplete or closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if this.live {
		info, err := this.headFile.Stat()
		if err != nil || !info.Mode().IsRegular() || !os.SameFile(info, this.headLease) {
			return fmt.Errorf("native audit head lease changed: %v", err)
		}
		identity, err := verifierFileIdentity(filepath.Join(this.directory, nativeHeadFileName), this.headFile, info)
		if err != nil || identity != this.headIdentity {
			return fmt.Errorf("native audit head lease identity changed: %v", err)
		}
		return nil
	}
	path := filepath.Join(this.directory, nativeHeadFileName)
	headAfter, _, err := readVerifierFile(path, nativeformat.MaxMetadataPayload)
	if err != nil || !bytes.Equal(this.head, headAfter) {
		return fmt.Errorf("native audit head %q changed during verification: %v", path, err)
	}
	after, err := snapshotNativeProducerContent(ctx, this.directory)
	if err != nil {
		return err
	}
	if this.verified != after {
		return fmt.Errorf("native producer %s changed during verification", this.id)
	}
	this.after = after
	return nil
}

func (this *nativeAuditProducerSnapshot) Close() error {
	if this.closed {
		return nil
	}
	this.closed = true
	var err error
	if this.inventory != nil {
		err = this.inventory.segments.Close()
	}
	if this.headFile != nil {
		err = goerrors.Join(err, this.headFile.Close())
		this.headFile = nil
	}
	return err
}
