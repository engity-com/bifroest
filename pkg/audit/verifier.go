package audit

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	bfcrypto "github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
)

type JournalSource struct {
	Name                        string
	Directory                   string
	ExpectedProducerId          ProducerId
	ExpectedEncryptionRecipient string
	DecryptionIdentities        []bfcrypto.PrivateKey
	WithSensitive               bool
}

type VerifiedRecord struct {
	Auditlog           string     `json:"auditlog"`
	ProducerId         ProducerId `json:"producerId"`
	SegmentSequence    uint64     `json:"segmentSequence"`
	SegmentRecordIndex uint64     `json:"segmentRecordIndex"`
	Id                 uuid.UUID  `json:"id"`
	RecordedAt         time.Time  `json:"recordedAt"`
	Event              Event      `json:"event"`
	PreviousHash       string     `json:"previousHash"`
	Hash               string     `json:"hash"`
}

type VerifiedJournal struct {
	Name          string `json:"name"`
	Directory     string `json:"directory"`
	ProducerCount uint64 `json:"producerCount"`
	SegmentCount  uint64 `json:"segmentCount"`
	RecordCount   uint64 `json:"recordCount"`
}

type Verification struct {
	Journals      []VerifiedJournal `json:"journals"`
	records       []VerifiedRecord
	withSensitive bool
}

const (
	maxMaterializedVerifiedRecords = 250_000
	maxMaterializedVerifiedBytes   = 64 << 20
)

type verifierBudget struct {
	records uint64
	bytes   int64
}

func (this *verifierBudget) consume(payloadBytes int64, materialize bool) error {
	if materialize && (this.records >= maxMaterializedVerifiedRecords || payloadBytes > maxMaterializedVerifiedBytes-this.bytes) {
		return errors.System.Newf("verified audit output exceeds the materialization limit of %d records or %d bytes", maxMaterializedVerifiedRecords, maxMaterializedVerifiedBytes)
	}
	this.records++
	if materialize {
		this.bytes += payloadBytes
	}
	return nil
}

func (this *Verification) Records() []VerifiedRecord {
	if this == nil {
		return nil
	}
	return append([]VerifiedRecord(nil), this.records...)
}

type verifierDirectorySnapshot struct {
	entries uint64
	digest  [sha256.Size]byte
}

type verifierFileSnapshot struct {
	info       os.FileInfo
	identity   [16]byte
	digest     [sha256.Size]byte
	hasContent bool
}

// VerifyJournalIntegrity verifies bytes read from stable file handles and then
// revalidates the selected journal tree. It does not lock live journals, so a
// writer may change a file after that file's final revalidation.
func VerifyJournalIntegrity(ctx context.Context, sources []JournalSource) error {
	sources = append([]JournalSource(nil), sources...)
	for i := range sources {
		sources[i].WithSensitive = false
	}
	_, err := verifyNativeJournals(ctx, sources, false)
	return err
}

// VerifyJournals has the same point-in-time semantics as VerifyJournalIntegrity
// and materializes records from the handles whose contents were verified.
func VerifyJournals(ctx context.Context, sources []JournalSource) (*Verification, error) {
	return verifyNativeJournals(ctx, sources, true)
}

func (this *verifierDirectorySnapshot) add(name string, file verifierFileSnapshot) {
	hash := sha256.New()
	_, _ = io.WriteString(hash, "BIFROEST-AUDIT-VERIFIER-DIRECTORY-ENTRY/v1\x00")
	var fixed [8]byte
	binary.BigEndian.PutUint64(fixed[:], uint64(len(name)))
	_, _ = hash.Write(fixed[:])
	_, _ = io.WriteString(hash, name)
	binary.BigEndian.PutUint64(fixed[:], uint64(file.info.Mode()))
	_, _ = hash.Write(fixed[:])
	binary.BigEndian.PutUint64(fixed[:], uint64(file.info.Size()))
	_, _ = hash.Write(fixed[:])
	binary.BigEndian.PutUint64(fixed[:], uint64(file.info.ModTime().UnixNano()))
	_, _ = hash.Write(fixed[:])
	_, _ = hash.Write(file.identity[:])
	if file.hasContent {
		_, _ = hash.Write([]byte{1})
		_, _ = hash.Write(file.digest[:])
	} else {
		_, _ = hash.Write([]byte{0})
	}
	this.addDigest(hash.Sum(nil))
}

func (this *verifierDirectorySnapshot) addSnapshot(name string, snapshot verifierDirectorySnapshot) {
	hash := sha256.New()
	_, _ = io.WriteString(hash, "BIFROEST-AUDIT-VERIFIER-PRODUCER-SNAPSHOT/v1\x00")
	var fixed [8]byte
	binary.BigEndian.PutUint64(fixed[:], uint64(len(name)))
	_, _ = hash.Write(fixed[:])
	_, _ = io.WriteString(hash, name)
	binary.BigEndian.PutUint64(fixed[:], snapshot.entries)
	_, _ = hash.Write(fixed[:])
	_, _ = hash.Write(snapshot.digest[:])
	this.addDigest(hash.Sum(nil))
}

func (this *verifierDirectorySnapshot) addDigest(entryDigest []byte) {
	carry := uint16(0)
	for index := len(this.digest) - 1; index >= 0; index-- {
		sum := uint16(this.digest[index]) + uint16(entryDigest[index]) + carry
		this.digest[index] = byte(sum)
		carry = sum >> 8
	}
	this.entries++
}

func snapshotVerifierDirectory(ctx context.Context, directory string) (verifierDirectorySnapshot, error) {
	result := verifierDirectorySnapshot{}
	directorySnapshot, err := snapshotVerifierPath(directory)
	if err != nil {
		return verifierDirectorySnapshot{}, err
	}
	if !directorySnapshot.info.IsDir() {
		return verifierDirectorySnapshot{}, errors.Config.Newf("audit journal path %q is not a directory", directory)
	}
	result.add(".", directorySnapshot)
	err = forEachJournalDirectoryEntry(ctx, directory, func(entry os.DirEntry) error {
		if entry.Name() == remoteDeliveryStateDirectoryName || entry.Name() == journalWorkDirectoryName {
			return nil
		}
		fileSnapshot, err := snapshotVerifierPath(filepath.Join(directory, entry.Name()))
		if err != nil {
			return errors.System.Newf("cannot inspect audit directory entry %q: %w", entry.Name(), err)
		}
		result.add(entry.Name(), fileSnapshot)
		return nil
	})
	if err != nil {
		return verifierDirectorySnapshot{}, err
	}
	return result, nil
}

func digestVerifierFile(ctx context.Context, path string) (verifierFileSnapshot, error) {
	file, err := openVerifierFile(path)
	if err != nil {
		return verifierFileSnapshot{}, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return verifierFileSnapshot{}, errors.System.Newf("cannot inspect audit file %q before hashing: %w", path, err)
	}
	identity, err := verifierFileIdentity(path, file, info)
	if err != nil {
		_ = file.Close()
		return verifierFileSnapshot{}, err
	}
	maximum := int64(nativeMaxSize)
	if info.Size() > maximum {
		_ = file.Close()
		return verifierFileSnapshot{}, errors.System.Newf("audit segment %q exceeds %d bytes", path, maximum)
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			_ = file.Close()
			return verifierFileSnapshot{}, errors.System.Newf("audit verification canceled: %w", err)
		}
		read, readErr := file.Read(buffer)
		if read > 0 {
			total += int64(read)
			if total > maximum {
				_ = file.Close()
				return verifierFileSnapshot{}, errors.System.Newf("audit segment %q exceeds %d bytes", path, maximum)
			}
			_, _ = hash.Write(buffer[:read])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = file.Close()
			return verifierFileSnapshot{}, errors.System.Newf("cannot hash audit file %q: %w", path, readErr)
		}
	}
	infoAfter, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return verifierFileSnapshot{}, errors.System.Newf("cannot inspect audit file %q after hashing: %w", path, err)
	}
	if info.Size() != infoAfter.Size() || !os.SameFile(info, infoAfter) {
		_ = file.Close()
		return verifierFileSnapshot{}, errors.System.Newf("audit file %q changed while hashing", path)
	}
	identityAfter, err := verifierFileIdentity(path, file, infoAfter)
	if err != nil {
		_ = file.Close()
		return verifierFileSnapshot{}, err
	}
	if identity != identityAfter {
		_ = file.Close()
		return verifierFileSnapshot{}, errors.System.Newf("audit file %q changed while hashing", path)
	}
	closeErr := file.Close()
	if closeErr != nil {
		return verifierFileSnapshot{}, errors.System.Newf("cannot close audit file %q after hashing: %w", path, closeErr)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return verifierFileSnapshot{info: infoAfter, identity: identityAfter, digest: digest, hasContent: true}, nil
}

func readVerifierFile(path string, maximum int64) ([]byte, verifierFileSnapshot, error) {
	file, err := openVerifierFile(path)
	if err != nil {
		return nil, verifierFileSnapshot{}, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, verifierFileSnapshot{}, errors.System.Newf("cannot inspect audit file %q before reading: %w", path, err)
	}
	identity, err := verifierFileIdentity(path, file, info)
	if err != nil {
		_ = file.Close()
		return nil, verifierFileSnapshot{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		_ = file.Close()
		return nil, verifierFileSnapshot{}, errors.System.Newf("cannot read audit file %q: %w", path, err)
	}
	if int64(len(raw)) > maximum {
		_ = file.Close()
		return nil, verifierFileSnapshot{}, errors.System.Newf("audit file %q exceeds %d bytes", path, maximum)
	}
	infoAfter, err := file.Stat()
	if err != nil || info.Size() != infoAfter.Size() || !os.SameFile(info, infoAfter) {
		_ = file.Close()
		return nil, verifierFileSnapshot{}, errors.System.Newf("audit file %q changed while reading", path)
	}
	identityAfter, err := verifierFileIdentity(path, file, infoAfter)
	if err != nil {
		_ = file.Close()
		return nil, verifierFileSnapshot{}, err
	}
	if identity != identityAfter {
		_ = file.Close()
		return nil, verifierFileSnapshot{}, errors.System.Newf("audit file %q changed while reading", path)
	}
	if err := file.Close(); err != nil {
		return nil, verifierFileSnapshot{}, errors.System.Newf("cannot close audit file %q: %w", path, err)
	}
	return raw, verifierFileSnapshot{info: infoAfter, identity: identityAfter, digest: sha256.Sum256(raw), hasContent: true}, nil
}

func snapshotVerifierPath(path string) (verifierFileSnapshot, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return verifierFileSnapshot{}, errors.System.Newf("cannot inspect audit path %q: %w", path, err)
	}
	if !pathInfo.Mode().IsRegular() && !pathInfo.IsDir() {
		return verifierFileSnapshot{}, errors.Config.Newf("audit path %q is neither a regular file nor a directory", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return verifierFileSnapshot{}, errors.System.Newf("cannot open audit path %q: %w", path, err)
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) {
		_ = file.Close()
		return verifierFileSnapshot{}, errors.System.Newf("audit path %q changed while opening", path)
	}
	identity, err := verifierFileIdentity(path, file, info)
	if err != nil {
		_ = file.Close()
		return verifierFileSnapshot{}, err
	}
	if err := file.Close(); err != nil {
		return verifierFileSnapshot{}, errors.System.Newf("cannot close audit path %q: %w", path, err)
	}
	return verifierFileSnapshot{info: info, identity: identity}, nil
}

func openVerifierFile(path string) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, errors.System.Newf("required audit file %q does not exist: %w", path, err)
		}
		return nil, errors.System.Newf("cannot inspect audit file %q: %w", path, err)
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.Config.Newf("audit file %q is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.System.Newf("cannot open audit file %q: %w", path, err)
	}
	fileInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, errors.System.Newf("cannot inspect open audit file %q: %w", path, err)
	}
	if !os.SameFile(pathInfo, fileInfo) {
		_ = file.Close()
		return nil, errors.System.Newf("audit file %q changed while opening", path)
	}
	return file, nil
}
