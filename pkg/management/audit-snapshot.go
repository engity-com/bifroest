package management

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/engity-com/bifroest/pkg/audit"
)

const WireAuditCommand = "_bifroest-management-audit-v1"
const MaxAuditSnapshotBytes int64 = 1 << 30
const maxAuditSnapshotFileBytes int64 = 17 << 20
const maxAuditSnapshotHeaderBytes = 4 << 20

type AuditSnapshotEntry struct {
	Name   string `cbor:"1,keyasint"`
	Size   int64  `cbor:"2,keyasint"`
	SHA256 string `cbor:"3,keyasint"`
}

type AuditSnapshotHeader struct {
	Version   uint8                `cbor:"1,keyasint"`
	Name      string               `cbor:"2,keyasint"`
	Producer  string               `cbor:"3,keyasint"`
	Recipient string               `cbor:"4,keyasint"`
	Files     []AuditSnapshotEntry `cbor:"5,keyasint"`
}

type AuditSnapshot struct {
	header AuditSnapshotHeader
	root   string
}

func (this *AuditSnapshot) Close() error {
	if this == nil || this.root == "" {
		return nil
	}
	root := this.root
	this.root = ""
	return os.RemoveAll(root)
}

func permittedAuditSnapshotName(name string, encrypted bool) bool {
	if name == "head.cbor" {
		return true
	}
	suffix := ".baudit"
	if encrypted {
		suffix = ".beaudit"
	}
	return name == "active"+suffix || strings.HasPrefix(name, "segment-") && strings.HasSuffix(name, suffix) && !strings.ContainsAny(name, "/\\")
}

// SnapshotAudit copies a live signed checkpoint into private temporary storage.
// A concurrent append/rotation is retried; no partially verified snapshot is
// ever returned to the SSH transport.
func SnapshotAudit(ctx context.Context, source audit.JournalSource) (*AuditSnapshot, error) {
	if source.Name == "" || source.Directory == "" || source.ExpectedProducerId.IsZero() {
		return nil, fmt.Errorf("audit snapshot requires name, directory and trusted producer")
	}
	source.WithSensitive = false
	source.DecryptionIdentities = nil
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := audit.VerifyLiveJournalIntegrity(ctx, []audit.JournalSource{source}); err != nil {
			lastErr = err
			continue
		}
		root, err := os.MkdirTemp("", "bifroest-management-audit-*")
		if err != nil {
			return nil, err
		}
		snapshot := &AuditSnapshot{root: root, header: AuditSnapshotHeader{
			Version: 1, Name: source.Name, Producer: source.ExpectedProducerId.String(), Recipient: source.ExpectedEncryptionRecipient,
		}}
		if err = snapshot.copy(ctx, source); err == nil {
			err = audit.VerifyJournalIntegrity(ctx, []audit.JournalSource{{
				Name: source.Name, Directory: snapshot.Directory(), ExpectedProducerId: source.ExpectedProducerId,
				ExpectedEncryptionRecipient: source.ExpectedEncryptionRecipient,
			}})
		}
		if err == nil {
			return snapshot, nil
		}
		lastErr = err
		_ = snapshot.Close()
	}
	return nil, fmt.Errorf("cannot capture a stable signed audit checkpoint: %w", lastErr)
}

func (this *AuditSnapshot) Directory() string { return filepath.Join(this.root, "journal") }

func (this *AuditSnapshot) copy(ctx context.Context, source audit.JournalSource) error {
	producer := source.ExpectedProducerId.String()
	input := filepath.Join(source.Directory, producer)
	output := filepath.Join(this.Directory(), producer)
	if err := os.MkdirAll(output, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(input)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var total int64
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if !permittedAuditSnapshotName(name, source.ExpectedEncryptionRecipient != "") || !entry.Type().IsRegular() {
			return fmt.Errorf("invalid signed audit snapshot entry %q", name)
		}
		path := filepath.Join(input, name)
		initial, err := os.Lstat(path)
		if err != nil || !initial.Mode().IsRegular() || initial.Size() > maxAuditSnapshotFileBytes || initial.Size() < 1 {
			return fmt.Errorf("invalid audit source file %q: %v", path, err)
		}
		if total > MaxAuditSnapshotBytes-initial.Size() {
			return fmt.Errorf("audit snapshot exceeds %d bytes", MaxAuditSnapshotBytes)
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		opened, err := file.Stat()
		if err != nil || !os.SameFile(initial, opened) {
			_ = file.Close()
			return fmt.Errorf("audit file %q changed while opening: %v", path, err)
		}
		data, err := io.ReadAll(io.LimitReader(file, maxAuditSnapshotFileBytes+1))
		closeErr := file.Close()
		if err != nil || closeErr != nil || int64(len(data)) != initial.Size() {
			return fmt.Errorf("audit file %q changed while copying: %v", path, errors.Join(err, closeErr))
		}
		current, err := os.Lstat(path)
		if err != nil || !os.SameFile(initial, current) || current.Size() != initial.Size() || !current.ModTime().Equal(initial.ModTime()) {
			return fmt.Errorf("audit file %q changed during snapshot: %v", path, err)
		}
		if err := os.WriteFile(filepath.Join(output, name), data, 0600); err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		this.header.Files = append(this.header.Files, AuditSnapshotEntry{Name: name, Size: int64(len(data)), SHA256: hex.EncodeToString(digest[:])})
		total += int64(len(data))
	}
	return nil
}

func (this *AuditSnapshot) WriteTo(output io.Writer) error {
	if this == nil || this.root == "" || output == nil {
		return fmt.Errorf("closed audit snapshot or missing output")
	}
	header, err := cbor.Marshal(this.header)
	if err != nil || len(header) > maxAuditSnapshotHeaderBytes {
		return fmt.Errorf("invalid audit snapshot header: %v", err)
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(header)))
	if _, err := io.Copy(output, bytes.NewReader(length[:])); err != nil {
		return err
	}
	if _, err := io.Copy(output, bytes.NewReader(header)); err != nil {
		return err
	}
	producerDir := filepath.Join(this.Directory(), this.header.Producer)
	for _, entry := range this.header.Files {
		file, err := os.Open(filepath.Join(producerDir, entry.Name))
		if err != nil {
			return err
		}
		written, err := io.CopyN(output, file, entry.Size)
		closeErr := file.Close()
		if err != nil || closeErr != nil || written != entry.Size {
			return errors.Join(err, closeErr, io.ErrUnexpectedEOF)
		}
	}
	return nil
}

func ReadAuditSnapshot(input io.Reader, root string) (AuditSnapshotHeader, error) {
	var length [4]byte
	if _, err := io.ReadFull(input, length[:]); err != nil {
		return AuditSnapshotHeader{}, err
	}
	size := binary.BigEndian.Uint32(length[:])
	if size < 1 || size > maxAuditSnapshotHeaderBytes {
		return AuditSnapshotHeader{}, fmt.Errorf("invalid audit snapshot header length")
	}
	encoded := make([]byte, size)
	if _, err := io.ReadFull(input, encoded); err != nil {
		return AuditSnapshotHeader{}, err
	}
	var header AuditSnapshotHeader
	if err := cbor.Unmarshal(encoded, &header); err != nil {
		return AuditSnapshotHeader{}, err
	}
	var producer audit.ProducerId
	if header.Version != 1 || header.Name == "" || producer.Set(header.Producer) != nil || len(header.Files) == 0 {
		return AuditSnapshotHeader{}, fmt.Errorf("unsupported audit snapshot header")
	}
	directory := filepath.Join(root, "journal", header.Producer)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return AuditSnapshotHeader{}, err
	}
	seen := map[string]bool{}
	var total int64
	for _, entry := range header.Files {
		if !permittedAuditSnapshotName(entry.Name, header.Recipient != "") || seen[entry.Name] || entry.Size <= 0 || entry.Size > maxAuditSnapshotFileBytes || total > MaxAuditSnapshotBytes-entry.Size {
			return AuditSnapshotHeader{}, fmt.Errorf("invalid audit snapshot file entry %q", entry.Name)
		}
		seen[entry.Name] = true
		total += entry.Size
		path := filepath.Join(directory, entry.Name)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return AuditSnapshotHeader{}, err
		}
		hasher := sha256.New()
		_, err = io.CopyN(io.MultiWriter(file, hasher), input, entry.Size)
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return AuditSnapshotHeader{}, errors.Join(err, closeErr)
		}
		if hex.EncodeToString(hasher.Sum(nil)) != entry.SHA256 {
			return AuditSnapshotHeader{}, fmt.Errorf("audit snapshot file %q has the wrong digest", entry.Name)
		}
	}
	if !seen["head.cbor"] {
		return AuditSnapshotHeader{}, fmt.Errorf("audit snapshot has no signed head")
	}
	var trailing [1]byte
	if _, err := io.ReadFull(input, trailing[:]); err != io.EOF {
		return AuditSnapshotHeader{}, fmt.Errorf("audit snapshot has trailing bytes or was truncated: %v", err)
	}
	return header, nil
}
