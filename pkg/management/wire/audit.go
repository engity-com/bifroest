package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
)

const WireAuditCommand = "_bifroest-management-audit-v1"
const MaxAuditSnapshotBytes int64 = 1 << 30
const MaxAuditSnapshotFileBytes int64 = 17 << 20
const MaxAuditSnapshotHeaderBytes = 4 << 20

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

// AuditSnapshotSink owns provisional storage, not verification or publication.
// Begin runs only after the entire bounded header has been validated, and gets
// an independent copy of its file list. Open receives one validated entry at a
// time. Every successfully opened writer is closed, including on read errors.
// The caller owns cleanup even on Begin/Open failure and must not publish until
// decoding, owning transport completion and independent evidence checks succeed.
type AuditSnapshotSink interface {
	Begin(AuditSnapshotHeader) error
	Open(AuditSnapshotEntry) (io.WriteCloser, error)
}

// PermittedAuditSnapshotName is a wire-level basename guard, not proof that a
// segment's name/content/signature belongs to a trusted journal.
func PermittedAuditSnapshotName(name string, encrypted bool) bool {
	if len(name) > 255 || !utf8.ValidString(name) || strings.ContainsAny(name, `/\:"<>|?*`) || strings.ContainsFunc(name, unicode.IsControl) {
		return false
	}
	if name == "head.cbor" {
		return true
	}
	suffix := ".baudit"
	if encrypted {
		suffix = ".beaudit"
	}
	return name == "active"+suffix || strings.HasPrefix(name, "segment-") && strings.HasSuffix(name, suffix)
}

func auditSnapshotHeaderValid(header AuditSnapshotHeader) error {
	producer, err := hex.DecodeString(header.Producer)
	if header.Version != 1 || header.Name == "" || err != nil || len(producer) != sha256.Size || len(header.Files) == 0 {
		return fmt.Errorf("unsupported audit snapshot header")
	}
	seen := map[string]bool{}
	var total int64
	for _, entry := range header.Files {
		digest, err := hex.DecodeString(entry.SHA256)
		if !PermittedAuditSnapshotName(entry.Name, header.Recipient != "") || seen[entry.Name] || entry.Size <= 0 || entry.Size > MaxAuditSnapshotFileBytes || total > MaxAuditSnapshotBytes-entry.Size || err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != entry.SHA256 {
			return fmt.Errorf("invalid audit snapshot file entry %q", entry.Name)
		}
		seen[entry.Name] = true
		total += entry.Size
	}
	if !seen["head.cbor"] {
		return fmt.Errorf("audit snapshot has no signed head")
	}
	return nil
}

func WriteAuditSnapshotHeader(output io.Writer, header AuditSnapshotHeader) error {
	if err := auditSnapshotHeaderValid(header); err != nil {
		return err
	}
	encoded, err := cbor.Marshal(header)
	if err != nil || len(encoded) > MaxAuditSnapshotHeaderBytes {
		return fmt.Errorf("invalid audit snapshot header: %v", err)
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(encoded)))
	if _, err := io.Copy(output, bytes.NewReader(length[:])); err != nil {
		return err
	}
	_, err = io.Copy(output, bytes.NewReader(encoded))
	return err
}

// ReadAuditSnapshot checks the existing transfer envelope, file digests and final
// EOF. Header producer/recipient and head.cbor are untrusted transport assertions;
// no signatures, checkpoints, chains, trust anchors or private keys are checked.
func ReadAuditSnapshot(input io.Reader, sink AuditSnapshotSink) (AuditSnapshotHeader, error) {
	if sink == nil {
		return AuditSnapshotHeader{}, fmt.Errorf("missing audit snapshot sink")
	}
	var length [4]byte
	if _, err := io.ReadFull(input, length[:]); err != nil {
		return AuditSnapshotHeader{}, err
	}
	size := binary.BigEndian.Uint32(length[:])
	if size < 1 || size > MaxAuditSnapshotHeaderBytes {
		return AuditSnapshotHeader{}, fmt.Errorf("invalid audit snapshot header length")
	}
	encoded := make([]byte, size)
	if _, err := io.ReadFull(input, encoded); err != nil {
		return AuditSnapshotHeader{}, err
	}
	mode, err := (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF}).DecMode()
	if err != nil {
		return AuditSnapshotHeader{}, err
	}
	var header AuditSnapshotHeader
	if err := mode.Unmarshal(encoded, &header); err != nil {
		return AuditSnapshotHeader{}, err
	}
	if err := auditSnapshotHeaderValid(header); err != nil {
		return AuditSnapshotHeader{}, err
	}
	copyHeader := header
	copyHeader.Files = append([]AuditSnapshotEntry(nil), header.Files...)
	if err := sink.Begin(copyHeader); err != nil {
		return AuditSnapshotHeader{}, err
	}
	for _, entry := range header.Files {
		file, err := sink.Open(entry)
		if err != nil {
			return AuditSnapshotHeader{}, err
		}
		if file == nil {
			return AuditSnapshotHeader{}, fmt.Errorf("audit snapshot sink returned no writer")
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
	var trailing [1]byte
	if _, err := io.ReadFull(input, trailing[:]); err != io.EOF {
		return AuditSnapshotHeader{}, fmt.Errorf("audit snapshot has trailing bytes or was truncated: %v", err)
	}
	return header, nil
}
