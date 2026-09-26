package nativeformat

import (
	"bytes"
	"fmt"
	"io"

	"github.com/engity-com/bifroest/pkg/crypto"
)

// EncodeStoredPayload produces a separate Zstd frame and optional age message
// for one audit record or recording chunk. The signed container supplies the
// recipient fingerprint and binds the resulting stored bytes.
func EncodeStoredPayload(plaintext []byte, recipient *crypto.AgeSshRecipient, limits PayloadLimits) ([]byte, error) {
	frame, err := EncodeZstdFrame(plaintext, limits)
	if err != nil || recipient == nil {
		return frame, err
	}
	var output bytes.Buffer
	writer, err := recipient.Encrypt(&output)
	if err != nil {
		return nil, fmt.Errorf("cannot encrypt native payload: %w", err)
	}
	written, writeErr := writer.Write(frame)
	closeErr := writer.Close()
	if writeErr != nil {
		return nil, fmt.Errorf("cannot write encrypted native payload: %w", writeErr)
	}
	if written != len(frame) {
		return nil, fmt.Errorf("cannot write encrypted native payload: %w", io.ErrShortWrite)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("cannot finish encrypted native payload: %w", closeErr)
	}
	if output.Len() == 0 || output.Len() > limits.MaxStored {
		return nil, fmt.Errorf("encrypted native payload exceeds stored limit %d", limits.MaxStored)
	}
	return bytes.Clone(output.Bytes()), nil
}

// DecodeStoredPayload never returns partial plaintext: age must authenticate
// through EOF before the single Zstd frame can be accepted.
func DecodeStoredPayload(stored []byte, identities *crypto.AgeSshIdentities, recipientFingerprint string, limits PayloadLimits) ([]byte, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if len(stored) == 0 || len(stored) > limits.MaxStored {
		return nil, fmt.Errorf("native payload exceeds stored limit %d", limits.MaxStored)
	}
	if recipientFingerprint == "" {
		return DecodeZstdFrame(stored, limits)
	}
	if identities == nil {
		return nil, fmt.Errorf("missing native payload decryption identity")
	}
	reader, err := identities.DecryptForFingerprint(bytes.NewReader(stored), recipientFingerprint)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt native payload: %w", err)
	}
	frame, err := io.ReadAll(io.LimitReader(reader, int64(limits.MaxStored)+1))
	if err != nil {
		return nil, fmt.Errorf("cannot authenticate native payload: %w", err)
	}
	if len(frame) == 0 || len(frame) > limits.MaxStored {
		return nil, fmt.Errorf("decrypted native Zstd frame exceeds stored limit %d", limits.MaxStored)
	}
	return DecodeZstdFrame(frame, limits)
}
