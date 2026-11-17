package browserevidence

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/engity-com/bifroest/pkg/uuidtext"

	"github.com/engity-com/bifroest/pkg/audit/evidence"
	"github.com/engity-com/bifroest/pkg/browserkey"
	"github.com/engity-com/bifroest/pkg/crypto/keydata"
	"github.com/engity-com/bifroest/pkg/management/protocol"
	"github.com/engity-com/bifroest/pkg/nativeformat"
	"github.com/engity-com/bifroest/pkg/recording/cast"
	"golang.org/x/crypto/ssh"
)

type RecordingInfo struct {
	RecordingID string `json:"recordingId"`
	Producer    string `json:"producer"`
	Recipient   string `json:"recipient"`
	Encrypted   bool   `json:"encrypted"`
	RequiresKey bool   `json:"requiresKey"`
	Decryption  string `json:"decryption"`
	Flow        string `json:"flow"`
	SessionID   string `json:"sessionId"`
}
type OpenedPlayback struct {
	Info     RecordingInfo     `json:"info"`
	Playback *PlaybackMetadata `json:"playback"`
	Frames   []byte            `json:"-"`
}

// OpenPlayback decodes an immutable recording for display. It deliberately does
// not establish signatures, provenance or producer trust. Encrypted payloads
// MUST pass age authentication. Nothing is returned from an incomplete decode.
func OpenPlayback(ctx context.Context, data []byte, id string, private, passphrase []byte) (_ *OpenedPlayback, resultErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !protocol.ValidID(id) {
		return nil, ErrInput
	}
	if len(data) == 0 || int64(len(data)) > MaximumInputBytes {
		return nil, ErrLimit
	}
	info := RecordingInfo{RecordingID: id, Decryption: "not-encrypted"}
	var keys *keydata.AgeSshIdentities
	native := bytes.HasPrefix(data, []byte(nativeformat.RecordingMagic))
	if native {
		header, err := cast.ReadNativeRecordingHeader(bytes.NewReader(data), int64(len(data)))
		if err != nil || !uuidtext.Equal(cast.Id(header.RecordingId).String(), id) {
			return nil, ErrInput
		}
		info.Producer, info.Recipient, info.Encrypted = evidence.ProducerId(header.ProducerId).String(), header.Recipient, header.Encryption == 1
		if info.Encrypted {
			info.Decryption = "not-checked"
			if len(private) == 0 {
				info.RequiresKey = true
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return &OpenedPlayback{Info: info}, nil
			}
			parsed, err := browserkey.ParsePrivateKey(private, passphrase)
			if err != nil {
				return nil, ErrKey
			}
			key, err := keydata.PrivateKeyFromSdk(parsed)
			if err != nil || ssh.FingerprintSHA256(key.PublicKey().ToSsh()) != info.Recipient {
				return nil, ErrKey
			}
			keys, err = keydata.NewAgeSshIdentities([]keydata.PrivateKey{key})
			if err != nil {
				return nil, ErrKey
			}
		}
	}
	var frames boundedOutput
	defer func() { clear(frames.Bytes()) }()
	var count, frameCount uint32
	var elapsed int64
	visit := func(event cast.CastEvent) error {
		count++
		if count > MaximumPlaybackEvents {
			return ErrLimit
		}
		elapsed = event.Elapsed.Microseconds()
		var kind byte
		var payload []byte
		switch event.Code {
		case "o":
			switch event.Stream {
			case cast.OutputStreamTerminal:
				kind = 0
			case cast.OutputStreamStdout:
				kind = 1
			case cast.OutputStreamStderr:
				kind = 2
			default:
				return ErrInput
			}
			payload = event.Data
		case "r":
			if !playbackDimensions(event.Columns, event.Rows) {
				return ErrLimit
			}
			kind, payload = 3, make([]byte, 8)
			binary.LittleEndian.PutUint32(payload, event.Columns)
			binary.LittleEndian.PutUint32(payload[4:], event.Rows)
		default:
			return nil
		}
		var header [PlaybackFrameHeaderBytes]byte
		binary.LittleEndian.PutUint64(header[:8], uint64(elapsed))
		header[8] = kind
		binary.LittleEndian.PutUint32(header[9:], uint32(len(payload)))
		if _, err := frames.Write(header[:]); err != nil {
			return err
		}
		if _, err := frames.Write(payload); err != nil {
			return err
		}
		frameCount++
		return nil
	}
	var contents *cast.CastContents
	var err error
	if native {
		contents, err = cast.ReadNativeRecordingContents(ctx, bytes.NewReader(data), int64(len(data)), MaximumInputBytes, keys, visit)
	} else {
		contents, err = cast.ReadCastContents(bytes.NewReader(data), ctx, MaximumInputBytes, visit)
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !uuidtext.Equal(contents.Metadata.RecordingId.String(), id) {
		return nil, ErrInput
	}
	if !playbackDimensions(contents.Header.Terminal.Columns, contents.Header.Terminal.Rows) {
		return nil, ErrLimit
	}
	info.Producer = contents.Metadata.ProducerId.String()
	info.Flow, info.SessionID = contents.Metadata.Flow.String(), contents.Metadata.SessionId.String()
	if info.Encrypted {
		info.Decryption = "authenticated"
	}
	metadata := &PlaybackMetadata{Version: 1, RecordingID: id, Producer: info.Producer, Trust: "not-checked", Columns: contents.Header.Terminal.Columns, Rows: contents.Header.Terminal.Rows, Pty: contents.Metadata.Pty, Frames: frameCount, DurationUs: elapsed, Status: contents.Result.Status, ExitStatus: contents.ExitStatus}
	return &OpenedPlayback{Info: info, Playback: metadata, Frames: bytes.Clone(frames.Bytes())}, nil
}
