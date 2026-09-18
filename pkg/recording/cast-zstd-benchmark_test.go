package recording

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"
)

type castZstdBenchmarkCorpus struct {
	name string
	data []byte
}

func BenchmarkCastZstdLevels(b *testing.B) {
	for _, corpus := range castZstdBenchmarkCorpora() {
		b.Run(corpus.name, func(b *testing.B) {
			for _, level := range []struct {
				name  string
				value zstd.EncoderLevel
			}{
				{name: "level=1-fastest", value: zstd.EncoderLevelFromZstd(1)},
				{name: "level=3-default", value: zstd.EncoderLevelFromZstd(3)},
				{name: "level=8-better", value: zstd.EncoderLevelFromZstd(8)},
			} {
				b.Run(level.name, func(b *testing.B) {
					encoder, err := zstd.NewWriter(nil,
						zstd.WithEncoderLevel(level.value),
						zstd.WithEncoderCRC(true),
						zstd.WithEncoderConcurrency(1),
						zstd.WithWindowSize(castZstdWindowSize),
						zstd.WithSingleSegment(true),
					)
					if err != nil {
						b.Fatal(err)
					}
					b.Cleanup(func() {
						if err := encoder.Close(); err != nil {
							b.Errorf("close encoder: %v", err)
						}
					})

					frame := encoder.EncodeAll(corpus.data, nil)
					compressedBytes := len(frame)
					b.SetBytes(int64(len(corpus.data)))
					b.ReportAllocs()

					for b.Loop() {
						frame = encoder.EncodeAll(corpus.data, nil)
					}
					if len(frame) != compressedBytes {
						b.Fatalf("compressed size changed from %d to %d bytes", compressedBytes, len(frame))
					}
					b.ReportMetric(100*float64(compressedBytes)/float64(len(corpus.data)), "compressed-%")
				})
			}
		})
	}
}

func castZstdBenchmarkCorpora() []castZstdBenchmarkCorpus {
	const size = DefaultCastZstdChunkSize
	commands := [...]string{
		"kubectl get pods -n production",
		"git status --short",
		"journalctl -u bifroest --since -5m",
		"docker ps --format '{{.Names}} {{.Status}}'",
	}
	shell := castZstdBenchmarkPattern(size, func(n int) []byte {
		return fmt.Appendf(nil,
			"deploy@bifroest:/srv/app$ %s\r\nsession-%04d  running  ready=1/1  restarts=%d\r\n",
			commands[n%len(commands)], n%4096, n%4,
		)
	})

	logLevels := [...]string{"DEBUG", "INFO", "WARN", "ERROR"}
	logs := castZstdBenchmarkPattern(size, func(n int) []byte {
		return fmt.Appendf(nil,
			`{"time":"2026-09-18T12:%02d:%02d.%03dZ",`+
				`"level":"%s","service":"bifroest","session":"%08x",`+
				`"message":"forwarded %d bytes"}`+"\n",
			(n/60)%60, n%60, n%1000, logLevels[n%len(logLevels)], n%2048, 512+n%8192,
		)
	})

	tui := castZstdBenchmarkPattern(size, func(n int) []byte {
		return fmt.Appendf(nil,
			"\x1b[2J\x1b[H\x1b[1;36mBifröst sessions\x1b[0m\r\n"+
				"ID        STATE      CPU       TRANSFER\r\n"+
				"%08x  \x1b[32mrunning\x1b[0m    %3d%%      %6d KiB\r\n",
			n%4096, n%100, 256+n%16384,
		)
	})

	random := castZstdBenchmarkCastData(size, castZstdBenchmarkRandom(size, 0x243f6a8885a308d3))
	base64Source := castZstdBenchmarkRandom(size*3/4, 0x13198a2e03707344)
	base64Data := make([]byte, base64.StdEncoding.EncodedLen(len(base64Source)))
	base64.StdEncoding.Encode(base64Data, base64Source)
	base64Cast := castZstdBenchmarkCastData(size, base64Data)

	return []castZstdBenchmarkCorpus{
		{name: "shell", data: shell},
		{name: "log", data: logs},
		{name: "tui", data: tui},
		{name: "random", data: random},
		{name: "base64", data: base64Cast},
	}
}

func castZstdBenchmarkPattern(size int, record func(int) []byte) []byte {
	data := make([]byte, 0, size)
	for n := 0; len(data) < size; n++ {
		group := castZstdBenchmarkOutputGroup(uint64(n+1), record(n))
		if len(data) > 0 && len(data)+len(group) > size {
			break
		}
		data = append(data, group...)
	}
	return data
}

func castZstdBenchmarkCastData(size int, source []byte) []byte {
	data := make([]byte, 0, size)
	for offset, sequence := 0, uint64(1); offset < len(source); sequence++ {
		end := min(offset+4096, len(source))
		group := castZstdBenchmarkOutputGroup(sequence, source[offset:end])
		if len(data) > 0 && len(data)+len(group) > size {
			break
		}
		data = append(data, group...)
		offset = end
	}
	return data
}

func castZstdBenchmarkOutputGroup(sequence uint64, output []byte) []byte {
	result := make([]byte, 0, len(output)+64)
	text := string(output)
	if !utf8.Valid(output) {
		metadata, err := json.Marshal(castEventMetadata{
			Schema:   castEventMetadataSchema,
			Sequence: sequence,
			Stream:   OutputStreamTerminal,
			Raw:      output,
		})
		if err != nil {
			panic(err)
		}
		result = append(result, castEventCommentPrefix...)
		result = append(result, metadata...)
		result = append(result, '\n')
		text = strings.ToValidUTF8(text, "\uFFFD")
	}
	result = fmt.Appendf(result, "[0.001,%q,%s]\n", "o", marshalCastEventString(text))
	return result
}

func castZstdBenchmarkRandom(size int, state uint64) []byte {
	data := make([]byte, size)
	for index := range data {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		data[index] = byte(state >> 56)
	}
	return data
}
