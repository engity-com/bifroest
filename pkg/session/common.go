package session

import (
	"bytes"
	"io"

	"github.com/engity-com/bifroest/pkg/errors"
)

func isReaderEqualToBytes(left io.Reader, right []byte) (bool, error) {
	bufL := 4 * 1024
	leftBuf := make([]byte, bufL)
	rightL := len(right)
	for offset := 0; offset < rightL; offset += bufL {
		segmentL := rightL - offset
		if segmentL > bufL {
			segmentL = bufL
		}
		fsL, err := left.Read(leftBuf)
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, err
		}

		if fsL != segmentL {
			return false, nil
		}
		leftSegment := leftBuf[:segmentL]
		rightSegment := right[offset : offset+segmentL]
		if !bytes.Equal(leftSegment, rightSegment) {
			return false, nil
		}
	}
	return true, nil
}
