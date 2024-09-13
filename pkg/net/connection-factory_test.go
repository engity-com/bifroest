package net

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/engity-com/bifroest/pkg/errors"
)

func TestNewFileConnection(t *testing.T) {
	givenReader := toClosingReader(strings.NewReader("just-a-reader"))
	givenWriter := toClosingWriter(&strings.Builder{}, func(t *closingWriter[*strings.Builder]) {
		t.delegate.WriteString("just-a-writer")
	})

	cases := []struct {
		reader io.ReadCloser
		writer io.WriteCloser
		opts   []ConnectionFromOpt

		expected connectionFrom
	}{{
		reader: givenReader,
		writer: givenWriter,

		expected: connectionFrom{
			reader:     givenReader,
			writer:     givenWriter,
			localAddr:  pipeAddrV,
			remoteAddr: pipeAddrV,
		},
	}, {
		reader: givenReader,
		writer: givenWriter,
		opts: []ConnectionFromOpt{
			ConnectionWithRemoteAddr(someAddr("remote")),
			ConnectionWithLocalAddr(someAddr("local")),
		},

		expected: connectionFrom{
			reader:     givenReader,
			writer:     givenWriter,
			localAddr:  someAddr("local"),
			remoteAddr: someAddr("remote"),
		},
	}}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			actual := NewConnectionFrom(c.reader, c.writer, c.opts...)

			assert.Equal(t, &c.expected, actual)
		})
	}
}

func TestFileConnection_LocalAddr(t *testing.T) {
	givenAddr := someAddr("just-and-address")

	instance := connectionFrom{
		localAddr: givenAddr,
	}

	actual := instance.LocalAddr()
	assert.Equal(t, actual, givenAddr)
}

func TestFileConnection_RemoteAddr(t *testing.T) {
	givenAddr := someAddr("just-and-address")

	instance := connectionFrom{
		remoteAddr: givenAddr,
	}

	actual := instance.RemoteAddr()
	assert.Equal(t, actual, givenAddr)
}

func TestFileConnection_SetDeadline(t *testing.T) {
	instance := connectionFrom{}

	actual := instance.SetDeadline(time.Now())
	assert.ErrorContains(t, actual, "set deadline not supported")
}

func TestFileConnection_SetReadDeadline(t *testing.T) {
	instance := connectionFrom{}

	actual := instance.SetReadDeadline(time.Now())
	assert.ErrorContains(t, actual, "set read deadline not supported")
}

func TestFileConnection_SetWriteDeadline(t *testing.T) {
	instance := connectionFrom{}

	actual := instance.SetWriteDeadline(time.Now())
	assert.ErrorContains(t, actual, "set write deadline not supported")
}

func TestFileConnection_Close(t *testing.T) {
	givenReader := toClosingReader(strings.NewReader(""))
	givenWriter := toClosingWriter(&strings.Builder{})
	instance := connectionFrom{
		reader: givenReader,
		writer: givenWriter,
	}

	assert.Equal(t, false, givenReader.isClosed())
	assert.Equal(t, false, givenWriter.isClosed())

	assert.NoError(t, instance.Close())

	assert.Equal(t, true, givenReader.isClosed())
	assert.Equal(t, true, givenWriter.isClosed())
}

func TestFileConnection_Read(t *testing.T) {
	givenReader := toClosingReader(strings.NewReader("abc"))
	instance := connectionFrom{
		reader:     givenReader,
		remoteAddr: pipeAddrV,
	}

	buf := make([]byte, 4)
	actualN, actualErr := instance.Read(buf)
	assert.NoError(t, actualErr)
	assert.Equal(t, 3, actualN)
	assert.Equal(t, "abc", string(buf[:actualN]))

	givenReader.error = errors.System.Newf("expected")
	actualN, actualErr = instance.Read(buf)
	assert.ErrorIs(t, actualErr, givenReader.error)
	assert.Equal(t, 0, actualN)
}

func TestFileConnection_Write(t *testing.T) {
	givenWriter := toClosingWriter(&bytes.Buffer{})
	instance := connectionFrom{
		writer:     givenWriter,
		remoteAddr: pipeAddrV,
	}

	actualN, actualErr := instance.Write([]byte("abc"))
	assert.NoError(t, actualErr)
	assert.Equal(t, 3, actualN)

	givenWriter.error = errors.System.Newf("expected")
	actualN, actualErr = instance.Write([]byte("abc"))
	assert.ErrorIs(t, actualErr, givenWriter.error)
	assert.Equal(t, 0, actualN)
}
