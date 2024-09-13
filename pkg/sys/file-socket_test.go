package sys

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/common"
)

func TestNewFileSocket(t *testing.T) {
	from, to := newSocketFiles(t)
	defer common.IgnoreCloseError(from)
	defer common.IgnoreCloseError(to)

	actual1, actualChan1 := NewFileSocket(from, to)
	require.IsType(t, (*fileSocket)(nil), actual1)
	require.NotNil(t, actualChan1)
	defer close(actualChan1)
	actual1Casted := actual1.(*fileSocket)
	assert.Same(t, from, actual1Casted.reader)
	assert.Same(t, to, actual1Casted.writer)
	assert.Equal(t, "file", actual1.Addr().Network())
	assert.Equal(t, fmt.Sprintf("file:%s>%s", from.Name(), to.Name()), actual1.Addr().String())
	assert.Equal(t, fmt.Sprintf("file:%s>%s", from.Name(), to.Name()), actual1Casted.String())

	givenAddr := someAddr("foobar")

	actual2, actualChan2 := NewFileSocket(from, to, FileListenerWithAddr(givenAddr))
	require.IsType(t, (*fileSocket)(nil), actual2)
	require.NotNil(t, actualChan2)
	defer close(actualChan2)
	actual2Casted := actual2.(*fileSocket)
	assert.Same(t, from, actual2Casted.reader)
	assert.Same(t, to, actual2Casted.writer)
	assert.Equal(t, givenAddr, actual2.Addr())
	assert.Equal(t, givenAddr.String(), actual2Casted.String())
}

func TestFileSocket_Accept(t *testing.T) {
	from, to := newSocketFiles(t)
	defer common.IgnoreCloseError(from)
	defer common.IgnoreCloseError(to)

	instance := fileSocket{
		reader:        from,
		writer:        to,
		addr:          someAddr("foobar"),
		trigger:       make(chan struct{}),
		localDone:     make(chan struct{}),
		onBeforeClose: func() {},
	}
	defer func() {
		assert.NoError(t, instance.Close())
	}()

	parallel := 3
	var wg sync.WaitGroup
	handle := func(id byte) {
		defer wg.Done()
		start := time.Now()
		conn, err := instance.Accept()
		require.NoError(t, err)
		require.NotNil(t, conn)
		defer common.IgnoreCloseError(conn)
		end1 := time.Since(start)
		assert.GreaterOrEqual(t, end1, 150*time.Millisecond)
		assert.LessOrEqual(t, end1, 750*time.Millisecond)

		expected := ":abcdefg"
		buf := make([]byte, 9)
		n, err := from.Read(buf)
		require.NoError(t, err)
		require.Equal(t, 9, n)
		assert.GreaterOrEqual(t, buf[0]-'0', byte(0))
		assert.Less(t, buf[0]-'0', byte(parallel))
		assert.Equal(t, expected, string(buf[1:]))

		n, err = conn.Write([]byte{id})
		require.NoError(t, err)
		require.Equal(t, 1, n)
	}

	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go handle(byte(i))
	}

	time.Sleep(150 * time.Millisecond)
	instance.trigger <- struct{}{}
	time.Sleep(50 * time.Millisecond)
	instance.trigger <- struct{}{}
	instance.trigger <- struct{}{}

	wg.Wait()

	toFi, err := to.Stat()
	require.NoError(t, err)
	require.Equal(t, parallel, int(toFi.Size()))
	_, err = to.Seek(0, 0)
	require.NoError(t, err)

	buf := make([]byte, parallel)
	_, err = to.Read(buf)
	require.NoError(t, err)
	for _, b := range buf {
		assert.GreaterOrEqual(t, b, byte(0))
		assert.Less(t, b, byte(parallel))
	}
}

func newSocketFiles(t *testing.T) (from *os.File, to *os.File) {
	var err error
	dir := t.TempDir()
	from, err = os.Create(filepath.Join(dir, "from"))
	require.NoError(t, err)
	for lineN := 0; lineN < 10; lineN++ {
		_, err = fmt.Fprintf(from, "%d:abcdefg", lineN)
		require.NoError(t, err)
	}
	_, err = from.Seek(0, 0)
	require.NoError(t, err)

	to, err = os.Create(filepath.Join(dir, "to"))
	require.NoError(t, err)
	return from, to
}
