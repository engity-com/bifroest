//nolint:golint,unused
package user

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/sys"
)

var (
	keepPkgUserFiles = os.Getenv("KEEP_PKG_USER_TEST_FILES") == "yes" //nolint:golint,unused
)

func b(in string) []byte {
	return []byte(in)
}

func bs(ins ...string) [][]byte {
	result := make([][]byte, len(ins))
	for i, in := range ins {
		result[i] = b(in)
	}
	return result
}

func newTestFile(t testing.TB, name string) *testFile {
	return newTestDir(t).file(name)
}

func newNamedTestFile(t testing.TB, fn string) *testFile {
	f, err := os.OpenFile(fn, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	result := &testFile{t, nil, f.Name()}

	return result
}

type testFile struct {
	t     testing.TB
	root  *testDir
	_name string
}

func (this *testFile) dispose() {
	if keepPkgUserFiles {
		this.t.Logf("File %q preserved", this)
		return
	}

	dir := filepath.Dir(this.name())
	if err := os.RemoveAll(dir); err != nil && !sys.IsNotExist(err) {
		this.t.Errorf("test directory %q should be deleted after the test; but was: %v", dir, err)
	}
}

func (this *testFile) setContent(with string) *testFile {
	f, err := os.OpenFile(this.name(), os.O_TRUNC|os.O_WRONLY, 0600)
	require.NoError(this.t, err)
	defer func() {
		require.NoError(this.t, f.Close())
	}()

	_, err = io.Copy(f, strings.NewReader(strings.ReplaceAll(with, "$space$", " ")))
	require.NoError(this.t, err)
	return this
}

func (this *testFile) setPerms(mode os.FileMode) *testFile {
	err := os.Chmod(this.name(), mode)
	require.NoError(this.t, err)
	return this
}

func (this *testFile) content() string {
	f, err := os.OpenFile(this.name(), os.O_RDONLY, 0)
	require.NoError(this.t, err)
	defer func() {
		require.NoError(this.t, f.Close())
	}()

	all, err := io.ReadAll(f)
	require.NoError(this.t, err)

	return string(all)
}

func (this *testFile) perms() os.FileMode {
	fi, err := os.Stat(this.name())
	require.NoError(this.t, err)
	return fi.Mode()
}

func (this testFile) name() string {
	return this._name
}

func (this testFile) String() string {
	return this.name()
}

type namedReader struct {
	io.Reader
	name string
}

func (this namedReader) Name() string {
	return this.name
}

type namedBytesBuffer struct {
	bytes.Buffer
}

func (this namedBytesBuffer) Name() string {
	return "test"
}

func (this namedBytesBuffer) Seek(offset int64, whence int) (int64, error) {
	if offset != 0 {
		return 0, fmt.Errorf("cannot seek to non-zero offset")
	}
	if whence != io.SeekStart {
		return 0, fmt.Errorf("cannot seek to non-start whence")
	}
	this.Buffer.Reset()
	return 0, nil
}

func (this namedBytesBuffer) Truncate(n int64) error {
	this.Buffer.Truncate(int(n))
	return nil
}

func newTestDir(t testing.TB) *testDir {
	prefix := t.Name()
	prefix = strings.ReplaceAll(prefix, "/", "_")
	prefix = strings.ReplaceAll(prefix, "\\", "_")
	prefix = strings.ReplaceAll(prefix, "*", "_")
	prefix = strings.ReplaceAll(prefix, "$", "_")

	resultPath, err := os.MkdirTemp("", "go-test-"+prefix+"-*")
	require.NoError(t, err)

	result := &testDir{t, nil, resultPath}
	t.Cleanup(func() {
		result.dispose()
	})
	return result
}

type testDir struct {
	t     testing.TB
	root  *testDir
	_name string
}

func (this *testDir) dispose() {
	if keepPkgUserFiles {
		this.t.Logf("Directory %q preserved", this)
		return
	}

	err := os.RemoveAll(this._name)
	if sys.IsNotExist(err) {
		return
	}
	assert.NoError(this.t, err, "test directory %v should be deleted after the test", this)
}

func (this *testDir) name() string {
	return this._name
}

func (this *testDir) String() string {
	return this.name()
}

func (this *testDir) child(name string, sub ...string) string {
	return filepath.Join(append([]string{this.name(), name}, sub...)...)
}

func (this *testDir) setPerms(mode os.FileMode) *testDir {
	err := os.Chmod(this.name(), mode)
	require.NoError(this.t, err)
	return this
}

func (this *testDir) dir(name string, sub ...string) *testDir {
	fn := this.child(name, sub...)
	err := os.MkdirAll(fn, 0700)
	require.NoError(this.t, err)

	result := &testDir{this.t, this.root, fn}
	if result.root == nil {
		result.root = this
	}

	return result
}

func (this *testDir) file(name string, sub ...string) *testFile {
	fn := this.child(name, sub...)
	err := os.MkdirAll(filepath.Dir(fn), 0700)
	require.NoError(this.t, err)

	result := newNamedTestFile(this.t, fn)
	result.root = this.root
	if result.root == nil {
		result.root = this
	}

	return result
}
