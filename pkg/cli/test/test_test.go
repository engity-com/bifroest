package test

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/engity-com/bifroest/pkg/errors"
	bftest "github.com/engity-com/bifroest/pkg/test"
	"github.com/stretchr/testify/require"
)

func TestReportWriteFailureKeepsOldReportAndPreservesCause(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.xml")
	require.NoError(t, os.WriteFile(path, []byte("original XML"), 0600))
	err := writeReport(path, func(out io.Writer) error {
		_, err := io.WriteString(out, "partial XML")
		require.NoError(t, err)
		return io.ErrUnexpectedEOF
	})
	var command *bftest.CommandError
	require.ErrorAs(t, err, &command)
	require.Equal(t, 2, command.Code)
	require.False(t, command.Reported)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.ErrorContains(t, err, strconv.Quote(path))
	category, ok := errors.IsError(err)
	require.True(t, ok)
	require.Equal(t, errors.System, category.Type)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "original XML", string(data))
	require.NoError(t, writeReport(path, func(out io.Writer) error { _, err := io.WriteString(out, "new XML"); return err }))
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "new XML", string(data))
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 1, "temporary report files must be cleaned up")
}

func TestReportErrorsRetainCategoriesAndCloseFailures(t *testing.T) {
	for _, kind := range []string{"category", "close"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "nested", "report.xml")
			err := writeReport(path, func(out io.Writer) error {
				if kind == "category" {
					return errors.Permission.Newf("specific report permission cause")
				}
				return out.(*os.File).Close()
			})
			var command *bftest.CommandError
			require.ErrorAs(t, err, &command)
			require.Equal(t, 2, command.Code)
			require.False(t, command.Reported)
			require.ErrorContains(t, err, strconv.Quote(path))
			if kind == "category" {
				category, ok := errors.IsError(err)
				require.True(t, ok)
				require.Equal(t, errors.Permission, category.Type)
				require.ErrorContains(t, err, "specific report permission cause")
			} else {
				require.ErrorIs(t, err, os.ErrClosed)
			}
			_, statErr := os.Stat(path)
			require.True(t, os.IsNotExist(statErr))
		})
	}
}
