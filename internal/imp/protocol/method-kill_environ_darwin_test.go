//go:build darwin

package protocol

import (
	"encoding/binary"
	"os"
	"os/exec"
	"testing"

	"github.com/shirou/gopsutil/v4/process"
	"github.com/stretchr/testify/require"
)

func TestParseDarwinProcessEnvironmentSeparatesArguments(t *testing.T) {
	raw := darwinProcessArgumentsForTest(
		[]string{"helper", "BIFROEST_EXECUTION_ID=forged", "argument"},
		[]string{"PATH=/usr/bin", "BIFROEST_EXECUTION_ID=owned"},
	)

	actual, err := parseDarwinProcessEnvironment(raw)
	require.NoError(t, err)
	require.Equal(t, []string{"PATH=/usr/bin", "BIFROEST_EXECUTION_ID=owned"}, actual)
	require.NotContains(t, actual, "BIFROEST_EXECUTION_ID=forged")
}

func TestParseDarwinProcessEnvironmentRejectsMalformedInput(t *testing.T) {
	argcWithoutArguments := make([]byte, 8)
	binary.LittleEndian.PutUint32(argcWithoutArguments, 2)
	copy(argcWithoutArguments[4:], "x\x00")
	unterminatedVariable := darwinProcessArgumentsForTest([]string{"helper"}, []string{"X=1"})
	unterminatedVariable = unterminatedVariable[:len(unterminatedVariable)-2]
	for name, raw := range map[string][]byte{
		"short header":          {1, 2, 3},
		"unterminated path":     append([]byte{0, 0, 0, 0}, []byte("/bin/test")...),
		"impossible argc":       {255, 255, 255, 127, 0},
		"missing arguments":     argcWithoutArguments,
		"unterminated variable": unterminatedVariable,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseDarwinProcessEnvironment(raw)
			require.Error(t, err)
		})
	}
}

func TestDarwinProcessEnvironmentLookup(t *testing.T) {
	const expected = "BIFROEST_TEST_PROCESS_ENVIRONMENT=owned"
	cmd := exec.Command(os.Args[0], "-test.run=^TestKillProcessEnvironmentHelper$")
	cmd.Env = append(os.Environ(), expected, killProcessEnvironmentHelper+"=1")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	candidate, err := process.NewProcess(int32(cmd.Process.Pid))
	require.NoError(t, err)
	environment, err := processEnviron(candidate)
	require.NoError(t, err)
	require.Contains(t, environment, expected)
	require.True(t, processHasEnvironment(cmd.Process.Pid, expected))
	require.False(t, processHasEnvironment(cmd.Process.Pid, expected+"-suffix"))
}

func darwinProcessArgumentsForTest(arguments, environment []string) []byte {
	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, uint32(len(arguments)))
	result = append(result, "/bin/helper\x00\x00"...)
	for _, value := range arguments {
		result = append(result, value...)
		result = append(result, 0)
	}
	for _, value := range environment {
		result = append(result, value...)
		result = append(result, 0)
	}
	return append(result, 0)
}
