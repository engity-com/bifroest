package common

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

type outputMount struct {
	id     uint64
	points []string
}

func locateSingleLinkOutput(output *os.File, _ fs.FileInfo) (string, outputMount, bool) {
	var stat unix.Statx_t
	const required = unix.STATX_NLINK | unix.STATX_MNT_ID
	if err := unix.Statx(int(output.Fd()), "", unix.AT_EMPTY_PATH, required, &stat); err != nil || stat.Mask&required != required || stat.Nlink != 1 {
		return "", outputMount{}, false
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", output.Fd()))
	if err != nil {
		return "", outputMount{}, false
	}
	points, err := outputMountPoints()
	return path, outputMount{stat.Mnt_id, points}, err == nil
}

func (this outputMount) matches(directory string) bool {
	var stat unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, directory, 0, unix.STATX_MNT_ID, &stat); err != nil || stat.Mask&unix.STATX_MNT_ID == 0 {
		return false
	}
	return this.id == stat.Mnt_id && !hasMountBelow(directory, this.points)
}

func outputMountPoints() (result []string, resultErr error) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.Close(); resultErr == nil {
			resultErr = err
		}
	}()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	unescape := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			return nil, fmt.Errorf("invalid mount information")
		}
		result = append(result, unescape.Replace(fields[4]))
	}
	return result, scanner.Err()
}
