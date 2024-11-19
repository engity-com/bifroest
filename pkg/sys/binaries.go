package sys

const (
	BifroestBinaryDirLocationUnix    = `/usr/bin`
	BifroestBinaryDirLocationWindows = `C:\Program Files\Engity\Bifroest`

	BifroestBinaryFileLocationUnix    = BifroestBinaryDirLocationUnix + `/bifroest`
	BifroestBinaryFileLocationWindows = BifroestBinaryDirLocationWindows + `\bifroest.exe`
)

func BifroestBinaryFileLocation(os Os) string {
	switch os {
	case OsWindows:
		return BifroestBinaryFileLocationWindows
	case OsLinux:
		return BifroestBinaryFileLocationUnix
	default:
		return ""
	}
}

func BifroestBinaryDirLocation(os Os) string {
	switch os {
	case OsWindows:
		return BifroestBinaryDirLocationWindows
	case OsLinux:
		return BifroestBinaryDirLocationUnix
	default:
		return ""
	}
}
