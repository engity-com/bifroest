package sys

const (
	BifroestBinaryLocationUnix    = `/usr/bin/bifroest`
	BifroestBinaryLocationWindows = `C:\Program Files\Engity\Bifroest\bifroest.exe`
)

func BifroestBinaryLocation(os Os) string {
	switch os {
	case OsWindows:
		return BifroestBinaryLocationWindows
	case OsLinux:
		return BifroestBinaryLocationUnix
	default:
		return ""
	}
}
