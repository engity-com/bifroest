package sys

const (
	BifroestBinaryDirLocationUnix    = `/usr/bin`
	BifroestBinaryDirLocationDarwin  = `/usr/local/bin`
	BifroestBinaryDirLocationWindows = `C:\Program Files\Engity\Bifroest`

	BifroestBinaryFileLocationUnix    = BifroestBinaryDirLocationUnix + `/bifroest`
	BifroestBinaryFileLocationDarwin  = BifroestBinaryDirLocationDarwin + `/bifroest`
	BifroestBinaryFileLocationWindows = BifroestBinaryDirLocationWindows + `\bifroest.exe`
)

func BifroestBinaryFileLocation(os Os) string {
	switch os {
	case OsWindows:
		return BifroestBinaryFileLocationWindows
	case OsDarwin:
		return BifroestBinaryFileLocationDarwin
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
	case OsDarwin:
		return BifroestBinaryDirLocationDarwin
	case OsLinux:
		return BifroestBinaryDirLocationUnix
	default:
		return ""
	}
}

func BifroestOciBinaryFileLocation(os Os) string {
	switch os {
	case OsLinux, OsWindows:
		return BifroestBinaryFileLocation(os)
	default:
		return ""
	}
}

func BifroestOciBinaryDirLocation(os Os) string {
	switch os {
	case OsLinux, OsWindows:
		return BifroestBinaryDirLocation(os)
	default:
		return ""
	}
}
