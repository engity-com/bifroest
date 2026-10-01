//go:build unix && !linux && !darwin

package environment

import "github.com/engity-com/bifroest/pkg/sys"

const localTargetOs = sys.OsLinux
