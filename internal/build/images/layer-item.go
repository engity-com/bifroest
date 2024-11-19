package images

import (
	"io/fs"
	gos "os"
)

type LayerItem struct {
	SourceFs   fs.FS
	SourceFile string
	TargetFile string
	Mode       gos.FileMode
}
