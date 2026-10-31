package recording

import (
	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/recording/cast"
	"io"
)

type CastWriter = cast.CastWriter

func NewCastWriter(output io.Writer, identity *audit.Identity, header CastHeader, metadata CastMetadata) (*CastWriter, error) {
	return cast.NewCastWriter(output, identity, header, metadata)
}
