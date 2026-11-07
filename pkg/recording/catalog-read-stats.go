package recording

import (
	"context"
	"sync/atomic"
)

// CatalogReadStats is optional in-process diagnostic instrumentation. It reports
// work, not identities, permissions or a verification result. No wire input can
// install it or influence verification through it.
type CatalogReadStats struct {
	MetadataReads atomic.Int64
	ContentReads  atomic.Int64
}
type catalogReadStatsKey struct{}

func WithCatalogReadStats(ctx context.Context, stats *CatalogReadStats) context.Context {
	return context.WithValue(ctx, catalogReadStatsKey{}, stats)
}
func catalogReadWork(ctx context.Context, content bool) {
	if stats, ok := ctx.Value(catalogReadStatsKey{}).(*CatalogReadStats); ok && stats != nil {
		if content {
			stats.ContentReads.Add(1)
		} else {
			stats.MetadataReads.Add(1)
		}
	}
}
