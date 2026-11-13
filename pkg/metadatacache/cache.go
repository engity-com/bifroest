// Package metadatacache stores bounded, process-local selection hints outside
// evidence repositories. Cached metadata is never content-verification authority.
package metadatacache

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type entry struct {
	stamp  [32]byte
	digest [32]byte
	path   string
	bytes  int64
	used   uint64
}

type Cache struct {
	lock           chan struct{}
	entries        map[string]entry
	directory      string
	maximumBytes   int64
	maximumEntries int
	bytes          int64
	clock          uint64
	closed         bool
	forbidden      []string
}

func New(maximumBytes int64, maximumEntries int, forbidden ...string) *Cache {
	return &Cache{lock: make(chan struct{}, 1), entries: make(map[string]entry), maximumBytes: maximumBytes, maximumEntries: maximumEntries, forbidden: append([]string(nil), forbidden...)}
}

// Use keeps data provisional until the complete cached image's digest and all
// resource closes have succeeded. A consumer must not publish from its callback.
// The caller supplies a reusable key, not a potentially delayed filesystem time
// observation. Filesystem fingerprints must go through UseFile instead.
func (c *Cache) Use(ctx context.Context, key string, stamp [32]byte, maximum int64, build func(io.Writer) error, consume func(io.Reader) error) (resultErr error) {
	return c.use(ctx, key, stamp, maximum, build, consume, true)
}

// UseFile never reuses a timestamp-only observation on platforms where identical
// observations can conceal completed writes. It still reads metadata only, not
// full evidence contents, and keeps provisional image/digest/close guarantees.
func (c *Cache) UseFile(ctx context.Context, key string, stamp [32]byte, maximum int64, build func(io.Writer) error, consume func(io.Reader) error) error {
	return c.use(ctx, key, stamp, maximum, build, consume, FileStampReuse)
}

func (c *Cache) use(ctx context.Context, key string, stamp [32]byte, maximum int64, build func(io.Writer) error, consume func(io.Reader) error, reuse bool) (resultErr error) {
	if c == nil || maximum < 1 || maximum > c.maximumBytes || c.maximumEntries < 1 {
		return fmt.Errorf("invalid metadata cache limits")
	}
	select {
	case c.lock <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-c.lock }()
	if c.closed {
		return fmt.Errorf("metadata cache is closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, found := c.entries[key]
	if found && (!reuse || current.stamp != stamp) {
		if err := c.remove(key); err != nil {
			return err
		}
		found = false
	}
	if !found {
		if c.directory == "" {
			if err := outsideEvidence(c.forbidden); err != nil {
				return err
			}
			var err error
			c.directory, err = os.MkdirTemp("", "bifroest-metadata-cache-*")
			if err != nil {
				return err
			}
		}
		file, err := os.CreateTemp(c.directory, "entry-*")
		if err != nil {
			return err
		}
		committed := false
		defer func() {
			if !committed {
				resultErr = errors.Join(resultErr, os.Remove(file.Name()))
			}
		}()
		digest := sha256.New()
		writer := &boundedWriter{ctx: ctx, output: io.MultiWriter(file, digest), maximum: maximum}
		buildErr := build(writer)
		if err := errors.Join(buildErr, file.Close(), ctx.Err()); err != nil {
			return err
		}
		for len(c.entries) >= c.maximumEntries || c.bytes+writer.bytes > c.maximumBytes {
			oldest := ""
			used := ^uint64(0)
			for name, value := range c.entries {
				if value.used < used {
					oldest, used = name, value.used
				}
			}
			if oldest == "" {
				return fmt.Errorf("metadata cache quota exhausted")
			}
			if err := c.remove(oldest); err != nil {
				return err
			}
		}
		current = entry{stamp: stamp, path: file.Name(), bytes: writer.bytes}
		copy(current.digest[:], digest.Sum(nil))
		c.bytes += writer.bytes
		c.entries[key] = current
		committed = true
	}
	c.clock++
	current.used = c.clock
	c.entries[key] = current
	file, err := os.Open(current.path)
	if err != nil {
		_ = c.remove(key)
		return fmt.Errorf("cannot open metadata cache: %w", err)
	}
	invalid := false
	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
		if invalid || !reuse {
			resultErr = errors.Join(resultErr, c.remove(key))
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != current.bytes {
		invalid = true
		return fmt.Errorf("metadata cache changed: %v", err)
	}
	digest := sha256.New()
	reader := io.TeeReader(&contextReader{ctx: ctx, source: io.LimitReader(file, maximum+1)}, digest)
	if err := consume(reader); err != nil {
		invalid = ctx.Err() == nil
		return err
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return err
	}
	var actual [32]byte
	copy(actual[:], digest.Sum(nil))
	if actual != current.digest {
		invalid = true
		return fmt.Errorf("metadata cache integrity failed")
	}
	return ctx.Err()
}

func (c *Cache) remove(key string) error {
	value, ok := c.entries[key]
	if !ok {
		return nil
	}
	if err := os.Remove(value.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	delete(c.entries, key)
	c.bytes -= value.bytes
	return nil
}
func (c *Cache) Close() error {
	if c == nil {
		return nil
	}
	c.lock <- struct{}{}
	defer func() { <-c.lock }()
	if c.closed {
		return nil
	}
	c.closed = true
	c.entries = nil
	if c.directory != "" {
		return os.RemoveAll(c.directory)
	} // Only this cache's uniquely created private directory.
	return nil
}

type boundedWriter struct {
	ctx            context.Context
	output         io.Writer
	maximum, bytes int64
}

func (w *boundedWriter) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(data)) > w.maximum-w.bytes {
		return 0, fmt.Errorf("metadata cache entry exceeds bound")
	}
	n, err := w.output.Write(data)
	w.bytes += int64(n)
	return n, err
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r *contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(data)
}

// Fingerprint observes identity, size and times without reading evidence bodies.
// Equality is not a reusable content version on every platform; use UseFile.
func Fingerprint(file *os.File) ([32]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return [32]byte{}, err
	}
	if !info.Mode().IsRegular() {
		return [32]byte{}, fmt.Errorf("metadata source is not a regular file")
	}
	identity, err := identityAndChange(file, info)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256([]byte(fmt.Sprintf("%d/%d/%d/%d/%s", info.Size(), info.Mode(), info.ModTime().Unix(), info.ModTime().Nanosecond(), identity))), nil
}

func outsideEvidence(roots []string) error {
	temporary, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		return err
	}
	temporary, err = filepath.Abs(temporary)
	if err != nil {
		return err
	}
	for _, root := range roots {
		info, err := os.Stat(root)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		for parent := temporary; ; parent = filepath.Dir(parent) {
			current, err := os.Stat(parent)
			if err != nil {
				return err
			}
			if os.SameFile(info, current) {
				return fmt.Errorf("metadata cache temporary directory is inside an evidence repository")
			}
			if parent == filepath.Dir(parent) {
				break
			}
		}
	}
	return nil
}
