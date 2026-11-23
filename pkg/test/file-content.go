package test

import (
	"errors"
	"os"
	"path/filepath"
)

type contentEntry struct {
	file    *os.File
	info    os.FileInfo
	content string
}

// Each physical suite gets its own root and immutable content snapshot. Capture
// on first use; later replays do not reread or depend on filesystem changes.
type fileContents struct {
	root      *os.Root
	byPath    map[string]string
	entries   []contentEntry
	bytes     int
	directory string
	inputs    []string
}

func newFileContents(directory string) (*fileContents, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	return &fileContents{root: root, directory: directory, byPath: map[string]string{}}, nil
}

func (this *fileContents) Close() error {
	var result error
	for _, entry := range this.entries {
		result = errors.Join(result, entry.file.Close())
	}
	return errors.Join(result, this.root.Close())
}

func (this *fileContents) read(name string) (string, error) {
	if !filepath.IsLocal(name) || len(name) > maxString {
		return "", invalid("file_content requires a confined relative path")
	}
	name = filepath.Clean(name)
	if content, found := this.byPath[name]; found {
		return content, nil
	}
	if len(this.byPath) >= 64 {
		return "", invalid("file_content file count limit exceeded")
	}
	file, err := this.root.OpenFile(name, os.O_RDONLY|sourceOpenFlags, 0)
	if err != nil {
		return "", invalid("file_content input is unavailable or outside the suite directory")
	}
	this.inputs = append(this.inputs, filepath.Join(this.directory, name))
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return "", invalid("file_content requires a regular file")
	}
	for _, previous := range this.entries {
		if os.SameFile(previous.info, info) {
			_ = file.Close()
			this.byPath[name] = previous.content
			return previous.content, nil
		}
	}
	content, err := readSource(file)
	if err != nil {
		_ = file.Close()
		return "", err
	}
	if this.bytes+len(content) > 4<<20 {
		_ = file.Close()
		return "", invalid("file_content total size limit exceeded")
	}
	this.bytes += len(content)
	plain := string(content)
	this.byPath[name] = plain
	// Pin the identity until the suite finishes. FileInfo alone would let a
	// deleted file's reused inode/file ID alias an unrelated new input. The
	// existing 64-path bound also bounds these retained handles.
	this.entries = append(this.entries, contentEntry{file: file, info: info, content: plain})
	return plain, nil
}
