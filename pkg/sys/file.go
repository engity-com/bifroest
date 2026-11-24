package sys

import "os"

// OpenFileForRotation opens an existing file read-only without preventing an
// atomic replacement of its name. Existing handles keep reading the old file.
// Callers remain responsible for validating the file's identity and permissions.
func OpenFileForRotation(path string) (*os.File, error) {
	return openFileForRotation(path)
}

type CloneableFile interface {
	Fd() uintptr
	Name() string
}

func CloneFile(f CloneableFile) (*os.File, error) {
	cf, err := cloneFile(f)
	if err != nil {
		return nil, &os.PathError{
			Op: "clone", Path: f.Name(), Err: err,
		}
	}
	return cf, nil
}
