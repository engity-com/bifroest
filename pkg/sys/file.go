package sys

import "os"

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
