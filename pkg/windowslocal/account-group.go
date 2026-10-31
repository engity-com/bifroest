package windowslocal

import "fmt"

type group struct {
	Name string
	SID  string
}

func (g group) GetField(name string) (any, bool, error) {
	switch name {
	case "name":
		return g.Name, true, nil
	case "gid":
		return g.SID, true, nil
	default:
		return nil, false, fmt.Errorf("unknown group field %q", name)
	}
}
