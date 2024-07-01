package user

import "fmt"

type Group struct {
	Gid  uint64
	Name string
}

func (this Group) String() string {
	return fmt.Sprintf("%d(%s)", this.Gid, this.Name)
}
