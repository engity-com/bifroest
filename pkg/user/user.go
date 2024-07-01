package user

import (
	"fmt"
	"strconv"
)

type User struct {
	Name        string
	DisplayName string
	Uid         uint64
	Gid         uint64
	Shell       string
	HomeDir     string
}

func (this User) String() string {
	return fmt.Sprintf("%d(%s)", this.Uid, this.Name)
}

func (this User) GetGroup() (*Group, error) {
	g, err := LookupGid(this.Gid)
	if err != nil {
		return nil, fmt.Errorf("user %v: %w", this, err)
	}

	if g == nil {
		return &Group{
			Gid:  this.Gid,
			Name: strconv.FormatUint(this.Gid, 10),
		}, nil
	}

	return g, nil
}

func (this User) GetGroups() ([]*Group, error) {
	gids, err := this.GetGids()
	if err != nil {
		return nil, err
	}
	gs := make([]*Group, len(gids))
	for i, gid := range gids {
		g, err := LookupGid(gid)
		if err != nil {
			return nil, fmt.Errorf("user %v: %w", this, err)
		}
		if g == nil {
			gs[i] = &Group{
				Gid:  gid,
				Name: strconv.FormatUint(gid, 10),
			}
		} else {
			gs[i] = g
		}
	}
	return gs, nil
}
