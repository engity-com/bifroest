package user

import "syscall"

func (this User) ToCredentials() syscall.Credential {
	gids := make([]uint32, len(this.Groups))
	for i, gid := range this.Groups {
		gids[i] = uint32(gid.Gid)
	}
	return syscall.Credential{
		Uid:    uint32(this.Uid),
		Gid:    uint32(this.Group.Gid),
		Groups: gids,
	}
}
