//go:build unix && !darwin

package user

func (this Requirement) doesFulfilRef(target *etcPasswdRef) bool {
	if target == nil || (this.Name == "" && this.Uid == nil) {
		return false
	}
	uid := Id(target.uid)
	return (this.Name == "" || this.Name == string(target.etcPasswdEntry.name)) &&
		this.DisplayName == string(target.etcPasswdEntry.geocs) &&
		(this.Uid == nil || *this.Uid == uid) &&
		this.Shell == string(target.etcPasswdEntry.shell) &&
		this.HomeDir == string(target.etcPasswdEntry.homeDir)
}

func (this GroupRequirement) doesFulfilRef(ref *etcGroupRef) bool {
	if ref == nil || (this.Name == "" && this.Gid == nil) {
		return false
	}
	gid := GroupId(ref.gid)
	return (this.Gid == nil || *this.Gid == gid) &&
		(this.Name == "" || this.Name == string(ref.name))
}
