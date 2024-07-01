package user

type Requirement struct {
	Name        string
	DisplayName string
	Uid         uint64
	Group       GroupRequirement
	Groups      []GroupRequirement
	Shell       string
}
