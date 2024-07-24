package user

type Repository interface {
	LookupByName(string) (*User, error)
	LookupById(Id) (*User, error)

	LookupGroupByName(string) (*Group, error)
	LookupGroupById(GroupId) (*Group, error)
}
