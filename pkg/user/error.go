package user

type StringError string

func (this StringError) Error() string {
	return string(this)
}
