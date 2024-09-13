package sys

type someAddr string

func (someAddr) Network() string     { return "someAddr" }
func (this someAddr) String() string { return string(this) }
