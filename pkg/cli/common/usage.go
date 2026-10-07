package common

type Usage uint8

const (
	UsageExecutable Usage = iota
	UsageManagement
)

func (this Usage) IncludeService() bool {
	switch this {
	case UsageExecutable:
		return true
	default:
		return false
	}
}

func (this Usage) IncludeExec() bool {
	switch this {
	case UsageExecutable:
		return true
	default:
		return false
	}
}
