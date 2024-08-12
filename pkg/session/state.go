package session

import "fmt"

type State uint8

const (
	StateUnchanged State = iota
	StateNew
	StateAuthorized
)

func (this *State) UnmarshalText(text []byte) error {
	switch string(text) {
	case "", "unchanged":
		*this = StateUnchanged
	case "new":
		*this = StateNew
	case "authorized":
		*this = StateAuthorized
	default:
		return fmt.Errorf("illegal state %s", string(text))
	}
	return nil
}

func (this State) MarshalText() (text []byte, err error) {
	switch this {
	case StateUnchanged:
		return nil, nil
	case StateNew:
		return []byte("new"), nil
	case StateAuthorized:
		return []byte("authorized"), nil
	default:
		return nil, fmt.Errorf("illegal state %d", this)
	}
}

func (this State) String() string {
	str, err := this.MarshalText()
	if err != nil {
		return fmt.Sprintf("illegal-state-%d", this)
	}
	return string(str)
}
