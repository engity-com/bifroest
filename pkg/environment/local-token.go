package environment

type localToken struct {
	User                  localTokenUser `json:"user"`
	PortForwardingAllowed bool           `json:"portForwardingAllowed"`
}
