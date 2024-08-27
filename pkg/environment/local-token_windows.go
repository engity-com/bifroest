//go:build windows

package environment

type localToken struct {
	PortForwardingAllowed bool `json:"portForwardingAllowed"`
}

func (this *LocalRepository) newLocalToken(req Request) (*localToken, error) {
	fail := func(err error) (*localToken, error) {
		return nil, err
	}

	portForwardingAllowed, err := this.conf.PortForwardingAllowed.Render(req)
	if err != nil {
		return fail(err)
	}

	return &localToken{
		portForwardingAllowed,
	}, nil
}
