package authorization

import glssh "github.com/gliderlabs/ssh"

type ContextEnabled interface {
	Context() glssh.Context
}

func getField(name string, ce ContextEnabled, of Authorization, def func() (any, bool, error)) (any, bool, error) {
	switch name {
	case "remote":
		return of.Remote(), true, nil
	case "isAuthorized":
		return of.IsAuthorized(), true, nil
	case "envVars":
		return of.EnvVars(), true, nil
	case "flow":
		return of.Flow(), true, nil
	case "session":
		sess := of.FindSession()
		if sess == nil {
			return nil, true, nil
		}
		si, err := sess.Info(ce.Context())
		return si, true, err
	case "sessionsPublicKey":
		return of.FindSessionsPublicKey(), true, nil
	default:
		return def()
	}
}
