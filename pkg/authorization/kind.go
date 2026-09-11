package authorization

type kindAware interface {
	AuthorizationKind() string
}

func KindOf(auth Authorization) string {
	if value, ok := auth.(kindAware); ok {
		return value.AuthorizationKind()
	}
	return ""
}
