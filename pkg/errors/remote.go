package errors

func AsRemoteError(err error) error {
	if err == nil {
		return nil
	}
	return RemoteError{err}
}

type RemoteError struct {
	Err error
}

func (this RemoteError) Error() string {
	if v := this.Err; v != nil {
		return v.Error()
	}
	return ""
}

func (this RemoteError) String() string {
	return this.Error()
}

func (this RemoteError) Unwrap() error {
	return this.Err
}
